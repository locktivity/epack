package sync

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strings"

	"github.com/locktivity/epack/internal/component/config"
	"github.com/locktivity/epack/internal/component/github"
	"github.com/locktivity/epack/internal/component/lockfile"
	"github.com/locktivity/epack/internal/componenttypes"
	"github.com/locktivity/epack/internal/platform"
	"github.com/locktivity/epack/internal/timestamp"
)

// Locker resolves component sources and writes lockfile entries.
type Locker struct {
	Registry     RegistryClient
	LockfilePath string
	BaseDir      string           // .epack directory
	Verifier     SigstoreVerifier // nil verifies with Sigstore
}

// NewLocker creates a locker with default paths using the default GitHub registry.
func NewLocker(workDir string) *Locker {
	return &Locker{
		Registry:     NewGitHubRegistry(),
		LockfilePath: filepath.Join(workDir, lockfile.FileName),
		BaseDir:      filepath.Join(workDir, ".epack"),
	}
}

// NewLockerWithRegistry creates a locker with a custom registry client.
// Useful for testing or multi-registry support.
func NewLockerWithRegistry(registry RegistryClient, workDir string) *Locker {
	return &Locker{
		Registry:     registry,
		LockfilePath: filepath.Join(workDir, lockfile.FileName),
		BaseDir:      filepath.Join(workDir, ".epack"),
	}
}

// LockOpts controls locking behavior.
type LockOpts struct {
	Platforms    []string // Platforms to lock (e.g., "linux/amd64"). Empty = current platform only.
	AllPlatforms bool     // Lock all available platforms from release.
	// Prune drops entries for components and files the config no longer
	// lists. Only a caller passing the whole config may set it: a config
	// filtered to a few components would drop every other entry.
	Prune bool
	// KeepPins keeps each pinned version its range still admits from the
	// same source, and resolves only components that are new, out of range,
	// or from another source. Without it every range resolves to its newest
	// release.
	KeepPins bool
}

// LockResult contains the result of a lock operation.
type LockResult struct {
	Name      string // Component name (collector, tool, or remote)
	Kind      string // "collector", "tool", "remote", "profile", "overlay", or "mapping"
	Version   string
	Platforms []string
	IsNew     bool
	Updated   bool
	Removed   bool // Dropped because the config no longer lists it
	Kept      bool // Pin carried over because its range still admits it
}

// DisplayName returns the formatted component name for output.
// Components with versions display as "name@version", others as just "name".
func (r LockResult) DisplayName() string {
	if r.Version != "" {
		return r.Name + "@" + r.Version
	}
	return r.Name
}

// PlatformSuffix returns the platform list formatted for display, or empty string if none.
func (r LockResult) PlatformSuffix() string {
	if len(r.Platforms) == 0 {
		return ""
	}
	return " (" + strings.Join(r.Platforms, ", ") + ")"
}

// Summary is the line lock output prints for the entry, such as
// "updated github@v0.2.1 (linux/amd64)" or "removed okta@v0.2.0 (not in config)".
func (r LockResult) Summary() string {
	switch {
	case r.Removed:
		return "removed " + r.DisplayName() + " (not in config)"
	case r.Kept:
		return "kept " + r.DisplayName() + r.PlatformSuffix()
	case r.Updated:
		return "updated " + r.DisplayName() + r.PlatformSuffix()
	case r.IsNew:
		return "added " + r.DisplayName() + r.PlatformSuffix()
	default:
		return "locked " + r.DisplayName() + r.PlatformSuffix()
	}
}

// Lock resolves all source-based collectors and tools in config and updates lockfile.
func (l *Locker) Lock(ctx context.Context, cfg *config.JobConfig, opts LockOpts) ([]LockResult, error) {
	// Load existing lockfile or create new
	lf, err := l.LoadOrCreateLockfile()
	if err != nil {
		return nil, err
	}

	collectorResults, err := l.lockCollectors(ctx, cfg.Collectors, lf, opts)
	if err != nil {
		return nil, err
	}

	toolResults, err := l.lockTools(ctx, cfg.Tools, lf, opts)
	if err != nil {
		return nil, err
	}

	remoteResults, err := l.lockRemotes(ctx, cfg.Remotes, lf, opts)
	if err != nil {
		return nil, err
	}

	// Lock profiles and overlays (computes digests for local files)
	profileResults, err := LockLocalFiles(cfg, lf, filepath.Dir(l.LockfilePath))
	if err != nil {
		return nil, fmt.Errorf("locking profiles: %w", err)
	}

	var removed []LockResult
	if opts.Prune {
		removed = pruneStaleEntries(cfg, lf)
	}

	// Save lockfile
	if err := lf.Save(l.LockfilePath); err != nil {
		return nil, fmt.Errorf("saving lockfile: %w", err)
	}

	results := make([]LockResult, 0, len(collectorResults)+len(toolResults)+len(remoteResults)+len(profileResults))
	results = append(results, collectorResults...)
	results = append(results, toolResults...)
	results = append(results, remoteResults...)

	// Convert profile results to LockResult format
	for _, pr := range profileResults {
		results = append(results, LockResult{
			Name:    pr.Source,
			Kind:    pr.Kind,
			IsNew:   pr.IsNew,
			Updated: pr.Updated,
		})
	}

	return append(results, removed...), nil
}

// StaleLockEntries lists the lockfile entries for components and local files
// the config no longer lists, in kind and then name order. A locked sync
// refuses a lockfile that has any.
func StaleLockEntries(cfg *config.JobConfig, lf *lockfile.LockFile) []LockResult {
	var stale []LockResult
	stale = appendStale(stale, "collector", lf.Collectors, keySet(mapKeys(cfg.Collectors)), func(e lockfile.LockedCollector) string { return e.Version })
	stale = appendStale(stale, "tool", lf.Tools, keySet(mapKeys(cfg.Tools)), func(e lockfile.LockedTool) string { return e.Version })
	stale = appendStale(stale, "remote", lf.Remotes, keySet(mapKeys(cfg.Remotes)), func(e lockfile.LockedRemote) string { return e.Version })
	stale = appendStale(stale, profileKind.name, lf.Profiles, keySet(profileKind.configKeys(cfg)), func(e lockfile.LockedProfile) string { return e.Version })
	stale = appendStale(stale, overlayKind.name, lf.Overlays, keySet(overlayKind.configKeys(cfg)), func(e lockfile.LockedOverlay) string { return e.Version })
	stale = appendStale(stale, mappingKind.name, lf.Mappings, keySet(mappingKind.configKeys(cfg)), func(lockfile.LockedMapping) string { return "" })
	return stale
}

func pruneStaleEntries(cfg *config.JobConfig, lf *lockfile.LockFile) []LockResult {
	stale := StaleLockEntries(cfg, lf)
	for _, entry := range stale {
		switch entry.Kind {
		case "collector":
			delete(lf.Collectors, entry.Name)
		case "tool":
			delete(lf.Tools, entry.Name)
		case "remote":
			delete(lf.Remotes, entry.Name)
		case profileKind.name:
			delete(lf.Profiles, entry.Name)
		case overlayKind.name:
			delete(lf.Overlays, entry.Name)
		case mappingKind.name:
			delete(lf.Mappings, entry.Name)
		}
	}
	return stale
}

func appendStale[V any](stale []LockResult, kind string, locked map[string]V, listed map[string]bool, version func(V) string) []LockResult {
	names := make([]string, 0, len(locked))
	for name := range locked {
		if !listed[name] {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	for _, name := range names {
		stale = append(stale, LockResult{Name: name, Kind: kind, Version: version(locked[name]), Removed: true})
	}
	return stale
}

func keySet(keys []string) map[string]bool {
	set := make(map[string]bool, len(keys))
	for _, key := range keys {
		set[key] = true
	}
	return set
}

func (l *Locker) lockCollectors(ctx context.Context, collectors map[string]config.CollectorConfig, lf *lockfile.LockFile, opts LockOpts) ([]LockResult, error) {
	return lockByKind(ctx, collectors, lf, opts,
		func(ctx context.Context, name string, collector config.CollectorConfig, lf *lockfile.LockFile, opts LockOpts) (*LockResult, error) {
			if collector.Source == "" {
				result, err := l.lockExternalCollector(ctx, name, collector, lf, opts)
				if err != nil {
					return nil, fmt.Errorf("locking external collector %q: %w", name, err)
				}
				return result, nil
			}
			result, err := l.lockSourceCollector(ctx, name, collector, lf, opts)
			if err != nil {
				return nil, fmt.Errorf("locking collector %q: %w", name, err)
			}
			return result, nil
		})
}

func (l *Locker) lockTools(ctx context.Context, tools map[string]config.ToolConfig, lf *lockfile.LockFile, opts LockOpts) ([]LockResult, error) {
	return lockByKind(ctx, tools, lf, opts,
		func(ctx context.Context, name string, tool config.ToolConfig, lf *lockfile.LockFile, opts LockOpts) (*LockResult, error) {
			if tool.Source == "" {
				result, err := l.lockExternalTool(ctx, name, tool, lf, opts)
				if err != nil {
					return nil, fmt.Errorf("locking external tool %q: %w", name, err)
				}
				return result, nil
			}
			result, err := l.lockSourceTool(ctx, name, tool, lf, opts)
			if err != nil {
				return nil, fmt.Errorf("locking tool %q: %w", name, err)
			}
			return result, nil
		})
}

func (l *Locker) lockRemotes(ctx context.Context, remotes map[string]config.RemoteConfig, lf *lockfile.LockFile, opts LockOpts) ([]LockResult, error) {
	return lockByKind(ctx, remotes, lf, opts,
		func(ctx context.Context, name string, remoteCfg config.RemoteConfig, lf *lockfile.LockFile, opts LockOpts) (*LockResult, error) {
			if remoteCfg.Source == "" {
				// Adapter-only remotes don't need locking.
				if remoteCfg.Binary == "" {
					return nil, nil
				}
				result, err := l.lockExternalRemote(ctx, name, remoteCfg, lf, opts)
				if err != nil {
					return nil, fmt.Errorf("locking external remote %q: %w", name, err)
				}
				return result, nil
			}
			result, err := l.lockSourceRemote(ctx, name, remoteCfg, lf, opts)
			if err != nil {
				return nil, fmt.Errorf("locking remote %q: %w", name, err)
			}
			return result, nil
		})
}

type lockKindFunc[T any] func(context.Context, string, T, *lockfile.LockFile, LockOpts) (*LockResult, error)

// lockByKind runs a per-component lock function in deterministic name order.
func lockByKind[T any](
	ctx context.Context,
	components map[string]T,
	lf *lockfile.LockFile,
	opts LockOpts,
	fn lockKindFunc[T],
) ([]LockResult, error) {
	names := make([]string, 0, len(components))
	for name := range components {
		names = append(names, name)
	}
	sort.Strings(names)

	results := make([]LockResult, 0, len(names))
	for _, name := range names {
		result, err := fn(ctx, name, components[name], lf, opts)
		if err != nil {
			return nil, err
		}
		if result != nil {
			results = append(results, *result)
		}
	}
	return results, nil
}

// lockSourceCollector locks a source-based collector.
func (l *Locker) lockSourceCollector(ctx context.Context, name string, cfg config.CollectorConfig, lf *lockfile.LockFile, opts LockOpts) (*LockResult, error) {
	return l.lockSourceComponent(ctx, name, cfg.Source, name, "collector", opts,
		func() (lockedPin, bool) {
			existing, exists := lf.GetCollector(name)
			return lockedPin{Kind: existing.Kind, Source: existing.Source, Version: existing.Version, Signer: existing.Signer, Platforms: existing.Platforms}, exists
		},
		func(sourceURI, selectedTag, commit string, signer *componenttypes.LockedSigner, platforms map[string]componenttypes.LockedPlatform) {
			lf.Collectors[name] = lockfile.LockedCollector{
				Source:  sourceURI,
				Version: selectedTag,
				Commit:  commit,
				Signer:  signer,
				Verification: &componenttypes.Verification{
					Status:     "verified",
					VerifiedAt: timestamp.Now().String(),
				},
				LockedAt:  timestamp.Now().String(),
				Platforms: platforms,
			}
		})
}

// lockExternalCollector locks an external binary collector (digest only).
func (l *Locker) lockExternalCollector(ctx context.Context, name string, cfg config.CollectorConfig, lf *lockfile.LockFile, opts LockOpts) (*LockResult, error) {
	if cfg.Binary == "" {
		return nil, nil
	}

	// Compute digest of external binary
	digest, err := ComputeDigest(cfg.Binary)
	if err != nil {
		return nil, fmt.Errorf("computing digest of %s: %w", cfg.Binary, err)
	}

	platformKey := platform.Key(runtime.GOOS, runtime.GOARCH)

	existing, exists := lf.GetCollector(name)
	isNew := !exists

	// For external, we only track the current platform's digest
	platforms := make(map[string]componenttypes.LockedPlatform)
	if exists {
		// Preserve other platforms
		for p, entry := range existing.Platforms {
			platforms[p] = entry
		}
	}
	platforms[platformKey] = componenttypes.LockedPlatform{Digest: digest}

	lf.Collectors[name] = lockfile.LockedCollector{
		Kind:         "external",
		Verification: &componenttypes.Verification{Status: "skipped"},
		LockedAt:     timestamp.Now().String(),
		Platforms:    platforms,
	}

	return &LockResult{
		Name:      name,
		Kind:      "collector",
		Platforms: []string{platformKey},
		IsNew:     isNew,
		Updated:   !isNew,
	}, nil
}

// LoadOrCreateLockfile loads the existing lockfile or creates a new one.
func (l *Locker) LoadOrCreateLockfile() (*lockfile.LockFile, error) {
	lf, err := lockfile.Load(l.LockfilePath)
	if os.IsNotExist(err) {
		return lockfile.New(), nil
	}
	if err != nil {
		return nil, fmt.Errorf("loading lockfile: %w", err)
	}
	return lf, nil
}

// resolvePlatforms determines which platforms to lock.
func (l *Locker) resolvePlatforms(opts LockOpts, release *ReleaseInfo, componentName string) []string {
	if opts.AllPlatforms {
		return l.DetectAvailablePlatforms(release, componentName)
	}
	if len(opts.Platforms) > 0 {
		return opts.Platforms
	}
	return []string{platform.Key(runtime.GOOS, runtime.GOARCH)}
}

// DetectAvailablePlatforms finds all platforms available in a release.
func (l *Locker) DetectAvailablePlatforms(release *ReleaseInfo, componentName string) []string {
	knownPlatforms := []string{
		"linux/amd64", "linux/arm64",
		"darwin/amd64", "darwin/arm64",
		"windows/amd64",
	}

	var available []string
	for _, plat := range knownPlatforms {
		goos, goarch := platform.Split(plat)
		if _, err := l.Registry.FindBinaryAsset(release, componentName, goos, goarch); err == nil {
			available = append(available, plat)
		}
	}
	return available
}

// lockSourceTool locks a source-based tool.
// Tools use the same locking mechanism as collectors.
func (l *Locker) lockSourceTool(ctx context.Context, name string, cfg config.ToolConfig, lf *lockfile.LockFile, opts LockOpts) (*LockResult, error) {
	return l.lockSourceComponent(ctx, name, cfg.Source, name, "tool", opts,
		func() (lockedPin, bool) {
			existing, exists := lf.GetTool(name)
			return lockedPin{Kind: existing.Kind, Source: existing.Source, Version: existing.Version, Signer: existing.Signer, Platforms: existing.Platforms}, exists
		},
		func(sourceURI, selectedTag, commit string, signer *componenttypes.LockedSigner, platforms map[string]componenttypes.LockedPlatform) {
			lf.Tools[name] = lockfile.LockedTool{
				Source:  sourceURI,
				Version: selectedTag,
				Commit:  commit,
				Signer:  signer,
				Verification: &componenttypes.Verification{
					Status:     "verified",
					VerifiedAt: timestamp.Now().String(),
				},
				LockedAt:  timestamp.Now().String(),
				Platforms: platforms,
			}
		})
}

// lockExternalTool locks an external binary tool (digest only).
func (l *Locker) lockExternalTool(ctx context.Context, name string, cfg config.ToolConfig, lf *lockfile.LockFile, opts LockOpts) (*LockResult, error) {
	if cfg.Binary == "" {
		return nil, nil
	}

	// Compute digest of external binary
	digest, err := ComputeDigest(cfg.Binary)
	if err != nil {
		return nil, fmt.Errorf("computing digest of %s: %w", cfg.Binary, err)
	}

	platformKey := platform.Key(runtime.GOOS, runtime.GOARCH)

	existing, exists := lf.GetTool(name)
	isNew := !exists

	// For external, we only track the current platform's digest
	platforms := make(map[string]componenttypes.LockedPlatform)
	if exists {
		// Preserve other platforms
		for p, entry := range existing.Platforms {
			platforms[p] = entry
		}
	}
	platforms[platformKey] = componenttypes.LockedPlatform{Digest: digest}

	lf.Tools[name] = lockfile.LockedTool{
		Kind:         "external",
		Verification: &componenttypes.Verification{Status: "skipped"},
		LockedAt:     timestamp.Now().String(),
		Platforms:    platforms,
	}

	return &LockResult{
		Name:      name,
		Kind:      "tool",
		Platforms: []string{platformKey},
		IsNew:     isNew,
		Updated:   !isNew,
	}, nil
}

// lockSourceRemote locks a source-based remote adapter.
// LockRemote resolves one remote's source into lf without saving it. The
// user-level remotes lock lives outside any project and is saved by its owner.
func (l *Locker) LockRemote(ctx context.Context, name string, cfg config.RemoteConfig, lf *lockfile.LockFile, opts LockOpts) (*LockResult, error) {
	if cfg.Source == "" {
		return nil, fmt.Errorf("remote %q has no source to lock", name)
	}
	return l.lockSourceRemote(ctx, name, cfg, lf, opts)
}

// Remote adapters use the same locking mechanism as collectors and tools.
func (l *Locker) lockSourceRemote(ctx context.Context, name string, cfg config.RemoteConfig, lf *lockfile.LockFile, opts LockOpts) (*LockResult, error) {
	adapterName := cfg.EffectiveAdapter()
	if adapterName == "" {
		return nil, fmt.Errorf("cannot determine adapter name for remote %q", name)
	}
	binaryName := "epack-remote-" + adapterName
	return l.lockSourceComponent(ctx, name, cfg.Source, binaryName, "remote", opts,
		func() (lockedPin, bool) {
			existing, exists := lf.GetRemote(name)
			return lockedPin{Kind: existing.Kind, Source: existing.Source, Version: existing.Version, Signer: existing.Signer, Platforms: existing.Platforms}, exists
		},
		func(sourceURI, selectedTag, commit string, signer *componenttypes.LockedSigner, platforms map[string]componenttypes.LockedPlatform) {
			lf.Remotes[name] = lockfile.LockedRemote{
				Source:  sourceURI,
				Version: selectedTag,
				Commit:  commit,
				Signer:  signer,
				Verification: &componenttypes.Verification{
					Status:     "verified",
					VerifiedAt: timestamp.Now().String(),
				},
				LockedAt:  timestamp.Now().String(),
				Platforms: platforms,
			}
		})
}

func (l *Locker) lockSourceComponent(
	ctx context.Context,
	name, sourceRef, binaryLookupName, kind string,
	opts LockOpts,
	getExisting func() (lockedPin, bool),
	updateEntry func(sourceURI, selectedTag, commit string, signer *componenttypes.LockedSigner, platforms map[string]componenttypes.LockedPlatform),
) (*LockResult, error) {
	existing, exists := getExisting()
	pinnedTag := ""
	if opts.KeepPins && exists && pinAdmitted(kind, name, sourceRef, existing) {
		if !missingRequestedPlatform(opts, existing.Platforms) {
			result := buildSourceLockResult(name, kind, existing.Version, existing.Platforms, true, existing.Version)
			result.Kept = true
			return result, nil
		}
		pinnedTag = existing.Version
	}
	resolved, err := l.resolveSourceComponentVersion(ctx, sourceRef, binaryLookupName, opts, pinnedTag)
	if err != nil {
		return nil, err
	}
	platforms := platformsToLock(resolved.platforms, existing.Platforms, exists && existing.Version != resolved.selectedTag, opts.AllPlatforms)
	lockedPlatforms, signer, err := l.lockSourcePlatforms(
		ctx, name, binaryLookupName, resolved.owner, resolved.repo, resolved.selectedTag, resolved.release, platforms, opts,
	)
	if err != nil {
		return nil, err
	}
	if len(lockedPlatforms) == 0 {
		return nil, fmt.Errorf("no platforms could be locked")
	}

	mergeExistingPlatforms(lockedPlatforms, existing.Platforms, exists, opts.AllPlatforms)
	updateEntry(BuildSourceURI(resolved.owner, resolved.repo), resolved.selectedTag, resolved.commit, signer, lockedPlatforms)
	return buildSourceLockResult(name, kind, resolved.selectedTag, lockedPlatforms, exists, existing.Version), nil
}

// lockedPin is what an existing entry for a source component records.
type lockedPin struct {
	Kind      string
	Source    string
	Version   string
	Signer    *componenttypes.LockedSigner
	Platforms map[string]componenttypes.LockedPlatform
}

// pinAdmitted reports whether an existing entry has the configured
// repository, a signer from that repository, and a version the range admits.
// A locked sync checks the same things, so a kept pin installs.
func pinAdmitted(kind, name, sourceRef string, pin lockedPin) bool {
	if pin.Kind == "external" || pin.Version == "" || pin.Signer == nil {
		return false
	}
	if validateSourceAndSignerMatch(kind, name, sourceRef, pin.Source, pin.Signer, "epack lock") != nil {
		return false
	}
	return ValidateVersionSatisfaction(kind, name, sourceRef, pin.Version, "epack lock") == nil
}

// missingRequestedPlatform reports whether a kept pin lacks a platform the
// caller asked for. Locking all platforms keeps whatever the pin carries.
func missingRequestedPlatform(opts LockOpts, locked map[string]componenttypes.LockedPlatform) bool {
	if opts.AllPlatforms {
		return false
	}
	requested := opts.Platforms
	if len(requested) == 0 {
		requested = []string{platform.Key(runtime.GOOS, runtime.GOARCH)}
	}
	for _, plat := range requested {
		if _, ok := locked[plat]; !ok {
			return true
		}
	}
	return false
}

type resolvedSourceComponent struct {
	owner       string
	repo        string
	selectedTag string
	commit      string
	release     *ReleaseInfo
	platforms   []string
}

// A pinnedTag skips resolving the range and locks that release.
func (l *Locker) resolveSourceComponentVersion(
	ctx context.Context,
	sourceRef, binaryLookupName string,
	opts LockOpts,
	pinnedTag string,
) (*resolvedSourceComponent, error) {
	owner, repo, versionConstraint, err := github.ParseSource(sourceRef)
	if err != nil {
		return nil, err
	}
	source := fmt.Sprintf("%s/%s", owner, repo)
	selectedTag := pinnedTag
	if selectedTag == "" {
		selectedTag, err = l.Registry.ResolveVersion(ctx, source, versionConstraint)
		if err != nil {
			return nil, fmt.Errorf("resolving version: %w", err)
		}
	}
	release, err := l.Registry.FetchRelease(ctx, source, selectedTag)
	if err != nil {
		return nil, fmt.Errorf("fetching release %s: %w", selectedTag, err)
	}
	platforms := l.resolvePlatforms(opts, release, binaryLookupName)
	if len(platforms) == 0 {
		return nil, fmt.Errorf("no platforms to lock")
	}
	return &resolvedSourceComponent{
		owner:       owner,
		repo:        repo,
		selectedTag: selectedTag,
		commit:      release.Commit,
		release:     release,
		platforms:   platforms,
	}, nil
}

// Existing entries hold the previous release's digests, so a new version
// relocks every platform already in the lockfile.
func platformsToLock(requested []string, existing map[string]componenttypes.LockedPlatform, versionChanged, allPlatforms bool) []string {
	if !versionChanged || allPlatforms {
		return requested
	}
	platforms := slices.Clone(requested)
	for p := range existing {
		if !slices.Contains(platforms, p) {
			platforms = append(platforms, p)
		}
	}
	sort.Strings(platforms)
	return platforms
}

func mergeExistingPlatforms(lockedPlatforms, existingPlatforms map[string]componenttypes.LockedPlatform, exists, allPlatforms bool) {
	if !exists || allPlatforms {
		return
	}
	for p, entry := range existingPlatforms {
		if _, alreadyLocked := lockedPlatforms[p]; !alreadyLocked {
			lockedPlatforms[p] = entry
		}
	}
}

func buildSourceLockResult(name, kind, selectedTag string, lockedPlatforms map[string]componenttypes.LockedPlatform, exists bool, existingVersion string) *LockResult {
	lockedPlatformNames := make([]string, 0, len(lockedPlatforms))
	for p := range lockedPlatforms {
		lockedPlatformNames = append(lockedPlatformNames, p)
	}
	sort.Strings(lockedPlatformNames)
	return &LockResult{
		Name:      name,
		Kind:      kind,
		Version:   selectedTag,
		Platforms: lockedPlatformNames,
		IsNew:     !exists,
		Updated:   exists && existingVersion != selectedTag,
	}
}

func (l *Locker) lockSourcePlatforms(
	ctx context.Context,
	name, binaryLookupName, owner, repo, selectedTag string,
	release *ReleaseInfo,
	platforms []string,
	opts LockOpts,
) (map[string]componenttypes.LockedPlatform, *componenttypes.LockedSigner, error) {
	lockedPlatforms := make(map[string]componenttypes.LockedPlatform)
	var signer *componenttypes.LockedSigner

	for _, plat := range platforms {
		locked, platformSigner, err := l.lockOneSourcePlatform(ctx, name, binaryLookupName, owner, repo, selectedTag, release, plat, opts)
		if err != nil {
			return nil, nil, err
		}
		if locked == nil {
			continue
		}

		if signer == nil {
			signer = platformSigner
		} else if err := ensureSignerMatches(signer, platformSigner, name, plat); err != nil {
			return nil, nil, err
		}
		lockedPlatforms[plat] = *locked
	}

	return lockedPlatforms, signer, nil
}

func (l *Locker) lockOneSourcePlatform(
	ctx context.Context,
	name, binaryLookupName, owner, repo, selectedTag string,
	release *ReleaseInfo,
	plat string,
	opts LockOpts,
) (*componenttypes.LockedPlatform, *componenttypes.LockedSigner, error) {
	goos, goarch := platform.Split(plat)
	asset, err := l.Registry.FindBinaryAsset(release, binaryLookupName, goos, goarch)
	if err != nil {
		if opts.AllPlatforms {
			return nil, nil, nil
		}
		return nil, nil, fmt.Errorf("finding asset for %s: %w", plat, err)
	}

	digest, platformSigner, err := l.verifyAndDigestAsset(ctx, name, owner, repo, selectedTag, release, asset)
	if err != nil {
		return nil, nil, err
	}

	return &componenttypes.LockedPlatform{Digest: digest, Asset: asset.Name}, platformSigner, nil
}

func (l *Locker) verifyAndDigestAsset(
	ctx context.Context,
	name, owner, repo, selectedTag string,
	release *ReleaseInfo,
	asset *AssetInfo,
) (string, *componenttypes.LockedSigner, error) {
	tmpDir, err := os.MkdirTemp("", "epack-lock-*")
	if err != nil {
		return "", nil, fmt.Errorf("creating temp dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	safeBinaryName, err := SanitizeAssetName(asset.Name)
	if err != nil {
		return "", nil, fmt.Errorf("invalid binary asset name: %w", err)
	}
	binaryPath := filepath.Join(tmpDir, safeBinaryName)
	if err := l.Registry.DownloadAsset(ctx, asset.URL, binaryPath); err != nil {
		return "", nil, fmt.Errorf("downloading %s: %w", asset.Name, err)
	}

	bundleAsset, err := l.Registry.FindSigstoreBundle(release, asset.Name)
	if err != nil {
		return "", nil, fmt.Errorf("finding sigstore bundle for %s: %w", asset.Name, err)
	}
	safeBundleName, err := SanitizeAssetName(bundleAsset.Name)
	if err != nil {
		return "", nil, fmt.Errorf("invalid bundle asset name: %w", err)
	}
	bundlePath := filepath.Join(tmpDir, safeBundleName)
	if err := l.Registry.DownloadAsset(ctx, bundleAsset.URL, bundlePath); err != nil {
		return "", nil, fmt.Errorf("downloading sigstore bundle: %w", err)
	}

	expectedRepoURI := BuildGitHubRepoURL(owner, repo)
	expectedRef := BuildGitHubRefTag(selectedTag)
	expectedIdentity := &ExpectedIdentity{
		SourceRepositoryURI: expectedRepoURI,
		SourceRepositoryRef: expectedRef,
	}
	sigResult, err := l.verifier().Verify(bundlePath, binaryPath, expectedIdentity)
	if err != nil {
		return "", nil, fmt.Errorf("verifying sigstore signature: %w (expected repo=%s, ref=%s)", err, expectedRepoURI, expectedRef)
	}
	if sigResult.SourceRepositoryURI != expectedRepoURI {
		return "", nil, fmt.Errorf("sigstore certificate source_repository_uri mismatch for %s: expected %q, got %q",
			name, expectedRepoURI, sigResult.SourceRepositoryURI)
	}
	if sigResult.SourceRepositoryRef != expectedRef {
		return "", nil, fmt.Errorf("sigstore certificate source_repository_ref mismatch for %s: expected %q, got %q",
			name, expectedRef, sigResult.SourceRepositoryRef)
	}

	digest, err := ComputeDigest(binaryPath)
	if err != nil {
		return "", nil, fmt.Errorf("computing digest: %w", err)
	}

	return digest, &componenttypes.LockedSigner{
		Issuer:              sigResult.Issuer,
		SourceRepositoryURI: sigResult.SourceRepositoryURI,
		SourceRepositoryRef: sigResult.SourceRepositoryRef,
	}, nil
}

func (l *Locker) verifier() SigstoreVerifier {
	if l.Verifier != nil {
		return l.Verifier
	}
	return DefaultSigstoreVerifier{}
}

func ensureSignerMatches(base, candidate *componenttypes.LockedSigner, name, platform string) error {
	if base.Issuer != candidate.Issuer ||
		base.SourceRepositoryURI != candidate.SourceRepositoryURI ||
		base.SourceRepositoryRef != candidate.SourceRepositoryRef {
		return fmt.Errorf("signer mismatch across platforms for %s: %s has different signer than previous platforms", name, platform)
	}
	return nil
}

// lockExternalRemote locks an external binary remote adapter (digest only).
func (l *Locker) lockExternalRemote(ctx context.Context, name string, cfg config.RemoteConfig, lf *lockfile.LockFile, opts LockOpts) (*LockResult, error) {
	if cfg.Binary == "" {
		return nil, nil
	}

	// Compute digest of external binary
	digest, err := ComputeDigest(cfg.Binary)
	if err != nil {
		return nil, fmt.Errorf("computing digest of %s: %w", cfg.Binary, err)
	}

	platformKey := platform.Key(runtime.GOOS, runtime.GOARCH)

	existing, exists := lf.GetRemote(name)
	isNew := !exists

	// For external, we only track the current platform's digest
	platforms := make(map[string]componenttypes.LockedPlatform)
	if exists {
		// Preserve other platforms
		for p, entry := range existing.Platforms {
			platforms[p] = entry
		}
	}
	platforms[platformKey] = componenttypes.LockedPlatform{Digest: digest}

	lf.Remotes[name] = lockfile.LockedRemote{
		Kind:         "external",
		Verification: &componenttypes.Verification{Status: "skipped"},
		LockedAt:     timestamp.Now().String(),
		Platforms:    platforms,
	}

	return &LockResult{
		Name:      name,
		Kind:      "remote",
		Platforms: []string{platformKey},
		IsNew:     isNew,
		Updated:   !isNew,
	}, nil
}
