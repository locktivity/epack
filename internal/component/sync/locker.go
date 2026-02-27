package sync

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"

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
	BaseDir      string // .epack directory
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
}

// LockResult contains the result of a lock operation.
type LockResult struct {
	Name      string // Component name (collector, tool, or remote)
	Kind      string // "collector", "tool", or "remote"
	Version   string
	Platforms []string
	IsNew     bool
	Updated   bool
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

	// Save lockfile
	if err := lf.Save(l.LockfilePath); err != nil {
		return nil, fmt.Errorf("saving lockfile: %w", err)
	}

	results := make([]LockResult, 0, len(collectorResults)+len(toolResults)+len(remoteResults))
	results = append(results, collectorResults...)
	results = append(results, toolResults...)
	results = append(results, remoteResults...)
	return results, nil
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
		func() (string, map[string]componenttypes.LockedPlatform, bool) {
			existing, exists := lf.GetCollector(name)
			return existing.Version, existing.Platforms, exists
		},
		func(sourceURI, selectedTag string, signer *componenttypes.LockedSigner, platforms map[string]componenttypes.LockedPlatform) {
			lf.Collectors[name] = lockfile.LockedCollector{
				Source:    sourceURI,
				Version:   selectedTag,
				Signer:    signer,
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
		Kind:      "external",
		LockedAt:  timestamp.Now().String(),
		Platforms: platforms,
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
		func() (string, map[string]componenttypes.LockedPlatform, bool) {
			existing, exists := lf.GetTool(name)
			return existing.Version, existing.Platforms, exists
		},
		func(sourceURI, selectedTag string, signer *componenttypes.LockedSigner, platforms map[string]componenttypes.LockedPlatform) {
			lf.Tools[name] = lockfile.LockedTool{
				Source:    sourceURI,
				Version:   selectedTag,
				Signer:    signer,
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
		Kind:      "external",
		LockedAt:  timestamp.Now().String(),
		Platforms: platforms,
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
// Remote adapters use the same locking mechanism as collectors and tools.
func (l *Locker) lockSourceRemote(ctx context.Context, name string, cfg config.RemoteConfig, lf *lockfile.LockFile, opts LockOpts) (*LockResult, error) {
	adapterName := cfg.EffectiveAdapter()
	if adapterName == "" {
		return nil, fmt.Errorf("cannot determine adapter name for remote %q", name)
	}
	binaryName := "epack-remote-" + adapterName
	return l.lockSourceComponent(ctx, name, cfg.Source, binaryName, "remote", opts,
		func() (string, map[string]componenttypes.LockedPlatform, bool) {
			existing, exists := lf.GetRemote(name)
			return existing.Version, existing.Platforms, exists
		},
		func(sourceURI, selectedTag string, signer *componenttypes.LockedSigner, platforms map[string]componenttypes.LockedPlatform) {
			lf.Remotes[name] = lockfile.LockedRemote{
				Source:    sourceURI,
				Version:   selectedTag,
				Signer:    signer,
				LockedAt:  timestamp.Now().String(),
				Platforms: platforms,
			}
		})
}

func (l *Locker) lockSourceComponent(
	ctx context.Context,
	name, sourceRef, binaryLookupName, kind string,
	opts LockOpts,
	getExisting func() (version string, platforms map[string]componenttypes.LockedPlatform, exists bool),
	updateEntry func(sourceURI, selectedTag string, signer *componenttypes.LockedSigner, platforms map[string]componenttypes.LockedPlatform),
) (*LockResult, error) {
	resolved, err := l.resolveSourceComponentVersion(ctx, sourceRef, binaryLookupName, opts)
	if err != nil {
		return nil, err
	}
	existingVersion, existingPlatforms, exists := getExisting()
	lockedPlatforms, signer, err := l.lockSourcePlatforms(
		ctx, name, binaryLookupName, resolved.owner, resolved.repo, resolved.selectedTag, resolved.release, resolved.platforms, opts,
	)
	if err != nil {
		return nil, err
	}
	if len(lockedPlatforms) == 0 {
		return nil, fmt.Errorf("no platforms could be locked")
	}

	mergeExistingPlatforms(lockedPlatforms, existingPlatforms, exists, opts.AllPlatforms)
	updateEntry(BuildSourceURI(resolved.owner, resolved.repo), resolved.selectedTag, signer, lockedPlatforms)
	return buildSourceLockResult(name, kind, resolved.selectedTag, lockedPlatforms, exists, existingVersion), nil
}

type resolvedSourceComponent struct {
	owner       string
	repo        string
	selectedTag string
	release     *ReleaseInfo
	platforms   []string
}

func (l *Locker) resolveSourceComponentVersion(
	ctx context.Context,
	sourceRef, binaryLookupName string,
	opts LockOpts,
) (*resolvedSourceComponent, error) {
	owner, repo, versionConstraint, err := github.ParseSource(sourceRef)
	if err != nil {
		return nil, err
	}
	source := fmt.Sprintf("%s/%s", owner, repo)
	selectedTag, err := l.Registry.ResolveVersion(ctx, source, versionConstraint)
	if err != nil {
		return nil, fmt.Errorf("resolving version: %w", err)
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
		release:     release,
		platforms:   platforms,
	}, nil
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
	sigResult, err := VerifySigstoreBundle(bundlePath, binaryPath, expectedIdentity)
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
		Kind:      "external",
		LockedAt:  timestamp.Now().String(),
		Platforms: platforms,
	}

	return &LockResult{
		Name:      name,
		Kind:      "remote",
		Platforms: []string{platformKey},
		IsNew:     isNew,
		Updated:   !isNew,
	}, nil
}
