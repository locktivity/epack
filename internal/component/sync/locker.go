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

	var results []LockResult

	collectorResults, err := lockByKind(ctx, cfg.Collectors, lf, opts,
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
	if err != nil {
		return nil, err
	}
	results = append(results, collectorResults...)

	toolResults, err := lockByKind(ctx, cfg.Tools, lf, opts,
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
	if err != nil {
		return nil, err
	}
	results = append(results, toolResults...)

	remoteResults, err := lockByKind(ctx, cfg.Remotes, lf, opts,
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
	if err != nil {
		return nil, err
	}
	results = append(results, remoteResults...)

	// Save lockfile
	if err := lf.Save(l.LockfilePath); err != nil {
		return nil, fmt.Errorf("saving lockfile: %w", err)
	}

	return results, nil
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
	owner, repo, versionConstraint, err := github.ParseSource(cfg.Source)
	if err != nil {
		return nil, err
	}

	// Build source string for registry calls
	source := fmt.Sprintf("%s/%s", owner, repo)

	// Resolve version using registry
	selectedTag, err := l.Registry.ResolveVersion(ctx, source, versionConstraint)
	if err != nil {
		return nil, fmt.Errorf("resolving version: %w", err)
	}

	// Fetch the selected release
	release, err := l.Registry.FetchRelease(ctx, source, selectedTag)
	if err != nil {
		return nil, fmt.Errorf("fetching release %s: %w", selectedTag, err)
	}

	// Determine platforms to lock
	platforms := l.resolvePlatforms(opts, release, name)
	if len(platforms) == 0 {
		return nil, fmt.Errorf("no platforms to lock")
	}

	// Check if this is new or updated
	existing, exists := lf.GetCollector(name)
	isNew := !exists
	updated := exists && existing.Version != selectedTag

	// Lock each platform
	lockedPlatforms := make(map[string]componenttypes.LockedPlatform)
	var signer *componenttypes.LockedSigner

	for _, plat := range platforms {
		goos, goarch := platform.Split(plat)

		// Find binary asset
		asset, err := l.Registry.FindBinaryAsset(release, name, goos, goarch)
		if err != nil {
			// Platform not available in release - skip if AllPlatforms, error otherwise
			if opts.AllPlatforms {
				continue
			}
			return nil, fmt.Errorf("finding asset for %s: %w", plat, err)
		}

		// Download to temp file for verification
		tmpDir, err := os.MkdirTemp("", "epack-lock-*")
		if err != nil {
			return nil, fmt.Errorf("creating temp dir: %w", err)
		}
		defer func() { _ = os.RemoveAll(tmpDir) }()

		// Sanitize asset name to prevent path traversal
		safeBinaryName, err := SanitizeAssetName(asset.Name)
		if err != nil {
			return nil, fmt.Errorf("invalid binary asset name: %w", err)
		}

		binaryPath := filepath.Join(tmpDir, safeBinaryName)
		if err := l.Registry.DownloadAsset(ctx, asset.URL, binaryPath); err != nil {
			return nil, fmt.Errorf("downloading %s: %w", asset.Name, err)
		}

		// Find and download sigstore bundle
		bundleAsset, err := l.Registry.FindSigstoreBundle(release, asset.Name)
		if err != nil {
			return nil, fmt.Errorf("finding sigstore bundle for %s: %w", asset.Name, err)
		}

		// Sanitize bundle asset name to prevent path traversal
		safeBundleName, err := SanitizeAssetName(bundleAsset.Name)
		if err != nil {
			return nil, fmt.Errorf("invalid bundle asset name: %w", err)
		}

		bundlePath := filepath.Join(tmpDir, safeBundleName)
		if err := l.Registry.DownloadAsset(ctx, bundleAsset.URL, bundlePath); err != nil {
			return nil, fmt.Errorf("downloading sigstore bundle: %w", err)
		}

		// SECURITY: Build expected identity from declared source and selected tag.
		// This prevents collector substitution attacks where an attacker's signed
		// binary could be locked in place of the declared collector.
		expectedRepoURI := BuildGitHubRepoURL(owner, repo)
		expectedRef := BuildGitHubRefTag(selectedTag)
		expectedIdentity := &ExpectedIdentity{
			SourceRepositoryURI: expectedRepoURI,
			SourceRepositoryRef: expectedRef,
		}

		// Verify sigstore signature with identity enforcement.
		// This MUST match the declared source repository and selected tag.
		sigResult, err := VerifySigstoreBundle(bundlePath, binaryPath, expectedIdentity)
		if err != nil {
			return nil, fmt.Errorf("verifying sigstore signature: %w (expected repo=%s, ref=%s)", err, expectedRepoURI, expectedRef)
		}

		// Defense in depth: verify returned claims match expected
		if sigResult.SourceRepositoryURI != expectedRepoURI {
			return nil, fmt.Errorf("sigstore certificate source_repository_uri mismatch for %s: expected %q, got %q",
				name, expectedRepoURI, sigResult.SourceRepositoryURI)
		}
		if sigResult.SourceRepositoryRef != expectedRef {
			return nil, fmt.Errorf("sigstore certificate source_repository_ref mismatch for %s: expected %q, got %q",
				name, expectedRef, sigResult.SourceRepositoryRef)
		}

		// Capture and validate signer (must be same for all platforms)
		platformSigner := &componenttypes.LockedSigner{
			Issuer:              sigResult.Issuer,
			SourceRepositoryURI: sigResult.SourceRepositoryURI,
			SourceRepositoryRef: sigResult.SourceRepositoryRef,
		}
		if signer == nil {
			signer = platformSigner
		} else {
			// Validate signer matches across platforms
			if signer.Issuer != platformSigner.Issuer ||
				signer.SourceRepositoryURI != platformSigner.SourceRepositoryURI ||
				signer.SourceRepositoryRef != platformSigner.SourceRepositoryRef {
				return nil, fmt.Errorf("signer mismatch across platforms for %s: %s has different signer than previous platforms", name, plat)
			}
		}

		// Compute digest
		digest, err := ComputeDigest(binaryPath)
		if err != nil {
			return nil, fmt.Errorf("computing digest: %w", err)
		}

		lockedPlatforms[plat] = componenttypes.LockedPlatform{
			Digest: digest,
			Asset:  asset.Name,
		}
	}

	if len(lockedPlatforms) == 0 {
		return nil, fmt.Errorf("no platforms could be locked")
	}

	// Merge with existing platforms if additive mode
	if exists && !opts.AllPlatforms {
		for p, entry := range existing.Platforms {
			if _, locked := lockedPlatforms[p]; !locked {
				lockedPlatforms[p] = entry
			}
		}
	}

	// Update lockfile entry
	lf.Collectors[name] = lockfile.LockedCollector{
		Source:    BuildSourceURI(owner, repo),
		Version:   selectedTag,
		Signer:    signer,
		LockedAt:  timestamp.Now().String(),
		Platforms: lockedPlatforms,
	}

	lockedPlatformNames := make([]string, 0, len(lockedPlatforms))
	for p := range lockedPlatforms {
		lockedPlatformNames = append(lockedPlatformNames, p)
	}
	sort.Strings(lockedPlatformNames) // Deterministic ordering

	return &LockResult{
		Name:      name,
		Kind:      "collector",
		Version:   selectedTag,
		Platforms: lockedPlatformNames,
		IsNew:     isNew,
		Updated:   updated,
	}, nil
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
	owner, repo, versionConstraint, err := github.ParseSource(cfg.Source)
	if err != nil {
		return nil, err
	}

	// Build source string for registry calls
	source := fmt.Sprintf("%s/%s", owner, repo)

	// Resolve version using registry
	selectedTag, err := l.Registry.ResolveVersion(ctx, source, versionConstraint)
	if err != nil {
		return nil, fmt.Errorf("resolving version: %w", err)
	}

	// Fetch the selected release
	release, err := l.Registry.FetchRelease(ctx, source, selectedTag)
	if err != nil {
		return nil, fmt.Errorf("fetching release %s: %w", selectedTag, err)
	}

	// Determine platforms to lock
	platforms := l.resolvePlatforms(opts, release, name)
	if len(platforms) == 0 {
		return nil, fmt.Errorf("no platforms to lock")
	}

	// Check if this is new or updated
	existing, exists := lf.GetTool(name)
	isNew := !exists
	updated := exists && existing.Version != selectedTag

	// Lock each platform
	lockedPlatforms := make(map[string]componenttypes.LockedPlatform)
	var signer *componenttypes.LockedSigner

	for _, plat := range platforms {
		goos, goarch := platform.Split(plat)

		// Find binary asset
		asset, err := l.Registry.FindBinaryAsset(release, name, goos, goarch)
		if err != nil {
			// Platform not available in release - skip if AllPlatforms, error otherwise
			if opts.AllPlatforms {
				continue
			}
			return nil, fmt.Errorf("finding asset for %s: %w", plat, err)
		}

		// Download to temp file for verification
		tmpDir, err := os.MkdirTemp("", "epack-lock-*")
		if err != nil {
			return nil, fmt.Errorf("creating temp dir: %w", err)
		}
		defer func() { _ = os.RemoveAll(tmpDir) }()

		// Sanitize asset name to prevent path traversal
		safeBinaryName, err := SanitizeAssetName(asset.Name)
		if err != nil {
			return nil, fmt.Errorf("invalid binary asset name: %w", err)
		}

		binaryPath := filepath.Join(tmpDir, safeBinaryName)
		if err := l.Registry.DownloadAsset(ctx, asset.URL, binaryPath); err != nil {
			return nil, fmt.Errorf("downloading %s: %w", asset.Name, err)
		}

		// Find and download sigstore bundle
		bundleAsset, err := l.Registry.FindSigstoreBundle(release, asset.Name)
		if err != nil {
			return nil, fmt.Errorf("finding sigstore bundle for %s: %w", asset.Name, err)
		}

		// Sanitize bundle asset name to prevent path traversal
		safeBundleName, err := SanitizeAssetName(bundleAsset.Name)
		if err != nil {
			return nil, fmt.Errorf("invalid bundle asset name: %w", err)
		}

		bundlePath := filepath.Join(tmpDir, safeBundleName)
		if err := l.Registry.DownloadAsset(ctx, bundleAsset.URL, bundlePath); err != nil {
			return nil, fmt.Errorf("downloading sigstore bundle: %w", err)
		}

		// SECURITY: Build expected identity from declared source and selected tag.
		expectedRepoURI := BuildGitHubRepoURL(owner, repo)
		expectedRef := BuildGitHubRefTag(selectedTag)
		expectedIdentity := &ExpectedIdentity{
			SourceRepositoryURI: expectedRepoURI,
			SourceRepositoryRef: expectedRef,
		}

		// Verify sigstore signature with identity enforcement.
		sigResult, err := VerifySigstoreBundle(bundlePath, binaryPath, expectedIdentity)
		if err != nil {
			return nil, fmt.Errorf("verifying sigstore signature: %w (expected repo=%s, ref=%s)", err, expectedRepoURI, expectedRef)
		}

		// Defense in depth: verify returned claims match expected
		if sigResult.SourceRepositoryURI != expectedRepoURI {
			return nil, fmt.Errorf("sigstore certificate source_repository_uri mismatch for %s: expected %q, got %q",
				name, expectedRepoURI, sigResult.SourceRepositoryURI)
		}
		if sigResult.SourceRepositoryRef != expectedRef {
			return nil, fmt.Errorf("sigstore certificate source_repository_ref mismatch for %s: expected %q, got %q",
				name, expectedRef, sigResult.SourceRepositoryRef)
		}

		// Capture and validate signer (must be same for all platforms)
		platformSigner := &componenttypes.LockedSigner{
			Issuer:              sigResult.Issuer,
			SourceRepositoryURI: sigResult.SourceRepositoryURI,
			SourceRepositoryRef: sigResult.SourceRepositoryRef,
		}
		if signer == nil {
			signer = platformSigner
		} else {
			// Validate signer matches across platforms
			if signer.Issuer != platformSigner.Issuer ||
				signer.SourceRepositoryURI != platformSigner.SourceRepositoryURI ||
				signer.SourceRepositoryRef != platformSigner.SourceRepositoryRef {
				return nil, fmt.Errorf("signer mismatch across platforms for %s: %s has different signer than previous platforms", name, plat)
			}
		}

		// Compute digest
		digest, err := ComputeDigest(binaryPath)
		if err != nil {
			return nil, fmt.Errorf("computing digest: %w", err)
		}

		lockedPlatforms[plat] = componenttypes.LockedPlatform{
			Digest: digest,
			Asset:  asset.Name,
		}
	}

	if len(lockedPlatforms) == 0 {
		return nil, fmt.Errorf("no platforms could be locked")
	}

	// Merge with existing platforms if additive mode
	if exists && !opts.AllPlatforms {
		for p, entry := range existing.Platforms {
			if _, locked := lockedPlatforms[p]; !locked {
				lockedPlatforms[p] = entry
			}
		}
	}

	// Update lockfile entry
	lf.Tools[name] = lockfile.LockedTool{
		Source:    BuildSourceURI(owner, repo),
		Version:   selectedTag,
		Signer:    signer,
		LockedAt:  timestamp.Now().String(),
		Platforms: lockedPlatforms,
	}

	lockedPlatformNames := make([]string, 0, len(lockedPlatforms))
	for p := range lockedPlatforms {
		lockedPlatformNames = append(lockedPlatformNames, p)
	}
	sort.Strings(lockedPlatformNames) // Deterministic ordering

	return &LockResult{
		Name:      name,
		Kind:      "tool",
		Version:   selectedTag,
		Platforms: lockedPlatformNames,
		IsNew:     isNew,
		Updated:   updated,
	}, nil
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
	owner, repo, versionConstraint, err := github.ParseSource(cfg.Source)
	if err != nil {
		return nil, err
	}

	// Build source string for registry calls
	source := fmt.Sprintf("%s/%s", owner, repo)

	// Resolve version using registry
	selectedTag, err := l.Registry.ResolveVersion(ctx, source, versionConstraint)
	if err != nil {
		return nil, fmt.Errorf("resolving version: %w", err)
	}

	// Fetch the selected release
	release, err := l.Registry.FetchRelease(ctx, source, selectedTag)
	if err != nil {
		return nil, fmt.Errorf("fetching release %s: %w", selectedTag, err)
	}

	// Get the effective adapter name for binary asset lookup
	adapterName := cfg.EffectiveAdapter()
	if adapterName == "" {
		return nil, fmt.Errorf("cannot determine adapter name for remote %q", name)
	}
	binaryName := "epack-remote-" + adapterName

	// Determine platforms to lock
	platforms := l.resolvePlatforms(opts, release, binaryName)
	if len(platforms) == 0 {
		return nil, fmt.Errorf("no platforms to lock")
	}

	// Check if this is new or updated
	existing, exists := lf.GetRemote(name)
	isNew := !exists
	updated := exists && existing.Version != selectedTag

	// Lock each platform
	lockedPlatforms := make(map[string]componenttypes.LockedPlatform)
	var signer *componenttypes.LockedSigner

	for _, plat := range platforms {
		goos, goarch := platform.Split(plat)

		// Find binary asset
		asset, err := l.Registry.FindBinaryAsset(release, binaryName, goos, goarch)
		if err != nil {
			// Platform not available in release - skip if AllPlatforms, error otherwise
			if opts.AllPlatforms {
				continue
			}
			return nil, fmt.Errorf("finding asset for %s: %w", plat, err)
		}

		// Download to temp file for verification
		tmpDir, err := os.MkdirTemp("", "epack-lock-*")
		if err != nil {
			return nil, fmt.Errorf("creating temp dir: %w", err)
		}
		defer func() { _ = os.RemoveAll(tmpDir) }()

		// Sanitize asset name to prevent path traversal
		safeBinaryName, err := SanitizeAssetName(asset.Name)
		if err != nil {
			return nil, fmt.Errorf("invalid binary asset name: %w", err)
		}

		binaryPath := filepath.Join(tmpDir, safeBinaryName)
		if err := l.Registry.DownloadAsset(ctx, asset.URL, binaryPath); err != nil {
			return nil, fmt.Errorf("downloading %s: %w", asset.Name, err)
		}

		// Find and download sigstore bundle
		bundleAsset, err := l.Registry.FindSigstoreBundle(release, asset.Name)
		if err != nil {
			return nil, fmt.Errorf("finding sigstore bundle for %s: %w", asset.Name, err)
		}

		// Sanitize bundle asset name to prevent path traversal
		safeBundleName, err := SanitizeAssetName(bundleAsset.Name)
		if err != nil {
			return nil, fmt.Errorf("invalid bundle asset name: %w", err)
		}

		bundlePath := filepath.Join(tmpDir, safeBundleName)
		if err := l.Registry.DownloadAsset(ctx, bundleAsset.URL, bundlePath); err != nil {
			return nil, fmt.Errorf("downloading sigstore bundle: %w", err)
		}

		// SECURITY: Build expected identity from declared source and selected tag.
		expectedRepoURI := BuildGitHubRepoURL(owner, repo)
		expectedRef := BuildGitHubRefTag(selectedTag)
		expectedIdentity := &ExpectedIdentity{
			SourceRepositoryURI: expectedRepoURI,
			SourceRepositoryRef: expectedRef,
		}

		// Verify sigstore signature with identity enforcement.
		sigResult, err := VerifySigstoreBundle(bundlePath, binaryPath, expectedIdentity)
		if err != nil {
			return nil, fmt.Errorf("verifying sigstore signature: %w (expected repo=%s, ref=%s)", err, expectedRepoURI, expectedRef)
		}

		// Defense in depth: verify returned claims match expected
		if sigResult.SourceRepositoryURI != expectedRepoURI {
			return nil, fmt.Errorf("sigstore certificate source_repository_uri mismatch for %s: expected %q, got %q",
				name, expectedRepoURI, sigResult.SourceRepositoryURI)
		}
		if sigResult.SourceRepositoryRef != expectedRef {
			return nil, fmt.Errorf("sigstore certificate source_repository_ref mismatch for %s: expected %q, got %q",
				name, expectedRef, sigResult.SourceRepositoryRef)
		}

		// Capture and validate signer (must be same for all platforms)
		platformSigner := &componenttypes.LockedSigner{
			Issuer:              sigResult.Issuer,
			SourceRepositoryURI: sigResult.SourceRepositoryURI,
			SourceRepositoryRef: sigResult.SourceRepositoryRef,
		}
		if signer == nil {
			signer = platformSigner
		} else {
			// Validate signer matches across platforms
			if signer.Issuer != platformSigner.Issuer ||
				signer.SourceRepositoryURI != platformSigner.SourceRepositoryURI ||
				signer.SourceRepositoryRef != platformSigner.SourceRepositoryRef {
				return nil, fmt.Errorf("signer mismatch across platforms for %s: %s has different signer than previous platforms", name, plat)
			}
		}

		// Compute digest
		digest, err := ComputeDigest(binaryPath)
		if err != nil {
			return nil, fmt.Errorf("computing digest: %w", err)
		}

		lockedPlatforms[plat] = componenttypes.LockedPlatform{
			Digest: digest,
			Asset:  asset.Name,
		}
	}

	if len(lockedPlatforms) == 0 {
		return nil, fmt.Errorf("no platforms could be locked")
	}

	// Merge with existing platforms if additive mode
	if exists && !opts.AllPlatforms {
		for p, entry := range existing.Platforms {
			if _, locked := lockedPlatforms[p]; !locked {
				lockedPlatforms[p] = entry
			}
		}
	}

	// Update lockfile entry
	lf.Remotes[name] = lockfile.LockedRemote{
		Source:    BuildSourceURI(owner, repo),
		Version:   selectedTag,
		Signer:    signer,
		LockedAt:  timestamp.Now().String(),
		Platforms: lockedPlatforms,
	}

	lockedPlatformNames := make([]string, 0, len(lockedPlatforms))
	for p := range lockedPlatforms {
		lockedPlatformNames = append(lockedPlatformNames, p)
	}
	sort.Strings(lockedPlatformNames) // Deterministic ordering

	return &LockResult{
		Name:      name,
		Kind:      "remote",
		Version:   selectedTag,
		Platforms: lockedPlatformNames,
		IsNew:     isNew,
		Updated:   updated,
	}, nil
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
