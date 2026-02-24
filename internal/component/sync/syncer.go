package sync

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"

	"github.com/locktivity/epack/errors"
	"github.com/locktivity/epack/internal/component/config"
	"github.com/locktivity/epack/internal/component/github"
	"github.com/locktivity/epack/internal/component/lockfile"
	"github.com/locktivity/epack/internal/componenttypes"
	"github.com/locktivity/epack/internal/exitcode"
	"github.com/locktivity/epack/internal/platform"
	"github.com/locktivity/epack/internal/safefile"
)

// Syncer downloads components from lockfile.
type Syncer struct {
	Registry     RegistryClient
	LockfilePath string
	BaseDir      string // .epack directory
}

// lockedComponent abstracts the common fields between LockedCollector and LockedTool.
type lockedComponent struct {
	Source    string
	Version   string
	Platforms map[string]componenttypes.LockedPlatform
	Signer    *componenttypes.LockedSigner
}

// componentAccessor provides uniform access to locked components from lockfile.
type componentAccessor interface {
	GetLocked(lf *lockfile.LockFile, name string) (*lockedComponent, bool)
	Kind() string                               // "collector" or "tool"
	LockfileKind() componenttypes.ComponentKind // componenttypes.KindCollector or componenttypes.KindTool
}

type collectorAccessor struct{}

func (collectorAccessor) Kind() string { return "collector" }
func (collectorAccessor) LockfileKind() componenttypes.ComponentKind {
	return componenttypes.KindCollector
}
func (collectorAccessor) GetLocked(lf *lockfile.LockFile, name string) (*lockedComponent, bool) {
	locked, ok := lf.GetCollector(name)
	if !ok {
		return nil, false
	}
	return &lockedComponent{
		Source:    locked.Source,
		Version:   locked.Version,
		Platforms: locked.Platforms,
		Signer:    locked.Signer,
	}, true
}

type toolAccessor struct{}

func (toolAccessor) Kind() string                               { return "tool" }
func (toolAccessor) LockfileKind() componenttypes.ComponentKind { return componenttypes.KindTool }
func (toolAccessor) GetLocked(lf *lockfile.LockFile, name string) (*lockedComponent, bool) {
	locked, ok := lf.GetTool(name)
	if !ok {
		return nil, false
	}
	return &lockedComponent{
		Source:    locked.Source,
		Version:   locked.Version,
		Platforms: locked.Platforms,
		Signer:    locked.Signer,
	}, true
}

type remoteAccessor struct{}

func (remoteAccessor) Kind() string                               { return "remote" }
func (remoteAccessor) LockfileKind() componenttypes.ComponentKind { return componenttypes.KindRemote }
func (remoteAccessor) GetLocked(lf *lockfile.LockFile, name string) (*lockedComponent, bool) {
	locked, ok := lf.GetRemote(name)
	if !ok {
		return nil, false
	}
	return &lockedComponent{
		Source:    locked.Source,
		Version:   locked.Version,
		Platforms: locked.Platforms,
		Signer:    locked.Signer,
	}, true
}

// NewSyncer creates a syncer with default paths using the default GitHub registry.
func NewSyncer(workDir string) *Syncer {
	return &Syncer{
		Registry:     NewGitHubRegistry(),
		LockfilePath: filepath.Join(workDir, lockfile.FileName),
		BaseDir:      filepath.Join(workDir, ".epack"),
	}
}

// NewSyncerWithRegistry creates a syncer with a custom registry client.
// Useful for testing or multi-registry support.
func NewSyncerWithRegistry(registry RegistryClient, workDir string) *Syncer {
	return &Syncer{
		Registry:     registry,
		LockfilePath: filepath.Join(workDir, lockfile.FileName),
		BaseDir:      filepath.Join(workDir, ".epack"),
	}
}

// SyncOpts controls sync behavior.
type SyncOpts struct {
	Frozen               bool // Verify only, don't download.
	InsecureSkipVerify   bool // Skip Sigstore verification (NOT RECOMMENDED).
	InsecureTrustOnFirst bool // Trust digest from lockfile without Sigstore (NOT RECOMMENDED).
}

// SyncResult contains the result of syncing a component.
type SyncResult struct {
	Name      string // Component name
	Kind      string // "collector" or "tool"
	Version   string
	Platform  string
	Installed bool
	Verified  bool
	Skipped   bool // External binary, skipped
}

// Sync downloads and verifies all components for the current platform.
func (s *Syncer) Sync(ctx context.Context, cfg *config.JobConfig, opts SyncOpts) ([]SyncResult, error) {
	// SECURITY: Defense-in-depth validation of config structure.
	// Config should already be validated by Load/Parse, but we
	// validate again in case the config was constructed programmatically.
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	// Ensure base directory exists for component installation.
	// This is done early so safefile.MkdirAll can use it as the security boundary.
	if err := os.MkdirAll(s.BaseDir, 0755); err != nil {
		return nil, fmt.Errorf("creating base directory: %w", err)
	}

	// Validate option combinations
	if opts.Frozen && opts.InsecureSkipVerify {
		return nil, fmt.Errorf("cannot combine --frozen with --insecure-skip-verify")
	}

	// Load lockfile
	lf, err := lockfile.Load(s.LockfilePath)
	if err != nil {
		return nil, errors.WithHint(errors.LockfileInvalid, exitcode.LockInvalid,
			"lockfile not found or invalid", "Run 'epack lock' first", nil)
	}

	// SECURITY: Validate config and lockfile alignment BEFORE proceeding.
	// This prevents "lockfile retargeting" attacks where an attacker modifies
	// the config to point to a different repository while reusing a valid lockfile.
	if err := s.ValidateAlignment(cfg, lf); err != nil {
		return nil, err
	}

	platform := platform.Key(runtime.GOOS, runtime.GOARCH)
	var results []SyncResult

	collectorResults, err := syncByKind(ctx, cfg.Collectors, lf, platform, opts, s.syncCollector)
	if err != nil {
		return nil, err
	}
	results = append(results, collectorResults...)

	toolResults, err := syncByKind(ctx, cfg.Tools, lf, platform, opts, s.syncTool)
	if err != nil {
		return nil, err
	}
	results = append(results, toolResults...)

	remoteResults, err := syncByKind(ctx, cfg.Remotes, lf, platform, opts, s.syncRemote)
	if err != nil {
		return nil, err
	}
	results = append(results, remoteResults...)

	return results, nil
}

type syncKindFunc[T any] func(context.Context, string, T, *lockfile.LockFile, string, SyncOpts) (*SyncResult, error)

// syncByKind runs a per-component sync function in deterministic name order.
func syncByKind[T any](
	ctx context.Context,
	components map[string]T,
	lf *lockfile.LockFile,
	platform string,
	opts SyncOpts,
	fn syncKindFunc[T],
) ([]SyncResult, error) {
	names := make([]string, 0, len(components))
	for name := range components {
		names = append(names, name)
	}
	sort.Strings(names)

	results := make([]SyncResult, 0, len(names))
	for _, name := range names {
		result, err := fn(ctx, name, components[name], lf, platform, opts)
		if err != nil {
			return nil, err
		}
		if result != nil {
			results = append(results, *result)
		}
	}
	return results, nil
}

// ValidateAlignment checks that config and lockfile collectors match.
// SECURITY: This validates that the config source matches the lockfile source,
// preventing "lockfile retargeting" attacks where an attacker modifies the config
// to point to a different repository while reusing a valid lockfile entry.
func (s *Syncer) ValidateAlignment(cfg *config.JobConfig, lf *lockfile.LockFile) error {
	// Check all config collectors are in lockfile with matching kind AND source.
	// Iterate in sorted order for deterministic error messages.
	configCollectorNames := make([]string, 0, len(cfg.Collectors))
	for name := range cfg.Collectors {
		configCollectorNames = append(configCollectorNames, name)
	}
	sort.Strings(configCollectorNames)

	for _, name := range configCollectorNames {
		collector := cfg.Collectors[name]
		locked, ok := lf.GetCollector(name)
		if collector.Source != "" {
			// Source-based collector
			if !ok {
				return errors.WithHint(errors.LockfileInvalid, exitcode.LockInvalid,
					fmt.Sprintf("config declares collector %q not found in lockfile", name),
					"Run 'epack collector lock' to update the lockfile", nil)
			}
			// Verify lockfile entry is also source-based (not external)
			if locked.Kind == "external" {
				return errors.WithHint(errors.LockfileInvalid, exitcode.LockInvalid,
					fmt.Sprintf("config declares %q as source-based but lockfile has it as external", name),
					"Run 'epack collector lock' to update the lockfile", nil)
			}

			// SECURITY: Verify config source matches lockfile source.
			// This prevents lockfile retargeting attacks where the config is modified
			// to point to a different repository while reusing a valid lockfile.
			configOwner, configRepo, _, err := github.ParseSource(collector.Source)
			if err != nil {
				return errors.WithHint(errors.LockfileInvalid, exitcode.LockInvalid,
					fmt.Sprintf("invalid source in config for collector %q: %v", name, err),
					"Check the source format in epack.yaml", nil)
			}
			expectedSource := fmt.Sprintf("github.com/%s/%s", configOwner, configRepo)
			if locked.Source != expectedSource {
				return errors.WithHint(errors.LockfileInvalid, exitcode.LockInvalid,
					fmt.Sprintf("config source mismatch for collector %q: config declares %q but lockfile has %q", name, expectedSource, locked.Source),
					"Run 'epack collector lock' to update the lockfile with the new source", nil)
			}

			// SECURITY: Also verify signer identity matches config source.
			// The lockfile signer must be from the same repository declared in config.
			if locked.Signer != nil {
				expectedRepoURI := fmt.Sprintf("https://github.com/%s/%s", configOwner, configRepo)
				if locked.Signer.SourceRepositoryURI != expectedRepoURI {
					return errors.WithHint(errors.LockfileInvalid, exitcode.LockInvalid,
						fmt.Sprintf("signer source mismatch for collector %q: config declares %q but lockfile signer is from %q", name, expectedRepoURI, locked.Signer.SourceRepositoryURI),
						"Run 'epack collector lock' to update the lockfile", nil)
				}
			}
		} else if collector.Binary != "" {
			// External binary collector
			if ok && locked.Kind != "external" {
				return errors.WithHint(errors.LockfileInvalid, exitcode.LockInvalid,
					fmt.Sprintf("config declares %q as external binary but lockfile has it as source-based", name),
					"Run 'epack collector lock' to update the lockfile", nil)
			}
		}
	}

	// Check all lockfile collectors are in config (for source-based).
	// Iterate in sorted order for deterministic error messages.
	lockfileCollectorNames := make([]string, 0, len(lf.Collectors))
	for name := range lf.Collectors {
		lockfileCollectorNames = append(lockfileCollectorNames, name)
	}
	sort.Strings(lockfileCollectorNames)

	for _, name := range lockfileCollectorNames {
		locked := lf.Collectors[name]
		if locked.Kind == "external" {
			continue
		}
		cfgCollector, ok := cfg.Collectors[name]
		if !ok {
			return errors.WithHint(errors.LockfileInvalid, exitcode.LockInvalid,
				fmt.Sprintf("lockfile has collector %q not found in config", name),
				"Remove stale entries or add collector to config", nil)
		}
		// Verify config entry is also source-based (not external)
		if cfgCollector.Source == "" {
			return errors.WithHint(errors.LockfileInvalid, exitcode.LockInvalid,
				fmt.Sprintf("lockfile has %q as source-based but config declares it as external", name),
				"Run 'epack collector lock' to update the lockfile", nil)
		}
	}

	// Validate remotes alignment (source-based remotes only)
	configRemoteNames := make([]string, 0, len(cfg.Remotes))
	for name := range cfg.Remotes {
		configRemoteNames = append(configRemoteNames, name)
	}
	sort.Strings(configRemoteNames)

	for _, name := range configRemoteNames {
		remote := cfg.Remotes[name]
		locked, ok := lf.GetRemote(name)
		if remote.Source != "" {
			// Source-based remote
			if !ok {
				return errors.WithHint(errors.LockfileInvalid, exitcode.LockInvalid,
					fmt.Sprintf("config declares remote %q not found in lockfile", name),
					"Run 'epack lock' to update the lockfile", nil)
			}
			// Verify lockfile entry is also source-based (not external)
			if locked.Kind == "external" {
				return errors.WithHint(errors.LockfileInvalid, exitcode.LockInvalid,
					fmt.Sprintf("config declares %q as source-based but lockfile has it as external", name),
					"Run 'epack lock' to update the lockfile", nil)
			}

			// SECURITY: Verify config source matches lockfile source.
			configOwner, configRepo, _, err := github.ParseSource(remote.Source)
			if err != nil {
				return errors.WithHint(errors.LockfileInvalid, exitcode.LockInvalid,
					fmt.Sprintf("invalid source in config for remote %q: %v", name, err),
					"Check the source format in epack.yaml", nil)
			}
			expectedSource := fmt.Sprintf("github.com/%s/%s", configOwner, configRepo)
			if locked.Source != expectedSource {
				return errors.WithHint(errors.LockfileInvalid, exitcode.LockInvalid,
					fmt.Sprintf("config source mismatch for remote %q: config declares %q but lockfile has %q", name, expectedSource, locked.Source),
					"Run 'epack lock' to update the lockfile with the new source", nil)
			}

			// SECURITY: Also verify signer identity matches config source.
			if locked.Signer != nil {
				expectedRepoURI := fmt.Sprintf("https://github.com/%s/%s", configOwner, configRepo)
				if locked.Signer.SourceRepositoryURI != expectedRepoURI {
					return errors.WithHint(errors.LockfileInvalid, exitcode.LockInvalid,
						fmt.Sprintf("signer source mismatch for remote %q: config declares %q but lockfile signer is from %q", name, expectedRepoURI, locked.Signer.SourceRepositoryURI),
						"Run 'epack lock' to update the lockfile", nil)
				}
			}
		} else if remote.Binary != "" {
			// External binary remote
			if ok && locked.Kind != "external" {
				return errors.WithHint(errors.LockfileInvalid, exitcode.LockInvalid,
					fmt.Sprintf("config declares %q as external binary but lockfile has it as source-based", name),
					"Run 'epack lock' to update the lockfile", nil)
			}
		}
		// Adapter-only remotes (no source or binary) don't need lockfile validation
	}

	// Check all lockfile remotes are in config (for source-based)
	lockfileRemoteNames := make([]string, 0, len(lf.Remotes))
	for name := range lf.Remotes {
		lockfileRemoteNames = append(lockfileRemoteNames, name)
	}
	sort.Strings(lockfileRemoteNames)

	for _, name := range lockfileRemoteNames {
		locked := lf.Remotes[name]
		if locked.Kind == "external" {
			continue
		}
		cfgRemote, ok := cfg.Remotes[name]
		if !ok {
			return errors.WithHint(errors.LockfileInvalid, exitcode.LockInvalid,
				fmt.Sprintf("lockfile has remote %q not found in config", name),
				"Remove stale entries or add remote to config", nil)
		}
		// Verify config entry is also source-based (not external)
		if cfgRemote.Source == "" {
			return errors.WithHint(errors.LockfileInvalid, exitcode.LockInvalid,
				fmt.Sprintf("lockfile has %q as source-based but config declares it as external", name),
				"Run 'epack lock' to update the lockfile", nil)
		}
	}

	return nil
}

// syncSourceComponent is the unified implementation for syncing source-based components.
// It handles both collectors and tools through the componentAccessor interface.
func (s *Syncer) syncSourceComponent(ctx context.Context, name string, accessor componentAccessor, lf *lockfile.LockFile, platform string, opts SyncOpts) (*SyncResult, error) {
	kind := accessor.Kind()

	locked, ok := accessor.GetLocked(lf, name)
	if !ok {
		return nil, errors.WithHint(errors.LockfileInvalid, exitcode.LockInvalid,
			fmt.Sprintf("%s %q not in lockfile", kind, name), "Run 'epack lock' first", nil)
	}

	platformEntry, ok := locked.Platforms[platform]
	if !ok {
		return nil, errors.WithHint(errors.BinaryNotFound, exitcode.MissingBinary,
			fmt.Sprintf("%s %q has no entry for platform %s", kind, name, platform),
			fmt.Sprintf("Run 'epack lock --platform %s'", platform), nil)
	}

	// Compute install path
	installPath, err := InstallPath(s.BaseDir, accessor.LockfileKind(), name, locked.Version, name)
	if err != nil {
		return nil, fmt.Errorf("computing install path: %w", err)
	}
	installDir := filepath.Dir(installPath)

	result := &SyncResult{
		Name:     name,
		Kind:     kind,
		Version:  locked.Version,
		Platform: platform,
	}

	// Check if already installed and verified
	if _, err := os.Stat(installPath); err == nil {
		// Binary exists - verify digest
		if err := VerifyDigest(installPath, platformEntry.Digest); err == nil {
			// Remove insecure marker on successful verification
			ClearInsecureMarker(installDir)
			result.Verified = true
			return result, nil
		}
		// Digest mismatch - need to re-download
		if opts.Frozen {
			return nil, errors.WithHint(errors.DigestMismatch, exitcode.DigestMismatch,
				fmt.Sprintf("%s %q digest mismatch (expected %s)", kind, name, platformEntry.Digest),
				"Run 'epack sync' to re-download", nil)
		}
	}

	// In frozen mode, don't download
	if opts.Frozen {
		return nil, errors.WithHint(errors.BinaryNotFound, exitcode.MissingBinary,
			fmt.Sprintf("%s %q not installed", kind, name), "Run 'epack sync' to install", nil)
	}

	// Download and install
	owner, repo, err := ParseSourceURI(locked.Source)
	if err != nil {
		return nil, err
	}

	// Build source string for registry calls
	source := fmt.Sprintf("%s/%s", owner, repo)

	release, err := s.Registry.FetchRelease(ctx, source, locked.Version)
	if err != nil {
		return nil, errors.WithHint(errors.NetworkError, exitcode.Network,
			fmt.Sprintf("fetching release %s: %v", locked.Version, err),
			"Check network connection and GITHUB_TOKEN", nil)
	}

	asset, err := s.Registry.FindBinaryAsset(release, name, runtime.GOOS, runtime.GOARCH)
	if err != nil {
		return nil, fmt.Errorf("finding binary asset: %w", err)
	}

	// Create install directory
	// SECURITY: Use MkdirAll to refuse symlinks during directory walk.
	if err := safefile.MkdirAll(s.BaseDir, installDir); err != nil {
		return nil, fmt.Errorf("creating install directory: %w", err)
	}

	// Download binary
	tmpPath := installPath + ".tmp"
	if err := s.Registry.DownloadAsset(ctx, asset.URL, tmpPath); err != nil {
		_ = os.Remove(tmpPath)
		return nil, errors.WithHint(errors.NetworkError, exitcode.Network,
			fmt.Sprintf("downloading %s: %v", asset.Name, err),
			"Check network connection", nil)
	}

	// Verify or mark as insecure
	if opts.InsecureSkipVerify || opts.InsecureTrustOnFirst {
		// Skip signature verification - just check digest
		if err := VerifyDigest(tmpPath, platformEntry.Digest); err != nil {
			_ = os.Remove(tmpPath)
			return nil, errors.WithHint(errors.DigestMismatch, exitcode.DigestMismatch,
				fmt.Sprintf("%s %q digest mismatch (expected %s)", kind, name, platformEntry.Digest),
				"Downloaded binary doesn't match lockfile", nil)
		}
		// Write insecure marker
		if err := WriteInsecureMarker(installDir); err != nil {
			_ = os.Remove(tmpPath)
			return nil, fmt.Errorf("writing insecure marker: %w", err)
		}
	} else {
		// Full sigstore verification
		bundleAsset, err := s.Registry.FindSigstoreBundle(release, asset.Name)
		if err != nil {
			_ = os.Remove(tmpPath)
			return nil, errors.WithHint(errors.SignatureInvalid, exitcode.SignatureMismatch,
				fmt.Sprintf("sigstore bundle not found for %s", asset.Name),
				"Release may not be signed, use --insecure-skip-verify to bypass (NOT RECOMMENDED)", nil)
		}

		// Sanitize bundle asset name
		safeBundleName, err := SanitizeAssetName(bundleAsset.Name)
		if err != nil {
			_ = os.Remove(tmpPath)
			return nil, fmt.Errorf("invalid bundle asset name: %w", err)
		}

		bundlePath := filepath.Join(installDir, safeBundleName)
		if err := s.Registry.DownloadAsset(ctx, bundleAsset.URL, bundlePath); err != nil {
			_ = os.Remove(tmpPath)
			return nil, errors.WithHint(errors.NetworkError, exitcode.Network,
				fmt.Sprintf("downloading sigstore bundle: %v", err),
				"Check network connection", nil)
		}

		// Build expected identity from lockfile
		expectedRepoURI := BuildGitHubRepoURL(owner, repo)
		expectedRef := BuildGitHubRefTag(locked.Version)
		expectedIdentity := &ExpectedIdentity{
			SourceRepositoryURI: expectedRepoURI,
			SourceRepositoryRef: expectedRef,
		}

		// Verify signature
		sigResult, err := VerifySigstoreBundle(bundlePath, tmpPath, expectedIdentity)
		_ = os.Remove(bundlePath) // Clean up bundle after verification
		if err != nil {
			_ = os.Remove(tmpPath)
			return nil, errors.WithHint(errors.SignatureInvalid, exitcode.SignatureMismatch,
				fmt.Sprintf("sigstore verification failed: %v", err),
				"Binary signature doesn't match expected signer", nil)
		}

		// Verify signer matches lockfile
		if locked.Signer != nil {
			if err := MatchSigner(sigResult, locked.Signer); err != nil {
				_ = os.Remove(tmpPath)
				return nil, errors.WithHint(errors.SignatureInvalid, exitcode.SignatureMismatch,
					fmt.Sprintf("signer mismatch: %v", err),
					"Release was signed by different identity than lockfile recorded", nil)
			}
		}

		// Verify digest
		if err := VerifyDigest(tmpPath, platformEntry.Digest); err != nil {
			_ = os.Remove(tmpPath)
			return nil, errors.WithHint(errors.DigestMismatch, exitcode.DigestMismatch,
				fmt.Sprintf("%s %q digest mismatch (expected %s)", kind, name, platformEntry.Digest),
				"Downloaded binary doesn't match lockfile", nil)
		}

		// Clear any stale insecure marker
		ClearInsecureMarker(installDir)
	}

	// Make executable and rename atomically
	if err := os.Chmod(tmpPath, 0755); err != nil {
		_ = os.Remove(tmpPath)
		return nil, fmt.Errorf("making binary executable: %w", err)
	}
	if err := os.Rename(tmpPath, installPath); err != nil {
		_ = os.Remove(tmpPath)
		return nil, fmt.Errorf("installing binary: %w", err)
	}

	result.Installed = true
	return result, nil
}

// syncCollector syncs a single collector.
func (s *Syncer) syncCollector(ctx context.Context, name string, cfg config.CollectorConfig, lf *lockfile.LockFile, platform string, opts SyncOpts) (*SyncResult, error) {
	if cfg.Source == "" {
		// External binary - verify if in lockfile
		if cfg.Binary != "" {
			return s.VerifyExternalCollector(name, cfg, lf, platform, opts)
		}
		return nil, nil
	}

	return s.syncSourceComponent(ctx, name, collectorAccessor{}, lf, platform, opts)
}

// VerifyExternalCollector verifies an external binary against lockfile.
func (s *Syncer) VerifyExternalCollector(name string, cfg config.CollectorConfig, lf *lockfile.LockFile, platform string, opts SyncOpts) (*SyncResult, error) {
	locked, ok := lf.GetCollector(name)
	if !ok {
		// External not in lockfile - that's OK unless frozen
		if opts.Frozen {
			return nil, errors.WithHint(errors.LockfileInvalid, exitcode.LockInvalid,
				fmt.Sprintf("external collector %q not found in lockfile", name),
				"Run 'epack collector lock' to add external collectors", nil)
		}
		return &SyncResult{
			Name:     name,
			Kind:     "collector",
			Platform: platform,
			Skipped:  true,
		}, nil
	}

	platformEntry, ok := locked.Platforms[platform]
	if !ok || platformEntry.Digest == "" {
		// Platform not locked - in frozen mode this is an error
		if opts.Frozen {
			return nil, errors.WithHint(errors.BinaryNotFound, exitcode.MissingBinary,
				fmt.Sprintf("external collector %q missing platform %s in lockfile", name, platform),
				fmt.Sprintf("Run 'epack collector lock --platform %s' to add this platform", platform), nil)
		}
		// Non-frozen: allow unverified external
		return &SyncResult{
			Name:     name,
			Kind:     "collector",
			Platform: platform,
			Skipped:  true,
		}, nil
	}

	if !opts.InsecureSkipVerify {
		if err := VerifyDigest(cfg.Binary, platformEntry.Digest); err != nil {
			return nil, errors.WithHint(errors.DigestMismatch, exitcode.DigestMismatch,
				fmt.Sprintf("digest mismatch for external collector %q (expected %s)", name, platformEntry.Digest),
				"External binary has changed. Run 'epack collector lock' to update", nil)
		}
	}

	// SECURITY: Only set Verified=true when we actually verified.
	// If InsecureSkipVerify was set, we didn't verify so Verified must be false.
	return &SyncResult{
		Name:     name,
		Kind:     "collector",
		Platform: platform,
		Verified: !opts.InsecureSkipVerify,
		Skipped:  true,
	}, nil
}

// syncTool syncs a single tool.
func (s *Syncer) syncTool(ctx context.Context, name string, cfg config.ToolConfig, lf *lockfile.LockFile, platform string, opts SyncOpts) (*SyncResult, error) {
	if cfg.Source == "" {
		// External binary - verify if in lockfile
		if cfg.Binary != "" {
			return s.verifyExternalTool(name, cfg, lf, platform, opts)
		}
		return nil, nil
	}

	return s.syncSourceComponent(ctx, name, toolAccessor{}, lf, platform, opts)
}

// verifyExternalTool verifies an external binary against lockfile.
func (s *Syncer) verifyExternalTool(name string, cfg config.ToolConfig, lf *lockfile.LockFile, platform string, opts SyncOpts) (*SyncResult, error) {
	locked, ok := lf.GetTool(name)
	if !ok {
		// Not in lockfile - skip unless frozen
		if opts.Frozen {
			return nil, errors.WithHint(errors.LockfileInvalid, exitcode.LockInvalid,
				fmt.Sprintf("external tool %q not in lockfile", name),
				"Run 'epack lock' to pin external tools", nil)
		}
		return &SyncResult{
			Name:    name,
			Kind:    "tool",
			Skipped: true,
		}, nil
	}

	platformEntry, ok := locked.Platforms[platform]
	if !ok {
		if opts.Frozen {
			return nil, errors.WithHint(errors.LockfileInvalid, exitcode.LockInvalid,
				fmt.Sprintf("external tool %q has no entry for platform %s", name, platform),
				fmt.Sprintf("Run 'epack lock --platform %s'", platform), nil)
		}
		return &SyncResult{
			Name:    name,
			Kind:    "tool",
			Skipped: true,
		}, nil
	}

	// Verify digest
	if err := VerifyDigest(cfg.Binary, platformEntry.Digest); err != nil {
		return nil, errors.WithHint(errors.DigestMismatch, exitcode.DigestMismatch,
			fmt.Sprintf("external tool %q digest mismatch (expected %s)", name, platformEntry.Digest),
			"External binary was modified. Run 'epack lock' to update", nil)
	}

	return &SyncResult{
		Name:     name,
		Kind:     "tool",
		Verified: true,
	}, nil
}

// SyncRemote syncs a single remote adapter.
// This is the exported version for use by other packages that need to install
// a specific remote adapter on-demand.
func (s *Syncer) SyncRemote(ctx context.Context, name string, cfg config.RemoteConfig, lf *lockfile.LockFile, platform string, opts SyncOpts) (*SyncResult, error) {
	return s.syncRemote(ctx, name, cfg, lf, platform, opts)
}

// syncRemote syncs a single remote adapter.
func (s *Syncer) syncRemote(ctx context.Context, name string, cfg config.RemoteConfig, lf *lockfile.LockFile, platform string, opts SyncOpts) (*SyncResult, error) {
	if cfg.Source == "" {
		// External binary - verify if in lockfile
		if cfg.Binary != "" {
			return s.verifyExternalRemote(name, cfg, lf, platform, opts)
		}
		// Adapter-only mode (discover from PATH) - nothing to sync
		return nil, nil
	}

	return s.syncSourceComponent(ctx, name, remoteAccessor{}, lf, platform, opts)
}

// verifyExternalRemote verifies an external remote adapter binary against lockfile.
func (s *Syncer) verifyExternalRemote(name string, cfg config.RemoteConfig, lf *lockfile.LockFile, platform string, opts SyncOpts) (*SyncResult, error) {
	locked, ok := lf.GetRemote(name)
	if !ok {
		// Not in lockfile - skip unless frozen
		if opts.Frozen {
			return nil, errors.WithHint(errors.LockfileInvalid, exitcode.LockInvalid,
				fmt.Sprintf("external remote %q not in lockfile", name),
				"Run 'epack lock' to pin external remotes", nil)
		}
		return &SyncResult{
			Name:    name,
			Kind:    "remote",
			Skipped: true,
		}, nil
	}

	platformEntry, ok := locked.Platforms[platform]
	if !ok {
		if opts.Frozen {
			return nil, errors.WithHint(errors.LockfileInvalid, exitcode.LockInvalid,
				fmt.Sprintf("external remote %q has no entry for platform %s", name, platform),
				fmt.Sprintf("Run 'epack lock --platform %s'", platform), nil)
		}
		return &SyncResult{
			Name:    name,
			Kind:    "remote",
			Skipped: true,
		}, nil
	}

	// Verify digest
	if err := VerifyDigest(cfg.Binary, platformEntry.Digest); err != nil {
		return nil, errors.WithHint(errors.DigestMismatch, exitcode.DigestMismatch,
			fmt.Sprintf("external remote %q digest mismatch (expected %s)", name, platformEntry.Digest),
			"External binary was modified. Run 'epack lock' to update", nil)
	}

	return &SyncResult{
		Name:     name,
		Kind:     "remote",
		Verified: true,
	}, nil
}
