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
	"github.com/locktivity/epack/internal/safefile/tx"
	"github.com/locktivity/epack/internal/securityaudit"
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
	Kind() string                               // "collector", "tool", or "remote"
	LockfileKind() componenttypes.ComponentKind // componenttypes.KindCollector, KindTool, or KindRemote
	BinaryName(name string) string              // Binary filename for installation
}

type collectorAccessor struct{}

func (collectorAccessor) Kind() string { return "collector" }
func (collectorAccessor) LockfileKind() componenttypes.ComponentKind {
	return componenttypes.KindCollector
}
func (collectorAccessor) BinaryName(name string) string { return name }
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
func (toolAccessor) BinaryName(name string) string              { return name }
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
func (remoteAccessor) BinaryName(name string) string              { return name }
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
	Secure SyncSecureOptions
	Unsafe SyncUnsafeOverrides

	// SkipStaleEntryCheck skips validation that lockfile entries exist in config.
	// This is safe to use when installing new components with a filtered config,
	// where the full config has all entries but we only want to sync specific ones.
	// The forward direction (config entries must exist in lockfile) is still validated.
	SkipStaleEntryCheck bool
}

type SyncSecureOptions struct {
	Frozen bool // Verify only, don't download.
}

type SyncUnsafeOverrides struct {
	SkipVerify   bool // Skip Sigstore verification (NOT RECOMMENDED).
	TrustOnFirst bool // Trust digest from lockfile without Sigstore (NOT RECOMMENDED).
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
	if err := safefile.EnsureBaseDir(s.BaseDir); err != nil {
		return nil, fmt.Errorf("creating base directory: %w", err)
	}

	// Validate option combinations
	if opts.Secure.Frozen && opts.Unsafe.SkipVerify {
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
	if err := s.validateAlignmentWithOpts(cfg, lf, opts); err != nil {
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
	return s.validateAlignmentWithOpts(cfg, lf, SyncOpts{})
}

func (s *Syncer) validateAlignmentWithOpts(cfg *config.JobConfig, lf *lockfile.LockFile, opts SyncOpts) error {
	if err := s.validateCollectorAlignment(cfg, lf, opts.SkipStaleEntryCheck); err != nil {
		return err
	}
	return s.validateRemoteAlignment(cfg, lf, opts.SkipStaleEntryCheck)
}

func (s *Syncer) validateCollectorAlignment(cfg *config.JobConfig, lf *lockfile.LockFile, skipStaleCheck bool) error {
	for _, name := range sortedMapNames(cfg.Collectors) {
		if err := validateCollectorConfigEntry(name, cfg.Collectors[name], lf); err != nil {
			return err
		}
	}

	// Skip the reverse check (lockfile entries must exist in config) when installing
	// specific components with a filtered config.
	if skipStaleCheck {
		return nil
	}

	for _, name := range sortedMapNames(lf.Collectors) {
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
		if cfgCollector.Source == "" {
			return errors.WithHint(errors.LockfileInvalid, exitcode.LockInvalid,
				fmt.Sprintf("lockfile has %q as source-based but config declares it as external", name),
				"Run 'epack collector lock' to update the lockfile", nil)
		}
	}
	return nil
}

func validateCollectorConfigEntry(name string, collector config.CollectorConfig, lf *lockfile.LockFile) error {
	locked, ok := lf.GetCollector(name)

	if collector.Source != "" {
		if !ok {
			return errors.WithHint(errors.LockfileInvalid, exitcode.LockInvalid,
				fmt.Sprintf("config declares collector %q not found in lockfile", name),
				"Run 'epack collector lock' to update the lockfile", nil)
		}
		if locked.Kind == "external" {
			return errors.WithHint(errors.LockfileInvalid, exitcode.LockInvalid,
				fmt.Sprintf("config declares %q as source-based but lockfile has it as external", name),
				"Run 'epack collector lock' to update the lockfile", nil)
		}
		return validateSourceAndSignerMatch("collector", name, collector.Source, locked.Source, locked.Signer, "epack collector lock")
	}

	if collector.Binary != "" && ok && locked.Kind != "external" {
		return errors.WithHint(errors.LockfileInvalid, exitcode.LockInvalid,
			fmt.Sprintf("config declares %q as external binary but lockfile has it as source-based", name),
			"Run 'epack collector lock' to update the lockfile", nil)
	}

	return nil
}

func (s *Syncer) validateRemoteAlignment(cfg *config.JobConfig, lf *lockfile.LockFile, skipStaleCheck bool) error {
	for _, name := range sortedMapNames(cfg.Remotes) {
		if err := validateRemoteConfigEntry(name, cfg.Remotes[name], lf); err != nil {
			return err
		}
	}

	// Skip the reverse check (lockfile entries must exist in config) when installing
	// specific components with a filtered config.
	if skipStaleCheck {
		return nil
	}

	for _, name := range sortedMapNames(lf.Remotes) {
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
		if cfgRemote.Source == "" {
			return errors.WithHint(errors.LockfileInvalid, exitcode.LockInvalid,
				fmt.Sprintf("lockfile has %q as source-based but config declares it as external", name),
				"Run 'epack lock' to update the lockfile", nil)
		}
	}
	return nil
}

func validateRemoteConfigEntry(name string, remote config.RemoteConfig, lf *lockfile.LockFile) error {
	locked, ok := lf.GetRemote(name)

	if remote.Source != "" {
		if !ok {
			return errors.WithHint(errors.LockfileInvalid, exitcode.LockInvalid,
				fmt.Sprintf("config declares remote %q not found in lockfile", name),
				"Run 'epack lock' to update the lockfile", nil)
		}
		if locked.Kind == "external" {
			return errors.WithHint(errors.LockfileInvalid, exitcode.LockInvalid,
				fmt.Sprintf("config declares %q as source-based but lockfile has it as external", name),
				"Run 'epack lock' to update the lockfile", nil)
		}
		return validateSourceAndSignerMatch("remote", name, remote.Source, locked.Source, locked.Signer, "epack lock")
	}

	if remote.Binary != "" && ok && locked.Kind != "external" {
		return errors.WithHint(errors.LockfileInvalid, exitcode.LockInvalid,
			fmt.Sprintf("config declares %q as external binary but lockfile has it as source-based", name),
			"Run 'epack lock' to update the lockfile", nil)
	}

	// Adapter-only remotes (no source or binary) don't need lockfile validation.
	return nil
}

func validateSourceAndSignerMatch(kind, name, configuredSource, lockedSource string, signer *componenttypes.LockedSigner, lockCmd string) error {
	configOwner, configRepo, _, err := github.ParseSource(configuredSource)
	if err != nil {
		return errors.WithHint(errors.LockfileInvalid, exitcode.LockInvalid,
			fmt.Sprintf("invalid source in config for %s %q: %v", kind, name, err),
			"Check the source format in epack.yaml", nil)
	}

	expectedSource := fmt.Sprintf("github.com/%s/%s", configOwner, configRepo)
	if lockedSource != expectedSource {
		return errors.WithHint(errors.LockfileInvalid, exitcode.LockInvalid,
			fmt.Sprintf("config source mismatch for %s %q: config declares %q but lockfile has %q", kind, name, expectedSource, lockedSource),
			fmt.Sprintf("Run '%s' to update the lockfile with the new source", lockCmd), nil)
	}

	if signer != nil {
		expectedRepoURI := fmt.Sprintf("https://github.com/%s/%s", configOwner, configRepo)
		if signer.SourceRepositoryURI != expectedRepoURI {
			return errors.WithHint(errors.LockfileInvalid, exitcode.LockInvalid,
				fmt.Sprintf("signer source mismatch for %s %q: config declares %q but lockfile signer is from %q", kind, name, expectedRepoURI, signer.SourceRepositoryURI),
				fmt.Sprintf("Run '%s' to update the lockfile", lockCmd), nil)
		}
	}

	return nil
}

func sortedMapNames[T any](m map[string]T) []string {
	names := make([]string, 0, len(m))
	for name := range m {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// syncSourceComponent is the unified implementation for syncing source-based components.
// It handles both collectors and tools through the componentAccessor interface.
func (s *Syncer) syncSourceComponent(ctx context.Context, name string, accessor componentAccessor, lf *lockfile.LockFile, platform string, opts SyncOpts) (*SyncResult, error) {
	kind := accessor.Kind()

	locked, platformEntry, err := getLockedComponentForPlatform(accessor, lf, kind, name, platform)
	if err != nil {
		return nil, err
	}

	installPath, installDir, err := computeInstallPaths(s.BaseDir, accessor, name, locked.Version)
	if err != nil {
		return nil, err
	}

	result := &SyncResult{
		Name:     name,
		Kind:     kind,
		Version:  locked.Version,
		Platform: platform,
	}

	alreadyVerified, err := verifyExistingInstall(kind, name, installPath, installDir, platformEntry.Digest, opts.Secure.Frozen)
	if err != nil {
		return nil, err
	}
	if alreadyVerified {
		result.Verified = true
		return result, nil
	}

	if opts.Secure.Frozen {
		return nil, errors.WithHint(errors.BinaryNotFound, exitcode.MissingBinary,
			fmt.Sprintf("%s %q not installed", kind, name), "Run 'epack sync' to install", nil)
	}

	if err := s.downloadAndInstallComponent(ctx, name, kind, locked, platformEntry, installPath, installDir, opts); err != nil {
		return nil, err
	}

	result.Installed = true
	return result, nil
}

func getLockedComponentForPlatform(accessor componentAccessor, lf *lockfile.LockFile, kind, name, platform string) (*lockedComponent, componenttypes.LockedPlatform, error) {
	locked, ok := accessor.GetLocked(lf, name)
	if !ok {
		return nil, componenttypes.LockedPlatform{}, errors.WithHint(errors.LockfileInvalid, exitcode.LockInvalid,
			fmt.Sprintf("%s %q not in lockfile", kind, name), "Run 'epack lock' first", nil)
	}
	platformEntry, ok := locked.Platforms[platform]
	if !ok {
		return nil, componenttypes.LockedPlatform{}, errors.WithHint(errors.BinaryNotFound, exitcode.MissingBinary,
			fmt.Sprintf("%s %q has no entry for platform %s", kind, name, platform),
			fmt.Sprintf("Run 'epack lock --platform %s'", platform), nil)
	}
	return locked, platformEntry, nil
}

func computeInstallPaths(baseDir string, accessor componentAccessor, name, version string) (installPath, installDir string, err error) {
	binaryName := accessor.BinaryName(name)
	installPath, err = InstallPath(baseDir, accessor.LockfileKind(), name, version, binaryName)
	if err != nil {
		return "", "", fmt.Errorf("computing install path: %w", err)
	}
	return installPath, filepath.Dir(installPath), nil
}

func verifyExistingInstall(kind, name, installPath, installDir, digest string, frozen bool) (bool, error) {
	if _, err := os.Stat(installPath); err != nil {
		return false, nil
	}
	if err := VerifyDigest(installPath, digest); err == nil {
		ClearInsecureMarker(installDir)
		return true, nil
	}
	if frozen {
		return false, errors.WithHint(errors.DigestMismatch, exitcode.DigestMismatch,
			fmt.Sprintf("%s %q digest mismatch (expected %s)", kind, name, digest),
			"Run 'epack sync' to re-download", nil)
	}
	return false, nil
}

func (s *Syncer) downloadAndInstallComponent(
	ctx context.Context,
	name, kind string,
	locked *lockedComponent,
	platformEntry componenttypes.LockedPlatform,
	installPath, installDir string,
	opts SyncOpts,
) error {
	owner, repo, release, asset, err := s.resolveReleaseAsset(ctx, name, locked)
	if err != nil {
		return err
	}

	if err := safefile.MkdirAll(s.BaseDir, installDir); err != nil {
		return fmt.Errorf("creating install directory: %w", err)
	}

	tmpPath := installPath + ".tmp"
	if err := s.Registry.DownloadAsset(ctx, asset.URL, tmpPath); err != nil {
		_ = os.Remove(tmpPath)
		return errors.WithHint(errors.NetworkError, exitcode.Network,
			fmt.Sprintf("downloading %s: %v", asset.Name, err),
			"Check network connection", nil)
	}

	if err := s.verifyDownloadedBinary(ctx, kind, name, owner, repo, locked, platformEntry, tmpPath, installDir, release, asset, opts); err != nil {
		return err
	}

	data, err := os.ReadFile(tmpPath)
	if err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("reading downloaded binary: %w", err)
	}
	if err := tx.WriteAtomicPath(installPath, data, 0755); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("installing binary: %w", err)
	}
	if err := os.Remove(tmpPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("cleaning temporary binary: %w", err)
	}

	return nil
}

func (s *Syncer) resolveReleaseAsset(ctx context.Context, name string, locked *lockedComponent) (owner, repo string, release *ReleaseInfo, asset *AssetInfo, err error) {
	owner, repo, err = ParseSourceURI(locked.Source)
	if err != nil {
		return "", "", nil, nil, err
	}
	source := fmt.Sprintf("%s/%s", owner, repo)

	release, err = s.Registry.FetchRelease(ctx, source, locked.Version)
	if err != nil {
		return "", "", nil, nil, errors.WithHint(errors.NetworkError, exitcode.Network,
			fmt.Sprintf("fetching release %s: %v", locked.Version, err),
			"Check network connection and GITHUB_TOKEN", nil)
	}

	asset, err = s.Registry.FindBinaryAsset(release, name, runtime.GOOS, runtime.GOARCH)
	if err != nil {
		return "", "", nil, nil, fmt.Errorf("finding binary asset: %w", err)
	}
	return owner, repo, release, asset, nil
}

func (s *Syncer) verifyDownloadedBinary(
	ctx context.Context,
	kind, name, owner, repo string,
	locked *lockedComponent,
	platformEntry componenttypes.LockedPlatform,
	tmpPath, installDir string,
	release *ReleaseInfo,
	asset *AssetInfo,
	opts SyncOpts,
) error {
	if opts.Unsafe.SkipVerify || opts.Unsafe.TrustOnFirst {
		return verifyDownloadedBinaryInsecure(kind, name, platformEntry.Digest, tmpPath, installDir)
	}
	return s.verifyDownloadedBinarySigstore(ctx, kind, name, owner, repo, locked, platformEntry.Digest, tmpPath, installDir, release, asset)
}

func verifyDownloadedBinaryInsecure(kind, name, expectedDigest, tmpPath, installDir string) error {
	if err := VerifyDigest(tmpPath, expectedDigest); err != nil {
		securityaudit.Emit(securityaudit.Event{
			Type:        securityaudit.EventVerificationFail,
			Component:   kind,
			Name:        name,
			Description: "component digest verification failed in insecure install path",
		})
		_ = os.Remove(tmpPath)
		return errors.WithHint(errors.DigestMismatch, exitcode.DigestMismatch,
			fmt.Sprintf("%s %q digest mismatch (expected %s)", kind, name, expectedDigest),
			"Downloaded binary doesn't match lockfile", nil)
	}
	securityaudit.Emit(securityaudit.Event{
		Type:        securityaudit.EventInsecureBypass,
		Component:   kind,
		Name:        name,
		Description: "component install running with insecure verification override",
	})
	if err := WriteInsecureMarker(installDir); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("writing insecure marker: %w", err)
	}
	return nil
}

func (s *Syncer) verifyDownloadedBinarySigstore(
	ctx context.Context,
	kind, name, owner, repo string,
	locked *lockedComponent,
	expectedDigest, tmpPath, installDir string,
	release *ReleaseInfo,
	asset *AssetInfo,
) error {
	bundleAsset, err := s.Registry.FindSigstoreBundle(release, asset.Name)
	if err != nil {
		securityaudit.Emit(securityaudit.Event{
			Type:        securityaudit.EventVerificationFail,
			Component:   kind,
			Name:        name,
			Description: "sigstore bundle not found for component install",
		})
		_ = os.Remove(tmpPath)
		return errors.WithHint(errors.SignatureInvalid, exitcode.SignatureMismatch,
			fmt.Sprintf("sigstore bundle not found for %s", asset.Name),
			"Release may not be signed, use --insecure-skip-verify to bypass (NOT RECOMMENDED)", nil)
	}

	safeBundleName, err := SanitizeAssetName(bundleAsset.Name)
	if err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("invalid bundle asset name: %w", err)
	}
	bundlePath := filepath.Join(installDir, safeBundleName)
	if err := s.Registry.DownloadAsset(ctx, bundleAsset.URL, bundlePath); err != nil {
		_ = os.Remove(tmpPath)
		return errors.WithHint(errors.NetworkError, exitcode.Network,
			fmt.Sprintf("downloading sigstore bundle: %v", err),
			"Check network connection", nil)
	}

	expectedIdentity := &ExpectedIdentity{
		SourceRepositoryURI: BuildGitHubRepoURL(owner, repo),
		SourceRepositoryRef: BuildGitHubRefTag(locked.Version),
	}
	sigResult, err := VerifySigstoreBundle(bundlePath, tmpPath, expectedIdentity)
	_ = os.Remove(bundlePath)
	if err != nil {
		securityaudit.Emit(securityaudit.Event{
			Type:        securityaudit.EventVerificationFail,
			Component:   kind,
			Name:        name,
			Description: "sigstore verification failed for component install",
		})
		_ = os.Remove(tmpPath)
		return errors.WithHint(errors.SignatureInvalid, exitcode.SignatureMismatch,
			fmt.Sprintf("sigstore verification failed: %v", err),
			"Binary signature doesn't match expected signer", nil)
	}

	if locked.Signer != nil {
		if err := MatchSigner(sigResult, locked.Signer); err != nil {
			securityaudit.Emit(securityaudit.Event{
				Type:        securityaudit.EventVerificationFail,
				Component:   kind,
				Name:        name,
				Description: "signer identity verification failed for component install",
			})
			_ = os.Remove(tmpPath)
			return errors.WithHint(errors.SignatureInvalid, exitcode.SignatureMismatch,
				fmt.Sprintf("signer mismatch: %v", err),
				"Release was signed by different identity than lockfile recorded", nil)
		}
	}

	if err := VerifyDigest(tmpPath, expectedDigest); err != nil {
		securityaudit.Emit(securityaudit.Event{
			Type:        securityaudit.EventVerificationFail,
			Component:   kind,
			Name:        name,
			Description: "component digest verification failed after sigstore verification",
		})
		_ = os.Remove(tmpPath)
		return errors.WithHint(errors.DigestMismatch, exitcode.DigestMismatch,
			fmt.Sprintf("%s %q digest mismatch (expected %s)", kind, name, expectedDigest),
			"Downloaded binary doesn't match lockfile", nil)
	}

	ClearInsecureMarker(installDir)
	return nil
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
		if opts.Secure.Frozen {
			return nil, errors.WithHint(errors.LockfileInvalid, exitcode.LockInvalid,
				fmt.Sprintf("external collector %q not found in lockfile", name),
				"Run 'epack collector lock' to add external collectors", nil)
		}
		securityaudit.Emit(securityaudit.Event{
			Type:        securityaudit.EventUnpinnedExecution,
			Component:   string(componenttypes.KindCollector),
			Name:        name,
			Description: "external collector not pinned in lockfile",
		})
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
		if opts.Secure.Frozen {
			return nil, errors.WithHint(errors.BinaryNotFound, exitcode.MissingBinary,
				fmt.Sprintf("external collector %q missing platform %s in lockfile", name, platform),
				fmt.Sprintf("Run 'epack collector lock --platform %s' to add this platform", platform), nil)
		}
		// Non-frozen: allow unverified external
		securityaudit.Emit(securityaudit.Event{
			Type:        securityaudit.EventUnpinnedExecution,
			Component:   string(componenttypes.KindCollector),
			Name:        name,
			Description: "external collector missing platform digest in lockfile",
		})
		return &SyncResult{
			Name:     name,
			Kind:     "collector",
			Platform: platform,
			Skipped:  true,
		}, nil
	}

	if !opts.Unsafe.SkipVerify {
		if err := VerifyDigest(cfg.Binary, platformEntry.Digest); err != nil {
			securityaudit.Emit(securityaudit.Event{
				Type:        securityaudit.EventVerificationFail,
				Component:   string(componenttypes.KindCollector),
				Name:        name,
				Description: "external collector digest verification failed",
			})
			return nil, errors.WithHint(errors.DigestMismatch, exitcode.DigestMismatch,
				fmt.Sprintf("digest mismatch for external collector %q (expected %s)", name, platformEntry.Digest),
				"External binary has changed. Run 'epack collector lock' to update", nil)
		}
	}
	if opts.Unsafe.SkipVerify {
		securityaudit.Emit(securityaudit.Event{
			Type:        securityaudit.EventInsecureBypass,
			Component:   string(componenttypes.KindCollector),
			Name:        name,
			Description: "external collector execution allowed with insecure skip-verify override",
		})
	}

	// SECURITY: Only set Verified=true when we actually verified.
	// If SkipVerify was set, we didn't verify so Verified must be false.
	return &SyncResult{
		Name:     name,
		Kind:     "collector",
		Platform: platform,
		Verified: !opts.Unsafe.SkipVerify,
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
		if opts.Secure.Frozen {
			return nil, errors.WithHint(errors.LockfileInvalid, exitcode.LockInvalid,
				fmt.Sprintf("external tool %q not in lockfile", name),
				"Run 'epack lock' to pin external tools", nil)
		}
		securityaudit.Emit(securityaudit.Event{
			Type:        securityaudit.EventUnpinnedExecution,
			Component:   string(componenttypes.KindTool),
			Name:        name,
			Description: "external tool not pinned in lockfile",
		})
		return &SyncResult{
			Name:    name,
			Kind:    "tool",
			Skipped: true,
		}, nil
	}

	platformEntry, ok := locked.Platforms[platform]
	if !ok {
		if opts.Secure.Frozen {
			return nil, errors.WithHint(errors.LockfileInvalid, exitcode.LockInvalid,
				fmt.Sprintf("external tool %q has no entry for platform %s", name, platform),
				fmt.Sprintf("Run 'epack lock --platform %s'", platform), nil)
		}
		securityaudit.Emit(securityaudit.Event{
			Type:        securityaudit.EventUnpinnedExecution,
			Component:   string(componenttypes.KindTool),
			Name:        name,
			Description: "external tool missing platform digest in lockfile",
		})
		return &SyncResult{
			Name:    name,
			Kind:    "tool",
			Skipped: true,
		}, nil
	}

	// Verify digest
	if err := VerifyDigest(cfg.Binary, platformEntry.Digest); err != nil {
		securityaudit.Emit(securityaudit.Event{
			Type:        securityaudit.EventVerificationFail,
			Component:   string(componenttypes.KindTool),
			Name:        name,
			Description: "external tool digest verification failed",
		})
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
		if opts.Secure.Frozen {
			return nil, errors.WithHint(errors.LockfileInvalid, exitcode.LockInvalid,
				fmt.Sprintf("external remote %q not in lockfile", name),
				"Run 'epack lock' to pin external remotes", nil)
		}
		securityaudit.Emit(securityaudit.Event{
			Type:        securityaudit.EventUnpinnedExecution,
			Component:   string(componenttypes.KindRemote),
			Name:        name,
			Description: "external remote not pinned in lockfile",
		})
		return &SyncResult{
			Name:    name,
			Kind:    "remote",
			Skipped: true,
		}, nil
	}

	platformEntry, ok := locked.Platforms[platform]
	if !ok {
		if opts.Secure.Frozen {
			return nil, errors.WithHint(errors.LockfileInvalid, exitcode.LockInvalid,
				fmt.Sprintf("external remote %q has no entry for platform %s", name, platform),
				fmt.Sprintf("Run 'epack lock --platform %s'", platform), nil)
		}
		securityaudit.Emit(securityaudit.Event{
			Type:        securityaudit.EventUnpinnedExecution,
			Component:   string(componenttypes.KindRemote),
			Name:        name,
			Description: "external remote missing platform digest in lockfile",
		})
		return &SyncResult{
			Name:    name,
			Kind:    "remote",
			Skipped: true,
		}, nil
	}

	// Verify digest
	if err := VerifyDigest(cfg.Binary, platformEntry.Digest); err != nil {
		securityaudit.Emit(securityaudit.Event{
			Type:        securityaudit.EventVerificationFail,
			Component:   string(componenttypes.KindRemote),
			Name:        name,
			Description: "external remote digest verification failed",
		})
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
