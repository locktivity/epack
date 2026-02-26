package userconfig

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/locktivity/epack/internal/component/github"
	"github.com/locktivity/epack/internal/component/sync"
	"github.com/locktivity/epack/internal/componenttypes"
	"github.com/locktivity/epack/internal/platform"
	"github.com/locktivity/epack/internal/safefile"
	"github.com/locktivity/epack/internal/safefile/tx"
	"github.com/locktivity/epack/internal/securityaudit"
	"github.com/locktivity/epack/internal/securitypolicy"
	"github.com/locktivity/epack/internal/timestamp"
)

// UtilitySyncer handles downloading and verifying utilities.
type UtilitySyncer struct {
	Registry sync.RegistryClient
}

// NewUtilitySyncer creates a syncer with the default GitHub registry.
func NewUtilitySyncer() *UtilitySyncer {
	return &UtilitySyncer{
		Registry: sync.NewGitHubRegistry(),
	}
}

// InstallOpts controls utility installation behavior.
type InstallOpts struct {
	Secure SecureInstallOptions
	Unsafe UnsafeInstallOverrides
}

type SecureInstallOptions struct{}

type UnsafeInstallOverrides struct {
	SkipVerify   bool // Skip Sigstore verification (NOT RECOMMENDED)
	TrustOnFirst bool // Trust digest without Sigstore (NOT RECOMMENDED)
}

// InstallResult contains the result of installing a utility.
type InstallResult struct {
	Name      string
	Version   string
	Platform  string
	Installed bool
	Verified  bool
	Path      string
}

// Install downloads and installs a utility from a source.
// Source format: owner/repo@version (e.g., "locktivity/epack-tools-viewer@v1.0.0")
func (s *UtilitySyncer) Install(ctx context.Context, name, source string, opts InstallOpts) (*InstallResult, error) {
	hasUnsafeOverrides := opts.Unsafe.SkipVerify || opts.Unsafe.TrustOnFirst
	if err := securitypolicy.EnforceStrictProduction("utility_install", hasUnsafeOverrides); err != nil {
		return nil, err
	}
	if hasUnsafeOverrides {
		securityaudit.Emit(securityaudit.Event{
			Type:        securityaudit.EventInsecureBypass,
			Component:   string(componenttypes.KindUtility),
			Name:        name,
			Description: "utility install running with insecure verification override",
			Attrs: map[string]string{
				"skip_verify":    fmt.Sprintf("%t", opts.Unsafe.SkipVerify),
				"trust_on_first": fmt.Sprintf("%t", opts.Unsafe.TrustOnFirst),
			},
		})
	}

	owner, repo, version, err := s.resolveInstallSource(ctx, source)
	if err != nil {
		return nil, err
	}

	platform := platform.Key(runtime.GOOS, runtime.GOARCH)
	repoSource := fmt.Sprintf("%s/%s", owner, repo)
	release, asset, err := s.fetchReleaseAssetForInstall(ctx, repoSource, version, name)
	if err != nil {
		return nil, err
	}

	installPath, tmpPath, installDir, err := prepareUtilityInstallPath(name, version)
	if err != nil {
		return nil, err
	}
	cleanupTmp := func() { _ = os.Remove(tmpPath) }

	if err := ensureUtilityInstallDir(installDir); err != nil {
		return nil, err
	}

	digest, err := s.downloadAndDigestUtility(ctx, asset, tmpPath)
	if err != nil {
		cleanupTmp()
		return nil, err
	}

	sigResult, verified, err := s.maybeVerifyUtilitySigstore(ctx, name, release, asset, tmpPath, installDir, owner, repo, version, opts)
	if err != nil {
		cleanupTmp()
		return nil, err
	}

	if err := installUtilityBinary(tmpPath, installPath); err != nil {
		cleanupTmp()
		return nil, err
	}

	if err := s.updateUtilitiesLock(name, source, owner, repo, version, platform, digest, asset, sigResult, opts); err != nil {
		return nil, err
	}

	return &InstallResult{
		Name:      name,
		Version:   version,
		Platform:  platform,
		Installed: true,
		Verified:  verified,
		Path:      installPath,
	}, nil
}

func (s *UtilitySyncer) resolveInstallSource(ctx context.Context, source string) (owner, repo, version string, err error) {
	owner, repo, constraint, err := github.ParseSource(source)
	if err != nil {
		return "", "", "", fmt.Errorf("invalid source %q: %w", source, err)
	}
	repoSource := fmt.Sprintf("%s/%s", owner, repo)
	version, err = s.Registry.ResolveVersion(ctx, repoSource, constraint)
	if err != nil {
		return "", "", "", fmt.Errorf("resolving version: %w", err)
	}
	return owner, repo, version, nil
}

func (s *UtilitySyncer) fetchReleaseAssetForInstall(ctx context.Context, repoSource, version, name string) (*sync.ReleaseInfo, *sync.AssetInfo, error) {
	release, err := s.Registry.FetchRelease(ctx, repoSource, version)
	if err != nil {
		return nil, nil, fmt.Errorf("fetching release %s: %w", version, err)
	}

	binaryName := fmt.Sprintf("epack-util-%s", name)
	asset, err := s.Registry.FindBinaryAsset(release, binaryName, runtime.GOOS, runtime.GOARCH)
	if err != nil {
		return nil, nil, fmt.Errorf("finding binary asset: %w", err)
	}
	return release, asset, nil
}

func prepareUtilityInstallPath(name, version string) (installPath, tmpPath, installDir string, err error) {
	installPath, err = UtilityInstallPath(name, version)
	if err != nil {
		return "", "", "", fmt.Errorf("computing install path: %w", err)
	}
	installDir = filepath.Dir(installPath)
	return installPath, installPath + ".tmp", installDir, nil
}

func ensureUtilityInstallDir(installDir string) error {
	binDir, err := BinPath()
	if err != nil {
		return err
	}
	if err := safefile.MkdirAll(binDir, installDir); err != nil {
		return fmt.Errorf("creating install directory: %w", err)
	}
	return nil
}

func (s *UtilitySyncer) downloadAndDigestUtility(ctx context.Context, asset *sync.AssetInfo, tmpPath string) (string, error) {
	if err := s.Registry.DownloadAsset(ctx, asset.URL, tmpPath); err != nil {
		return "", fmt.Errorf("downloading %s: %w", asset.Name, err)
	}
	digest, err := sync.ComputeDigest(tmpPath)
	if err != nil {
		return "", fmt.Errorf("computing digest: %w", err)
	}
	return digest, nil
}

func (s *UtilitySyncer) maybeVerifyUtilitySigstore(ctx context.Context, name string, release *sync.ReleaseInfo, asset *sync.AssetInfo, tmpPath, installDir, owner, repo, version string, opts InstallOpts) (*sync.SigstoreResult, bool, error) {
	if opts.Unsafe.SkipVerify || opts.Unsafe.TrustOnFirst {
		return nil, false, nil
	}

	bundleAsset, err := s.Registry.FindSigstoreBundle(release, asset.Name)
	if err != nil {
		securityaudit.Emit(securityaudit.Event{
			Type:        securityaudit.EventVerificationFail,
			Component:   string(componenttypes.KindUtility),
			Name:        name,
			Description: "sigstore bundle not found for utility install",
		})
		return nil, false, fmt.Errorf("sigstore bundle not found for %s: use --insecure-skip-verify to bypass", asset.Name)
	}

	safeBundleName, err := sync.SanitizeAssetName(bundleAsset.Name)
	if err != nil {
		return nil, false, fmt.Errorf("invalid bundle asset name: %w", err)
	}

	bundlePath := filepath.Join(installDir, safeBundleName)
	if err := s.Registry.DownloadAsset(ctx, bundleAsset.URL, bundlePath); err != nil {
		securityaudit.Emit(securityaudit.Event{
			Type:        securityaudit.EventVerificationFail,
			Component:   string(componenttypes.KindUtility),
			Name:        name,
			Description: "failed to download sigstore bundle for utility install",
		})
		return nil, false, fmt.Errorf("downloading sigstore bundle: %w", err)
	}
	defer func() { _ = os.Remove(bundlePath) }()

	expectedIdentity := &sync.ExpectedIdentity{
		SourceRepositoryURI: sync.BuildGitHubRepoURL(owner, repo),
		SourceRepositoryRef: sync.BuildGitHubRefTag(version),
	}
	sigResult, err := sync.VerifySigstoreBundle(bundlePath, tmpPath, expectedIdentity)
	if err != nil {
		securityaudit.Emit(securityaudit.Event{
			Type:        securityaudit.EventVerificationFail,
			Component:   string(componenttypes.KindUtility),
			Name:        name,
			Description: "sigstore verification failed for utility install",
		})
		return nil, false, fmt.Errorf("sigstore verification failed: %w", err)
	}
	return sigResult, true, nil
}

func installUtilityBinary(tmpPath, installPath string) error {
	data, err := os.ReadFile(tmpPath)
	if err != nil {
		return fmt.Errorf("reading downloaded utility: %w", err)
	}
	if err := tx.WriteAtomicPath(installPath, data, 0755); err != nil {
		return fmt.Errorf("installing binary: %w", err)
	}
	if err := os.Remove(tmpPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("cleaning temp utility binary: %w", err)
	}

	return nil
}

func (s *UtilitySyncer) updateUtilitiesLock(name, source, owner, repo, version, platform, digest string, asset *sync.AssetInfo, sigResult *sync.SigstoreResult, opts InstallOpts) error {
	lf, err := LoadUtilitiesLock()
	if err != nil {
		return fmt.Errorf("loading utilities lock: %w", err)
	}

	lockedUtil := componenttypes.LockedUtility{
		Source:   fmt.Sprintf("github.com/%s/%s", owner, repo),
		Version:  version,
		LockedAt: timestamp.Now().String(),
		Platforms: map[string]componenttypes.LockedPlatform{
			platform: {
				Digest: digest,
				Asset:  asset.Name,
				URL:    asset.URL,
			},
		},
	}

	if sigResult != nil {
		lockedUtil.Signer = &componenttypes.LockedSigner{
			Issuer:              sigResult.Issuer,
			SourceRepositoryURI: sigResult.SourceRepositoryURI,
			SourceRepositoryRef: sigResult.SourceRepositoryRef,
		}
		lockedUtil.Verification = &componenttypes.Verification{
			Status:     "verified",
			VerifiedAt: timestamp.Now().String(),
		}
	} else if opts.Unsafe.SkipVerify || opts.Unsafe.TrustOnFirst {
		lockedUtil.Verification = &componenttypes.Verification{
			Status: "skipped",
		}
	}

	lockedUtil.ResolvedFrom = &componenttypes.ResolvedFrom{
		Registry:   "github",
		Descriptor: source,
	}

	lf.SetUtility(name, lockedUtil)
	if err := lf.Save(); err != nil {
		return fmt.Errorf("saving utilities lock: %w", err)
	}
	return nil
}

// Remove uninstalls a utility.
func (s *UtilitySyncer) Remove(name string) error {
	lf, err := LoadUtilitiesLock()
	if err != nil {
		return fmt.Errorf("loading utilities lock: %w", err)
	}

	utility, ok := lf.GetUtility(name)
	if !ok {
		return fmt.Errorf("utility %q not installed", name)
	}

	// Remove binary directory
	binDir, err := BinPath()
	if err != nil {
		return err
	}
	utilDir := filepath.Join(binDir, name)
	if err := os.RemoveAll(utilDir); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("removing utility directory: %w", err)
	}

	// Update lockfile
	lf.RemoveUtility(name)
	if err := lf.Save(); err != nil {
		return fmt.Errorf("saving utilities lock: %w", err)
	}

	_ = utility // Silence unused variable warning
	return nil
}

// Verify checks that an installed utility matches its lockfile digest.
func (s *UtilitySyncer) Verify(name string) error {
	lf, err := LoadUtilitiesLock()
	if err != nil {
		return fmt.Errorf("loading utilities lock: %w", err)
	}

	utility, ok := lf.GetUtility(name)
	if !ok {
		return fmt.Errorf("utility %q not installed", name)
	}

	platform := platform.Key(runtime.GOOS, runtime.GOARCH)
	platformEntry, ok := utility.Platforms[platform]
	if !ok {
		return fmt.Errorf("utility %q has no entry for platform %s", name, platform)
	}

	installPath, err := UtilityInstallPath(name, utility.Version)
	if err != nil {
		return err
	}

	if err := sync.VerifyDigest(installPath, platformEntry.Digest); err != nil {
		return fmt.Errorf("digest mismatch: %w", err)
	}

	return nil
}
