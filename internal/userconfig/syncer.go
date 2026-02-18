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
	InsecureSkipVerify   bool // Skip Sigstore verification (NOT RECOMMENDED)
	InsecureTrustOnFirst bool // Trust digest without Sigstore (NOT RECOMMENDED)
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
	// Parse source
	owner, repo, constraint, err := github.ParseSource(source)
	if err != nil {
		return nil, fmt.Errorf("invalid source %q: %w", source, err)
	}

	// Resolve version
	repoSource := fmt.Sprintf("%s/%s", owner, repo)
	version, err := s.Registry.ResolveVersion(ctx, repoSource, constraint)
	if err != nil {
		return nil, fmt.Errorf("resolving version: %w", err)
	}

	platform := platform.Key(runtime.GOOS, runtime.GOARCH)

	// Fetch release info
	release, err := s.Registry.FetchRelease(ctx, repoSource, version)
	if err != nil {
		return nil, fmt.Errorf("fetching release %s: %w", version, err)
	}

	// Find binary asset - utilities use epack-util-{name} naming
	binaryName := fmt.Sprintf("epack-util-%s", name)
	asset, err := s.Registry.FindBinaryAsset(release, binaryName, runtime.GOOS, runtime.GOARCH)
	if err != nil {
		return nil, fmt.Errorf("finding binary asset: %w", err)
	}

	// Compute install path
	installPath, err := UtilityInstallPath(name, version)
	if err != nil {
		return nil, fmt.Errorf("computing install path: %w", err)
	}
	installDir := filepath.Dir(installPath)

	// Create install directory
	binDir, err := BinPath()
	if err != nil {
		return nil, err
	}
	if err := safefile.MkdirAll(binDir, installDir); err != nil {
		return nil, fmt.Errorf("creating install directory: %w", err)
	}

	// Download binary
	tmpPath := installPath + ".tmp"
	if err := s.Registry.DownloadAsset(ctx, asset.URL, tmpPath); err != nil {
		_ = os.Remove(tmpPath)
		return nil, fmt.Errorf("downloading %s: %w", asset.Name, err)
	}

	// Compute digest
	digest, err := sync.ComputeDigest(tmpPath)
	if err != nil {
		_ = os.Remove(tmpPath)
		return nil, fmt.Errorf("computing digest: %w", err)
	}

	var sigResult *sync.SigstoreResult
	verified := false

	if !opts.InsecureSkipVerify && !opts.InsecureTrustOnFirst {
		// Full Sigstore verification
		bundleAsset, err := s.Registry.FindSigstoreBundle(release, asset.Name)
		if err != nil {
			_ = os.Remove(tmpPath)
			return nil, fmt.Errorf("sigstore bundle not found for %s: use --insecure-skip-verify to bypass", asset.Name)
		}

		safeBundleName, err := sync.SanitizeAssetName(bundleAsset.Name)
		if err != nil {
			_ = os.Remove(tmpPath)
			return nil, fmt.Errorf("invalid bundle asset name: %w", err)
		}

		bundlePath := filepath.Join(installDir, safeBundleName)
		if err := s.Registry.DownloadAsset(ctx, bundleAsset.URL, bundlePath); err != nil {
			_ = os.Remove(tmpPath)
			return nil, fmt.Errorf("downloading sigstore bundle: %w", err)
		}

		// Build expected identity
		expectedRepoURI := sync.BuildGitHubRepoURL(owner, repo)
		expectedRef := sync.BuildGitHubRefTag(version)
		expectedIdentity := &sync.ExpectedIdentity{
			SourceRepositoryURI: expectedRepoURI,
			SourceRepositoryRef: expectedRef,
		}

		sigResult, err = sync.VerifySigstoreBundle(bundlePath, tmpPath, expectedIdentity)
		_ = os.Remove(bundlePath) // Clean up bundle
		if err != nil {
			_ = os.Remove(tmpPath)
			return nil, fmt.Errorf("sigstore verification failed: %w", err)
		}
		verified = true
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

	// Update utilities lockfile
	lf, err := LoadUtilitiesLock()
	if err != nil {
		return nil, fmt.Errorf("loading utilities lock: %w", err)
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
	} else if opts.InsecureSkipVerify || opts.InsecureTrustOnFirst {
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
		return nil, fmt.Errorf("saving utilities lock: %w", err)
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
