package sync

import (
	"context"
	"strings"

	"github.com/locktivity/epack/internal/component/github"
	"github.com/locktivity/epack/internal/component/semver"
	"github.com/locktivity/epack/internal/platform"
)

// RegistryClient is the interface for resolving and fetching components.
// Implementations include GitHub (default) and future registries like Locktivity.
type RegistryClient interface {
	// Name returns the registry identifier (e.g., "github", "locktivity").
	Name() string

	// ResolveVersion resolves a version constraint to a concrete version.
	// For example, "^1.0.0" might resolve to "v1.2.3".
	// Returns the resolved version tag and any error.
	ResolveVersion(ctx context.Context, source, constraint string) (string, error)

	// FetchRelease fetches release metadata for a specific version.
	// The source is registry-specific (e.g., "owner/repo" for GitHub).
	FetchRelease(ctx context.Context, source, version string) (*ReleaseInfo, error)

	// DownloadAsset downloads a release asset to the specified path.
	DownloadAsset(ctx context.Context, url, destPath string) error

	// FindBinaryAsset finds the binary asset for a specific platform.
	// Returns the asset info or an error if not found.
	FindBinaryAsset(release *ReleaseInfo, componentName, goos, goarch string) (*AssetInfo, error)

	// FindSigstoreBundle finds the Sigstore bundle for a binary asset.
	// Returns the bundle asset or an error if not found.
	FindSigstoreBundle(release *ReleaseInfo, binaryAssetName string) (*AssetInfo, error)
}

// ReleaseInfo contains metadata about a component release.
// This is a registry-agnostic representation of release data.
type ReleaseInfo struct {
	// Version is the resolved version tag (e.g., "v1.2.3").
	Version string

	// Commit is the git commit SHA the release points to (if available).
	Commit string

	// Assets contains platform-specific binaries and their metadata.
	Assets []AssetInfo

	// SigningInfo contains Sigstore signing metadata if available.
	SigningInfo *SigningInfo
}

// AssetInfo contains metadata about a release asset.
type AssetInfo struct {
	// Name is the asset filename.
	Name string

	// URL is the download URL for this asset.
	URL string

	// Size is the asset size in bytes (0 if unknown).
	Size int64

	// Platform is the target platform (e.g., "linux/amd64").
	// Empty if the asset is not platform-specific.
	Platform string

	// IsSigstoreBundle indicates this is a .sigstore.json bundle.
	IsSigstoreBundle bool
}

// SigningInfo contains Sigstore signing metadata.
type SigningInfo struct {
	// Issuer is the OIDC issuer that authenticated the signer.
	Issuer string

	// Subject is the certificate subject (e.g., workflow path).
	Subject string

	// SourceRepositoryURI is the source repository URI from the certificate.
	SourceRepositoryURI string

	// SourceRepositoryRef is the source repository ref from the certificate.
	SourceRepositoryRef string
}

// GitHubRegistry adapts github.Client to the RegistryClient interface.
type GitHubRegistry struct {
	client *github.Client
}

// NewGitHubRegistry creates a RegistryClient backed by GitHub.
func NewGitHubRegistry() *GitHubRegistry {
	return &GitHubRegistry{
		client: github.NewClient(),
	}
}

// NewGitHubRegistryWithClient injects a github.Client for tests and alternate transports.
func NewGitHubRegistryWithClient(client *github.Client) *GitHubRegistry {
	return &GitHubRegistry{client: client}
}

// Name returns the stable registry identifier used in resolution and lockfile metadata.
func (r *GitHubRegistry) Name() string {
	return "github"
}

// ResolveVersion resolves a version constraint to a concrete version.
// For GitHub, this uses semver constraint matching against available releases.
func (r *GitHubRegistry) ResolveVersion(ctx context.Context, source, constraint string) (string, error) {
	owner, repo, _, err := github.ParseSource(source + "@" + constraint)
	if err != nil {
		return "", err
	}

	// Parse the constraint
	c, err := semver.ParseConstraint(constraint)
	if err != nil {
		return "", err
	}

	// For exact constraints, just format and return
	if c.Type == semver.ConstraintExact {
		return semver.NormalizeTag(constraint), nil
	}

	// Otherwise, list releases and find best match
	releases, err := r.client.ListReleases(ctx, owner, repo)
	if err != nil {
		return "", err
	}

	// Find best matching version using semver
	return semver.SelectVersion(releaseTags(releases), c)
}

// FetchRelease fetches release metadata for a specific version.
func (r *GitHubRegistry) FetchRelease(ctx context.Context, source, version string) (*ReleaseInfo, error) {
	owner, repo, _, err := github.ParseSource(source + "@" + version)
	if err != nil {
		return nil, err
	}

	release, err := r.client.FetchRelease(ctx, owner, repo, version)
	if err != nil {
		return nil, err
	}

	info := &ReleaseInfo{
		Version: release.TagName,
		Commit:  normalizeCommitSHA(release.TargetCommitish),
		Assets:  make([]AssetInfo, 0, len(release.Assets)),
	}

	for _, asset := range release.Assets {
		ai := AssetInfo{
			Name:             asset.Name,
			URL:              asset.BrowserDownloadURL,
			Size:             asset.Size,
			IsSigstoreBundle: isSigstoreBundle(asset.Name),
		}
		info.Assets = append(info.Assets, ai)
	}

	return info, nil
}

func normalizeCommitSHA(v string) string {
	s := strings.TrimSpace(v)
	if s == "" {
		return ""
	}
	if len(s) < 7 || len(s) > 40 {
		return ""
	}
	for _, r := range s {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') && (r < 'A' || r > 'F') {
			return ""
		}
	}
	return strings.ToLower(s)
}

// DownloadAsset downloads a release asset to the specified path.
func (r *GitHubRegistry) DownloadAsset(ctx context.Context, url, destPath string) error {
	return r.client.DownloadAsset(ctx, url, destPath)
}

// FindBinaryAsset finds the binary asset for a specific platform.
// This is a convenience method that wraps the underlying client.
// Returns a copy of the asset to avoid pointer aliasing issues.
func (r *GitHubRegistry) FindBinaryAsset(release *ReleaseInfo, componentName, goos, goarch string) (*AssetInfo, error) {
	platform := platform.Key(goos, goarch)
	patterns := github.BinaryAssetPatterns(componentName, goos, goarch)

	for i := range release.Assets {
		for _, pattern := range patterns {
			if github.MatchAssetPattern(release.Assets[i].Name, pattern) {
				// Return a copy to avoid pointer aliasing issues
				asset := release.Assets[i]
				asset.Platform = platform
				return &asset, nil
			}
		}
	}

	return nil, &AssetNotFoundError{Component: componentName, Platform: platform}
}

// FindSigstoreBundle finds the Sigstore bundle for a binary asset.
// Returns a copy of the asset to avoid pointer aliasing issues.
func (r *GitHubRegistry) FindSigstoreBundle(release *ReleaseInfo, binaryAssetName string) (*AssetInfo, error) {
	bundleName := binaryAssetName + ".sigstore.json"
	for i := range release.Assets {
		if release.Assets[i].Name == bundleName {
			// Return a copy to avoid pointer aliasing issues
			asset := release.Assets[i]
			return &asset, nil
		}
	}
	return nil, &BundleNotFoundError{BinaryAsset: binaryAssetName}
}

// AssetNotFoundError indicates a binary asset was not found for a platform.
type AssetNotFoundError struct {
	Component string
	Platform  string
}

func (e *AssetNotFoundError) Error() string {
	return "no binary asset found for " + e.Component + " on " + e.Platform
}

// BundleNotFoundError indicates a Sigstore bundle was not found.
type BundleNotFoundError struct {
	BinaryAsset string
}

func (e *BundleNotFoundError) Error() string {
	return "sigstore bundle not found for " + e.BinaryAsset
}

// releaseTags extracts tag names in API order for semver resolution.
func releaseTags(releases []github.Release) []string {
	tags := make([]string, len(releases))
	for i, r := range releases {
		tags[i] = r.TagName
	}
	return tags
}

// isSigstoreBundle reports whether name ends with ".sigstore.json".
func isSigstoreBundle(name string) bool {
	return len(name) > 14 && name[len(name)-14:] == ".sigstore.json"
}
