// Package github provides a GitHub API client for fetching releases and assets.
package github

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/locktivity/epack/internal/limits"
	"github.com/locktivity/epack/internal/netpolicy"
	"github.com/locktivity/epack/internal/platform"
	"github.com/locktivity/epack/internal/safefile"
	"github.com/locktivity/epack/internal/safejson"
	"golang.org/x/time/rate"
)

// Rate limiting configuration.
// GitHub API allows 60 requests/hour unauthenticated, 5000/hour authenticated.
// We use conservative defaults to avoid hitting limits in CI environments.
const (
	// DefaultRateLimit is the default maximum requests per second.
	// This is conservative to avoid hitting GitHub's secondary rate limits.
	DefaultRateLimit = 10

	// DefaultRateBurst is the default burst size for rate limiting.
	// Allows short bursts while maintaining the average rate.
	DefaultRateBurst = 5
)

// defaultPolicy is the network security policy for GitHub API and asset hosts.
// SECURITY: Centralized in netpolicy package to ensure consistent enforcement.
var defaultPolicy = netpolicy.GitHubPolicy()

// Client fetches releases and assets from GitHub.
type Client struct {
	httpClient        *http.Client
	token             string
	baseURL           string // validated to be trusted host
	allowLoopbackHTTP bool   // TESTING ONLY: allow HTTP to localhost/127.0.0.1
	rateLimiter       *rate.Limiter
	policy            *netpolicy.Policy // network security policy
}

// NewClient returns a client using GITHUB_TOKEN from environment.
// Uses the default GitHub API endpoint (api.github.com).
func NewClient() *Client {
	return &Client{
		httpClient: &http.Client{
			Transport: netpolicy.SecureTransport(),
			Timeout:   limits.DefaultHTTPTimeout,
			// Disable automatic redirect following - we handle redirects manually
			// to validate each redirect destination against the allowlist
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		token:       os.Getenv("GITHUB_TOKEN"),
		baseURL:     "https://api.github.com",
		rateLimiter: rate.NewLimiter(rate.Limit(DefaultRateLimit), DefaultRateBurst),
		policy:      defaultPolicy,
	}
}

// NewClientWithBaseURL creates a client with a custom base URL.
// The base URL must be HTTPS and on a trusted API host.
// HTTP is only allowed for localhost/127.0.0.1 (for testing), and tokens are NEVER
// sent over HTTP connections regardless of destination.
// This is primarily for testing with mock servers.
func NewClientWithBaseURL(baseURL string) (*Client, error) {
	parsed, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid base URL: %w", err)
	}

	hostname := parsed.Hostname()
	isLoopback := netpolicy.IsLoopback(hostname)

	// HTTP is ONLY allowed for loopback addresses (testing)
	if parsed.Scheme == "http" {
		if !isLoopback {
			return nil, fmt.Errorf("HTTP scheme only allowed for localhost/127.0.0.1, refusing to send credentials to %q", parsed.Host)
		}
		// SECURITY: Even for loopback HTTP, never include the token.
		// HTTP traffic can be sniffed by other processes on the same machine.
		// Tests that need auth should use HTTPS or mock the auth check.
		return &Client{
			httpClient: &http.Client{
				Timeout: 30 * time.Second,
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					return http.ErrUseLastResponse
				},
			},
			token:   "", // Never send token over HTTP, even to loopback
			baseURL: baseURL,
			policy:  defaultPolicy,
		}, nil
	}

	if parsed.Scheme != "https" {
		return nil, fmt.Errorf("base URL must use https scheme, got %q", parsed.Scheme)
	}

	// For non-localhost HTTPS URLs, require trusted host
	if !isLoopback {
		if !defaultPolicy.IsTrustedAPIHost(hostname) {
			return nil, fmt.Errorf("base URL host %q is not in trusted API hosts allowlist", parsed.Host)
		}
	}

	return &Client{
		httpClient: &http.Client{
			Transport: netpolicy.SecureTransport(),
			Timeout:   30 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		token:       os.Getenv("GITHUB_TOKEN"),
		baseURL:     baseURL,
		rateLimiter: rate.NewLimiter(rate.Limit(DefaultRateLimit), DefaultRateBurst),
		policy:      defaultPolicy,
	}, nil
}

// Release represents a GitHub release.
type Release struct {
	TagName         string  `json:"tag_name"`
	TargetCommitish string  `json:"target_commitish,omitempty"`
	Assets          []Asset `json:"assets"`
}

// Asset represents a GitHub release asset.
type Asset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
	Size               int64  `json:"size"`
}

// FetchRelease fetches a specific release by tag from owner/repo.
// SECURITY: All path segments are URL-escaped to prevent path/query injection.
func (c *Client) FetchRelease(ctx context.Context, owner, repo, tag string) (*Release, error) {
	// Rate limit API requests to avoid hitting GitHub's limits
	if c.rateLimiter != nil {
		if err := c.rateLimiter.Wait(ctx); err != nil {
			return nil, fmt.Errorf("rate limit wait cancelled: %w", err)
		}
	}

	// SECURITY: Escape all path segments to prevent injection attacks.
	// Even though semver.go now validates version format, we escape as defense-in-depth.
	reqURL := fmt.Sprintf("%s/repos/%s/%s/releases/tags/%s",
		c.baseURL,
		url.PathEscape(owner),
		url.PathEscape(repo),
		url.PathEscape(tag))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, err
	}
	c.setHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching release: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("release %s not found in %s/%s", tag, owner, repo)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d fetching release", resp.StatusCode)
	}

	// SECURITY: Use safejson for bounded JSON parsing with duplicate key detection.
	// This provides defense-in-depth against malformed or malicious API responses.
	var release Release
	if err := safejson.DecodeReader(resp.Body, "release", limits.JSONResponse, &release); err != nil {
		return nil, fmt.Errorf("decoding release: %w", err)
	}
	return &release, nil
}

// FetchLatestRelease fetches the latest release from owner/repo.
// SECURITY: All path segments are URL-escaped to prevent path/query injection.
func (c *Client) FetchLatestRelease(ctx context.Context, owner, repo string) (*Release, error) {
	// Rate limit API requests to avoid hitting GitHub's limits
	if c.rateLimiter != nil {
		if err := c.rateLimiter.Wait(ctx); err != nil {
			return nil, fmt.Errorf("rate limit wait cancelled: %w", err)
		}
	}

	reqURL := fmt.Sprintf("%s/repos/%s/%s/releases/latest",
		c.baseURL,
		url.PathEscape(owner),
		url.PathEscape(repo))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, err
	}
	c.setHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching latest release: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("no releases found in %s/%s", owner, repo)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d fetching latest release", resp.StatusCode)
	}

	// SECURITY: Use safejson for bounded JSON parsing with duplicate key detection.
	// This provides defense-in-depth against malformed or malicious API responses.
	var release Release
	if err := safejson.DecodeReader(resp.Body, "latest release", limits.JSONResponse, &release); err != nil {
		return nil, fmt.Errorf("decoding release: %w", err)
	}
	return &release, nil
}

// ListReleases fetches all releases from owner/repo (up to 100).
// SECURITY: All path segments are URL-escaped to prevent path/query injection.
func (c *Client) ListReleases(ctx context.Context, owner, repo string) ([]Release, error) {
	// Rate limit API requests to avoid hitting GitHub's limits
	if c.rateLimiter != nil {
		if err := c.rateLimiter.Wait(ctx); err != nil {
			return nil, fmt.Errorf("rate limit wait cancelled: %w", err)
		}
	}

	reqURL := fmt.Sprintf("%s/repos/%s/%s/releases?per_page=100",
		c.baseURL,
		url.PathEscape(owner),
		url.PathEscape(repo))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, err
	}
	c.setHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("listing releases: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d listing releases", resp.StatusCode)
	}

	// SECURITY: Use safejson for bounded JSON parsing with duplicate key detection.
	// This provides defense-in-depth against malformed or malicious API responses.
	var releases []Release
	if err := safejson.DecodeReader(resp.Body, "releases list", limits.JSONResponse, &releases); err != nil {
		return nil, fmt.Errorf("decoding releases: %w", err)
	}
	return releases, nil
}

// DownloadAsset downloads an asset to the specified path.
// Only sends auth headers to trusted GitHub hosts over HTTPS.
// Validates redirect destinations against the allowlist.
// Enforces maximum download size to prevent disk exhaustion.
// SECURITY: HTTP is rejected for all URLs. Only HTTPS is allowed.
// The allowLoopbackHTTP flag (test-only) permits HTTP to localhost/127.0.0.1
// but NEVER sends auth headers over HTTP.
func (c *Client) DownloadAsset(ctx context.Context, assetURL, destPath string) error {
	currentURL := assetURL

	for redirects := 0; redirects <= limits.MaxHTTPRedirects; redirects++ {
		parsedURL, _, err := c.validateAssetURL(currentURL)
		if err != nil {
			return err
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, currentURL, nil)
		if err != nil {
			return err
		}

		// Only set auth headers for trusted hosts over HTTPS
		c.setHeadersForHost(req, parsedURL)
		req.Header.Set("Accept", "application/octet-stream")

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return fmt.Errorf("downloading asset: %w", err)
		}

		nextURL, redirected, err := resolveRedirect(resp, parsedURL)
		if err != nil {
			_ = resp.Body.Close()
			return err
		}
		if redirected {
			_ = resp.Body.Close()
			currentURL = nextURL
			continue
		}

		err = c.writeAssetResponse(resp, destPath)
		_ = resp.Body.Close()
		if err != nil {
			return err
		}
		return nil
	}

	return fmt.Errorf("too many redirects (max %d)", limits.MaxHTTPRedirects)
}

func (c *Client) validateAssetURL(rawURL string) (*url.URL, bool, error) {
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return nil, false, fmt.Errorf("invalid asset URL: %w", err)
	}
	hostname := parsedURL.Hostname()
	isLoopback := netpolicy.IsLoopback(hostname)

	if parsedURL.Scheme == "http" {
		if !isLoopback {
			return nil, false, fmt.Errorf("refusing to download over HTTP from %q: HTTPS required", parsedURL.Host)
		}
		if !c.allowLoopbackHTTP {
			return nil, false, fmt.Errorf("refusing to download over HTTP from loopback %q: HTTPS required (use test client for HTTP)", parsedURL.Host)
		}
	}

	if !isLoopback && !c.policy.IsTrustedAssetHost(hostname) {
		return nil, false, fmt.Errorf("refusing to download from untrusted host %q (not in allowlist)", parsedURL.Host)
	}
	return parsedURL, isLoopback, nil
}

func resolveRedirect(resp *http.Response, parsedURL *url.URL) (string, bool, error) {
	if resp.StatusCode < 300 || resp.StatusCode >= 400 {
		return "", false, nil
	}
	location := resp.Header.Get("Location")
	if location == "" {
		return "", false, fmt.Errorf("redirect response missing Location header")
	}
	redirectURL, err := parsedURL.Parse(location)
	if err != nil {
		return "", false, fmt.Errorf("invalid redirect URL: %w", err)
	}
	return redirectURL.String(), true, nil
}

func (c *Client) writeAssetResponse(resp *http.Response, destPath string) error {
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status %d downloading asset", resp.StatusCode)
	}
	if resp.ContentLength > limits.AssetDownload.Bytes() {
		return fmt.Errorf("asset size %d exceeds maximum allowed size %d bytes", resp.ContentLength, limits.AssetDownload.Bytes())
	}

	f, err := safefile.OpenForWrite(destPath)
	if err != nil {
		return fmt.Errorf("creating file: %w", err)
	}
	limitedReader := io.LimitReader(resp.Body, limits.AssetDownload.Bytes()+1)
	written, err := io.Copy(f, limitedReader)
	_ = f.Close()
	if err != nil {
		_ = os.Remove(destPath)
		return fmt.Errorf("writing asset: %w", err)
	}
	if written > limits.AssetDownload.Bytes() {
		_ = os.Remove(destPath)
		return fmt.Errorf("asset exceeded maximum allowed size %d bytes", limits.AssetDownload.Bytes())
	}
	return nil
}

// FindBinaryAsset finds the binary asset for a specific platform.
// Returns a copy of the asset and its base name (without platform suffix).
// Returns a copy to avoid pointer aliasing issues if the release is modified.
func (c *Client) FindBinaryAsset(release *Release, componentName, goos, goarch string) (*Asset, string, error) {
	platformKey := platform.Key(goos, goarch)
	patterns := BinaryAssetPatterns(componentName, goos, goarch)

	for i := range release.Assets {
		for _, pattern := range patterns {
			if MatchAssetPattern(release.Assets[i].Name, pattern) {
				// Return a copy to avoid pointer aliasing issues
				asset := release.Assets[i]
				return &asset, componentName, nil
			}
		}
	}

	return nil, "", fmt.Errorf("no binary asset found for %s on %s", componentName, platformKey)
}

// FindSigstoreBundle finds the .sigstore.json bundle for a binary asset.
// Returns a copy to avoid pointer aliasing issues if the release is modified.
func (c *Client) FindSigstoreBundle(release *Release, binaryAssetName string) (*Asset, error) {
	bundleName := binaryAssetName + ".sigstore.json"
	for i := range release.Assets {
		if release.Assets[i].Name == bundleName {
			// Return a copy to avoid pointer aliasing issues
			asset := release.Assets[i]
			return &asset, nil
		}
	}
	return nil, fmt.Errorf("sigstore bundle %s not found", bundleName)
}

func (c *Client) setHeaders(req *http.Request) {
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
}

// setHeadersForHost sets headers, only adding auth for trusted hosts over HTTPS.
// SECURITY: Never sends auth headers over HTTP, regardless of destination.
// Even loopback HTTP can be sniffed by other processes on the same machine.
func (c *Client) setHeadersForHost(req *http.Request, parsedURL *url.URL) {
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	// SECURITY: Never send auth header over HTTP, including to loopback.
	// HTTP traffic can be intercepted by other processes on the same machine.
	// A malicious release asset URL pointing to http://127.0.0.1:PORT could
	// exfiltrate tokens to a local listener.
	if parsedURL.Scheme != "https" {
		return // No auth header for non-HTTPS
	}

	hostname := parsedURL.Hostname()

	// Only send auth header to trusted GitHub hosts over HTTPS
	if c.token != "" && c.policy.IsTrustedAssetHost(hostname) {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
}

// BinaryAssetPatterns returns possible asset name patterns for a component.
func BinaryAssetPatterns(name, goos, goarch string) []string {
	// Map GOARCH to common naming conventions
	archVariants := []string{goarch}
	switch goarch {
	case "amd64":
		archVariants = append(archVariants, "x86_64", "x64")
	case "arm64":
		archVariants = append(archVariants, "aarch64")
	case "386":
		archVariants = append(archVariants, "i386", "x86")
	}

	// Map GOOS to common naming conventions
	osVariants := []string{goos}
	switch goos {
	case "darwin":
		osVariants = append(osVariants, "macos", "osx")
	case "windows":
		// windows is usually just "windows"
	}

	// Include epack component naming conventions (C-001)
	nameVariants := []string{
		name,
		"epack-tool-" + name,
		"epack-collector-" + name,
		"epack-remote-" + name,
		"epack-util-" + name,
	}

	var patterns []string
	for _, n := range nameVariants {
		for _, os := range osVariants {
			for _, arch := range archVariants {
				// Common patterns: name-os-arch, name_os_arch, name-os_arch
				patterns = append(patterns,
					fmt.Sprintf("%s-%s-%s", n, os, arch),
					fmt.Sprintf("%s_%s_%s", n, os, arch),
					fmt.Sprintf("%s-%s_%s", n, os, arch),
				)
			}
		}
	}

	return patterns
}

// MatchAssetPattern checks if an asset name matches a pattern.
// Handles optional extensions like .exe, .tar.gz, .zip.
func MatchAssetPattern(assetName, pattern string) bool {
	// Strip common extensions for comparison
	name := assetName
	for _, ext := range []string{".exe", ".tar.gz", ".tgz", ".zip", ".gz"} {
		name = strings.TrimSuffix(name, ext)
	}

	return strings.EqualFold(name, pattern)
}

// NewClientForTest creates a Client with custom httpClient and baseURL for testing.
// This bypasses the trusted host validation to allow mock servers.
// Sets allowLoopbackHTTP to permit HTTP to localhost for test servers.
// SECURITY: Auth tokens are NEVER sent over HTTP, even in tests.
// Only use in test files.
func NewClientForTest(httpClient *http.Client, baseURL string) *Client {
	return &Client{
		httpClient:        httpClient,
		baseURL:           baseURL,
		allowLoopbackHTTP: true, // Allow HTTP to localhost for test servers
		rateLimiter:       nil,  // No rate limiting in tests
		policy:            defaultPolicy.WithLoopbackHTTP(),
	}
}

// NewClientForTestWithHosts creates a Client for testing with additional trusted hosts.
// This is useful when testing with mock servers that need to be in the trusted hosts list.
// SECURITY: Auth tokens are NEVER sent over HTTP, even in tests.
// Only use in test files.
func NewClientForTestWithHosts(httpClient *http.Client, baseURL string, hosts ...string) *Client {
	return &Client{
		httpClient:        httpClient,
		baseURL:           baseURL,
		allowLoopbackHTTP: true,
		rateLimiter:       nil,
		policy:            defaultPolicy.WithLoopbackHTTP().WithAdditionalHosts(hosts...),
	}
}

// githubSlugRegex matches valid GitHub owner and repo names.
// GitHub allows alphanumeric characters, hyphens, underscores, and dots.
// Names cannot start or end with a hyphen/dot, and cannot contain consecutive dots.
// Simplified pattern: start with alphanumeric, then alphanumeric/hyphen/underscore/dot.
var githubSlugRegex = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$`)

// ParseSource parses a source string like "owner/repo@version".
// Returns owner, repo, version constraint.
// SECURITY: Validates that owner and repo are valid GitHub slugs to prevent
// path smuggling attacks where malicious values like "owner/../../repos/victim/repo"
// could manipulate API request paths.
func ParseSource(source string) (owner, repo, version string, err error) {
	parts := strings.SplitN(source, "@", 2)
	if len(parts) != 2 {
		return "", "", "", fmt.Errorf("invalid source format %q: expected owner/repo@version", source)
	}

	repoPath := parts[0]
	version = parts[1]

	repoParts := strings.SplitN(repoPath, "/", 2)
	if len(repoParts) != 2 {
		return "", "", "", fmt.Errorf("invalid source format %q: expected owner/repo", repoPath)
	}

	owner = repoParts[0]
	repo = repoParts[1]

	// SECURITY: Validate owner and repo are valid GitHub slugs.
	// This prevents path smuggling attacks via values like:
	// - "owner/../../../repos/victim/repo" (path traversal)
	// - "owner%2f..%2f.." (URL-encoded traversal)
	// - "owner/nested/repo" (extra path segments)
	if !githubSlugRegex.MatchString(owner) {
		return "", "", "", fmt.Errorf("invalid GitHub owner %q: must be alphanumeric with hyphens/underscores/dots", owner)
	}
	if !githubSlugRegex.MatchString(repo) {
		return "", "", "", fmt.Errorf("invalid GitHub repo %q: must be alphanumeric with hyphens/underscores/dots", repo)
	}

	// Additional safety: reject anything that could be URL-encoded path components
	if strings.Contains(owner, "%") || strings.Contains(repo, "%") {
		return "", "", "", fmt.Errorf("invalid source %q: percent-encoding not allowed", source)
	}

	return owner, repo, version, nil
}
