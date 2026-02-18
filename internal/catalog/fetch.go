package catalog

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/locktivity/epack/internal/boundedio"
	"github.com/locktivity/epack/internal/limits"
	"github.com/locktivity/epack/internal/netpolicy"
	"github.com/locktivity/epack/internal/redact"
)

// FetchTimeout is the maximum time to wait for catalog fetch.
// Uses the central HTTP timeout limit for consistency.
const FetchTimeout = limits.DefaultHTTPTimeout

// DefaultCatalogURL is the default catalog URL (placeholder until registry is implemented).
const DefaultCatalogURL = "https://registry.locktivity.com/catalog.json"

// trustedCatalogHosts is the allowlist of hosts that can serve the tool catalog.
// SECURITY: Catalog data influences discovery/display (not execution), but restricting
// sources prevents attackers from serving malicious catalog data via redirects or
// user-provided URLs.
var trustedCatalogHosts = map[string]bool{
	"registry.locktivity.com": true,
	"locktivity.com":          true,
}

// isLoopbackHost returns true if the hostname is localhost or 127.0.0.1.
func isLoopbackHost(hostname string) bool {
	return hostname == "localhost" || hostname == "127.0.0.1"
}

// FetchResult contains the outcome of a catalog fetch operation.
type FetchResult struct {
	Updated    bool       // true if catalog was updated, false if not modified
	Status     MetaStatus // ok, not_modified, or error
	HTTPStatus int        // HTTP status code
	Error      error      // error if Status == error
}

// FetchOptions configures the catalog fetch behavior.
type FetchOptions struct {
	// URL to fetch catalog from. If empty, uses DefaultCatalogURL.
	URL string

	// ETag from previous fetch for conditional request.
	ETag string

	// LastModified from previous fetch for conditional request.
	LastModified string

	// HTTPClient to use. If nil, uses default client with timeout.
	HTTPClient *http.Client

	// InsecureAllowHTTP permits HTTP requests to localhost/127.0.0.1 for testing.
	// SECURITY: Only set this in tests. Production code should never set this.
	// CLI: --insecure-allow-http
	InsecureAllowHTTP bool
}

// FetchCatalog fetches the catalog from the specified URL using conditional requests.
// If the catalog hasn't changed (304 Not Modified), returns Updated=false.
// On success, writes catalog to cache and updates meta.
func FetchCatalog(ctx context.Context, opts FetchOptions) (*FetchResult, error) {
	catalogURL := opts.URL
	if catalogURL == "" {
		catalogURL = DefaultCatalogURL
	}

	// Validate URL
	parsedURL, err := url.Parse(catalogURL)
	if err != nil {
		return nil, fmt.Errorf("invalid catalog URL: %w", err)
	}

	hostname := parsedURL.Hostname()
	isLoopback := isLoopbackHost(hostname)

	// SECURITY: Require HTTPS to prevent MITM attacks on catalog data.
	// While catalog data only affects discovery/display (not execution),
	// malicious catalogs could mislead users about tool provenance.
	// Allow HTTP only for loopback addresses in tests.
	if parsedURL.Scheme != "https" {
		if parsedURL.Scheme == "http" && isLoopback && opts.InsecureAllowHTTP {
			// Loopback HTTP allowed for testing
		} else {
			return nil, fmt.Errorf("catalog URL must use https scheme, got %q", parsedURL.Scheme)
		}
	}

	// SECURITY: Validate host against allowlist to prevent SSRF and
	// fetching catalogs from attacker-controlled servers.
	// Skip allowlist check for loopback addresses in tests.
	if !isLoopback && !trustedCatalogHosts[hostname] {
		return nil, fmt.Errorf("catalog host %q not in allowlist", hostname)
	}

	// SECURITY: Create secure redirect checker that validates each redirect
	// against the allowlist. This prevents SSRF attacks where an initial URL
	// redirects to a malicious host.
	secureCheckRedirect := func(req *http.Request, via []*http.Request) error {
		// Validate redirect target against allowlist
		targetHost := req.URL.Hostname()
		targetIsLoopback := isLoopbackHost(targetHost)

		// Check scheme - must be HTTPS (or HTTP for loopback in tests)
		if req.URL.Scheme != "https" {
			if req.URL.Scheme != "http" || !targetIsLoopback || !opts.InsecureAllowHTTP {
				// SECURITY: Use host-only in error to avoid leaking credentials in URL
				return fmt.Errorf("redirect to non-HTTPS URL not allowed: %s", redact.SanitizeURLHost(req.URL.String()))
			}
		}

		// Check host against allowlist (skip for loopback in tests)
		if !targetIsLoopback && !trustedCatalogHosts[targetHost] {
			return fmt.Errorf("redirect to untrusted host not allowed: %s", targetHost)
		}

		// Limit redirect chain length
		if len(via) >= limits.MaxHTTPRedirects {
			return fmt.Errorf("too many redirects (%d)", len(via))
		}

		return nil
	}

	// Create or wrap HTTP client with secure redirect policy.
	// SECURITY: We shallow-clone the client to avoid mutating the caller's client.
	// This prevents race conditions when the same client is reused concurrently,
	// and avoids surprising the caller with persistent CheckRedirect changes.
	var client *http.Client
	if opts.HTTPClient == nil {
		client = &http.Client{
			Transport:     netpolicy.SecureTransport(),
			Timeout:       FetchTimeout,
			CheckRedirect: secureCheckRedirect,
		}
	} else {
		// Shallow clone the client to avoid mutating the original
		clientCopy := *opts.HTTPClient
		client = &clientCopy

		// SECURITY: Even with custom HTTP client, always enforce redirect validation.
		// Wrap any existing CheckRedirect to add our security checks.
		originalCheckRedirect := opts.HTTPClient.CheckRedirect
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			// First apply our security checks
			if err := secureCheckRedirect(req, via); err != nil {
				return err
			}
			// Then apply original check if present
			if originalCheckRedirect != nil {
				return originalCheckRedirect(req, via)
			}
			// Default behavior: follow up to 10 redirects (http.Client default)
			if len(via) >= 10 {
				return fmt.Errorf("stopped after 10 redirects")
			}
			return nil
		}
	}

	// Create request
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, catalogURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "epack/1.0")

	// Add conditional request headers (prefer ETag)
	if opts.ETag != "" {
		req.Header.Set("If-None-Match", opts.ETag)
	}
	if opts.LastModified != "" {
		req.Header.Set("If-Modified-Since", opts.LastModified)
	}

	// Record attempt time
	attemptTime := time.Now().UTC().Format(time.RFC3339)

	// Make request
	resp, err := client.Do(req)
	if err != nil {
		// Update meta with error
		saveFetchError(catalogURL, attemptTime, 0, err)
		return &FetchResult{
			Updated:    false,
			Status:     MetaStatusError,
			HTTPStatus: 0,
			Error:      fmt.Errorf("fetching catalog: %w", err),
		}, nil
	}
	defer func() { _ = resp.Body.Close() }()

	// Handle 304 Not Modified
	if resp.StatusCode == http.StatusNotModified {
		updateMetaNotModified(catalogURL, attemptTime, resp)
		return &FetchResult{
			Updated:    false,
			Status:     MetaStatusNotModified,
			HTTPStatus: resp.StatusCode,
		}, nil
	}

	// Handle non-200 responses
	if resp.StatusCode != http.StatusOK {
		err := fmt.Errorf("unexpected status %d", resp.StatusCode)
		saveFetchError(catalogURL, attemptTime, resp.StatusCode, err)
		return &FetchResult{
			Updated:    false,
			Status:     MetaStatusError,
			HTTPStatus: resp.StatusCode,
			Error:      err,
		}, nil
	}

	// Check Content-Length if provided
	if resp.ContentLength > limits.Catalog.Bytes() {
		err := fmt.Errorf("catalog too large: %d bytes exceeds %d limit",
			resp.ContentLength, limits.Catalog.Bytes())
		saveFetchError(catalogURL, attemptTime, resp.StatusCode, err)
		return &FetchResult{
			Updated:    false,
			Status:     MetaStatusError,
			HTTPStatus: resp.StatusCode,
			Error:      err,
		}, nil
	}

	// Read body with size limit
	body, err := boundedio.ReadReaderWithLimit(resp.Body, "catalog response", limits.Catalog)
	if err != nil {
		saveFetchError(catalogURL, attemptTime, resp.StatusCode, err)
		return &FetchResult{
			Updated:    false,
			Status:     MetaStatusError,
			HTTPStatus: resp.StatusCode,
			Error:      fmt.Errorf("reading response: %w", err),
		}, nil
	}

	// Parse catalog
	cat, err := ParseCatalog(body)
	if err != nil {
		saveFetchError(catalogURL, attemptTime, resp.StatusCode, err)
		return &FetchResult{
			Updated:    false,
			Status:     MetaStatusError,
			HTTPStatus: resp.StatusCode,
			Error:      fmt.Errorf("parsing catalog: %w", err),
		}, nil
	}

	// Validate and sanitize
	_ = cat.Validate() // Warnings are non-fatal

	// Check component count
	if len(cat.Tools) > limits.MaxCatalogComponentCount {
		err := fmt.Errorf("catalog has %d components, exceeds limit of %d",
			len(cat.Tools), limits.MaxCatalogComponentCount)
		saveFetchError(catalogURL, attemptTime, resp.StatusCode, err)
		return &FetchResult{
			Updated:    false,
			Status:     MetaStatusError,
			HTTPStatus: resp.StatusCode,
			Error:      err,
		}, nil
	}

	// Write catalog to cache
	if err := WriteCatalog(cat); err != nil {
		return nil, fmt.Errorf("writing catalog: %w", err)
	}

	// Update meta with success
	fetchedAt := time.Now().UTC().Format(time.RFC3339)
	meta := &CatalogMeta{
		MetaVersion:    MetaVersion,
		LastStatus:     MetaStatusOK,
		ETag:           resp.Header.Get("ETag"),
		LastModified:   resp.Header.Get("Last-Modified"),
		FetchedAt:      fetchedAt,
		SourceURL:      redact.SanitizeURL(catalogURL), // SECURITY: Sanitize before persisting
		LastAttemptAt:  attemptTime,
		LastHTTPStatus: resp.StatusCode,
	}

	if err := WriteMeta(meta); err != nil {
		// Non-fatal - catalog was written successfully
		return &FetchResult{
			Updated:    true,
			Status:     MetaStatusOK,
			HTTPStatus: resp.StatusCode,
		}, nil
	}

	return &FetchResult{
		Updated:    true,
		Status:     MetaStatusOK,
		HTTPStatus: resp.StatusCode,
	}, nil
}

// saveFetchError updates the meta file with error information.
func saveFetchError(sourceURL, attemptTime string, httpStatus int, err error) {
	// Try to preserve existing meta if possible
	meta, _ := ReadMeta()
	if meta == nil {
		meta = &CatalogMeta{MetaVersion: MetaVersion}
	}

	meta.LastStatus = MetaStatusError
	// SECURITY: Sanitize URL to remove credentials before persisting to meta file.
	// URLs may contain userinfo (user:pass@host) or sensitive query params (?token=...).
	meta.SourceURL = redact.SanitizeURL(sourceURL)
	meta.LastAttemptAt = attemptTime
	meta.LastHTTPStatus = httpStatus

	// SECURITY: Sanitize error message to remove any embedded URLs with credentials.
	// Error messages from redirects or network errors may contain full URLs.
	errMsg := redact.Sensitive(err.Error())
	// Truncate error message to avoid huge meta files
	if len(errMsg) > 500 {
		errMsg = errMsg[:497] + "..."
	}
	meta.LastError = errMsg

	_ = WriteMeta(meta) // Best effort
}

// updateMetaNotModified updates meta for 304 response.
func updateMetaNotModified(sourceURL, attemptTime string, resp *http.Response) {
	meta, _ := ReadMeta()
	if meta == nil {
		meta = &CatalogMeta{MetaVersion: MetaVersion}
	}

	meta.LastStatus = MetaStatusNotModified
	// SECURITY: Sanitize URL before persisting
	meta.SourceURL = redact.SanitizeURL(sourceURL)
	meta.LastAttemptAt = attemptTime
	meta.LastHTTPStatus = resp.StatusCode

	// Update ETag/Last-Modified if provided (servers sometimes include them on 304)
	if etag := resp.Header.Get("ETag"); etag != "" {
		meta.ETag = etag
	}
	if lm := resp.Header.Get("Last-Modified"); lm != "" {
		meta.LastModified = lm
	}

	// Clear any previous error
	meta.LastError = ""

	_ = WriteMeta(meta) // Best effort
}

// GetCachedMeta returns the cached meta for use in conditional requests.
// Returns nil if no meta exists.
func GetCachedMeta() *CatalogMeta {
	meta, _ := ReadMeta()
	return meta
}
