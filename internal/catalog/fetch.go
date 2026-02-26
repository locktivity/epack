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

// DefaultCatalogURL is the default catalog URL.
const DefaultCatalogURL = "https://registry.epack.dev/catalog.json"

// trustedCatalogHosts is the allowlist of hosts that can serve the tool catalog.
// SECURITY: Catalog data influences discovery/display (not execution), but restricting
// sources prevents attackers from serving malicious catalog data via redirects or
// user-provided URLs.
var trustedCatalogHosts = map[string]bool{
	"registry.epack.dev": true,
	"epack.dev":          true,
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

	if err := validateCatalogURL(catalogURL, opts.InsecureAllowHTTP); err != nil {
		return nil, err
	}

	client := buildCatalogHTTPClient(opts, opts.InsecureAllowHTTP)
	req, err := buildCatalogRequest(ctx, catalogURL, opts)
	if err != nil {
		return nil, err
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

	return processCatalogResponse(catalogURL, attemptTime, resp)
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

func validateCatalogURL(catalogURL string, insecureAllowHTTP bool) error {
	parsedURL, err := url.Parse(catalogURL)
	if err != nil {
		return fmt.Errorf("invalid catalog URL: %w", err)
	}

	hostname := parsedURL.Hostname()
	isLoopback := isLoopbackHost(hostname)
	if parsedURL.Scheme != "https" {
		if parsedURL.Scheme != "http" || !isLoopback || !insecureAllowHTTP {
			return fmt.Errorf("catalog URL must use https scheme, got %q", parsedURL.Scheme)
		}
	}
	if !isLoopback && !trustedCatalogHosts[hostname] {
		return fmt.Errorf("catalog host %q not in allowlist", hostname)
	}

	return nil
}

func secureCatalogRedirectCheck(insecureAllowHTTP bool) func(req *http.Request, via []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		targetHost := req.URL.Hostname()
		targetIsLoopback := isLoopbackHost(targetHost)

		if req.URL.Scheme != "https" {
			if req.URL.Scheme != "http" || !targetIsLoopback || !insecureAllowHTTP {
				return fmt.Errorf("redirect to non-HTTPS URL not allowed: %s", redact.SanitizeURLHost(req.URL.String()))
			}
		}
		if !targetIsLoopback && !trustedCatalogHosts[targetHost] {
			return fmt.Errorf("redirect to untrusted host not allowed: %s", targetHost)
		}
		if len(via) >= limits.MaxHTTPRedirects {
			return fmt.Errorf("too many redirects (%d)", len(via))
		}
		return nil
	}
}

func buildCatalogHTTPClient(opts FetchOptions, insecureAllowHTTP bool) *http.Client {
	secureCheckRedirect := secureCatalogRedirectCheck(insecureAllowHTTP)
	if opts.HTTPClient == nil {
		return &http.Client{
			Transport:     netpolicy.SecureTransport(),
			Timeout:       FetchTimeout,
			CheckRedirect: secureCheckRedirect,
		}
	}

	clientCopy := *opts.HTTPClient
	client := &clientCopy
	originalCheckRedirect := opts.HTTPClient.CheckRedirect
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if err := secureCheckRedirect(req, via); err != nil {
			return err
		}
		if originalCheckRedirect != nil {
			return originalCheckRedirect(req, via)
		}
		if len(via) >= 10 {
			return fmt.Errorf("stopped after 10 redirects")
		}
		return nil
	}
	return client
}

func buildCatalogRequest(ctx context.Context, catalogURL string, opts FetchOptions) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, catalogURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "epack/1.0")
	if opts.ETag != "" {
		req.Header.Set("If-None-Match", opts.ETag)
	}
	if opts.LastModified != "" {
		req.Header.Set("If-Modified-Since", opts.LastModified)
	}
	return req, nil
}

func processCatalogResponse(catalogURL, attemptTime string, resp *http.Response) (*FetchResult, error) {
	if resp.StatusCode == http.StatusNotModified {
		updateMetaNotModified(catalogURL, attemptTime, resp)
		return &FetchResult{Updated: false, Status: MetaStatusNotModified, HTTPStatus: resp.StatusCode}, nil
	}
	if resp.StatusCode != http.StatusOK {
		err := fmt.Errorf("unexpected status %d", resp.StatusCode)
		saveFetchError(catalogURL, attemptTime, resp.StatusCode, err)
		return &FetchResult{Updated: false, Status: MetaStatusError, HTTPStatus: resp.StatusCode, Error: err}, nil
	}
	if resp.ContentLength > limits.Catalog.Bytes() {
		err := fmt.Errorf("catalog too large: %d bytes exceeds %d limit", resp.ContentLength, limits.Catalog.Bytes())
		saveFetchError(catalogURL, attemptTime, resp.StatusCode, err)
		return &FetchResult{Updated: false, Status: MetaStatusError, HTTPStatus: resp.StatusCode, Error: err}, nil
	}

	body, err := boundedio.ReadReaderWithLimit(resp.Body, "catalog response", limits.Catalog)
	if err != nil {
		saveFetchError(catalogURL, attemptTime, resp.StatusCode, err)
		return &FetchResult{Updated: false, Status: MetaStatusError, HTTPStatus: resp.StatusCode, Error: fmt.Errorf("reading response: %w", err)}, nil
	}

	cat, err := ParseCatalog(body)
	if err != nil {
		saveFetchError(catalogURL, attemptTime, resp.StatusCode, err)
		return &FetchResult{Updated: false, Status: MetaStatusError, HTTPStatus: resp.StatusCode, Error: fmt.Errorf("parsing catalog: %w", err)}, nil
	}

	_ = cat.Validate()
	if len(cat.Tools) > limits.MaxCatalogComponentCount {
		err := fmt.Errorf("catalog has %d components, exceeds limit of %d", len(cat.Tools), limits.MaxCatalogComponentCount)
		saveFetchError(catalogURL, attemptTime, resp.StatusCode, err)
		return &FetchResult{Updated: false, Status: MetaStatusError, HTTPStatus: resp.StatusCode, Error: err}, nil
	}
	if err := WriteCatalog(cat); err != nil {
		return nil, fmt.Errorf("writing catalog: %w", err)
	}

	_ = WriteMeta(&CatalogMeta{
		MetaVersion:    MetaVersion,
		LastStatus:     MetaStatusOK,
		ETag:           resp.Header.Get("ETag"),
		LastModified:   resp.Header.Get("Last-Modified"),
		FetchedAt:      time.Now().UTC().Format(time.RFC3339),
		SourceURL:      redact.SanitizeURL(catalogURL),
		LastAttemptAt:  attemptTime,
		LastHTTPStatus: resp.StatusCode,
	})
	return &FetchResult{Updated: true, Status: MetaStatusOK, HTTPStatus: resp.StatusCode}, nil
}
