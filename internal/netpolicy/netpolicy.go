package netpolicy

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// Policy defines network security policy for a set of trusted hosts.
// It validates URLs and determines whether credentials should be sent.
type Policy struct {
	// trustedAPIHosts can receive API requests with auth headers.
	trustedAPIHosts map[string]bool

	// trustedAssetHosts can receive auth headers for asset downloads.
	// This is typically a superset of trustedAPIHosts.
	trustedAssetHosts map[string]bool

	// allowLoopbackHTTP permits HTTP to localhost/127.0.0.1 (for testing).
	// SECURITY: Auth headers are NEVER sent over HTTP, even when this is true.
	allowLoopbackHTTP bool
}

// NewPolicy creates a new network policy with the given trusted hosts.
// apiHosts are trusted for API requests, assetHosts for asset downloads.
func NewPolicy(apiHosts, assetHosts []string) *Policy {
	p := &Policy{
		trustedAPIHosts:   make(map[string]bool),
		trustedAssetHosts: make(map[string]bool),
	}
	for _, h := range apiHosts {
		p.trustedAPIHosts[h] = true
	}
	for _, h := range assetHosts {
		p.trustedAssetHosts[h] = true
	}
	return p
}

// GitHubPolicy returns the default policy for GitHub API and asset hosts.
// This is the standard policy for production use with GitHub.
func GitHubPolicy() *Policy {
	return NewPolicy(
		// API hosts - can receive API requests with auth headers
		[]string{"api.github.com"},
		// Asset hosts - can receive auth headers for asset downloads
		[]string{
			"github.com",
			"api.github.com",
			"objects.githubusercontent.com",
			"github-releases.githubusercontent.com",
		},
	)
}

// WithLoopbackHTTP returns a copy of the policy that allows HTTP to loopback addresses.
// SECURITY: Auth headers are NEVER sent over HTTP, even to loopback.
// This is intended for testing with local mock servers.
func (p *Policy) WithLoopbackHTTP() *Policy {
	cp := p.copy()
	cp.allowLoopbackHTTP = true
	return cp
}

// WithAdditionalHosts returns a copy of the policy with additional trusted hosts.
// The hosts are added to both API and asset host lists.
// This is intended for testing with mock servers.
func (p *Policy) WithAdditionalHosts(hosts ...string) *Policy {
	cp := p.copy()
	for _, h := range hosts {
		cp.trustedAPIHosts[h] = true
		cp.trustedAssetHosts[h] = true
	}
	return cp
}

// copy returns a deep copy of the policy.
func (p *Policy) copy() *Policy {
	cp := &Policy{
		trustedAPIHosts:   make(map[string]bool),
		trustedAssetHosts: make(map[string]bool),
		allowLoopbackHTTP: p.allowLoopbackHTTP,
	}
	for k, v := range p.trustedAPIHosts {
		cp.trustedAPIHosts[k] = v
	}
	for k, v := range p.trustedAssetHosts {
		cp.trustedAssetHosts[k] = v
	}
	return cp
}

// IsLoopback reports whether hostname refers to the local machine.
// Recognizes IPv4 (127.0.0.1), IPv6 (::1, [::1]), and localhost.
// Used to enforce stricter policies on non-local connections.
func IsLoopback(hostname string) bool {
	// Strip brackets from IPv6 literal (e.g., "[::1]" -> "::1")
	h := strings.TrimPrefix(strings.TrimSuffix(hostname, "]"), "[")
	return h == "localhost" || h == "127.0.0.1" || h == "::1"
}

// ValidateAPIURL validates that a URL is allowed for API requests.
// Returns an error if:
//   - The scheme is not HTTPS (or HTTP for allowed loopback)
//   - The host is not in the trusted API hosts list (unless loopback)
func (p *Policy) ValidateAPIURL(rawURL string) error {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}

	hostname := parsed.Hostname()
	isLoopback := IsLoopback(hostname)

	// Check scheme
	if err := p.validateScheme(parsed, isLoopback); err != nil {
		return err
	}

	// For non-loopback, require trusted host
	if !isLoopback && !p.trustedAPIHosts[hostname] {
		return fmt.Errorf("host %q is not in trusted API hosts allowlist", hostname)
	}

	return nil
}

// ValidateAssetURL validates that a URL is allowed for asset downloads.
// Returns an error if:
//   - The scheme is not HTTPS (or HTTP for allowed loopback)
//   - The host is not in the trusted asset hosts list (unless loopback)
func (p *Policy) ValidateAssetURL(rawURL string) error {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}

	hostname := parsed.Hostname()
	isLoopback := IsLoopback(hostname)

	// Check scheme
	if err := p.validateScheme(parsed, isLoopback); err != nil {
		return err
	}

	// For non-loopback, require trusted host
	if !isLoopback && !p.trustedAssetHosts[hostname] {
		return fmt.Errorf("host %q is not in trusted asset hosts allowlist", hostname)
	}

	return nil
}

// validateScheme checks that the URL scheme is allowed.
func (p *Policy) validateScheme(parsed *url.URL, isLoopback bool) error {
	switch parsed.Scheme {
	case "https":
		return nil
	case "http":
		if !isLoopback {
			return fmt.Errorf("HTTP scheme only allowed for localhost/127.0.0.1, refusing for %q", parsed.Host)
		}
		if !p.allowLoopbackHTTP {
			return fmt.Errorf("HTTP to loopback %q not allowed (use WithLoopbackHTTP for testing)", parsed.Host)
		}
		return nil
	default:
		return fmt.Errorf("scheme %q not allowed, must be https", parsed.Scheme)
	}
}

// ShouldSendAuth returns true if auth headers should be sent to this URL.
// SECURITY: Never returns true for HTTP URLs, even to loopback.
// HTTP traffic can be sniffed by other processes on the same machine.
func (p *Policy) ShouldSendAuth(parsed *url.URL) bool {
	// SECURITY: Never send auth over HTTP, including to loopback.
	// A malicious URL pointing to http://127.0.0.1:PORT could
	// exfiltrate tokens to a local listener.
	if parsed.Scheme != "https" {
		return false
	}

	hostname := parsed.Hostname()
	return p.trustedAssetHosts[hostname]
}

// ShouldSendAPIAuth returns true if auth headers should be sent for API requests.
// Uses the stricter API hosts list. Returns false for HTTP URLs.
func (p *Policy) ShouldSendAPIAuth(parsed *url.URL) bool {
	if parsed.Scheme != "https" {
		return false
	}

	hostname := parsed.Hostname()
	return p.trustedAPIHosts[hostname]
}

// IsTrustedAPIHost returns true if the host is in the trusted API hosts list.
func (p *Policy) IsTrustedAPIHost(hostname string) bool {
	return p.trustedAPIHosts[hostname]
}

// IsTrustedAssetHost returns true if the host is in the trusted asset hosts list.
func (p *Policy) IsTrustedAssetHost(hostname string) bool {
	return p.trustedAssetHosts[hostname]
}

// SecureTransport returns an http.Transport configured with secure TLS defaults.
// This enforces TLS 1.2 minimum to prevent protocol downgrade attacks.
//
// Use this for all production HTTP clients that make external requests.
func SecureTransport() *http.Transport {
	return &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}
}
