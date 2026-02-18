package github

import (
	"net/http"
	"net/url"

	"github.com/locktivity/epack/internal/netpolicy"
)

// NewTestClientWithPolicy creates a test client with a custom network policy.
// This allows tests to specify exactly which hosts are trusted.
// SECURITY: Auth tokens are NEVER sent over HTTP, even in tests.
func NewTestClientWithPolicy(httpClient *http.Client, baseURL string, policy *netpolicy.Policy) *Client {
	return &Client{
		httpClient:        httpClient,
		baseURL:           baseURL,
		allowLoopbackHTTP: true,
		rateLimiter:       nil,
		policy:            policy,
	}
}

// NewTestClient creates a basic test client that allows loopback HTTP.
// Use NewClientForTestWithHosts if you need additional trusted hosts.
func NewTestClient(baseURL string) *Client {
	parsed, _ := url.Parse(baseURL)
	hostname := ""
	if parsed != nil {
		hostname = parsed.Hostname()
	}

	return &Client{
		httpClient: &http.Client{
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		baseURL:           baseURL,
		allowLoopbackHTTP: true,
		rateLimiter:       nil,
		policy:            defaultPolicy.WithLoopbackHTTP().WithAdditionalHosts(hostname),
	}
}
