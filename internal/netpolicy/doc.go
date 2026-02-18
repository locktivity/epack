// Package netpolicy provides URL and host validation for network requests.
//
// This package centralizes network security policy enforcement to ensure
// consistent validation across all code that makes external network requests.
// Using this package prevents divergence that could lead to SSRF vulnerabilities
// or credential leakage.
//
// # Security Properties
//
//   - Validates URLs against allowlists of trusted hosts
//   - Enforces HTTPS for all non-loopback connections
//   - Prevents credential transmission over HTTP (even to loopback)
//   - Provides separate allowlists for different trust levels (API vs asset hosts)
//   - Supports loopback addresses for testing while maintaining security
//
// # Usage
//
// Validate a URL before making a request:
//
//	policy := netpolicy.GitHubPolicy()
//	if err := policy.ValidateAPIURL(url); err != nil {
//	    return err // Host not trusted or scheme not allowed
//	}
//
// Check if auth headers should be sent:
//
//	if policy.ShouldSendAuth(parsedURL) {
//	    req.Header.Set("Authorization", "Bearer "+token)
//	}
//
// For testing with loopback addresses:
//
//	policy := netpolicy.GitHubPolicy().WithLoopbackHTTP()
//	// HTTP to localhost/127.0.0.1 now allowed (but auth never sent over HTTP)
package netpolicy
