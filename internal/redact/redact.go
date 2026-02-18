// Package redact provides structured redaction for output in CI environments.
//
// When enabled, redaction replaces sensitive information in error messages and
// logs with placeholder values. This is useful in CI environments where logs
// may be publicly visible or stored long-term.
//
// Redaction targets actually sensitive data:
//   - Bearer tokens and authorization headers
//   - JWT/OIDC tokens
//   - CI provider tokens (GitHub ghs_/gho_/ghp_, GitLab glpat-/glcbt-, etc.)
//   - API keys and secrets in key=value patterns
//   - Long base64 strings (likely encoded credentials)
//
// File paths are NOT redacted - they're useful for debugging and rarely secrets.
//
// This package is at the infrastructure layer (Layer 4) so it can be used by
// both workflow packages (internal/collector, internal/dispatch) and CLI packages.
//
// Usage:
//
//	// Enable redaction (typically via --redact flag or EPACK_REDACT env)
//	redact.Enable()
//
//	// Scan error messages for sensitive patterns
//	msg := redact.Sensitive("auth failed: Bearer eyJhbG...")
//	// Returns "auth failed: Bearer [REDACTED]"
//
//	// Explicitly mark a value as sensitive
//	token := os.Getenv("SECRET_TOKEN")
//	log.Printf("using token: %s", redact.Value(token))
//	// Returns "using token: [REDACTED]" when enabled
package redact

import (
	"net/url"
	"regexp"
	"strings"
	"sync"
)

// Placeholder is the replacement text for redacted values.
const Placeholder = "[REDACTED]"

// maxInputLength is the maximum string length to scan for redaction.
// Longer strings are truncated before scanning to prevent DoS via regex on huge inputs.
// While Go's RE2 is linear-time, very long inputs can still be slow.
const maxInputLength = 64 * 1024 // 64 KB

var (
	enabled bool
	mu      sync.RWMutex

	// Patterns for sensitive data

	// Bearer tokens: "Bearer xyz..." or "bearer xyz..."
	bearerPattern = regexp.MustCompile(`(?i)(bearer\s+)[A-Za-z0-9_\-\.=]+`)

	// JWT tokens: three base64url segments separated by dots (header.payload.signature)
	jwtPattern = regexp.MustCompile(`eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*`)

	// OIDC/CI provider tokens - these have distinctive prefixes
	// GitHub: ghs_ (installation), gho_ (OAuth), ghp_ (PAT), ghr_ (refresh)
	// GitLab: glpat- (PAT), glcbt- (CI job token), gloas- (OAuth), glsoat- (service account)
	// CircleCI: CIRCLE_OIDC_TOKEN format varies but is typically base64
	ciTokenPattern = regexp.MustCompile(`\b(ghs_|gho_|ghp_|ghr_|glpat-|glcbt-|gloas-|glsoat-)[A-Za-z0-9_-]+\b`)

	// API key patterns: key=value or key:value where key suggests a secret
	apiKeyPattern = regexp.MustCompile(`(?i)(api[_-]?key|secret|token|password|credential|auth)[=:\s]["']?[A-Za-z0-9_\-\.=+/]{8,}["']?`)

	// Long base64 strings (40+ chars) - likely encoded secrets, but exclude hex digests
	base64SecretPattern = regexp.MustCompile(`[A-Za-z0-9+/]{40,}={0,2}`)

	// URL pattern to find URLs in text for query parameter redaction
	urlPattern = regexp.MustCompile(`https?://[^\s<>"']+`)

	// Sensitive query parameter names (case-insensitive matching done in code)
	sensitiveQueryParams = []string{
		"token", "access_token", "api_key", "apikey", "secret",
		"password", "passwd", "pwd", "auth", "authorization",
		"bearer", "credential", "key", "private_key", "client_secret",
	}
)

// Enable turns on redaction globally.
func Enable() {
	mu.Lock()
	defer mu.Unlock()
	enabled = true
}

// Disable turns off redaction globally.
func Disable() {
	mu.Lock()
	defer mu.Unlock()
	enabled = false
}

// IsEnabled returns whether redaction is currently enabled.
func IsEnabled() bool {
	mu.RLock()
	defer mu.RUnlock()
	return enabled
}

// Value redacts an explicitly sensitive value.
// Use this when you know the value is sensitive (e.g., from an env var).
func Value(v string) string {
	if !IsEnabled() || v == "" {
		return v
	}
	return Placeholder
}

// Sensitive scans a string for patterns that look like secrets and redacts them.
// This includes:
//   - Bearer tokens (preserves "Bearer " prefix)
//   - JWT tokens (three-part base64url format)
//   - CI provider tokens (GitHub ghs_/gho_/ghp_, GitLab glpat-/glcbt-, etc.)
//   - API keys and secrets in key=value patterns
//   - Long base64 strings (40+ chars, likely encoded secrets)
//   - Sensitive URL query parameters (token, api_key, secret, etc.)
//
// SECURITY: Input is truncated to maxInputLength before scanning to prevent
// DoS via regex processing on very large inputs. Truncated content is replaced
// with a marker indicating potential secrets were not fully scanned.
func Sensitive(s string) string {
	if !IsEnabled() {
		return s
	}

	// Truncate very long inputs to prevent DoS
	truncated := false
	if len(s) > maxInputLength {
		s = s[:maxInputLength]
		truncated = true
	}

	// Redact sensitive URL query parameters first (before other patterns might match)
	s = redactURLQueryParams(s)

	// Redact CI provider tokens (GitHub ghs_/gho_/ghp_, GitLab glpat-/glcbt-, etc.)
	s = ciTokenPattern.ReplaceAllString(s, Placeholder)

	// Redact JWT tokens (most specific pattern)
	s = jwtPattern.ReplaceAllString(s, Placeholder)

	// Redact bearer tokens, keeping the "Bearer " prefix
	s = bearerPattern.ReplaceAllString(s, "${1}"+Placeholder)

	// Redact API key patterns, keeping the key name
	s = apiKeyPattern.ReplaceAllStringFunc(s, func(match string) string {
		// Find the separator and keep the key name
		for i, c := range match {
			if c == '=' || c == ':' || c == ' ' {
				prefix := match[:i+1]
				// Handle quoted values
				rest := match[i+1:]
				if len(rest) > 0 && (rest[0] == '"' || rest[0] == '\'') {
					return prefix + string(rest[0]) + Placeholder + string(rest[0])
				}
				return prefix + Placeholder
			}
		}
		return Placeholder
	})

	// Redact long base64 strings (but check it's not a hex digest pattern)
	s = base64SecretPattern.ReplaceAllStringFunc(s, func(match string) string {
		// Skip if it looks like a sha256 hex digest (64 hex chars)
		if len(match) == 64 && isHexString(match) {
			return match
		}
		return Placeholder
	})

	// Append truncation marker if input was too long
	if truncated {
		s += "... [TRUNCATED - additional content not scanned for secrets]"
	}

	return s
}

// Error is an alias for Sensitive - scans error messages for secrets.
func Error(msg string) string {
	return Sensitive(msg)
}

// isHexString checks if a string contains only hex characters.
func isHexString(s string) bool {
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}

// redactURLQueryParams finds URLs in text and redacts sensitive query parameters.
// This uses proper URL parsing rather than regex to safely handle URL-encoded values.
func redactURLQueryParams(s string) string {
	return urlPattern.ReplaceAllStringFunc(s, func(rawURL string) string {
		// Parse the URL
		u, err := url.Parse(rawURL)
		if err != nil {
			// If parsing fails, return as-is (other patterns may catch secrets)
			return rawURL
		}

		// Check if there are any query parameters
		if u.RawQuery == "" {
			return rawURL
		}

		// Parse query parameters
		query, err := url.ParseQuery(u.RawQuery)
		if err != nil {
			return rawURL
		}

		// Check and redact sensitive parameters
		modified := false
		for key := range query {
			if isSensitiveParam(key) {
				query.Set(key, Placeholder)
				modified = true
			}
		}

		if !modified {
			return rawURL
		}

		// Reconstruct the URL with redacted query params
		// We manually build the query string to avoid URL-encoding [REDACTED]
		u.RawQuery = encodeQueryWithPlaceholder(query)
		return u.String()
	})
}

// encodeQueryWithPlaceholder encodes query params but preserves [REDACTED] unescaped.
func encodeQueryWithPlaceholder(query url.Values) string {
	encoded := query.Encode()
	// Replace URL-encoded [REDACTED] with literal [REDACTED]
	encoded = strings.ReplaceAll(encoded, url.QueryEscape(Placeholder), Placeholder)
	return encoded
}

// isSensitiveParam checks if a query parameter name suggests it contains a secret.
func isSensitiveParam(name string) bool {
	lower := strings.ToLower(name)
	for _, sensitive := range sensitiveQueryParams {
		if lower == sensitive || strings.Contains(lower, sensitive) {
			return true
		}
	}
	return false
}

// SanitizeURL removes sensitive parts of a URL for safe logging/storage.
// It removes:
//   - Userinfo (user:password@host)
//   - Sensitive query parameters (token, key, secret, etc.)
//
// Always sanitizes regardless of redaction setting - URLs with credentials
// should never be persisted.
func SanitizeURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		// Can't parse - return just the scheme and host if visible, or placeholder
		return "[invalid URL]"
	}

	// Clear userinfo (user:password@host)
	u.User = nil

	// Sanitize query parameters
	if u.RawQuery != "" {
		query, err := url.ParseQuery(u.RawQuery)
		if err == nil {
			for key := range query {
				if isSensitiveParam(key) {
					query.Set(key, Placeholder)
				}
			}
			u.RawQuery = encodeQueryWithPlaceholder(query)
		}
	}

	return u.String()
}

// SanitizeURLHost returns only the scheme and host of a URL.
// This is the safest option for error messages where the full path isn't needed.
func SanitizeURLHost(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "[invalid URL]"
	}

	// Return only scheme://host (no path, query, or fragment)
	result := u.Scheme + "://" + u.Host
	return result
}
