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
//   - Long base64 strings (likely encoded credentials), unless they read as
//     words, such as an API error code or path
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
	"sort"
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

	// API key patterns: a keyword that suggests a secret, then its value after
	// "=", ":", or spaces. A quote may close a JSON key or open the value.
	apiKeyPattern = regexp.MustCompile(`(?i)(api[_-]?key|secret|token|password|credential|auth)("?\s*[=:]\s*|\s+)(["']?)([A-Za-z0-9_\-\.=+/]{8,})(["']?)`)

	// An ordinary word after a keyword and a space is prose, as in "token
	// endpoint returned 503", not a value.
	ordinaryWordPattern = regexp.MustCompile(`^(?:[a-z]+(?:[_-][a-z]+)*|[A-Z][a-z]+|[A-Z]+)$`)

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
//   - Long base64 strings (40+ chars, likely encoded secrets), unless they
//     read as words
//   - Sensitive URL query parameters (token, api_key, secret, etc.)
//
// SECURITY: Input is truncated to maxInputLength before scanning to prevent
// DoS via regex processing on very large inputs. Truncated content is replaced
// with a marker indicating potential secrets were not fully scanned.
func Sensitive(s string) string {
	if !IsEnabled() {
		return s
	}
	return SensitiveAlways(s)
}

// SensitiveAlways applies Sensitive's pattern redaction whether or not
// redaction is enabled globally. Collectors use it for text that reaches
// evidence, where the CLI's switch does not apply.
func SensitiveAlways(s string) string {
	truncatedInput, truncated := truncateForRedaction(s)
	redacted := applySensitiveRedactions(truncatedInput)
	if truncated {
		return redacted + "... [TRUNCATED - additional content not scanned for secrets]"
	}
	return redacted
}

func truncateForRedaction(s string) (string, bool) {
	if len(s) <= maxInputLength {
		return s, false
	}
	return s[:maxInputLength], true
}

func applySensitiveRedactions(s string) string {
	s = applyTokenRedactions(s)
	return base64SecretPattern.ReplaceAllStringFunc(s, redactBase64SecretMatch)
}

// applyTokenRedactions applies every rule but the one for long base64-like
// runs, which runs last.
func applyTokenRedactions(s string) string {
	s = redactURLQueryParams(s)
	s = ciTokenPattern.ReplaceAllString(s, Placeholder)
	s = jwtPattern.ReplaceAllString(s, Placeholder)
	s = bearerPattern.ReplaceAllString(s, "${1}"+Placeholder)
	return apiKeyPattern.ReplaceAllStringFunc(s, redactAPIKeyMatch)
}

// redactAPIKeyMatch redacts the value after a credential keyword: always
// after "=", after ":" with nothing between, and in quotes, and otherwise
// unless the value is an ordinary word.
func redactAPIKeyMatch(match string) string {
	m := apiKeyPattern.FindStringSubmatch(match)
	if m == nil {
		return match
	}
	keyword, sep, open, value, closing := m[1], m[2], m[3], m[4], m[5]
	spaced := !strings.Contains(sep, "=") && strings.TrimRight(sep, " \t\r\n\f\v") != sep
	if spaced && open == "" && ordinaryWordPattern.MatchString(strings.TrimRight(value, ".")) {
		return match
	}
	return keyword + sep + open + Placeholder + closing
}

// redactBase64SecretMatch redacts a long base64 run, except for 64-character
// hex digests and runs that read as words. A digest stays readable even
// inside a path or URL such as "blobs/<digest>/data", and the text around it
// is judged on its own.
func redactBase64SecretMatch(match string) string {
	out, _ := splitLongRun(match)
	return out
}

// splitLongRun returns match with each long run that does not read as words
// replaced by Placeholder, and the runs it replaced.
func splitLongRun(match string) (string, []string) {
	segments := strings.Split(match, "/")
	var out, run, hidden []string
	flush := func() {
		if len(run) == 0 {
			return
		}
		text := strings.Join(run, "/")
		if len(text) >= 40 && !wordShaped(text) {
			hidden = append(hidden, text)
			text = Placeholder
		}
		out = append(out, text)
		run = nil
	}
	for _, seg := range segments {
		if len(seg) == 64 && isHexString(seg) {
			flush()
			out = append(out, seg)
			continue
		}
		run = append(run, seg)
	}
	flush()
	return strings.Join(out, "/"), hidden
}

// wordShaped reports whether a long run reads as words, such as an API error
// code, a field name, or a path, so it stays readable. Each piece between
// slashes must be digits only, at most five characters, or letters that read
// as camel-case words. A random secret almost always has a digit, and a run
// of 40 random letters passes the word test about once in 100,000 tries.
func wordShaped(run string) bool {
	for _, seg := range strings.Split(run, "/") {
		if len(seg) > 5 && !isDigits(seg) && !readsAsWords(seg) {
			return false
		}
	}
	return true
}

// readsAsWords reports whether s is letters in camel case whose words
// average at least 4.5 letters and run at most 20. At most 35% of the
// letters may be capitals. Each word with lowercase letters needs a vowel,
// and no five lowercase consonants may run together.
func readsAsWords(s string) bool {
	if !isLetters(s) {
		return false
	}
	words := splitWords(s)
	uppers, consonants := 0, 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case isUpper(c):
			uppers++
			consonants = 0
		case isVowel(c):
			consonants = 0
		default:
			if consonants++; consonants == 5 {
				return false
			}
		}
	}
	if 2*len(s) < 9*len(words) || 20*uppers > 7*len(s) {
		return false
	}
	for _, w := range words {
		if len(w) > 20 {
			return false
		}
		if strings.ToUpper(w) != w && !strings.ContainsFunc(w, func(r rune) bool { return isVowel(byte(r) | 0x20) }) {
			return false
		}
	}
	return true
}

// splitWords splits a run of letters written in camel case into its words,
// so "ServerSideEncryption" has 3 and "ELBHealthCheck" has 3.
func splitWords(s string) []string {
	var words []string
	start := 0
	for i := 1; i < len(s); i++ {
		if isUpper(s[i]) && (!isUpper(s[i-1]) || (i+1 < len(s) && !isUpper(s[i+1]))) {
			words = append(words, s[start:i])
			start = i
		}
	}
	return append(words, s[start:])
}

func isVowel(c byte) bool {
	switch c {
	case 'a', 'e', 'i', 'o', 'u', 'y':
		return true
	}
	return false
}

// LongRunsHidden returns the long runs that Sensitive's rule for base64-like
// text hides in s, after the other rules. A test can then tell an identifier
// hidden by mistake from a secret. Runs inside a URL are left out. A URL's
// path can hold a secret, as a webhook URL does, so hiding it is expected.
func LongRunsHidden(s string) []string {
	s, _ = truncateForRedaction(s)
	s = urlPattern.ReplaceAllString(applyTokenRedactions(s), " ")
	var hidden []string
	for _, match := range base64SecretPattern.FindAllString(s, -1) {
		_, h := splitLongRun(match)
		hidden = append(hidden, h...)
	}
	return hidden
}

func isUpper(c byte) bool { return c >= 'A' && c <= 'Z' }

func isLetters(s string) bool {
	for i := 0; i < len(s); i++ {
		if c := s[i]; !isUpper(c) && (c < 'a' || c > 'z') {
			return false
		}
	}
	return true
}

func isDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return s != ""
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

// MinValueLength keeps trivial values such as "1" or "true" from shredding
// the output when redacting by value; nothing that short is a secret.
const MinValueLength = 6

// Values replaces every occurrence of the given secret values in s with the
// placeholder, longest first so a value that is part of another cannot
// expose the rest of it. Each value is also matched trimmed of surrounding
// whitespace, since a file-backed value often ends with a newline. Values
// shorter than MinValueLength are ignored.
func Values(s string, values ...string) string {
	candidates := make([]string, 0, 2*len(values))
	seen := map[string]bool{}
	for _, value := range values {
		for _, form := range []string{value, strings.TrimSpace(value)} {
			if len(form) < MinValueLength || seen[form] {
				continue
			}
			seen[form] = true
			candidates = append(candidates, form)
		}
	}
	sort.SliceStable(candidates, func(i, j int) bool { return len(candidates[i]) > len(candidates[j]) })
	for _, value := range candidates {
		s = strings.ReplaceAll(s, value, Placeholder)
	}
	return s
}
