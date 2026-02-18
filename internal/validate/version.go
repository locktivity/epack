package validate

import (
	"fmt"
	"regexp"
	"strings"
)

// VersionRegex matches semver versions with a safe prerelease charset.
// SECURITY: The prerelease pattern [a-zA-Z0-9.-]+ explicitly rejects
// URL-unsafe characters (/, ?, #, %, \, etc.) to prevent path/query
// smuggling when the version is used in GitHub API URLs.
var VersionRegex = regexp.MustCompile(`^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:-([a-zA-Z0-9][a-zA-Z0-9.-]*))?$`)

// MaxVersionLength is the maximum allowed version string length.
const MaxVersionLength = 128

// Version validates a version string for safe filesystem and URL use.
// Accepts semver-like versions: v1.2.3, v1.2.3-alpha.1, 1.2.3, etc.
// Rejects path traversal, path separators, and malformed semver.
//
// SECURITY: This is the canonical version validator. All version validation
// should use this function to ensure consistent security checks.
func Version(version string) error {
	if version == "" {
		return fmt.Errorf("version cannot be empty")
	}
	if len(version) > MaxVersionLength {
		return fmt.Errorf("version %q exceeds max length %d", version, MaxVersionLength)
	}

	// SECURITY: Reject all path traversal patterns
	if err := RejectPathTraversal(version); err != nil {
		return fmt.Errorf("version %q: %w", version, err)
	}

	// Must be valid semver
	if !VersionRegex.MatchString(version) {
		return fmt.Errorf("version %q is invalid: must be semver format (e.g., v1.2.3 or v1.2.3-beta.1)", version)
	}
	return nil
}

// RejectPathTraversal rejects strings containing path traversal patterns.
// Used by Version, ComponentName, and other validators.
//
// SECURITY: This catches all known path traversal attack vectors:
//   - Path separators (/ and \)
//   - Exact traversal segments (. and ..)
//   - Prefix traversal (../ and ..\)
//   - Embedded traversal (/../ and \..\)
//   - Double-dot sequences anywhere (catches edge cases like "foo.." or "..bar")
func RejectPathTraversal(s string) error {
	// Path separators
	if strings.Contains(s, "/") || strings.Contains(s, "\\") {
		return fmt.Errorf("contains path separator")
	}
	// Exact traversal
	if s == "." || s == ".." {
		return fmt.Errorf("is path traversal segment")
	}
	// Prefix traversal
	if strings.HasPrefix(s, "../") || strings.HasPrefix(s, "..\\") {
		return fmt.Errorf("starts with path traversal")
	}
	// Embedded traversal
	if strings.Contains(s, "/../") || strings.Contains(s, "\\..\\") {
		return fmt.Errorf("contains embedded path traversal")
	}
	// Double-dot anywhere (catches "foo..", "..bar", "foo..bar")
	// Note: This is checked after separators, so we know there's no path context
	if ContainsTraversal(s) {
		return fmt.Errorf("contains double-dot sequence")
	}
	return nil
}

// RejectTraversalInPath rejects path traversal patterns while allowing forward slashes.
// Use this for validating paths like stream identifiers ("org/prod") that legitimately
// contain "/" but should not contain traversal sequences.
//
// SECURITY: This catches traversal attacks while allowing hierarchical identifiers:
//   - Backslashes (Windows path separators)
//   - Exact traversal segments (. and ..)
//   - Prefix traversal (../)
//   - Embedded traversal (/../)
//   - Leading or trailing slashes (could indicate absolute path or ambiguous intent)
//   - Empty segments (consecutive slashes //)
func RejectTraversalInPath(s string) error {
	if s == "" {
		return fmt.Errorf("empty path")
	}
	// Backslash (Windows separator) - never allowed
	if strings.Contains(s, "\\") {
		return fmt.Errorf("contains backslash")
	}
	// Leading slash (absolute path)
	if strings.HasPrefix(s, "/") {
		return fmt.Errorf("starts with slash (absolute path)")
	}
	// Trailing slash
	if strings.HasSuffix(s, "/") {
		return fmt.Errorf("ends with slash")
	}
	// Empty segments (consecutive slashes)
	if strings.Contains(s, "//") {
		return fmt.Errorf("contains empty segment (consecutive slashes)")
	}
	// Check each segment for traversal
	segments := strings.Split(s, "/")
	for _, seg := range segments {
		if seg == "" {
			return fmt.Errorf("contains empty segment")
		}
		if seg == "." || seg == ".." {
			return fmt.Errorf("contains traversal segment %q", seg)
		}
		// Double-dot anywhere in segment
		if ContainsTraversal(seg) {
			return fmt.Errorf("segment %q contains double-dot", seg)
		}
	}
	return nil
}
