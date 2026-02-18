package validate

import (
	"regexp"
	"strings"
)

// ComponentNameRegex validates collector/tool/remote/utility/environment names.
// Names must start with alphanumeric and contain only alphanumeric, dash, underscore, or dot.
// Maximum length 64 characters. No path separators, .., or absolute paths allowed.
var ComponentNameRegex = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// ComponentName validates a component name for filesystem path safety.
// Returns ok=true if valid, or ok=false with a reason string.
//
// SECURITY: This is the canonical component name validator. All component
// name validation should use this function to ensure consistent security checks.
//
// The kind parameter is used only for error messages (e.g., "collector", "tool").
func ComponentName(name, kind string) (ok bool, reason string) {
	if name == "" {
		return false, kind + " name cannot be empty"
	}
	if !ComponentNameRegex.MatchString(name) {
		return false, kind + " name must start with lowercase alphanumeric, contain only [a-z0-9._-], max 64 chars"
	}
	// SECURITY: Reject names that could cause path traversal issues.
	// This catches "..", "0..", "foo..", "..foo", "foo..bar", etc.
	if name == "." || ContainsTraversal(name) {
		return false, kind + " name contains reserved path segment"
	}
	return true, ""
}

// ContainsTraversal checks if a string contains ".." path traversal sequences.
//
// SECURITY: Use this for quick traversal checks. For comprehensive path
// validation, use RejectPathTraversal which also checks separators.
func ContainsTraversal(s string) bool {
	return strings.Contains(s, "..")
}
