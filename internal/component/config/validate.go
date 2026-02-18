package config

import (
	"fmt"
	"regexp"

	"github.com/locktivity/epack/internal/validate"
)

// ValidateCollectorName checks if a collector name is safe for use in paths.
func ValidateCollectorName(name string) error {
	if ok, reason := validate.ComponentName(name, "collector"); !ok {
		return fmt.Errorf("invalid collector name %q: %s", name, reason)
	}
	return nil
}

// ValidateToolName checks if a tool name is safe for use in paths.
func ValidateToolName(name string) error {
	if ok, reason := validate.ComponentName(name, "tool"); !ok {
		return fmt.Errorf("invalid tool name %q: %s", name, reason)
	}
	return nil
}

// ValidateVersion checks if a version string is safe for use in filesystem paths.
// This prevents path traversal attacks via malicious lockfile version fields.
// Accepts semver-like versions: v1.2.3, v1.2.3-alpha.1, 1.2.3, etc.
// Rejects path separators, dot segments (..), and absolute paths.
func ValidateVersion(version string) error {
	return validate.Version(version)
}

// platformRegex validates platform strings (os/arch format).
var platformRegex = regexp.MustCompile(`^[a-z]+/[a-z0-9]+$`)

// ValidatePlatform checks if a platform string is valid (e.g., "linux/amd64").
func ValidatePlatform(platform string) error {
	if !platformRegex.MatchString(platform) {
		return fmt.Errorf("invalid platform %q: must be os/arch format (e.g., linux/amd64)", platform)
	}
	return nil
}

// ValidateRemoteName checks if a remote name is safe for use in paths and URLs.
func ValidateRemoteName(name string) error {
	if ok, reason := validate.ComponentName(name, "remote"); !ok {
		return fmt.Errorf("invalid remote name %q: %s", name, reason)
	}
	return nil
}

// ValidateEnvironmentName checks if an environment name is safe for use in paths.
func ValidateEnvironmentName(name string) error {
	if ok, reason := validate.ComponentName(name, "environment"); !ok {
		return fmt.Errorf("invalid environment name %q: %s", name, reason)
	}
	return nil
}

// ValidateUtilityName checks if a utility name is safe for use in paths.
func ValidateUtilityName(name string) error {
	if ok, reason := validate.ComponentName(name, "utility"); !ok {
		return fmt.Errorf("invalid utility name %q: %s", name, reason)
	}
	return nil
}
