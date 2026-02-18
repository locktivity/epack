// Package semver provides semantic version parsing and constraint matching.
package semver

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/locktivity/epack/internal/validate"
)

// versionRegex is an alias to the canonical version regex in the validate package.
// SECURITY: The prerelease pattern [a-zA-Z0-9.-]+ explicitly rejects
// URL-unsafe characters (/, ?, #, %, \, etc.) to prevent path/query
// smuggling when the version is used in GitHub API URLs.
var versionRegex = validate.VersionRegex

// maxVersionComponent is the maximum value for a version component.
// SECURITY: This prevents integer overflow on 32-bit systems where int is 32 bits.
// Also serves as a sanity check - real semver versions don't need billions.
const maxVersionComponent = 999999999

// ConstraintType represents the type of version constraint.
type ConstraintType int

const (
	ConstraintExact  ConstraintType = iota // v1.2.3
	ConstraintCaret                        // ^1.2.3
	ConstraintTilde                        // ~1.2.3
	ConstraintLatest                       // latest
)

// Constraint represents a parsed version constraint.
type Constraint struct {
	Type       ConstraintType
	Major      int
	Minor      int
	Patch      int
	Prerelease string // Prerelease suffix (e.g., "beta.1" for v1.2.3-beta.1)
	Raw        string // Original constraint string
	HasMinor   bool
	HasPatch   bool
}

// Version represents a parsed semantic version.
type Version struct {
	Major      int
	Minor      int
	Patch      int
	Prerelease string
	Raw        string
}

// ParseConstraint parses a version constraint string.
// Supported formats:
//   - "latest" - latest stable release
//   - "v1.2.3" or "1.2.3" - exact version
//   - "^1.2.3" - caret (compatible with 1.x.x, >=1.2.3 <2.0.0)
//   - "~1.2.3" - tilde (compatible with 1.2.x, >=1.2.3 <1.3.0)
//   - "^0.2.3" - caret with 0.x special case (>=0.2.3 <0.3.0)
func ParseConstraint(s string) (*Constraint, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("empty version constraint")
	}

	if strings.EqualFold(s, "latest") {
		return &Constraint{Type: ConstraintLatest, Raw: s}, nil
	}

	var constraintType ConstraintType
	versionPart := s

	switch {
	case strings.HasPrefix(s, "^"):
		constraintType = ConstraintCaret
		versionPart = s[1:]
	case strings.HasPrefix(s, "~"):
		constraintType = ConstraintTilde
		versionPart = s[1:]
	default:
		constraintType = ConstraintExact
	}

	matches := versionRegex.FindStringSubmatch(versionPart)
	if matches == nil {
		return nil, fmt.Errorf("invalid version format: %q", s)
	}

	// SECURITY: Parse with error checking and enforce maximum to prevent overflow.
	// strconv.Atoi returns int which is 32-bit on some platforms, so large numbers
	// could overflow. We enforce a maximum that fits comfortably in 32 bits.
	major, err := strconv.Atoi(matches[1])
	if err != nil || major > maxVersionComponent {
		return nil, fmt.Errorf("invalid major version in %q: exceeds maximum", s)
	}

	minor := 0
	patch := 0
	hasMinor := matches[2] != ""
	hasPatch := matches[3] != ""

	if hasMinor {
		minor, err = strconv.Atoi(matches[2])
		if err != nil || minor > maxVersionComponent {
			return nil, fmt.Errorf("invalid minor version in %q: exceeds maximum", s)
		}
	}
	if hasPatch {
		patch, err = strconv.Atoi(matches[3])
		if err != nil || patch > maxVersionComponent {
			return nil, fmt.Errorf("invalid patch version in %q: exceeds maximum", s)
		}
	}

	return &Constraint{
		Type:       constraintType,
		Major:      major,
		Minor:      minor,
		Patch:      patch,
		Prerelease: matches[4], // Capture prerelease suffix
		Raw:        s,
		HasMinor:   hasMinor,
		HasPatch:   hasPatch,
	}, nil
}

// ParseVersion parses a semantic version string.
func ParseVersion(s string) (*Version, error) {
	s = strings.TrimSpace(s)
	matches := versionRegex.FindStringSubmatch(s)
	if matches == nil {
		return nil, fmt.Errorf("invalid version: %q", s)
	}

	// SECURITY: Parse with error checking and enforce maximum to prevent overflow.
	major, err := strconv.Atoi(matches[1])
	if err != nil || major > maxVersionComponent {
		return nil, fmt.Errorf("invalid major version in %q: exceeds maximum", s)
	}

	minor := 0
	patch := 0

	if matches[2] != "" {
		minor, err = strconv.Atoi(matches[2])
		if err != nil || minor > maxVersionComponent {
			return nil, fmt.Errorf("invalid minor version in %q: exceeds maximum", s)
		}
	}
	if matches[3] != "" {
		patch, err = strconv.Atoi(matches[3])
		if err != nil || patch > maxVersionComponent {
			return nil, fmt.Errorf("invalid patch version in %q: exceeds maximum", s)
		}
	}

	return &Version{
		Major:      major,
		Minor:      minor,
		Patch:      patch,
		Prerelease: matches[4],
		Raw:        s,
	}, nil
}

// Matches checks if a version satisfies the constraint.
func (c *Constraint) Matches(v *Version) bool {
	switch c.Type {
	case ConstraintLatest:
		// Latest matches any non-prerelease version
		return v.Prerelease == ""

	case ConstraintExact:
		return v.Major == c.Major && v.Minor == c.Minor && v.Patch == c.Patch && v.Prerelease == c.Prerelease

	case ConstraintCaret:
		return c.matchesCaret(v)

	case ConstraintTilde:
		return c.matchesTilde(v)
	}

	return false
}

// matchesCaret implements caret semantics:
// ^1.2.3 := >=1.2.3 <2.0.0
// ^0.2.3 := >=0.2.3 <0.3.0 (0.x special case)
// ^0.0.3 := >=0.0.3 <0.0.4 (0.0.x special case)
func (c *Constraint) matchesCaret(v *Version) bool {
	// Skip prereleases unless exact match
	if v.Prerelease != "" {
		return false
	}

	// Must be >= constraint version
	if !c.isGreaterOrEqual(v) {
		return false
	}

	// Upper bound depends on leftmost non-zero component
	switch {
	case c.Major != 0:
		// ^1.2.3 -> <2.0.0
		return v.Major == c.Major
	case c.Minor != 0:
		// ^0.2.3 -> <0.3.0
		return v.Major == 0 && v.Minor == c.Minor
	default:
		// ^0.0.3 -> <0.0.4
		return v.Major == 0 && v.Minor == 0 && v.Patch == c.Patch
	}
}

// matchesTilde implements tilde semantics:
// ~1.2.3 := >=1.2.3 <1.3.0
// ~1.2 := >=1.2.0 <1.3.0
// ~1 := >=1.0.0 <2.0.0
func (c *Constraint) matchesTilde(v *Version) bool {
	// Skip prereleases
	if v.Prerelease != "" {
		return false
	}

	// Must be >= constraint version
	if !c.isGreaterOrEqual(v) {
		return false
	}

	// Upper bound: increment the rightmost specified component
	if c.HasPatch || c.HasMinor {
		// ~1.2.3 or ~1.2 -> <1.3.0
		return v.Major == c.Major && v.Minor == c.Minor
	}
	// ~1 -> <2.0.0
	return v.Major == c.Major
}

// isGreaterOrEqual checks if v >= c (as versions).
func (c *Constraint) isGreaterOrEqual(v *Version) bool {
	if v.Major != c.Major {
		return v.Major > c.Major
	}
	if v.Minor != c.Minor {
		return v.Minor > c.Minor
	}
	return v.Patch >= c.Patch
}

// SelectVersion finds the best matching version from a list of release tags.
// Returns the selected version tag.
func SelectVersion(tags []string, constraint *Constraint) (string, error) {
	if constraint.Type == ConstraintExact {
		// For exact constraints, just format and return (including prerelease if present)
		tag := fmt.Sprintf("v%d.%d.%d", constraint.Major, constraint.Minor, constraint.Patch)
		if constraint.Prerelease != "" {
			tag = tag + "-" + constraint.Prerelease
		}
		return tag, nil
	}

	var best *Version
	var bestTag string

	for _, tag := range tags {
		v, err := ParseVersion(tag)
		if err != nil {
			continue // Skip invalid versions
		}

		if !constraint.Matches(v) {
			continue
		}

		if best == nil || isNewer(v, best) {
			best = v
			bestTag = tag
		}
	}

	if best == nil {
		return "", fmt.Errorf("no version matching %s found", constraint.Raw)
	}

	return bestTag, nil
}

// isNewer returns true if a is newer than b.
func isNewer(a, b *Version) bool {
	if a.Major != b.Major {
		return a.Major > b.Major
	}
	if a.Minor != b.Minor {
		return a.Minor > b.Minor
	}
	return a.Patch > b.Patch
}

// NormalizeTag ensures a tag has the "v" prefix.
func NormalizeTag(tag string) string {
	if strings.HasPrefix(tag, "v") {
		return tag
	}
	return "v" + tag
}

// ValidateVersion checks if a version string is safe for use in filesystem paths.
// This prevents path traversal attacks via malicious lockfile version fields.
// Accepts semver-like versions: v1.2.3, v1.2.3-alpha.1, 1.2.3, etc.
// Rejects path separators, dot segments (..), and absolute paths.
//
// This delegates to the centralized validate.Version for consistent security checks.
func ValidateVersion(version string) error {
	return validate.Version(version)
}
