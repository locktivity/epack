package semver

import (
	"strings"
	"testing"
)

// FuzzParseConstraint tests version constraint parsing with fuzzed inputs.
// This helps find edge cases in:
// - Integer overflow in version components
// - ReDoS via regex patterns
// - Prerelease suffix handling
func FuzzParseConstraint(f *testing.F) {
	// Valid constraints
	f.Add("^1.2.3")
	f.Add("~1.2.3")
	f.Add("v1.2.3")
	f.Add("1.2.3")
	f.Add("latest")
	f.Add("LATEST") // case insensitive
	f.Add("^0.0.1")
	f.Add("~0.0.1")
	f.Add("^1.0.0-alpha.1")
	f.Add("v1.2.3-beta.2")

	// Edge cases - partial versions
	f.Add("^1")
	f.Add("~1.2")
	f.Add("v1")

	// Overflow attempts - should be rejected
	f.Add("v999999999.999999999.999999999")
	f.Add("v" + strings.Repeat("9", 20) + ".0.0")
	f.Add("^" + strings.Repeat("9", 15) + ".0.0")

	// Long prerelease
	f.Add("v1.0.0-" + strings.Repeat("a", 500))
	f.Add("v1.0.0-" + strings.Repeat("beta.", 100))

	// Invalid formats
	f.Add("")
	f.Add("   ")
	f.Add("invalid")
	f.Add("v-1.0.0") // negative
	f.Add("v1..0")
	f.Add("v1.2.3.4")
	f.Add(">>1.0.0")

	// Path traversal in prerelease (should be rejected by charset)
	f.Add("v1.0.0-../../../etc")
	f.Add("v1.0.0-foo/bar")
	f.Add("v1.0.0-foo\\bar")

	f.Fuzz(func(t *testing.T, s string) {
		c, err := ParseConstraint(s)

		if err == nil && c != nil {
			// SECURITY: Parsed components must not exceed maxVersionComponent
			if c.Major > maxVersionComponent {
				t.Errorf("SECURITY: major version %d exceeds max %d", c.Major, maxVersionComponent)
			}
			if c.Minor > maxVersionComponent {
				t.Errorf("SECURITY: minor version %d exceeds max %d", c.Minor, maxVersionComponent)
			}
			if c.Patch > maxVersionComponent {
				t.Errorf("SECURITY: patch version %d exceeds max %d", c.Patch, maxVersionComponent)
			}

			// SECURITY: Prerelease must not contain path-unsafe characters
			// The regex should reject /, \, ?, #, % in prerelease
			unsafeChars := []string{"/", "\\", "?", "#", "%"}
			for _, ch := range unsafeChars {
				if strings.Contains(c.Prerelease, ch) {
					t.Errorf("SECURITY: prerelease contains unsafe char %q: %q", ch, c.Prerelease)
				}
			}
		}
	})
}

// FuzzParseVersion tests semantic version parsing with fuzzed inputs.
func FuzzParseVersion(f *testing.F) {
	// Valid versions
	f.Add("v1.2.3")
	f.Add("1.2.3")
	f.Add("v0.0.0")
	f.Add("v1.0.0-alpha")
	f.Add("v1.0.0-alpha.1")
	f.Add("v1.0.0-0.3.7")
	f.Add("v1.0.0-x.7.z.92")

	// Partial versions
	f.Add("v1")
	f.Add("v1.2")

	// Overflow attempts
	f.Add("v" + strings.Repeat("9", 20) + ".0.0")

	// Invalid
	f.Add("")
	f.Add("vvv1.0.0")
	f.Add("v1.0.0+build") // build metadata not supported

	f.Fuzz(func(t *testing.T, s string) {
		v, err := ParseVersion(s)

		if err == nil && v != nil {
			// SECURITY: Components must not exceed maximum
			if v.Major > maxVersionComponent || v.Minor > maxVersionComponent || v.Patch > maxVersionComponent {
				t.Errorf("SECURITY: version component exceeds max: %d.%d.%d", v.Major, v.Minor, v.Patch)
			}

			// Property: Raw should preserve input (trimmed)
			if v.Raw != strings.TrimSpace(s) {
				t.Errorf("Raw mismatch: got %q, want %q", v.Raw, strings.TrimSpace(s))
			}
		}
	})
}

// FuzzValidateVersion tests version validation for filesystem safety.
func FuzzValidateVersion(f *testing.F) {
	// Valid versions
	f.Add("v1.2.3")
	f.Add("v1.0.0-alpha.1")
	f.Add("1.2.3")

	// Path traversal attempts
	f.Add("../../../etc/passwd")
	f.Add("..\\..\\..\\windows\\system32")
	f.Add("v1.0.0/../../../etc")
	f.Add("foo/../bar")
	f.Add("..")
	f.Add(".")

	// Path separators
	f.Add("v1.0.0/evil")
	f.Add("v1.0.0\\evil")

	// Null bytes
	f.Add("v1.0.0\x00evil")

	// Very long versions
	f.Add(strings.Repeat("v1.0.0-", 50))
	f.Add("v1.0.0-" + strings.Repeat("a", 200))

	// Empty
	f.Add("")

	f.Fuzz(func(t *testing.T, s string) {
		err := ValidateVersion(s)

		if err == nil {
			// SECURITY: Validated versions must not contain path traversal
			if strings.Contains(s, "..") {
				t.Errorf("SECURITY: accepted version with path traversal: %q", s)
			}

			// SECURITY: No path separators
			if strings.Contains(s, "/") || strings.Contains(s, "\\") {
				t.Errorf("SECURITY: accepted version with path separator: %q", s)
			}

			// SECURITY: No null bytes
			if strings.Contains(s, "\x00") {
				t.Errorf("SECURITY: accepted version with null byte: %q", s)
			}

			// SECURITY: Length limit enforced
			if len(s) > 128 {
				t.Errorf("SECURITY: accepted version exceeding length limit: %d chars", len(s))
			}

			// Property: Must be valid semver format
			if !versionRegex.MatchString(s) {
				t.Errorf("accepted version that doesn't match regex: %q", s)
			}
		}
	})
}

// FuzzConstraintMatches tests constraint matching logic.
func FuzzConstraintMatches(f *testing.F) {
	// constraint, version pairs
	f.Add("^1.0.0", "v1.2.3")
	f.Add("^1.0.0", "v2.0.0")
	f.Add("~1.2.0", "v1.2.5")
	f.Add("~1.2.0", "v1.3.0")
	f.Add("^0.1.0", "v0.1.5")
	f.Add("^0.1.0", "v0.2.0")
	f.Add("^0.0.1", "v0.0.1")
	f.Add("^0.0.1", "v0.0.2")
	f.Add("latest", "v1.0.0")
	f.Add("latest", "v1.0.0-alpha")
	f.Add("v1.2.3", "v1.2.3")
	f.Add("v1.2.3-alpha", "v1.2.3-alpha")

	f.Fuzz(func(t *testing.T, constraintStr, versionStr string) {
		c, cErr := ParseConstraint(constraintStr)
		v, vErr := ParseVersion(versionStr)

		if cErr != nil || vErr != nil {
			return // Skip invalid inputs
		}

		// Just verify no panic - matching logic is complex
		_ = c.Matches(v)

		// Property: Exact constraints should match exactly
		if c.Type == ConstraintExact && c.Matches(v) {
			if c.Major != v.Major || c.Minor != v.Minor || c.Patch != v.Patch {
				t.Errorf("exact constraint matched different version: %+v vs %+v", c, v)
			}
		}

		// Property: Latest should not match prereleases
		if c.Type == ConstraintLatest && c.Matches(v) && v.Prerelease != "" {
			t.Errorf("latest matched prerelease: %q", v.Prerelease)
		}
	})
}

// FuzzSelectVersion tests version selection from a list of tags.
func FuzzSelectVersion(f *testing.F) {
	f.Add("^1.0.0", "v1.0.0,v1.1.0,v1.2.0,v2.0.0")
	f.Add("~1.1.0", "v1.0.0,v1.1.0,v1.1.5,v1.2.0")
	f.Add("latest", "v1.0.0,v2.0.0-alpha,v1.5.0")
	f.Add("v1.2.3", "v1.0.0,v1.2.3,v2.0.0")

	f.Fuzz(func(t *testing.T, constraintStr, tagsStr string) {
		c, err := ParseConstraint(constraintStr)
		if err != nil {
			return
		}

		tags := strings.Split(tagsStr, ",")
		if len(tags) == 0 || (len(tags) == 1 && tags[0] == "") {
			return
		}

		selected, err := SelectVersion(tags, c)
		if err != nil {
			return // No matching version found - that's fine
		}

		// Property: Selected version should match constraint
		v, vErr := ParseVersion(selected)
		if vErr != nil {
			t.Errorf("SelectVersion returned unparseable version: %q", selected)
			return
		}

		if !c.Matches(v) {
			t.Errorf("SelectVersion returned non-matching version: constraint=%q, selected=%q", constraintStr, selected)
		}
	})
}
