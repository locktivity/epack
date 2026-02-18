package component

import (
	"testing"

	"github.com/locktivity/epack/internal/component/semver"
)

func TestParseConstraint(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		wantType   semver.ConstraintType
		wantMaj    int
		wantMin    int
		wantPat    int
		wantPrerel string
		wantErr    bool
	}{
		{"exact with v", "v1.2.3", semver.ConstraintExact, 1, 2, 3, "", false},
		{"exact without v", "1.2.3", semver.ConstraintExact, 1, 2, 3, "", false},
		{"exact with prerelease", "v1.2.3-beta.1", semver.ConstraintExact, 1, 2, 3, "beta.1", false},
		{"exact with prerelease no v", "1.2.3-rc.2", semver.ConstraintExact, 1, 2, 3, "rc.2", false},
		{"caret", "^1.2.3", semver.ConstraintCaret, 1, 2, 3, "", false},
		{"tilde", "~1.2.3", semver.ConstraintTilde, 1, 2, 3, "", false},
		{"latest", "latest", semver.ConstraintLatest, 0, 0, 0, "", false},
		{"LATEST", "LATEST", semver.ConstraintLatest, 0, 0, 0, "", false},
		{"caret partial", "^1.2", semver.ConstraintCaret, 1, 2, 0, "", false},
		{"tilde partial", "~1", semver.ConstraintTilde, 1, 0, 0, "", false},
		{"zero major", "^0.2.3", semver.ConstraintCaret, 0, 2, 3, "", false},
		{"empty", "", 0, 0, 0, 0, "", true},
		{"invalid", "not-a-version", 0, 0, 0, 0, "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := semver.ParseConstraint(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("semver.ParseConstraint(%q) expected error, got nil", tt.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("semver.ParseConstraint(%q) unexpected error: %v", tt.input, err)
			}
			if c.Type != tt.wantType {
				t.Errorf("Type = %v, want %v", c.Type, tt.wantType)
			}
			if c.Major != tt.wantMaj {
				t.Errorf("Major = %d, want %d", c.Major, tt.wantMaj)
			}
			if c.Minor != tt.wantMin {
				t.Errorf("Minor = %d, want %d", c.Minor, tt.wantMin)
			}
			if c.Patch != tt.wantPat {
				t.Errorf("Patch = %d, want %d", c.Patch, tt.wantPat)
			}
			if c.Prerelease != tt.wantPrerel {
				t.Errorf("Prerelease = %q, want %q", c.Prerelease, tt.wantPrerel)
			}
		})
	}
}

func TestParseVersion(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		wantMaj    int
		wantMin    int
		wantPat    int
		wantPrerel string
		wantErr    bool
	}{
		{"standard", "v1.2.3", 1, 2, 3, "", false},
		{"without v", "1.2.3", 1, 2, 3, "", false},
		{"with prerelease", "v1.2.3-beta.1", 1, 2, 3, "beta.1", false},
		{"partial major only", "v1", 1, 0, 0, "", false},
		{"partial major.minor", "v1.2", 1, 2, 0, "", false},
		{"zero version", "v0.0.0", 0, 0, 0, "", false},
		{"invalid", "not-version", 0, 0, 0, "", true},
		{"empty", "", 0, 0, 0, "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, err := semver.ParseVersion(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("ParseVersion(%q) expected error, got nil", tt.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseVersion(%q) unexpected error: %v", tt.input, err)
			}
			if v.Major != tt.wantMaj {
				t.Errorf("Major = %d, want %d", v.Major, tt.wantMaj)
			}
			if v.Minor != tt.wantMin {
				t.Errorf("Minor = %d, want %d", v.Minor, tt.wantMin)
			}
			if v.Patch != tt.wantPat {
				t.Errorf("Patch = %d, want %d", v.Patch, tt.wantPat)
			}
			if v.Prerelease != tt.wantPrerel {
				t.Errorf("Prerelease = %q, want %q", v.Prerelease, tt.wantPrerel)
			}
		})
	}
}

// TestParseVersionRejectsOverflow verifies that extremely large version numbers
// are rejected to prevent integer overflow on 32-bit systems.
// SECURITY REGRESSION TEST: Ensures version components that exceed maxVersionComponent
// are rejected instead of silently overflowing.
func TestParseVersionRejectsOverflow(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"overflow_major", "v99999999999999999999.0.0"},
		{"overflow_minor", "v1.99999999999999999999.0"},
		{"overflow_patch", "v1.0.99999999999999999999"},
		{"exceeds_max_major", "v1000000000.0.0"},
		{"exceeds_max_minor", "v1.1000000000.0"},
		{"exceeds_max_patch", "v1.0.1000000000"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := semver.ParseVersion(tt.input)
			if err == nil {
				t.Errorf("ParseVersion(%q) should have failed for overflow, but succeeded", tt.input)
			}
		})
	}
}

// TestParseConstraintRejectsOverflow verifies constraint parsing also rejects overflow.
func TestParseConstraintRejectsOverflow(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"overflow_major", "^99999999999999999999.0.0"},
		{"overflow_minor", "~1.99999999999999999999.0"},
		{"overflow_patch", "v1.0.99999999999999999999"},
		{"exceeds_max_major", "^1000000000.0.0"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := semver.ParseConstraint(tt.input)
			if err == nil {
				t.Errorf("semver.ParseConstraint(%q) should have failed for overflow, but succeeded", tt.input)
			}
		})
	}
}

func TestConstraintMatches(t *testing.T) {
	tests := []struct {
		name       string
		constraint string
		version    string
		want       bool
	}{
		// Exact match
		{"exact match", "v1.2.3", "v1.2.3", true},
		{"exact mismatch patch", "v1.2.3", "v1.2.4", false},
		{"exact mismatch minor", "v1.2.3", "v1.3.3", false},
		{"exact mismatch major", "v1.2.3", "v2.2.3", false},
		// Exact match with prerelease
		{"exact prerelease match", "v1.2.3-beta.1", "v1.2.3-beta.1", true},
		{"exact prerelease mismatch", "v1.2.3-beta.1", "v1.2.3-beta.2", false},
		{"exact prerelease vs stable", "v1.2.3-beta.1", "v1.2.3", false},
		{"exact stable vs prerelease", "v1.2.3", "v1.2.3-beta.1", false},

		// Caret (^) - compatible changes
		{"caret same version", "^1.2.3", "v1.2.3", true},
		{"caret newer patch", "^1.2.3", "v1.2.5", true},
		{"caret newer minor", "^1.2.3", "v1.5.0", true},
		{"caret newer major fails", "^1.2.3", "v2.0.0", false},
		{"caret older patch fails", "^1.2.3", "v1.2.2", false},
		{"caret prerelease fails", "^1.2.3", "v1.2.4-beta", false},

		// Caret 0.x special case
		{"caret 0.x same", "^0.2.3", "v0.2.3", true},
		{"caret 0.x newer patch", "^0.2.3", "v0.2.5", true},
		{"caret 0.x newer minor fails", "^0.2.3", "v0.3.0", false},
		{"caret 0.0.x same", "^0.0.3", "v0.0.3", true},
		{"caret 0.0.x newer patch fails", "^0.0.3", "v0.0.4", false},

		// Tilde (~) - patch-level changes
		{"tilde same version", "~1.2.3", "v1.2.3", true},
		{"tilde newer patch", "~1.2.3", "v1.2.9", true},
		{"tilde newer minor fails", "~1.2.3", "v1.3.0", false},
		{"tilde older patch fails", "~1.2.3", "v1.2.2", false},

		// Tilde partial
		{"tilde partial major.minor", "~1.2", "v1.2.0", true},
		{"tilde partial major.minor newer patch", "~1.2", "v1.2.5", true},
		{"tilde partial major.minor newer minor fails", "~1.2", "v1.3.0", false},
		{"tilde partial major only", "~1", "v1.0.0", true},
		{"tilde partial major newer minor", "~1", "v1.5.0", true},
		{"tilde partial major newer major fails", "~1", "v2.0.0", false},

		// Latest
		{"latest matches any", "latest", "v5.0.0", true},
		{"latest matches zero", "latest", "v0.0.1", true},
		{"latest skips prerelease", "latest", "v1.0.0-alpha", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := semver.ParseConstraint(tt.constraint)
			if err != nil {
				t.Fatalf("semver.ParseConstraint(%q) error: %v", tt.constraint, err)
			}
			v, err := semver.ParseVersion(tt.version)
			if err != nil {
				t.Fatalf("ParseVersion(%q) error: %v", tt.version, err)
			}
			if got := c.Matches(v); got != tt.want {
				t.Errorf("Constraint(%q).Matches(%q) = %v, want %v", tt.constraint, tt.version, got, tt.want)
			}
		})
	}
}

func TestSelectVersion(t *testing.T) {
	tags := []string{"v1.0.0", "v1.1.0", "v1.2.0", "v1.2.1", "v2.0.0", "v2.1.0-beta"}

	tests := []struct {
		name       string
		constraint string
		want       string
		wantErr    bool
	}{
		{"exact found", "v1.1.0", "v1.1.0", false},
		{"exact with prerelease", "v2.1.0-beta", "v2.1.0-beta", false},
		{"caret selects highest compatible", "^1.0.0", "v1.2.1", false},
		{"tilde selects highest in minor", "~1.2.0", "v1.2.1", false},
		{"latest selects highest non-prerelease", "latest", "v2.0.0", false},
		{"no match", "^3.0.0", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := semver.ParseConstraint(tt.constraint)
			if err != nil {
				t.Fatalf("semver.ParseConstraint(%q) error: %v", tt.constraint, err)
			}
			got, err := semver.SelectVersion(tags, c)
			if tt.wantErr {
				if err == nil {
					t.Errorf("SelectVersion() expected error, got %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("SelectVersion() error: %v", err)
			}
			if got != tt.want {
				t.Errorf("SelectVersion() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestNormalizeTag(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"v1.0.0", "v1.0.0"},
		{"1.0.0", "v1.0.0"},
		{"v0.1.0", "v0.1.0"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := semver.NormalizeTag(tt.input); got != tt.want {
				t.Errorf("NormalizeTag(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// Regression test: Version regex must reject URL-unsafe characters in prerelease.
// SECURITY: Prerelease strings like "beta/../../repos/victim/repo" could be used
// in GitHub API URLs to perform path injection attacks if not properly validated.
// The version regex now restricts prerelease to [a-zA-Z0-9][a-zA-Z0-9.-]* only.
func TestVersionRegex_RejectsURLUnsafeCharacters(t *testing.T) {
	// SECURITY REGRESSION TEST: versionRegex must reject URL-unsafe characters.
	// This test documents the fix for: Version constraint path/query smuggling
	// where a lockfile.yaml could contain malicious versions like:
	//   version: "v1.0.0-../../repos/victim/repo"
	// which would manipulate GitHub API request paths.

	// Characters that MUST be rejected in prerelease strings
	unsafeVersions := []string{
		// Path traversal attempts
		"v1.0.0-../evil",
		"v1.0.0-foo/../bar",
		"v1.0.0-..%2F..%2Fetc%2Fpasswd",

		// URL path injection
		"v1.0.0-beta/../../repos/victim/repo",
		"v1.0.0-/repos/other/repo",

		// Query string injection
		"v1.0.0-beta?access_token=steal",
		"v1.0.0-beta#fragment",

		// URL-encoded characters
		"v1.0.0-beta%2Fmalicious",
		"v1.0.0-%00null",

		// Backslash (Windows path)
		"v1.0.0-beta\\evil",

		// Other dangerous characters
		"v1.0.0-beta:evil",
		"v1.0.0-beta@evil",
		"v1.0.0-beta;cmd",
		"v1.0.0-beta|pipe",
		"v1.0.0-beta<tag>",
		"v1.0.0-beta`backtick`",
		"v1.0.0-beta'quote",
		`v1.0.0-beta"dquote`,
		"v1.0.0-beta evil",  // space
		"v1.0.0-beta\tevil", // tab
		"v1.0.0-beta\nevil", // newline
	}

	for _, version := range unsafeVersions {
		t.Run(version, func(t *testing.T) {
			_, err := semver.ParseVersion(version)
			if err == nil {
				t.Errorf("SECURITY REGRESSION: ParseVersion(%q) should reject URL-unsafe characters in prerelease", version)
			}

			_, err = semver.ParseConstraint(version)
			if err == nil {
				t.Errorf("SECURITY REGRESSION: semver.ParseConstraint(%q) should reject URL-unsafe characters in prerelease", version)
			}
		})
	}
}

// Regression test: ValidateVersion must reject path traversal and URL-unsafe chars.
func TestValidateVersion_RejectsPathTraversal(t *testing.T) {
	// SECURITY REGRESSION TEST: ValidateVersion must catch attempts to use
	// version strings for path traversal when versions are used in filesystem paths.

	unsafeVersions := []string{
		// Path separators
		"v1.0.0/evil",
		"v1.0.0\\evil",

		// Dot segments
		"..",
		".",
		"../etc/passwd",
		"..\\windows\\system32",
		"v1.0.0/../../../etc/passwd",

		// Path traversal embedded
		"v1.0.0-/../evil",
	}

	for _, version := range unsafeVersions {
		t.Run(version, func(t *testing.T) {
			err := semver.ValidateVersion(version)
			if err == nil {
				t.Errorf("SECURITY REGRESSION: ValidateVersion(%q) should reject path traversal attempts", version)
			}
		})
	}
}

// Test that safe prerelease strings ARE accepted.
func TestVersionRegex_AcceptsSafePrerelease(t *testing.T) {
	// These prerelease strings should be accepted (only alphanumeric, hyphens, dots)
	safeVersions := []string{
		"v1.0.0-alpha",
		"v1.0.0-beta.1",
		"v1.0.0-rc.2",
		"v1.0.0-alpha.beta.gamma",
		"v1.0.0-0.3.7",
		"v1.0.0-x.7.z.92",
		"v1.0.0-alpha-1",
		"v1.0.0-alpha.1-beta.2",
		"v1.0.0-20240101",
		"v1.0.0-sha.abcdef0",
	}

	for _, version := range safeVersions {
		t.Run(version, func(t *testing.T) {
			v, err := semver.ParseVersion(version)
			if err != nil {
				t.Errorf("ParseVersion(%q) should accept safe prerelease: %v", version, err)
			}
			if v == nil {
				t.Errorf("ParseVersion(%q) returned nil", version)
			}
		})
	}
}
