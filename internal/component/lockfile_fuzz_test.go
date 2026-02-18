package component

import (
	"strings"
	"testing"

	"github.com/locktivity/epack/internal/component/lockfile"
)

// FuzzParseLockFile tests lockfile YAML parsing with fuzzed inputs.
// This helps find edge cases in security-critical lockfile validation,
// including YAML alias bomb detection and path traversal prevention.
func FuzzParseLockFile(f *testing.F) {
	// Seed with valid lockfile
	f.Add([]byte(`schema_version: 1
collectors:
  audit:
    source: owner/repo
    version: v1.0.0
    platforms:
      linux/amd64:
        digest: sha256:abc123def456
`))

	// Seed with tools section
	f.Add([]byte(`schema_version: 1
collectors:
  scanner:
    source: locktivity/scanner
    version: v2.0.0
    signer:
      issuer: https://token.actions.githubusercontent.com
      subject: repo:locktivity/scanner:ref:refs/tags/v2.0.0
      source_repository_uri: https://github.com/locktivity/scanner
      source_repository_ref: refs/tags/v2.0.0
    platforms:
      linux/amd64:
        digest: sha256:abcdef123456
      darwin/arm64:
        digest: sha256:654321fedcba
tools:
  ai:
    source: locktivity/epack-tool-ai
    version: v1.0.0
    platforms:
      linux/amd64:
        digest: sha256:tooldigest123
`))

	// Seed with external collector (no version required)
	f.Add([]byte(`schema_version: 1
collectors:
  custom:
    kind: external
    platforms:
      linux/amd64:
        digest: sha256:externaldigest
`))

	// Seed with YAML alias pattern (potential bomb)
	f.Add([]byte(`schema_version: 1
a: &a [1,2]
b: &b [*a,*a]
c: &c [*b,*b]
collectors:
  test:
    source: test/repo
    version: v1.0.0
    platforms:
      linux/amd64:
        digest: sha256:abc
`))

	// Seed with deep alias chain
	f.Add([]byte(`schema_version: 1
base: &base
  digest: sha256:abc123
collectors:
  test:
    source: test/repo
    version: v1.0.0
    platforms:
      linux/amd64:
        <<: *base
`))

	// Seed with many aliases (bomb pattern)
	var manyAliases strings.Builder
	manyAliases.WriteString("schema_version: 1\n")
	manyAliases.WriteString("base: &base [1]\n")
	for i := 0; i < 50; i++ {
		manyAliases.WriteString("item" + string(rune('a'+i%26)) + ": *base\n")
	}
	manyAliases.WriteString("collectors:\n  test:\n    source: t/r\n    version: v1\n    platforms:\n      linux/amd64:\n        digest: sha256:x\n")
	f.Add([]byte(manyAliases.String()))

	// Seed with path traversal attempts in collector names
	f.Add([]byte(`schema_version: 1
collectors:
  "../etc/passwd":
    source: evil/repo
    version: v1.0.0
    platforms:
      linux/amd64:
        digest: sha256:evil
`))

	// Seed with control characters in names
	f.Add([]byte("schema_version: 1\ncollectors:\n  test\x00evil:\n    source: t/r\n    version: v1\n    platforms:\n      linux/amd64:\n        digest: sha256:x\n"))

	// Seed with very long collector name
	f.Add([]byte("schema_version: 1\ncollectors:\n  " + strings.Repeat("a", 500) + ":\n    source: t/r\n    version: v1\n    platforms:\n      linux/amd64:\n        digest: sha256:x\n"))

	// Seed with many collectors (DoS pattern)
	var manyCollectors strings.Builder
	manyCollectors.WriteString("schema_version: 1\ncollectors:\n")
	for i := 0; i < 100; i++ {
		manyCollectors.WriteString("  collector" + string(rune('a'+i%26)) + string(rune('0'+i/26)) + ":\n")
		manyCollectors.WriteString("    source: owner/repo\n")
		manyCollectors.WriteString("    version: v1.0.0\n")
		manyCollectors.WriteString("    platforms:\n")
		manyCollectors.WriteString("      linux/amd64:\n")
		manyCollectors.WriteString("        digest: sha256:abc\n")
	}
	f.Add([]byte(manyCollectors.String()))

	// Seed with many platforms per collector
	var manyPlatforms strings.Builder
	manyPlatforms.WriteString("schema_version: 1\ncollectors:\n  test:\n    source: t/r\n    version: v1\n    platforms:\n")
	for i := 0; i < 50; i++ {
		manyPlatforms.WriteString("      platform" + string(rune('a'+i%26)) + "/arch" + string(rune('0'+i/26)) + ":\n")
		manyPlatforms.WriteString("        digest: sha256:abc\n")
	}
	f.Add([]byte(manyPlatforms.String()))

	// Seed with invalid version format
	f.Add([]byte(`schema_version: 1
collectors:
  test:
    source: owner/repo
    version: not-a-semver
    platforms:
      linux/amd64:
        digest: sha256:abc
`))

	// Seed with empty version (should fail for source-based)
	f.Add([]byte(`schema_version: 1
collectors:
  test:
    source: owner/repo
    version: ""
    platforms:
      linux/amd64:
        digest: sha256:abc
`))

	f.Fuzz(func(t *testing.T, data []byte) {
		// ParseLockFile should not panic on any input
		lf, err := lockfile.Parse(data)

		if err == nil && lf != nil {
			// If parsing succeeded, verify security invariants

			// SECURITY: Collector names must not contain path traversal
			for name := range lf.Collectors {
				if strings.Contains(name, "..") {
					t.Errorf("SECURITY: accepted collector name with path traversal: %q", name)
				}
				if strings.Contains(name, "/") || strings.Contains(name, "\\") {
					t.Errorf("SECURITY: accepted collector name with path separator: %q", name)
				}
				// Check for control characters
				for _, r := range name {
					if r < 0x20 || r == 0x7f {
						t.Errorf("SECURITY: accepted collector name with control character: %q", name)
					}
				}
			}

			// SECURITY: Tool names must not contain path traversal
			for name := range lf.Tools {
				if strings.Contains(name, "..") {
					t.Errorf("SECURITY: accepted tool name with path traversal: %q", name)
				}
				if strings.Contains(name, "/") || strings.Contains(name, "\\") {
					t.Errorf("SECURITY: accepted tool name with path separator: %q", name)
				}
				// Check for control characters
				for _, r := range name {
					if r < 0x20 || r == 0x7f {
						t.Errorf("SECURITY: accepted tool name with control character: %q", name)
					}
				}
			}

			// SECURITY: Source-based collectors must have valid versions
			for name, collector := range lf.Collectors {
				if collector.Kind != "external" {
					if collector.Version == "" {
						t.Errorf("SECURITY: source-based collector %q accepted with empty version", name)
					}
				}
			}

			// SECURITY: Source-based tools must have valid versions
			for name, tool := range lf.Tools {
				if tool.Kind != "external" {
					if tool.Version == "" {
						t.Errorf("SECURITY: source-based tool %q accepted with empty version", name)
					}
				}
			}
		}
	})
}

// FuzzCheckLockFileYAMLAliasAbuse tests the lockfile YAML alias bomb detection via ParseLockFile.
// The alias abuse check is called internally by ParseLockFile.
func FuzzCheckLockFileYAMLAliasAbuse(f *testing.F) {
	// Normal YAML with anchors - wrapped in valid lockfile structure
	f.Add([]byte(`
schema_version: 1
base: &base
  key: value
collectors:
  test:
    source: github.com/test/test
    version: v1.0.0
    platforms:
      linux/amd64:
        digest: sha256:1234567890abcdef
`))

	// Potential bomb pattern - wrapped in valid lockfile structure
	f.Add([]byte(`
schema_version: 1
a: &a ["x","x"]
b: &b [*a,*a]
c: &c [*b,*b]
d: &d [*c,*c]
collectors:
  test:
    source: github.com/test/test
    version: v1.0.0
    platforms:
      linux/amd64:
        digest: sha256:1234567890abcdef
`))

	// Exponential expansion pattern
	f.Add([]byte(`
schema_version: 1
a: &a [1,2,3,4,5,6,7,8,9,0]
b: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a,*a]
c: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b,*b]
collectors:
  test:
    source: github.com/test/test
    version: v1.0.0
    platforms:
      linux/amd64:
        digest: sha256:1234567890abcdef
`))

	// Many aliases to single anchor
	var manyAliases strings.Builder
	manyAliases.WriteString("schema_version: 1\nbase: &base [1]\ncollectors:\n  test:\n    source: github.com/test/test\n    version: v1.0.0\n    platforms:\n      linux/amd64:\n        digest: sha256:1234\n")
	for i := 0; i < 100; i++ {
		manyAliases.WriteString("item" + string(rune('a'+i%26)) + string(rune('0'+i/26)) + ": *base\n")
	}
	f.Add([]byte(manyAliases.String()))

	// Deep nesting with aliases
	f.Add([]byte(`
schema_version: 1
a: &a [1]
b: &b [*a]
c: &c [*b]
d: &d [*c]
e: &e [*d]
f: &f [*e]
g: &g [*f]
h: &h [*g]
i: &i [*h]
j: &j [*i]
collectors:
  test:
    source: github.com/test/test
    version: v1.0.0
    platforms:
      linux/amd64:
        digest: sha256:1234567890abcdef
`))

	f.Fuzz(func(t *testing.T, data []byte) {
		// ParseLockFile calls checkLockFileYAMLAliasAbuse internally and should not panic
		_, _ = lockfile.Parse(data)
	})
}
