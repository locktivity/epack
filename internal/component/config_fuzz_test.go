package component

import (
	"strings"
	"testing"

	"github.com/locktivity/epack/internal/component/config"
)

// FuzzParseConfig tests YAML config parsing with fuzzed inputs.
// This helps find edge cases in security-critical config validation.
func FuzzParseConfig(f *testing.F) {
	// Seed with valid configs
	f.Add([]byte(`
stream: test/prod
collectors:
  audit:
    source: locktivity/audit-collector@v1.0.0
`))

	f.Add([]byte(`
stream: myorg/prod
collectors:
  scanner:
    binary: /usr/local/bin/scanner
    secrets:
      - API_KEY
tools:
  ai:
    source: locktivity/epack-tool-ai@v1.0.0
`))

	// Seed with edge cases - large numbers of collectors
	var manyCollectors strings.Builder
	manyCollectors.WriteString("stream: test\ncollectors:\n")
	for i := 0; i < 100; i++ {
		manyCollectors.WriteString("  collector" + string(rune('a'+i%26)) + ":\n")
		manyCollectors.WriteString("    source: owner/repo@v1.0.0\n")
	}
	f.Add([]byte(manyCollectors.String()))

	// Seed with YAML alias patterns (potential bombs)
	f.Add([]byte(`
stream: test
base: &base
  key: value
collectors:
  a:
    source: test@v1
    config:
      <<: *base
`))

	// Seed with suspicious alias patterns
	f.Add([]byte(`
stream: test
a: &a [1,2]
b: &b [*a,*a]
c: &c [*b,*b]
collectors:
  test:
    source: test@v1
`))

	// Seed with reserved secret names (should be rejected)
	f.Add([]byte(`
stream: test
collectors:
  test:
    source: test@v1
    secrets:
      - EPACK_SECRET
      - LD_PRELOAD
      - PATH
`))

	// Seed with path traversal attempts in names
	f.Add([]byte(`
stream: test
collectors:
  "../etc/passwd":
    source: test@v1
`))

	// Seed with control characters
	f.Add([]byte("stream: test\ncollectors:\n  test\x00evil:\n    source: test@v1\n"))

	// Seed with very long strings
	f.Add([]byte("stream: " + strings.Repeat("a", 10000) + "\ncollectors:\n  test:\n    source: test@v1\n"))

	f.Fuzz(func(t *testing.T, data []byte) {
		// config.Parse should not panic on any input
		cfg, err := config.Parse(data)

		if err == nil && cfg != nil {
			// If parsing succeeded, verify security invariants

			// SECURITY: Collector names must not contain path traversal
			for name := range cfg.Collectors {
				if strings.Contains(name, "..") {
					t.Errorf("SECURITY: accepted collector name with path traversal: %q", name)
				}
				if strings.Contains(name, "/") || strings.Contains(name, "\\") {
					t.Errorf("SECURITY: accepted collector name with path separator: %q", name)
				}
			}

			// SECURITY: Tool names must not contain path traversal
			for name := range cfg.Tools {
				if strings.Contains(name, "..") {
					t.Errorf("SECURITY: accepted tool name with path traversal: %q", name)
				}
				if strings.Contains(name, "/") || strings.Contains(name, "\\") {
					t.Errorf("SECURITY: accepted tool name with path separator: %q", name)
				}
			}

			// SECURITY: Secret names must not include reserved prefixes
			reservedPrefixes := []string{"EPACK_", "LD_", "DYLD_", "_"}
			for _, collector := range cfg.Collectors {
				for _, secret := range collector.Secrets {
					for _, prefix := range reservedPrefixes {
						if strings.HasPrefix(strings.ToUpper(secret), prefix) {
							t.Errorf("SECURITY: accepted reserved secret name: %q", secret)
						}
					}
				}
			}
			for _, tool := range cfg.Tools {
				for _, secret := range tool.Secrets {
					for _, prefix := range reservedPrefixes {
						if strings.HasPrefix(strings.ToUpper(secret), prefix) {
							t.Errorf("SECURITY: accepted reserved secret name: %q", secret)
						}
					}
				}
			}
		}
	})
}

// FuzzCheckYAMLAliasAbuse tests the YAML alias bomb detection via config.Parse.
// The alias abuse check is called internally by config.Parse.
func FuzzCheckYAMLAliasAbuse(f *testing.F) {
	// Normal YAML with anchors - wrapped in valid config structure
	f.Add([]byte(`
stream: test
base: &base
  key: value
collectors:
  test:
    source: test@v1
    config:
      <<: *base
`))

	// Potential bomb pattern - wrapped in valid config structure
	f.Add([]byte(`
stream: test
a: &a ["x","x"]
b: &b [*a,*a]
c: &c [*b,*b]
d: &d [*c,*c]
collectors:
  test:
    source: test@v1
`))

	// Many aliases - wrapped in valid config structure
	var manyAliases strings.Builder
	manyAliases.WriteString("stream: test\nbase: &base [1]\ncollectors:\n  test:\n    source: test@v1\n")
	for i := 0; i < 50; i++ {
		manyAliases.WriteString("item" + string(rune('a'+i%26)) + ": *base\n")
	}
	f.Add([]byte(manyAliases.String()))

	// Deep nesting - wrapped in valid config structure
	f.Add([]byte(`
stream: test
a: &a [1]
b: &b [*a]
c: &c [*b]
d: &d [*c]
e: &e [*d]
f: &f [*e]
g: &g [*f]
h: &h [*g]
collectors:
  test:
    source: test@v1
`))

	f.Fuzz(func(t *testing.T, data []byte) {
		// config.Parse calls checkYAMLAliasAbuse internally and should not panic
		_, err := config.Parse(data)

		// If no error, verify the data doesn't have suspicious patterns
		// that should have been caught
		if err == nil {
			// Count anchors and aliases manually
			anchors := strings.Count(string(data), "&")
			aliases := strings.Count(string(data), "*")

			// If there are many more aliases than anchors, it should be rejected
			// (unless the YAML is invalid and couldn't be parsed)
			if anchors > 0 && aliases > anchors*100 {
				// This is suspicious - verify it's actually invalid YAML
				// that couldn't be parsed rather than a bypass
				t.Logf("high alias:anchor ratio (%d:%d) was allowed - verify YAML validity",
					aliases, anchors)
			}
		}
	})
}
