package yamlpolicy

import (
	"testing"

	"github.com/locktivity/epack/internal/limits"
)

// FuzzValidateBeforeParse tests the YAML validation with adversarial inputs.
//
// This fuzz test specifically targets:
// - Alias bomb detection bypass attempts
// - Size limit boundary conditions
// - Malformed YAML that could crash the parser
// - Unicode edge cases in YAML syntax
func FuzzValidateBeforeParse(f *testing.F) {
	// Seed corpus with interesting YAML patterns

	// Normal YAML
	f.Add([]byte("key: value"))
	f.Add([]byte("list:\n  - item1\n  - item2"))

	// Simple anchors and aliases (valid)
	f.Add([]byte("a: &anchor value\nb: *anchor"))
	f.Add([]byte("defaults: &defaults\n  timeout: 30\nproduction:\n  <<: *defaults"))

	// Potential alias bombs (should be detected)
	f.Add([]byte("a: &a [x,x]\nb: &b [*a,*a]\nc: &c [*b,*b]\nd: &d [*c,*c]"))
	f.Add([]byte("a: &a {x: 1}\nb: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a,*a]"))

	// Self-referential (parser should handle)
	f.Add([]byte("a: &a\n  b: *a"))

	// Many anchors, few aliases (should pass)
	f.Add([]byte("a: &a 1\nb: &b 2\nc: &c 3\nd: &d 4\ne: *a"))

	// Edge cases
	f.Add([]byte(""))                      // empty
	f.Add([]byte("---"))                   // document marker only
	f.Add([]byte("null"))                  // null document
	f.Add([]byte("~"))                     // tilde null
	f.Add([]byte("---\n...\n---\nkey: v")) // multiple documents

	// Unicode in keys/values
	f.Add([]byte("键: 值"))
	f.Add([]byte("emoji: 🔐"))

	// Deeply nested structures
	f.Add([]byte("a:\n  b:\n    c:\n      d:\n        e: deep"))

	// Binary/special characters
	f.Add([]byte("binary: !!binary R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7"))

	// Multiline strings
	f.Add([]byte("text: |\n  line1\n  line2\n  line3"))
	f.Add([]byte("text: >\n  folded\n  text"))

	// Very long keys/values (within limits)
	longKey := make([]byte, 1000)
	for i := range longKey {
		longKey[i] = 'a'
	}
	f.Add(append(longKey, []byte(": value")...))

	f.Fuzz(func(t *testing.T, data []byte) {
		// The function should never panic
		// Errors are expected for malformed input - that's fine
		_ = ValidateBeforeParse(data, limits.ConfigFile.Bytes())

		// Also test with smaller size limits
		_ = ValidateBeforeParse(data, 1024)
		_ = ValidateBeforeParse(data, 100)
	})
}

// FuzzCheckAliasAbuse specifically targets the alias bomb detection.
func FuzzCheckAliasAbuse(f *testing.F) {
	// Focus on alias/anchor patterns

	// Valid patterns
	f.Add([]byte("a: &ref value\nb: *ref"))

	// Escalating alias bombs
	f.Add([]byte("a: &a [1]\nb: &b [*a,*a]"))
	f.Add([]byte("a: &a [1]\nb: &b [*a,*a]\nc: &c [*b,*b]"))
	f.Add([]byte("a: &a [1]\nb: &b [*a,*a]\nc: &c [*b,*b]\nd: &d [*c,*c]"))

	// Many aliases to single anchor
	f.Add([]byte("a: &a 1\nb: [*a,*a,*a,*a,*a,*a,*a,*a,*a,*a,*a,*a]"))

	// Merge key bombs
	f.Add([]byte("a: &a {x: 1}\nb: &b\n  <<: *a\n  <<: *a"))

	// Anchor in sequence
	f.Add([]byte("- &a x\n- *a\n- *a\n- *a"))

	// Complex nesting with aliases
	f.Add([]byte("root:\n  a: &a\n    nested: value\n  b: *a\n  c: *a"))

	f.Fuzz(func(t *testing.T, data []byte) {
		// Should never panic
		_ = CheckAliasAbuse(data)
	})
}
