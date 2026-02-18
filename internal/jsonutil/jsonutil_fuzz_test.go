package jsonutil

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/locktivity/epack/errors"
)

// =============================================================================
// FUZZ TESTS FOR JSON DUPLICATE KEY DETECTION
// =============================================================================
// These fuzz tests target the security-critical JSON parsing code that
// detects duplicate keys. Duplicate keys can lead to predicate shadowing
// attacks where an attacker includes multiple values for the same key.

// FuzzValidateNoDuplicateKeys tests the duplicate key detection logic.
func FuzzValidateNoDuplicateKeys(f *testing.F) {
	// Seed with valid JSON
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"a":1}`))
	f.Add([]byte(`{"a":1,"b":2}`))
	f.Add([]byte(`{"a":{"b":1}}`))
	f.Add([]byte(`{"a":[1,2,3]}`))
	f.Add([]byte(`[]`))
	f.Add([]byte(`[1,2,3]`))
	f.Add([]byte(`[{"a":1},{"b":2}]`))
	f.Add([]byte(`null`))
	f.Add([]byte(`true`))
	f.Add([]byte(`false`))
	f.Add([]byte(`"string"`))
	f.Add([]byte(`123`))
	f.Add([]byte(`123.456`))

	// Seed with duplicate keys at various levels
	f.Add([]byte(`{"a":1,"a":2}`))                                           // Simple duplicate
	f.Add([]byte(`{"a":{"b":1,"b":2}}`))                                     // Nested duplicate
	f.Add([]byte(`{"a":1,"b":2,"a":3}`))                                     // Non-adjacent duplicate
	f.Add([]byte(`{"a":{"x":1},"a":{"y":2}}`))                               // Duplicate with object values
	f.Add([]byte(`{"a":[1],"a":[2]}`))                                       // Duplicate with array values
	f.Add([]byte(`[{"a":1,"a":2}]`))                                         // Duplicate inside array
	f.Add([]byte(`{"a":{"b":{"c":1,"c":2}}}`))                               // Deeply nested duplicate
	f.Add([]byte(`{"a":1,"A":2}`))                                           // Case-sensitive keys (not duplicates)
	f.Add([]byte(`{"":1,"":2}`))                                             // Empty string key duplicate
	f.Add([]byte(`{"\u0061":1,"a":2}`))                                      // Unicode escape duplicate
	f.Add([]byte(`{"a":1,"a":2,"a":3}`))                                     // Triple duplicate
	f.Add([]byte(`{"x":{"a":1},"y":{"a":1}}`))                               // Same key in different objects (OK)
	f.Add([]byte(`{"a":{"b":1,"c":2},"a":{"d":3}}`))                         // Duplicate with nested content
	f.Add([]byte(`{"pack_digest":"sha256:abc","pack_digest":"sha256:def"}`)) // Attack pattern

	// Seed with invalid JSON
	f.Add([]byte(`{`))
	f.Add([]byte(`}`))
	f.Add([]byte(`{a:1}`))           // Unquoted key
	f.Add([]byte(`{"a":}`))          // Missing value
	f.Add([]byte(`{"a":1,}`))        // Trailing comma
	f.Add([]byte(`{,}`))             // Empty with comma
	f.Add([]byte(`{"a"}`))           // Missing colon and value
	f.Add([]byte(`{"a":1"b":2}`))    // Missing comma
	f.Add([]byte(`{"a":1,,,"b":2}`)) // Multiple commas
	f.Add([]byte(`[}`))              // Mismatched brackets
	f.Add([]byte(`{]`))              // Mismatched brackets
	f.Add([]byte(``))                // Empty
	f.Add([]byte(`   `))             // Whitespace only
	f.Add([]byte(`{"a":undefined}`)) // JavaScript undefined
	f.Add([]byte(`{"a":NaN}`))       // NaN
	f.Add([]byte(`{"a":Infinity}`))  // Infinity
	f.Add([]byte(`{'a':1}`))         // Single quotes
	f.Add([]byte(`{/* comment */}`)) // Comment

	// Seed with edge cases
	f.Add([]byte(`{"a\nb":1}`))                                                  // Newline in key
	f.Add([]byte(`{"a\tb":1}`))                                                  // Tab in key
	f.Add([]byte(`{"a\"b":1}`))                                                  // Quote in key
	f.Add([]byte(`{"a\\b":1}`))                                                  // Backslash in key
	f.Add([]byte(`{"\u0000":1}`))                                                // Null character in key
	f.Add([]byte(`{"😀":1}`))                                                     // Emoji key
	f.Add([]byte(`{"😀":1,"😀":2}`))                                               // Duplicate emoji key
	f.Add([]byte(strings.Repeat(`{"a":`, 100) + `1` + strings.Repeat(`}`, 100))) // Deep nesting

	f.Fuzz(func(t *testing.T, data []byte) {
		err := ValidateNoDuplicateKeys(data)

		// The function should not panic on any input
		// If it returns nil, verify there are no duplicates using alternate method
		if err == nil {
			// Only verify valid UTF-8 JSON (invalid UTF-8 may behave differently)
			if utf8.Valid(data) && json.Valid(data) {
				// Cross-check: if we accepted it, ensure no duplicates exist
				hasDuplicates := checkForDuplicatesManually(data)
				if hasDuplicates {
					t.Errorf("SECURITY: ValidateNoDuplicateKeys accepted JSON with duplicate keys: %s", string(data))
				}
			}
		} else {
			// If error returned, verify error code is appropriate
			code := errors.CodeOf(err)
			if code != "" && code != errors.DuplicateKeys && code != errors.InvalidJSON {
				t.Errorf("unexpected error code %q for input %q", code, string(data))
			}
		}
	})
}

// FuzzDecodeStrict tests the strict decoder that combines duplicate detection with parsing.
func FuzzDecodeStrict(f *testing.F) {
	// Simple valid objects
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"name":"test"}`))
	f.Add([]byte(`{"count":123}`))
	f.Add([]byte(`{"flag":true}`))
	f.Add([]byte(`{"data":null}`))
	f.Add([]byte(`{"list":[1,2,3]}`))
	f.Add([]byte(`{"nested":{"a":1}}`))

	// Duplicates
	f.Add([]byte(`{"name":"first","name":"second"}`))
	f.Add([]byte(`{"nested":{"a":1,"a":2}}`))

	// Trailing data (should be rejected)
	f.Add([]byte(`{}extra`))
	f.Add([]byte(`{}"more"`))
	f.Add([]byte(`{}123`))
	f.Add([]byte(`{}null`))
	f.Add([]byte(`{}{}`))

	// Invalid JSON
	f.Add([]byte(`{invalid}`))
	f.Add([]byte(`not json`))

	type testStruct struct {
		Name   string `json:"name,omitempty"`
		Count  int    `json:"count,omitempty"`
		Flag   bool   `json:"flag,omitempty"`
		Data   any    `json:"data,omitempty"`
		Nested struct {
			A int `json:"a,omitempty"`
		} `json:"nested,omitempty"`
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		result, err := DecodeStrict[testStruct](data)

		// Should not panic
		_ = result

		// If successful, the input should be valid JSON without duplicates
		if err == nil {
			if !json.Valid(data) {
				t.Errorf("DecodeStrict accepted invalid JSON: %s", string(data))
			}
			if checkForDuplicatesManually(data) {
				t.Errorf("SECURITY: DecodeStrict accepted JSON with duplicates: %s", string(data))
			}
		}
	})
}

// FuzzValidateNoDuplicateKeys_SecurityPatterns specifically targets attack patterns.
func FuzzValidateNoDuplicateKeys_SecurityPatterns(f *testing.F) {
	// Attack patterns for predicate shadowing
	f.Add([]byte(`{"pack_digest":"sha256:good","pack_digest":"sha256:evil"}`))
	f.Add([]byte(`{"predicate":{"a":1},"predicate":{"a":2}}`))
	f.Add([]byte(`{"subject":{"digest":"good"},"subject":{"digest":"evil"}}`))
	f.Add([]byte(`{"_type":"first","_type":"second"}`))

	// Unicode normalization attacks
	f.Add([]byte(`{"café":1,"cafe\u0301":2}`)) // Different Unicode representations
	f.Add([]byte(`{"ℌ":1,"\u210c":2}`))        // Same character, different encoding

	// Whitespace and control character tricks
	f.Add([]byte(`{"a ":1,"a":2}`))      // Trailing space
	f.Add([]byte(`{" a":1,"a":2}`))      // Leading space
	f.Add([]byte(`{"a\u0000":1,"a":2}`)) // Null byte
	f.Add([]byte(`{"a\u200b":1,"a":2}`)) // Zero-width space
	f.Add([]byte(`{"a\ufeff":1,"a":2}`)) // BOM character

	// Long key attacks
	longKey := strings.Repeat("a", 10000)
	f.Add([]byte(`{"` + longKey + `":1,"` + longKey + `":2}`))

	// Many duplicates
	f.Add([]byte(`{"a":1,"a":2,"a":3,"a":4,"a":5,"a":6,"a":7,"a":8,"a":9,"a":10}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		err := ValidateNoDuplicateKeys(data)

		// Should not panic
		if err == nil && utf8.Valid(data) && json.Valid(data) {
			// If accepted, verify no actual duplicates
			if checkForDuplicatesManually(data) {
				t.Errorf("SECURITY: accepted JSON with duplicates: %q", string(data))
			}
		}
	})
}

// checkForDuplicatesManually is an alternative implementation to cross-check.
// It parses JSON into a generic structure and tracks keys.
func checkForDuplicatesManually(data []byte) bool {
	if !json.Valid(data) {
		return false
	}

	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()

	var check func() bool
	check = func() bool {
		tok, err := dec.Token()
		if err != nil {
			return false
		}

		switch v := tok.(type) {
		case json.Delim:
			switch v {
			case '{':
				seen := make(map[string]bool)
				for dec.More() {
					keyTok, err := dec.Token()
					if err != nil {
						return false
					}
					key, ok := keyTok.(string)
					if !ok {
						return false
					}
					if seen[key] {
						return true // Duplicate found!
					}
					seen[key] = true

					// Recursively check the value
					if check() {
						return true
					}
				}
				// Consume closing brace
				_, _ = dec.Token()
			case '[':
				for dec.More() {
					if check() {
						return true
					}
				}
				// Consume closing bracket
				_, _ = dec.Token()
			}
		}
		return false
	}

	return check()
}
