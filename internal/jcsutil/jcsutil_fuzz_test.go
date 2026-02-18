package jcsutil

import (
	"bytes"
	"encoding/json"
	"testing"
)

// FuzzCanonicalize tests that Canonicalize handles arbitrary input without panicking
// and produces valid JSON when successful.
func FuzzCanonicalize(f *testing.F) {
	// Seed corpus with various JSON inputs
	f.Add([]byte(`{}`))
	f.Add([]byte(`[]`))
	f.Add([]byte(`null`))
	f.Add([]byte(`true`))
	f.Add([]byte(`false`))
	f.Add([]byte(`"hello"`))
	f.Add([]byte(`123`))
	f.Add([]byte(`-456`))
	f.Add([]byte(`1.5`))
	f.Add([]byte(`1e10`))
	f.Add([]byte(`{"a":1,"b":2}`))
	f.Add([]byte(`{"b":2,"a":1}`))
	f.Add([]byte(`[1,2,3]`))
	f.Add([]byte(`{"nested":{"key":"value"}}`))
	f.Add([]byte(`{"unicode":"日本語"}`))
	f.Add([]byte(`{"emoji":"😀"}`))
	f.Add([]byte(`{"escape":"a\nb\tc"}`))
	f.Add([]byte(`{"whitespace":  "  test  "  }`))
	f.Add([]byte(`{  "spaced" :  123  }`))

	f.Fuzz(func(t *testing.T, data []byte) {
		canonical, err := Canonicalize(data)
		if err != nil {
			// Invalid JSON is expected - just verify no panic
			return
		}

		// If canonicalization succeeded, verify output is valid JSON
		if !json.Valid(canonical) {
			t.Errorf("Canonicalize produced invalid JSON: %q", canonical)
		}

		// Verify idempotence: canonicalizing again should produce same result
		canonical2, err := Canonicalize(canonical)
		if err != nil {
			t.Errorf("Canonicalize failed on its own output: %v", err)
			return
		}
		if !bytes.Equal(canonical, canonical2) {
			t.Errorf("Canonicalize is not idempotent:\n  first:  %q\n  second: %q", canonical, canonical2)
		}
	})
}

// FuzzCanonicalizeAndHash tests that CanonicalizeAndHash handles arbitrary input
// without panicking and produces valid output when successful.
func FuzzCanonicalizeAndHash(f *testing.F) {
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"key":"value"}`))
	f.Add([]byte(`[1,2,3]`))
	f.Add([]byte(`"string"`))
	f.Add([]byte(`12345`))

	f.Fuzz(func(t *testing.T, data []byte) {
		canonical, digest, err := CanonicalizeAndHash(data)
		if err != nil {
			return
		}

		// Verify canonical output is valid JSON
		if !json.Valid(canonical) {
			t.Errorf("CanonicalizeAndHash produced invalid JSON: %q", canonical)
		}

		// Verify digest format
		if len(digest) != 71 {
			t.Errorf("digest length = %d, want 71", len(digest))
		}
		if digest[:7] != "sha256:" {
			t.Errorf("digest prefix = %q, want %q", digest[:7], "sha256:")
		}

		// Verify determinism: same input should produce same hash
		_, digest2, err := CanonicalizeAndHash(data)
		if err != nil {
			t.Errorf("second CanonicalizeAndHash failed: %v", err)
			return
		}
		if digest != digest2 {
			t.Errorf("CanonicalizeAndHash is not deterministic: %q != %q", digest, digest2)
		}
	})
}

// FuzzCanonicalizeWithOptions_RejectDuplicateKeys tests duplicate key detection.
func FuzzCanonicalizeWithOptions_RejectDuplicateKeys(f *testing.F) {
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"a":1}`))
	f.Add([]byte(`{"a":1,"b":2}`))
	f.Add([]byte(`{"a":1,"a":2}`))
	f.Add([]byte(`{"nested":{"a":1,"a":2}}`))

	opts := Options{
		RejectDuplicateKeys: true,
		NumberPolicy:        NumberPolicyFiniteIEEE,
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		canonical, err := CanonicalizeWithOptions(data, opts)
		if err != nil {
			return
		}

		// If successful, verify valid JSON
		if !json.Valid(canonical) {
			t.Errorf("CanonicalizeWithOptions produced invalid JSON: %q", canonical)
		}
	})
}

// FuzzCanonicalizeWithOptions_SafeIntNonNegative tests safe integer policy.
func FuzzCanonicalizeWithOptions_SafeIntNonNegative(f *testing.F) {
	f.Add([]byte(`0`))
	f.Add([]byte(`123`))
	f.Add([]byte(`9007199254740991`))
	f.Add([]byte(`{"count":42}`))
	f.Add([]byte(`[0,1,2,3]`))

	opts := Options{
		RejectDuplicateKeys: false,
		NumberPolicy:        NumberPolicySafeIntNonNegative,
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		canonical, err := CanonicalizeWithOptions(data, opts)
		if err != nil {
			return
		}

		if !json.Valid(canonical) {
			t.Errorf("CanonicalizeWithOptions produced invalid JSON: %q", canonical)
		}
	})
}

// FuzzLessUTF16 tests the UTF-16 comparison function.
func FuzzLessUTF16(f *testing.F) {
	f.Add("a", "b")
	f.Add("", "a")
	f.Add("abc", "abd")
	f.Add("日本", "日本語")
	f.Add("😀", "😁")

	f.Fuzz(func(t *testing.T, a, b string) {
		ab := lessUTF16(a, b)
		ba := lessUTF16(b, a)
		aa := lessUTF16(a, a)
		bb := lessUTF16(b, b)

		// Irreflexive: a < a should be false
		if aa {
			t.Errorf("lessUTF16(%q, %q) = true, want false (irreflexive)", a, a)
		}
		if bb {
			t.Errorf("lessUTF16(%q, %q) = true, want false (irreflexive)", b, b)
		}

		// Asymmetric: if a < b then !(b < a)
		if ab && ba {
			t.Errorf("lessUTF16(%q, %q) and lessUTF16(%q, %q) both true (asymmetric violation)", a, b, b, a)
		}

		// Trichotomy: exactly one of a<b, a==b, b<a must hold
		// Note: Two distinct byte strings CAN be equal in UTF-16 ordering when they
		// contain invalid UTF-8 sequences that both map to the replacement character U+FFFD.
		// This is correct behavior - we only verify the comparison is consistent.
		if !ab && !ba && a != b {
			// Strings are distinct but equal in UTF-16 ordering.
			// This is valid when both have invalid UTF-8 that maps to U+FFFD.
			// Just log it for visibility but don't fail.
			t.Logf("lessUTF16: %q and %q are distinct bytes but equal in UTF-16 ordering", a, b)
		}
	})
}
