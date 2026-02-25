package digest

import (
	"encoding/json"
	"strings"
	"testing"
)

// FuzzParse tests digest parsing with fuzzed inputs.
// Verifies:
// - Only canonical format accepted (sha256:<64 lowercase hex>)
// - No uppercase hex accepted
// - Exact length enforcement
func FuzzParse(f *testing.F) {
	// Valid digest
	f.Add("sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789")

	// Uppercase (should reject)
	f.Add("sha256:ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789")
	f.Add("sha256:AbCdEf0123456789abcdef0123456789abcdef0123456789abcdef0123456789")
	f.Add("SHA256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789")

	// Wrong length
	f.Add("sha256:abcdef")                                                            // too short
	f.Add("sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef01234567890") // 65 chars
	f.Add("sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef012345678")   // 63 chars

	// Wrong algorithm prefix
	f.Add("sha512:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789")
	f.Add("md5:abcdef0123456789abcdef0123456789")
	f.Add("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789") // no prefix

	// Whitespace
	f.Add(" sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789")
	f.Add("sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789 ")
	f.Add("sha256: abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789")

	// Invalid hex characters
	f.Add("sha256:ghijkl0123456789abcdef0123456789abcdef0123456789abcdef0123456789")
	f.Add("sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef012345678!")

	// Empty and edge cases
	f.Add("")
	f.Add("sha256:")
	f.Add(":")

	f.Fuzz(func(t *testing.T, s string) {
		d, err := Parse(s)

		if err == nil {
			// Property: String() round-trips exactly
			if d.String() != s {
				t.Errorf("round-trip failed: input=%q, output=%q", s, d.String())
			}

			// Property: Hex() returns exactly 64 chars
			if len(d.Hex()) != 64 {
				t.Errorf("hex length wrong: got %d, want 64", len(d.Hex()))
			}

			// Property: Must be lowercase
			if d.String() != strings.ToLower(d.String()) {
				t.Errorf("accepted non-lowercase digest: %q", s)
			}

			// Property: Must have sha256: prefix
			if !strings.HasPrefix(d.String(), "sha256:") {
				t.Errorf("accepted digest without sha256: prefix: %q", s)
			}

			// Property: IsZero must be false for valid digests
			if d.IsZero() {
				t.Errorf("valid digest reports IsZero: %q", s)
			}
		}
	})
}

// FuzzEqual tests constant-time comparison properties.
func FuzzEqual(f *testing.F) {
	validDigest := "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	otherDigest := "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"

	f.Add(validDigest, validDigest)
	f.Add(validDigest, otherDigest)
	f.Add(validDigest, "")
	f.Add("", validDigest)
	f.Add("", "")
	f.Add("invalid", "invalid")

	f.Fuzz(func(t *testing.T, s1, s2 string) {
		d1, err1 := Parse(s1)
		d2, err2 := Parse(s2)

		// Property: Reflexivity - valid digests equal themselves
		if err1 == nil && !d1.Equal(d1) {
			t.Errorf("reflexivity failed for %q", s1)
		}

		// Property: Symmetry - d1.Equal(d2) == d2.Equal(d1)
		if d1.Equal(d2) != d2.Equal(d1) {
			t.Errorf("symmetry failed: d1=%q, d2=%q", s1, s2)
		}

		// Property: Zero digests never equal anything (including themselves)
		if d1.IsZero() && d1.Equal(d2) {
			t.Errorf("zero digest equaled something: d1=%q, d2=%q", s1, s2)
		}
		if d2.IsZero() && d1.Equal(d2) {
			t.Errorf("something equaled zero digest: d1=%q, d2=%q", s1, s2)
		}

		// Property: If both valid and equal, strings must match
		if err1 == nil && err2 == nil && d1.Equal(d2) {
			if d1.String() != d2.String() {
				t.Errorf("equal digests have different strings: %q vs %q", d1.String(), d2.String())
			}
		}
	})
}

// FuzzFromBytes tests digest computation from byte slices.
func FuzzFromBytes(f *testing.F) {
	f.Add([]byte("hello world"))
	f.Add([]byte(""))
	f.Add([]byte{0, 1, 2, 3, 4, 5})
	f.Add([]byte(strings.Repeat("x", 10000)))

	f.Fuzz(func(t *testing.T, data []byte) {
		d := FromBytes(data)

		// Property: Result is always valid
		if d.IsZero() {
			t.Errorf("FromBytes returned zero digest")
		}

		// Property: Result parses back
		_, err := Parse(d.String())
		if err != nil {
			t.Errorf("FromBytes result doesn't parse: %v", err)
		}

		// Property: Same input = same output
		d2 := FromBytes(data)
		if !d.Equal(d2) {
			t.Errorf("FromBytes not deterministic: %q vs %q", d.String(), d2.String())
		}

		// Property: Different input = different output (with high probability)
		if len(data) > 0 {
			modified := make([]byte, len(data))
			copy(modified, data)
			modified[0] ^= 0xFF
			d3 := FromBytes(modified)
			if d.Equal(d3) {
				// This is astronomically unlikely for SHA256
				t.Logf("collision found (extremely unlikely): %x vs %x", data, modified)
			}
		}
	})
}

// FuzzJSONRoundTrip tests JSON marshaling/unmarshaling.
func FuzzJSONRoundTrip(f *testing.F) {
	f.Add("sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789")
	f.Add("")
	f.Add("invalid")

	f.Fuzz(func(t *testing.T, s string) {
		d, err := Parse(s)

		// Test marshaling
		jsonBytes, marshalErr := json.Marshal(d)
		if marshalErr != nil {
			t.Errorf("Marshal failed for %q: %v", s, marshalErr)
			return
		}

		// Test unmarshaling
		var d2 Digest
		if unmarshalErr := json.Unmarshal(jsonBytes, &d2); unmarshalErr != nil {
			// Invalid digests should still marshal (as empty) and unmarshal
			if err == nil {
				t.Errorf("Unmarshal failed for valid digest %q: %v", s, unmarshalErr)
			}
			return
		}

		// Property: Valid digests round-trip through JSON
		if err == nil {
			if !d.Equal(d2) {
				t.Errorf("JSON round-trip failed: %q -> %q", d.String(), d2.String())
			}
		}

		// Property: Zero digests marshal to empty string
		if d.IsZero() {
			if string(jsonBytes) != `""` {
				t.Errorf("zero digest didn't marshal to empty: %s", jsonBytes)
			}
		}
	})
}

// FuzzValidate tests the standalone validation function.
func FuzzValidate(f *testing.F) {
	f.Add("sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789")
	f.Add("sha256:ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef0123456789")
	f.Add("")
	f.Add("not-a-digest")

	f.Fuzz(func(t *testing.T, s string) {
		validateErr := Validate(s)
		_, parseErr := Parse(s)

		// Property: Validate and Parse must agree
		if (validateErr == nil) != (parseErr == nil) {
			t.Errorf("Validate and Parse disagree for %q: validate=%v, parse=%v",
				s, validateErr, parseErr)
		}
	})
}

// FuzzHasher tests incremental hashing.
func FuzzHasher(f *testing.F) {
	f.Add([]byte("hello"), []byte(" world"))
	f.Add([]byte(""), []byte(""))
	f.Add([]byte("single chunk"), []byte(""))

	f.Fuzz(func(t *testing.T, chunk1, chunk2 []byte) {
		// Compute digest incrementally
		h := NewHasher()
		_, _ = h.Write(chunk1)
		_, _ = h.Write(chunk2)
		incremental := h.Digest()

		// Compute digest in one shot
		combined := append(chunk1, chunk2...)
		oneShot := FromBytes(combined)

		// Property: Results must match
		if !incremental.Equal(oneShot) {
			t.Errorf("incremental != one-shot: %q vs %q", incremental.String(), oneShot.String())
		}

		// Property: Calling Digest() multiple times returns same result
		again := h.Digest()
		if !incremental.Equal(again) {
			t.Errorf("Digest() not idempotent: %q vs %q", incremental.String(), again.String())
		}
	})
}
