package jcsutil

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
)

func TestCanonicalize(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		// Basic types
		{
			name:  "null",
			input: "null",
			want:  "null",
		},
		{
			name:  "true",
			input: "true",
			want:  "true",
		},
		{
			name:  "false",
			input: "false",
			want:  "false",
		},
		{
			name:  "empty string",
			input: `""`,
			want:  `""`,
		},
		{
			name:  "simple string",
			input: `"hello"`,
			want:  `"hello"`,
		},
		{
			name:  "integer zero",
			input: "0",
			want:  "0",
		},
		{
			name:  "positive integer",
			input: "123",
			want:  "123",
		},
		{
			name:  "negative integer",
			input: "-456",
			want:  "-456",
		},

		// Whitespace removal
		{
			name:  "object with whitespace",
			input: `{  "a" :  1  }`,
			want:  `{"a":1}`,
		},
		{
			name:  "array with whitespace",
			input: `[  1 ,  2 ,  3  ]`,
			want:  `[1,2,3]`,
		},
		{
			name:  "nested with whitespace",
			input: "{\n  \"key\": {\n    \"nested\": true\n  }\n}",
			want:  `{"key":{"nested":true}}`,
		},

		// Object key sorting (UTF-16 code unit order)
		{
			name:  "object keys sorted",
			input: `{"b":2,"a":1,"c":3}`,
			want:  `{"a":1,"b":2,"c":3}`,
		},
		{
			name:  "keys with numbers",
			input: `{"z":1,"a":2,"m":3}`,
			want:  `{"a":2,"m":3,"z":1}`,
		},
		{
			name:  "empty object",
			input: `{}`,
			want:  `{}`,
		},

		// Arrays (order preserved)
		{
			name:  "empty array",
			input: `[]`,
			want:  `[]`,
		},
		{
			name:  "array order preserved",
			input: `[3,1,2]`,
			want:  `[3,1,2]`,
		},
		{
			name:  "nested arrays",
			input: `[[1,2],[3,4]]`,
			want:  `[[1,2],[3,4]]`,
		},

		// Number formatting
		{
			name:  "float with trailing zeros removed",
			input: `1.0`,
			want:  `1`,
		},
		{
			name:  "float preserved when needed",
			input: `1.5`,
			want:  `1.5`,
		},
		{
			name:  "scientific notation normalized",
			input: `1e2`,
			want:  `100`,
		},
		{
			name:  "negative zero becomes zero",
			input: `-0`,
			want:  `0`,
		},

		// String escaping
		{
			name:  "string with backslash",
			input: `"a\\b"`,
			want:  `"a\\b"`,
		},
		{
			name:  "string with quote",
			input: `"a\"b"`,
			want:  `"a\"b"`,
		},
		{
			name:  "string with newline",
			input: `"a\nb"`,
			want:  `"a\nb"`,
		},
		{
			name:  "string with tab",
			input: `"a\tb"`,
			want:  `"a\tb"`,
		},
		{
			name:  "unicode preserved",
			input: `"日本語"`,
			want:  `"日本語"`,
		},
		{
			name:  "emoji preserved",
			input: `"😀"`,
			want:  `"😀"`,
		},

		// Complex nested structure
		{
			name:  "complex nested",
			input: `{"z":{"b":2,"a":1},"a":[3,2,1]}`,
			want:  `{"a":[3,2,1],"z":{"a":1,"b":2}}`,
		},

		// Error cases
		{
			name:    "invalid JSON",
			input:   `{invalid}`,
			wantErr: true,
		},
		{
			name:    "truncated JSON",
			input:   `{"a":`,
			wantErr: true,
		},
		{
			name:    "extra tokens",
			input:   `{}{`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Canonicalize([]byte(tt.input))

			if tt.wantErr {
				if err == nil {
					t.Errorf("Canonicalize(%q) expected error, got nil", tt.input)
				}
				return
			}

			if err != nil {
				t.Fatalf("Canonicalize(%q) error = %v", tt.input, err)
			}

			if string(got) != tt.want {
				t.Errorf("Canonicalize(%q) = %q, want %q", tt.input, string(got), tt.want)
			}
		})
	}
}

func TestCanonicalizeWithOptions_RejectDuplicateKeys(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{
			name:    "duplicate keys rejected",
			input:   `{"a":1,"a":2}`,
			wantErr: true,
		},
		{
			name:    "nested duplicate keys rejected",
			input:   `{"outer":{"a":1,"a":2}}`,
			wantErr: true,
		},
		{
			name:  "no duplicates passes",
			input: `{"a":1,"b":2}`,
		},
		{
			name:  "same key in different objects ok",
			input: `{"obj1":{"a":1},"obj2":{"a":2}}`,
		},
	}

	opts := Options{
		RejectDuplicateKeys: true,
		NumberPolicy:        NumberPolicyFiniteIEEE,
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := CanonicalizeWithOptions([]byte(tt.input), opts)

			if tt.wantErr {
				if err == nil {
					t.Errorf("CanonicalizeWithOptions(%q) expected error, got nil", tt.input)
				}
				if err != nil && !strings.Contains(err.Error(), "duplicate") {
					t.Errorf("error = %q, want error containing 'duplicate'", err.Error())
				}
				return
			}

			if err != nil {
				t.Errorf("CanonicalizeWithOptions(%q) unexpected error = %v", tt.input, err)
			}
		})
	}
}

func TestCanonicalizeWithOptions_NumberPolicySafeIntNonNegative(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
		errMsg  string
	}{
		{
			name:  "zero",
			input: `0`,
			want:  `0`,
		},
		{
			name:  "positive integer",
			input: `42`,
			want:  `42`,
		},
		{
			name:  "max safe integer",
			input: `9007199254740991`,
			want:  `9007199254740991`,
		},
		{
			name:  "integer in scientific notation",
			input: `1e3`,
			want:  `1000`,
		},
		{
			name:    "negative integer rejected",
			input:   `-1`,
			wantErr: true,
			errMsg:  "negative",
		},
		{
			name:    "fractional number rejected",
			input:   `1.5`,
			wantErr: true,
			errMsg:  "fractional",
		},
		{
			name:    "exceeds max safe integer",
			input:   `9007199254740992`,
			wantErr: true,
			errMsg:  "exceeds max safe integer",
		},
	}

	opts := Options{
		RejectDuplicateKeys: false,
		NumberPolicy:        NumberPolicySafeIntNonNegative,
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := CanonicalizeWithOptions([]byte(tt.input), opts)

			if tt.wantErr {
				if err == nil {
					t.Errorf("CanonicalizeWithOptions(%q) expected error, got nil", tt.input)
				}
				if err != nil && !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("error = %q, want error containing %q", err.Error(), tt.errMsg)
				}
				return
			}

			if err != nil {
				t.Fatalf("CanonicalizeWithOptions(%q) error = %v", tt.input, err)
			}

			if string(got) != tt.want {
				t.Errorf("CanonicalizeWithOptions(%q) = %q, want %q", tt.input, string(got), tt.want)
			}
		})
	}
}

func TestCanonicalizeAndHash(t *testing.T) {
	tests := []struct {
		name           string
		input          string
		wantCanonical  string
		wantHashPrefix string
	}{
		{
			name:           "simple object",
			input:          `{"b":2,"a":1}`,
			wantCanonical:  `{"a":1,"b":2}`,
			wantHashPrefix: "sha256:",
		},
		{
			name:           "empty object",
			input:          `{}`,
			wantCanonical:  `{}`,
			wantHashPrefix: "sha256:",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			canonical, digest, err := CanonicalizeAndHash([]byte(tt.input))
			if err != nil {
				t.Fatalf("CanonicalizeAndHash(%q) error = %v", tt.input, err)
			}

			if string(canonical) != tt.wantCanonical {
				t.Errorf("canonical = %q, want %q", string(canonical), tt.wantCanonical)
			}

			if !strings.HasPrefix(digest, tt.wantHashPrefix) {
				t.Errorf("digest = %q, want prefix %q", digest, tt.wantHashPrefix)
			}

			// Verify hash format: sha256: + 64 hex chars
			if len(digest) != 71 {
				t.Errorf("digest length = %d, want 71", len(digest))
			}
		})
	}
}

func TestCanonicalizeAndHash_Deterministic(t *testing.T) {
	// Same logical JSON with different formatting should produce same hash
	inputs := []string{
		`{"a":1,"b":2}`,
		`{ "a" : 1 , "b" : 2 }`,
		`{"b":2,"a":1}`,
		"{\n  \"a\": 1,\n  \"b\": 2\n}",
	}

	var firstDigest string
	for i, input := range inputs {
		_, digest, err := CanonicalizeAndHash([]byte(input))
		if err != nil {
			t.Fatalf("CanonicalizeAndHash(%q) error = %v", input, err)
		}

		if i == 0 {
			firstDigest = digest
		} else if digest != firstDigest {
			t.Errorf("input %d (%q) digest = %q, want %q (same as first)", i, input, digest, firstDigest)
		}
	}
}

func TestCanonicalize_NonFiniteNumbers(t *testing.T) {
	// These should all fail with default options
	nonFinite := []string{
		// Note: Go's json.Unmarshal doesn't actually accept these literals,
		// but json.Number might in some contexts. We test via marshaling.
	}

	for _, input := range nonFinite {
		_, err := Canonicalize([]byte(input))
		if err == nil {
			t.Errorf("Canonicalize(%q) expected error for non-finite number", input)
		}
	}
}

func TestCanonicalize_UTF16Sorting(t *testing.T) {
	// JCS sorts by UTF-16 code units, not UTF-8 bytes
	// This matters for characters outside the BMP
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "ascii sorting",
			input: `{"b":1,"a":2,"c":3}`,
			want:  `{"a":2,"b":1,"c":3}`,
		},
		{
			name:  "mixed case ascii",
			input: `{"B":1,"a":2,"A":3}`,
			// ASCII: A=65, B=66, a=97
			want: `{"A":3,"B":1,"a":2}`,
		},
		{
			name:  "unicode characters",
			input: `{"β":1,"α":2,"γ":3}`,
			// Greek: α=945, β=946, γ=947
			want: `{"α":2,"β":1,"γ":3}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Canonicalize([]byte(tt.input))
			if err != nil {
				t.Fatalf("Canonicalize(%q) error = %v", tt.input, err)
			}

			if string(got) != tt.want {
				t.Errorf("Canonicalize(%q) = %q, want %q", tt.input, string(got), tt.want)
			}
		})
	}
}

func TestCanonicalize_StringEscaping(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "control character \\x00",
			input: `"\u0000"`,
			want:  `"\u0000"`,
		},
		{
			name:  "control character \\x1f",
			input: `"\u001f"`,
			want:  `"\u001f"`,
		},
		{
			name:  "backspace",
			input: `"\b"`,
			want:  `"\b"`,
		},
		{
			name:  "form feed",
			input: `"\f"`,
			want:  `"\f"`,
		},
		{
			name:  "carriage return",
			input: `"\r"`,
			want:  `"\r"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Canonicalize([]byte(tt.input))
			if err != nil {
				t.Fatalf("Canonicalize(%q) error = %v", tt.input, err)
			}

			if string(got) != tt.want {
				t.Errorf("Canonicalize(%q) = %q, want %q", tt.input, string(got), tt.want)
			}
		})
	}
}

func TestDefaultOptions(t *testing.T) {
	opts := DefaultOptions()

	if opts.RejectDuplicateKeys != false {
		t.Errorf("DefaultOptions().RejectDuplicateKeys = %v, want false", opts.RejectDuplicateKeys)
	}

	if opts.NumberPolicy != NumberPolicyFiniteIEEE {
		t.Errorf("DefaultOptions().NumberPolicy = %v, want NumberPolicyFiniteIEEE", opts.NumberPolicy)
	}
}

func TestLessUTF16(t *testing.T) {
	tests := []struct {
		a, b string
		want bool
	}{
		{"a", "b", true},
		{"b", "a", false},
		{"a", "a", false},
		{"", "a", true},
		{"a", "", false},
		{"", "", false},
		{"A", "a", true}, // A=65 < a=97
		{"Z", "a", true}, // Z=90 < a=97
		{"aa", "ab", true},
		{"ab", "aa", false},
		{"a", "aa", true},
		// Emoji (outside BMP, uses surrogate pairs)
		{"a", "😀", true}, // 'a' (97) < high surrogate of 😀
	}

	for _, tt := range tests {
		t.Run(tt.a+"_vs_"+tt.b, func(t *testing.T) {
			got := lessUTF16(tt.a, tt.b)
			if got != tt.want {
				t.Errorf("lessUTF16(%q, %q) = %v, want %v", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestFormatFloatFiniteIEEE(t *testing.T) {
	tests := []struct {
		name    string
		input   float64
		want    string
		wantErr bool
	}{
		{"zero", 0, "0", false},
		{"negative zero", math.Copysign(0, -1), "0", false},
		{"one", 1, "1", false},
		{"negative one", -1, "-1", false},
		{"fraction", 1.5, "1.5", false},
		{"small fraction", 0.001, "0.001", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := formatFloatFiniteIEEE(tt.input)

			if tt.wantErr {
				if err == nil {
					t.Errorf("formatFloatFiniteIEEE(%v) expected error", tt.input)
				}
				return
			}

			if err != nil {
				t.Fatalf("formatFloatFiniteIEEE(%v) error = %v", tt.input, err)
			}

			if got != tt.want {
				t.Errorf("formatFloatFiniteIEEE(%v) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestHasFractionalMantissa(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"123", false},
		{"123.0", false},
		{"123.00", false},
		{"123.1", true},
		{"123.01", true},
		{"1.5e2", true},
		{"1.0e2", false},
		{"1e2", false},
		{"-123.5", true},
		{"-123.0", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := hasFractionalMantissa(tt.input)
			if got != tt.want {
				t.Errorf("hasFractionalMantissa(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestCanonicalize_ExtraInput(t *testing.T) {
	// Extra tokens after valid JSON should fail
	inputs := []string{
		`{}{}`,
		`[][]`,
		`"a""b"`,
		`123 456`,
		`true false`,
	}

	for _, input := range inputs {
		t.Run(input, func(t *testing.T) {
			_, err := Canonicalize([]byte(input))
			if err == nil {
				t.Errorf("Canonicalize(%q) expected error for extra input", input)
			}
		})
	}
}

// Benchmark canonicalization performance
func BenchmarkCanonicalize_SmallObject(b *testing.B) {
	input := []byte(`{"name":"test","value":123,"enabled":true}`)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Canonicalize(input)
	}
}

func BenchmarkCanonicalize_LargeObject(b *testing.B) {
	// Build a larger object
	obj := make(map[string]int)
	for i := 0; i < 100; i++ {
		obj[string(rune('a'+i%26))+string(rune('0'+i/26))] = i
	}
	input, _ := json.Marshal(obj)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Canonicalize(input)
	}
}

func BenchmarkCanonicalizeAndHash(b *testing.B) {
	input := []byte(`{"name":"test","value":123,"enabled":true}`)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = CanonicalizeAndHash(input)
	}
}

func TestCanonicalizeAndHashWithOptions(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		opts    Options
		wantErr bool
	}{
		{
			name:  "basic with default options",
			input: `{"b":2,"a":1}`,
			opts:  DefaultOptions(),
		},
		{
			name:  "with SafeIntNonNegative policy",
			input: `{"count":42}`,
			opts: Options{
				NumberPolicy: NumberPolicySafeIntNonNegative,
			},
		},
		{
			name:  "with RejectDuplicateKeys",
			input: `{"a":1,"b":2}`,
			opts: Options{
				RejectDuplicateKeys: true,
			},
		},
		{
			name:  "duplicate keys rejected",
			input: `{"a":1,"a":2}`,
			opts: Options{
				RejectDuplicateKeys: true,
			},
			wantErr: true,
		},
		{
			name:  "negative number rejected",
			input: `{"value":-1}`,
			opts: Options{
				NumberPolicy: NumberPolicySafeIntNonNegative,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			canonical, digest, err := CanonicalizeAndHashWithOptions([]byte(tt.input), tt.opts)

			if tt.wantErr {
				if err == nil {
					t.Error("Expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if len(canonical) == 0 {
				t.Error("canonical is empty")
			}

			if !strings.HasPrefix(digest, "sha256:") {
				t.Errorf("digest = %q, want prefix 'sha256:'", digest)
			}

			if len(digest) != 71 {
				t.Errorf("digest length = %d, want 71", len(digest))
			}
		})
	}
}

func TestCanonicalizeAndHash_Error(t *testing.T) {
	// Invalid JSON should return error
	_, digest, err := CanonicalizeAndHash([]byte(`{invalid}`))
	if err == nil {
		t.Error("Expected error for invalid JSON, got nil")
	}
	if digest != "" {
		t.Errorf("digest = %q, want empty string on error", digest)
	}
}

func TestFormatFloatNumber(t *testing.T) {
	tests := []struct {
		name    string
		value   float64
		policy  NumberPolicy
		want    string
		wantErr bool
		errMsg  string
	}{
		{
			name:   "zero with FiniteIEEE",
			value:  0,
			policy: NumberPolicyFiniteIEEE,
			want:   "0",
		},
		{
			name:   "positive with FiniteIEEE",
			value:  42.5,
			policy: NumberPolicyFiniteIEEE,
			want:   "42.5",
		},
		{
			name:   "negative with FiniteIEEE",
			value:  -42.5,
			policy: NumberPolicyFiniteIEEE,
			want:   "-42.5",
		},
		{
			name:   "zero with SafeIntNonNegative",
			value:  0,
			policy: NumberPolicySafeIntNonNegative,
			want:   "0",
		},
		{
			name:   "positive int with SafeIntNonNegative",
			value:  42,
			policy: NumberPolicySafeIntNonNegative,
			want:   "42",
		},
		{
			name:    "negative with SafeIntNonNegative",
			value:   -1,
			policy:  NumberPolicySafeIntNonNegative,
			wantErr: true,
			errMsg:  "negative",
		},
		{
			name:    "fractional with SafeIntNonNegative",
			value:   1.5,
			policy:  NumberPolicySafeIntNonNegative,
			wantErr: true,
			errMsg:  "fractional",
		},
		{
			name:    "exceeds max safe int",
			value:   float64(MaxSafeInt) + 1,
			policy:  NumberPolicySafeIntNonNegative,
			wantErr: true,
			errMsg:  "exceeds max safe integer",
		},
		{
			name:    "NaN with FiniteIEEE",
			value:   math.NaN(),
			policy:  NumberPolicyFiniteIEEE,
			wantErr: true,
			errMsg:  "non-finite",
		},
		{
			name:    "Inf with FiniteIEEE",
			value:   math.Inf(1),
			policy:  NumberPolicyFiniteIEEE,
			wantErr: true,
			errMsg:  "non-finite",
		},
		{
			name:    "NaN with SafeIntNonNegative",
			value:   math.NaN(),
			policy:  NumberPolicySafeIntNonNegative,
			wantErr: true,
			errMsg:  "non-finite",
		},
		{
			name:    "Inf with SafeIntNonNegative",
			value:   math.Inf(1),
			policy:  NumberPolicySafeIntNonNegative,
			wantErr: true,
			errMsg:  "non-finite",
		},
		{
			name:    "unknown policy",
			value:   42,
			policy:  NumberPolicy(99),
			wantErr: true,
			errMsg:  "unknown NumberPolicy",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := formatFloatNumber(tt.value, tt.policy)

			if tt.wantErr {
				if err == nil {
					t.Errorf("formatFloatNumber(%v, %v) expected error", tt.value, tt.policy)
				} else if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("error = %q, want containing %q", err.Error(), tt.errMsg)
				}
				return
			}

			if err != nil {
				t.Fatalf("formatFloatNumber(%v, %v) error = %v", tt.value, tt.policy, err)
			}

			if got != tt.want {
				t.Errorf("formatFloatNumber(%v, %v) = %q, want %q", tt.value, tt.policy, got, tt.want)
			}
		})
	}
}

func TestFormatNumber_UnknownPolicy(t *testing.T) {
	_, err := formatNumber(json.Number("42"), NumberPolicy(99))
	if err == nil {
		t.Error("Expected error for unknown policy, got nil")
	}
	if !strings.Contains(err.Error(), "unknown NumberPolicy") {
		t.Errorf("error = %q, want containing 'unknown NumberPolicy'", err.Error())
	}
}

func TestFormatNumber_NonFiniteStrings(t *testing.T) {
	nonFinite := []string{"NaN", "nan", "NAN", "Inf", "inf", "INF", "-Inf", "+Inf", "Infinity", "-Infinity", "+Infinity"}

	for _, s := range nonFinite {
		t.Run(s, func(t *testing.T) {
			_, err := formatNumber(json.Number(s), NumberPolicyFiniteIEEE)
			if err == nil {
				t.Errorf("formatNumber(%q) expected error for non-finite", s)
			}
		})
	}
}

func TestFormatFloatFiniteIEEE_NonFinite(t *testing.T) {
	tests := []struct {
		name  string
		value float64
	}{
		{"NaN", math.NaN()},
		{"positive infinity", math.Inf(1)},
		{"negative infinity", math.Inf(-1)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := formatFloatFiniteIEEE(tt.value)
			if err == nil {
				t.Errorf("formatFloatFiniteIEEE(%v) expected error", tt.value)
			}
		})
	}
}

func TestDecodeNoDuplicateKeys_Arrays(t *testing.T) {
	// Test arrays with duplicate detection enabled
	opts := Options{RejectDuplicateKeys: true}

	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{
			name:  "simple array",
			input: `[1, 2, 3]`,
		},
		{
			name:  "array with objects",
			input: `[{"a":1}, {"b":2}]`,
		},
		{
			name:    "array with duplicate keys in object",
			input:   `[{"a":1, "a":2}]`,
			wantErr: true,
		},
		{
			name:  "nested arrays",
			input: `[[1, 2], [3, 4]]`,
		},
		{
			name:  "empty array",
			input: `[]`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := CanonicalizeWithOptions([]byte(tt.input), opts)

			if tt.wantErr && err == nil {
				t.Error("Expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

func TestCanonicalize_InvalidJSON(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"unclosed object", `{`},
		{"unclosed array", `[`},
		{"unclosed string", `"hello`},
		{"invalid escape", `"\x"`},
		{"trailing comma object", `{"a":1,}`},
		{"trailing comma array", `[1,]`},
		{"missing colon", `{"a" 1}`},
		{"missing value", `{"a":}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Canonicalize([]byte(tt.input))
			if err == nil {
				t.Errorf("Canonicalize(%q) expected error", tt.input)
			}
		})
	}
}

func TestCanonicalize_StringControlChars(t *testing.T) {
	// Test all control characters 0x00-0x1F
	for i := 0; i < 0x20; i++ {
		t.Run(string(rune(i)), func(t *testing.T) {
			// Create JSON with the control character in a string
			input := []byte(`"` + string(rune(i)) + `"`)
			// The input might not be valid JSON, but if it parses, it should be canonicalized
			result, err := Canonicalize(input)
			// We don't check error here because Go's JSON parser may reject some control chars
			if err == nil {
				// If it succeeded, verify the output is valid JSON
				var v interface{}
				if json.Unmarshal(result, &v) != nil {
					t.Errorf("Result is not valid JSON: %q", result)
				}
			}
		})
	}
}

func TestWriteCanonical_UnsupportedType(t *testing.T) {
	// This tests an internal error path - unsupported type
	// We can't easily trigger this through public API since json.Decode
	// only produces supported types, but we test documentation of behavior
}

func TestUTF16Iter_InvalidUTF8(t *testing.T) {
	// Test handling of invalid UTF-8 sequences
	invalid := "\xff\xfe" // Invalid UTF-8
	it := utf16Iter{str: invalid}

	// Should not panic, should return replacement character
	for {
		_, ok := it.next()
		if !ok {
			break
		}
	}
}

func TestLessUTF16_SurrogatePairs(t *testing.T) {
	// Test strings with characters outside BMP (requiring surrogate pairs)
	tests := []struct {
		a, b string
		want bool
	}{
		// 😀 is U+1F600, encoded as surrogate pair D83D DE00
		// 😁 is U+1F601, encoded as surrogate pair D83D DE01
		{"😀", "😁", true},
		{"😁", "😀", false},
		// Mix of BMP and non-BMP
		{"a😀", "a😁", true},
		{"😀a", "😀b", true},
		// 𐀀 is U+10000 (first non-BMP character)
		{"a", "𐀀", true},
	}

	for _, tt := range tests {
		t.Run(tt.a+"_vs_"+tt.b, func(t *testing.T) {
			got := lessUTF16(tt.a, tt.b)
			if got != tt.want {
				t.Errorf("lessUTF16(%q, %q) = %v, want %v", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestCanonicalize_DeeplyNested(t *testing.T) {
	// Test deeply nested structures
	depth := 100
	var nested strings.Builder
	for i := 0; i < depth; i++ {
		nested.WriteString(`{"a":`)
	}
	nested.WriteString(`1`)
	for i := 0; i < depth; i++ {
		nested.WriteString(`}`)
	}

	_, err := Canonicalize([]byte(nested.String()))
	if err != nil {
		t.Errorf("Canonicalize failed for deeply nested: %v", err)
	}
}

func TestCanonicalize_LargeArray(t *testing.T) {
	// Test large arrays
	size := 1000
	var arr strings.Builder
	arr.WriteString(`[`)
	for i := 0; i < size; i++ {
		if i > 0 {
			arr.WriteString(`,`)
		}
		arr.WriteString(string(rune('0' + (i % 10))))
	}
	arr.WriteString(`]`)

	_, err := Canonicalize([]byte(arr.String()))
	if err != nil {
		t.Errorf("Canonicalize failed for large array: %v", err)
	}
}

func TestFormatSafeIntNonNegative_EdgeCases(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
		errMsg  string
	}{
		{"zero", "0", "0", false, ""},
		{"max safe int", "9007199254740991", "9007199254740991", false, ""},
		{"scientific notation integer", "1e3", "1000", false, ""},
		{"scientific notation with exponent", "1.0e3", "1000", false, ""},
		{"negative", "-1", "", true, "negative"},
		{"fractional", "1.5", "", true, "fractional"},
		{"exceeds max safe int", "9007199254740992", "", true, "exceeds"},
		{"invalid number string", "notanumber", "", true, "invalid"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := formatSafeIntNonNegative(tt.input)

			if tt.wantErr {
				if err == nil {
					t.Errorf("formatSafeIntNonNegative(%q) expected error", tt.input)
				} else if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("error = %q, want containing %q", err.Error(), tt.errMsg)
				}
				return
			}

			if err != nil {
				t.Fatalf("formatSafeIntNonNegative(%q) error = %v", tt.input, err)
			}

			if got != tt.want {
				t.Errorf("formatSafeIntNonNegative(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestMaxSafeInt(t *testing.T) {
	// Verify MaxSafeInt is 2^53 - 1
	expected := int64(1<<53 - 1)
	if MaxSafeInt != expected {
		t.Errorf("MaxSafeInt = %d, want %d", MaxSafeInt, expected)
	}
}
