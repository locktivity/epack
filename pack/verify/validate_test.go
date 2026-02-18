package verify

import (
	"strings"
	"testing"

	"github.com/locktivity/epack/errors"
	"github.com/locktivity/epack/internal/limits"
)

func TestValidateAttestationSize(t *testing.T) {
	tests := []struct {
		name    string
		size    int
		wantErr bool
	}{
		{"empty", 0, false},
		{"small", 1000, false},
		{"at limit", int(limits.Attestation.Bytes()), false},
		{"over limit", int(limits.Attestation.Bytes()) + 1, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := make([]byte, tt.size)
			err := ValidateAttestationSize(data)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateAttestationSize() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil && errors.CodeOf(err) != errors.AttestationTooLarge {
				t.Errorf("expected AttestationTooLarge error code, got %v", errors.CodeOf(err))
			}
		})
	}
}

func TestValidateAttestationDepth(t *testing.T) {
	tests := []struct {
		name    string
		json    string
		wantErr bool
	}{
		{"empty object", `{}`, false},
		{"flat object", `{"a": 1, "b": 2}`, false},
		{"nested object", `{"a": {"b": {"c": 1}}}`, false},
		{"array", `[1, 2, 3]`, false},
		{"nested array", `[[[[1]]]]`, false},
		{"mixed nesting", `{"a": [{"b": [1]}]}`, false},
		{"string with braces", `{"a": "{{{"}`, false},
		{"escaped quote", `{"a": "\""}`, false},
		{"depth 32", generateNestedJSON(32), false},
		{"depth 33", generateNestedJSON(33), true},
		{"depth 50", generateNestedJSON(50), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateAttestationDepth([]byte(tt.json))
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateAttestationDepth() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil && errors.CodeOf(err) != errors.InvalidAttestation {
				t.Errorf("expected InvalidAttestation error code, got %v", errors.CodeOf(err))
			}
		})
	}
}

func TestValidateAttestation(t *testing.T) {
	t.Run("valid attestation", func(t *testing.T) {
		data := []byte(`{"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json"}`)
		if err := ValidateAttestation(data); err != nil {
			t.Errorf("ValidateAttestation() unexpected error: %v", err)
		}
	})

	t.Run("too large", func(t *testing.T) {
		data := make([]byte, limits.Attestation.Bytes()+1)
		err := ValidateAttestation(data)
		if err == nil {
			t.Error("ValidateAttestation() expected error for oversized data")
		}
	})

	t.Run("too deep", func(t *testing.T) {
		data := []byte(generateNestedJSON(50))
		err := ValidateAttestation(data)
		if err == nil {
			t.Error("ValidateAttestation() expected error for deeply nested JSON")
		}
	})
}

func generateNestedJSON(depth int) string {
	return strings.Repeat(`{"a":`, depth) + `1` + strings.Repeat(`}`, depth)
}

func TestValidateAttestationDepth_ArrayNesting(t *testing.T) {
	tests := []struct {
		name    string
		json    string
		wantErr bool
	}{
		{"array depth 32", generateNestedArray(32), false},
		{"array depth 33", generateNestedArray(33), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateAttestationDepth([]byte(tt.json))
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateAttestationDepth() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func generateNestedArray(depth int) string {
	return strings.Repeat(`[`, depth) + `1` + strings.Repeat(`]`, depth)
}

func TestValidateAttestationDepth_MixedNesting(t *testing.T) {
	// Test with alternating arrays and objects
	tests := []struct {
		name    string
		json    string
		wantErr bool
	}{
		{
			name:    "alternating within limit",
			json:    `{"a":[{"b":[{"c":[1]}]}]}`, // depth 6
			wantErr: false,
		},
		{
			name:    "complex nesting at limit",
			json:    generateMixedNesting(16), // 16 objects + 16 arrays = 32
			wantErr: false,
		},
		{
			name:    "complex nesting over limit",
			json:    generateMixedNesting(17), // 17 objects + 17 arrays = 34
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateAttestationDepth([]byte(tt.json))
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateAttestationDepth() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func generateMixedNesting(halfDepth int) string {
	var sb strings.Builder
	for i := 0; i < halfDepth; i++ {
		sb.WriteString(`{"a":[`)
	}
	sb.WriteString(`1`)
	for i := 0; i < halfDepth; i++ {
		sb.WriteString(`]}`)
	}
	return sb.String()
}

func TestValidateAttestationDepth_EscapedChars(t *testing.T) {
	tests := []struct {
		name string
		json string
	}{
		{
			name: "escaped backslash",
			json: `{"a": "\\"}`,
		},
		{
			name: "escaped quote inside string",
			json: `{"a": "he said \"hello\""}`,
		},
		{
			name: "escaped unicode",
			json: `{"a": "\u0041"}`,
		},
		{
			name: "multiple escapes",
			json: `{"a": "\\\"\\\""}`,
		},
		{
			name: "escaped brace chars in string",
			json: `{"a": "looks like { and [ but in string"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateAttestationDepth([]byte(tt.json))
			if err != nil {
				t.Errorf("ValidateAttestationDepth() unexpected error: %v", err)
			}
		})
	}
}

func TestValidateAttestationSize_Boundary(t *testing.T) {
	// Test exactly at the boundary
	data := make([]byte, limits.Attestation.Bytes())
	err := ValidateAttestationSize(data)
	if err != nil {
		t.Errorf("ValidateAttestationSize() should accept data exactly at limit: %v", err)
	}

	// Test one byte over
	dataOver := make([]byte, limits.Attestation.Bytes()+1)
	err = ValidateAttestationSize(dataOver)
	if err == nil {
		t.Error("ValidateAttestationSize() should reject data one byte over limit")
	}
}

func TestValidateAttestationDepth_ExactlyAtLimit(t *testing.T) {
	// Test exactly at depth 32 (should pass)
	json32 := generateNestedJSON(32)
	err := ValidateAttestationDepth([]byte(json32))
	if err != nil {
		t.Errorf("ValidateAttestationDepth() should accept depth exactly at limit: %v", err)
	}
}

func TestValidateAttestationDepth_UnbalancedJSON(t *testing.T) {
	// This tests that unbalanced JSON doesn't cause issues
	// (the depth tracker may go negative but shouldn't crash)
	tests := []struct {
		name string
		json string
	}{
		{
			name: "extra closing brace",
			json: `{"a": 1}}`,
		},
		{
			name: "extra closing bracket",
			json: `[1, 2]]`,
		},
		{
			name: "missing opening brace",
			json: `"a": 1}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Should not panic, even if JSON is invalid
			_ = ValidateAttestationDepth([]byte(tt.json))
		})
	}
}

func TestValidateAttestationDepth_LargeFlat(t *testing.T) {
	// Large but shallow JSON should pass
	var sb strings.Builder
	sb.WriteString(`{`)
	for i := 0; i < 1000; i++ {
		if i > 0 {
			sb.WriteString(`,`)
		}
		sb.WriteString(`"key`)
		sb.WriteString(strings.Repeat("x", 10))
		sb.WriteString(`": "value"`)
	}
	sb.WriteString(`}`)

	err := ValidateAttestationDepth([]byte(sb.String()))
	if err != nil {
		t.Errorf("ValidateAttestationDepth() should pass for large flat JSON: %v", err)
	}
}

func TestValidateAttestationDepth_DeepArraysOnly(t *testing.T) {
	// Test arrays only (no objects)
	depth31 := strings.Repeat("[", 31) + "1" + strings.Repeat("]", 31)
	err := ValidateAttestationDepth([]byte(depth31))
	if err != nil {
		t.Errorf("ValidateAttestationDepth() should pass for depth 31 array: %v", err)
	}

	depth32 := strings.Repeat("[", 32) + "1" + strings.Repeat("]", 32)
	err = ValidateAttestationDepth([]byte(depth32))
	if err != nil {
		t.Errorf("ValidateAttestationDepth() should pass for depth 32 array: %v", err)
	}

	depth33 := strings.Repeat("[", 33) + "1" + strings.Repeat("]", 33)
	err = ValidateAttestationDepth([]byte(depth33))
	if err == nil {
		t.Error("ValidateAttestationDepth() should fail for depth 33 array")
	}
}

func TestValidateAttestationDepth_StringsWithBrackets(t *testing.T) {
	// Brackets inside strings should not count toward depth
	json := `{"data": "{{{{[[[[nested brackets in string]]]]}}}}","nested": {"level": 1}}`
	err := ValidateAttestationDepth([]byte(json))
	if err != nil {
		t.Errorf("ValidateAttestationDepth() should pass (brackets in string): %v", err)
	}
}

func TestValidateAttestationDepth_UnicodeStrings(t *testing.T) {
	// Unicode content should not affect depth counting
	json := `{"emoji": "🎉🎊🎈", "chinese": "中文", "nested": {"level": 1}}`
	err := ValidateAttestationDepth([]byte(json))
	if err != nil {
		t.Errorf("ValidateAttestationDepth() should pass with unicode: %v", err)
	}
}

func TestValidateAttestationDepth_EmptyContainers(t *testing.T) {
	tests := []struct {
		name string
		json string
	}{
		{"empty object", `{}`},
		{"empty array", `[]`},
		{"nested empty objects", `{"a": {"b": {"c": {}}}}`},
		{"nested empty arrays", `[[[[]]]]`},
		{"mixed empty", `{"a": [], "b": {}}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateAttestationDepth([]byte(tt.json))
			if err != nil {
				t.Errorf("ValidateAttestationDepth() unexpected error: %v", err)
			}
		})
	}
}

func TestValidateAttestationDepth_NullValues(t *testing.T) {
	json := `{"a": null, "b": {"c": null, "d": [null, null]}}`
	err := ValidateAttestationDepth([]byte(json))
	if err != nil {
		t.Errorf("ValidateAttestationDepth() should handle null values: %v", err)
	}
}

func TestValidateAttestationDepth_Numbers(t *testing.T) {
	json := `{"int": 42, "float": 3.14, "negative": -123, "scientific": 1.23e10, "nested": {"value": 999}}`
	err := ValidateAttestationDepth([]byte(json))
	if err != nil {
		t.Errorf("ValidateAttestationDepth() should handle numbers: %v", err)
	}
}

func TestValidateAttestationDepth_Booleans(t *testing.T) {
	json := `{"true": true, "false": false, "nested": {"bool": true}}`
	err := ValidateAttestationDepth([]byte(json))
	if err != nil {
		t.Errorf("ValidateAttestationDepth() should handle booleans: %v", err)
	}
}

func TestValidateAttestation_CombinedValidation(t *testing.T) {
	// Test that ValidateAttestation checks both size and depth
	tests := []struct {
		name    string
		data    []byte
		wantErr bool
	}{
		{
			name:    "valid small shallow",
			data:    []byte(`{"valid": true}`),
			wantErr: false,
		},
		{
			name:    "valid at size limit",
			data:    make([]byte, limits.Attestation.Bytes()),
			wantErr: false,
		},
		{
			name:    "exceeds size",
			data:    make([]byte, limits.Attestation.Bytes()+1),
			wantErr: true,
		},
		{
			name:    "exceeds depth",
			data:    []byte(generateNestedJSON(50)),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateAttestation(tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateAttestation() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateAttestationSize_ZeroSize(t *testing.T) {
	err := ValidateAttestationSize([]byte{})
	if err != nil {
		t.Errorf("ValidateAttestationSize() should accept empty data: %v", err)
	}
}

func TestValidateAttestationDepth_ComplexSigstoreBundle(t *testing.T) {
	// Simulates a realistic Sigstore bundle structure
	bundle := `{
		"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
		"verificationMaterial": {
			"certificate": {
				"rawBytes": "base64encoded"
			},
			"tlogEntries": [
				{
					"logIndex": "12345",
					"logId": {"keyId": "abc123"},
					"kindVersion": {"kind": "hashedrekord", "version": "0.0.1"},
					"integratedTime": "1234567890",
					"inclusionPromise": {"signedEntryTimestamp": "base64"},
					"inclusionProof": {
						"logIndex": "12345",
						"rootHash": "abc",
						"treeSize": "1000",
						"hashes": ["a", "b", "c"]
					},
					"canonicalizedBody": "base64"
				}
			]
		},
		"dsseEnvelope": {
			"payloadType": "application/vnd.in-toto+json",
			"payload": "base64encoded",
			"signatures": [
				{"sig": "base64", "keyid": ""}
			]
		}
	}`

	err := ValidateAttestationDepth([]byte(bundle))
	if err != nil {
		t.Errorf("ValidateAttestationDepth() should pass for realistic bundle: %v", err)
	}
}
