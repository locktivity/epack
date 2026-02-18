package conformance

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/locktivity/epack/internal/jcsutil"
	"github.com/locktivity/epack/pack"
)

func TestManifestDigestVectors(t *testing.T) {
	SkipIfNoVectors(t)

	files, err := ListVectorFiles("manifest-digest")
	if err != nil {
		t.Fatalf("failed to list manifest-digest vectors: %v", err)
	}

	for _, file := range files {
		t.Run(file, func(t *testing.T) {
			raw, err := LoadVectorRaw("manifest-digest", file)
			if err != nil {
				t.Fatalf("failed to load vector %s: %v", file, err)
			}

			// Try to parse as ManifestDigestVector
			var v ManifestDigestVector
			if err := json.Unmarshal(raw, &v); err != nil {
				t.Fatalf("failed to parse vector %s: %v", file, err)
			}

			// Skip if no manifest input
			if len(v.Input.Manifest) == 0 {
				t.Skipf("skipping vector without manifest input: %s", v.Name)
			}

			// Determine what kind of validation to apply based on the test case:
			// - For "invalid-numbers" and "invalid-exponent" tests, we use ParseManifest
			//   to check integer validation (these have invalid number values)
			// - For other tests, we primarily test JCS canonicalization
			//   (some test vectors have schema-incompatible field types for testing JCS behavior)

			// Try to canonicalize the manifest
			canonical, canonErr := jcsutil.Canonicalize(v.Input.Manifest)

			// For tests that are specifically about number validation, also check ParseManifest
			var parseErr error
			if strings.HasPrefix(file, "invalid-") {
				_, parseErr = pack.ParseManifest(v.Input.Manifest)
			}

			// The manifest is invalid if canonicalization fails, or if this is a number
			// validation test and parsing fails
			isInvalid := canonErr != nil || parseErr != nil

			if v.Valid {
				if canonErr != nil {
					t.Errorf("expected valid manifest but canonicalization failed: %v", canonErr)
				}
			} else {
				if !isInvalid {
					t.Errorf("expected invalid manifest but validation succeeded")
				}
				return
			}

			// Check canonical output if expected
			if v.Expected.JCSCanonical != "" {
				if string(canonical) != v.Expected.JCSCanonical {
					t.Errorf("JCS canonical mismatch for %s:\n  expected: %s\n  computed: %s",
						v.Name, v.Expected.JCSCanonical, string(canonical))
				}
			}

			// Check SHA-256 hash if expected
			if v.Expected.SHA256 != "" {
				h := sha256.Sum256(canonical)
				computed := hex.EncodeToString(h[:])
				if computed != v.Expected.SHA256 {
					t.Errorf("SHA-256 mismatch for %s:\n  expected: %s\n  computed: %s",
						v.Name, v.Expected.SHA256, computed)
				}
			}
		})
	}
}

func TestManifestDigestInvalidNumbers(t *testing.T) {
	SkipIfNoVectors(t)

	raw, err := LoadVectorRaw("manifest-digest", "invalid-numbers.json")
	if err != nil {
		t.Skipf("invalid-numbers.json not found: %v", err)
	}

	var v struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		Tests       []struct {
			Name          string          `json:"name"`
			Input         json.RawMessage `json:"input"`
			Valid         bool            `json:"valid"`
			ExpectedError string          `json:"expected_error"`
			Description   string          `json:"description"`
		} `json:"tests"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("failed to parse vector: %v", err)
	}

	for _, tc := range v.Tests {
		t.Run(tc.Name, func(t *testing.T) {
			_, err := jcsutil.Canonicalize(tc.Input)
			if tc.Valid {
				if err != nil {
					t.Errorf("expected valid but got error: %v", err)
				}
			} else {
				if err == nil {
					t.Errorf("expected invalid (error: %s) but canonicalization succeeded", tc.ExpectedError)
				}
			}
		})
	}
}

func TestManifestDigestMalformedJSON(t *testing.T) {
	SkipIfNoVectors(t)

	raw, err := LoadVectorRaw("manifest-digest", "malformed-json.json")
	if err != nil {
		t.Skipf("malformed-json.json not found: %v", err)
	}

	var v struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		Tests       []struct {
			Name          string `json:"name"`
			Input         string `json:"input"`     // Raw string for malformed JSON
			InputHex      string `json:"input_hex"` // Hex-encoded input for binary cases
			Valid         bool   `json:"valid"`
			ExpectedError string `json:"expected_error"`
			Description   string `json:"description"`
		} `json:"tests"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("failed to parse vector: %v", err)
	}

	for _, tc := range v.Tests {
		t.Run(tc.Name, func(t *testing.T) {
			// Get the input bytes (either from input string or input_hex)
			var input []byte
			if tc.InputHex != "" {
				input, err = hex.DecodeString(tc.InputHex)
				if err != nil {
					t.Fatalf("failed to decode input_hex: %v", err)
				}
			} else {
				input = []byte(tc.Input)
			}

			// For manifest digest computation, we need to:
			// 1. Parse as JSON
			// 2. Verify it's a JSON object (not array, null, string, or number)
			// 3. Canonicalize

			// First try to parse as generic JSON
			var parsed interface{}
			parseErr := json.Unmarshal(input, &parsed)

			// Check if it's a valid JSON object
			var isValidManifestJSON bool
			if parseErr == nil {
				_, isValidManifestJSON = parsed.(map[string]interface{})
			}

			// Now try canonicalization
			_, canonErr := jcsutil.Canonicalize(input)

			// The input is invalid if:
			// - JSON parsing failed, OR
			// - It's not a JSON object (for "invalid_manifest" errors), OR
			// - Canonicalization failed
			isInvalid := parseErr != nil || !isValidManifestJSON || canonErr != nil

			if tc.Valid {
				if isInvalid {
					t.Errorf("expected valid but got invalid (parseErr=%v, isObject=%v, canonErr=%v)",
						parseErr, isValidManifestJSON, canonErr)
				}
			} else {
				if !isInvalid {
					t.Errorf("expected invalid (error: %s) but succeeded", tc.ExpectedError)
				}
			}
		})
	}
}
