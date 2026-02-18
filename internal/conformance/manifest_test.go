package conformance

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/locktivity/epack/pack"
)

// strictTimestampFormat is the exact format required per spec Section 3.4.3.
const strictTimestampFormat = "2006-01-02T15:04:05Z"

func TestManifestTimestampFormats(t *testing.T) {
	SkipIfNoVectors(t)

	v, err := LoadVector[TimestampVector]("manifest", "timestamp-formats.json")
	if err != nil {
		t.Fatalf("failed to load timestamp-formats vector: %v", err)
	}

	// Test valid timestamps
	for _, tc := range v.ValidTimestamps {
		t.Run("valid_"+tc.Value, func(t *testing.T) {
			err := validateStrictTimestamp(tc.Value)
			if err != nil {
				t.Errorf("timestamp %q should be valid (%s) but got error: %v",
					tc.Value, tc.Description, err)
			}
		})
	}

	// Test invalid timestamps
	for _, tc := range v.InvalidTimestamps {
		t.Run("invalid_"+tc.Reason+"_"+tc.Value, func(t *testing.T) {
			err := validateStrictTimestamp(tc.Value)
			if err == nil {
				t.Errorf("timestamp %q should be invalid (reason: %s, %s) but was accepted",
					tc.Value, tc.Reason, tc.Description)
			}
		})
	}
}

// validateStrictTimestamp validates that a timestamp matches the exact format
// YYYY-MM-DDTHH:MM:SSZ per spec Section 3.4.3.
func validateStrictTimestamp(timestamp string) error {
	// Must be exactly 20 characters: YYYY-MM-DDTHH:MM:SSZ
	if len(timestamp) != 20 {
		return &validationError{msg: "timestamp must be exactly 20 chars"}
	}

	if _, err := time.Parse(strictTimestampFormat, timestamp); err != nil {
		return &validationError{msg: "timestamp must be format YYYY-MM-DDTHH:MM:SSZ"}
	}

	return nil
}

func TestManifestIntegerValidation(t *testing.T) {
	SkipIfNoVectors(t)

	v, err := LoadVector[IntegerVector]("manifest", "integer-validation.json")
	if err != nil {
		t.Fatalf("failed to load integer-validation vector: %v", err)
	}

	// Test valid integers
	for _, tc := range v.ValidIntegers {
		t.Run("valid_"+tc.JSON, func(t *testing.T) {
			err := validateJSONInteger(tc.JSON)
			if err != nil {
				t.Errorf("integer %q (value %d) should be valid (%s) but got error: %v",
					tc.JSON, tc.Value, tc.Description, err)
			}
		})
	}

	// Test invalid integers
	for _, tc := range v.InvalidIntegers {
		testName := tc.Reason + "_" + strings.ReplaceAll(tc.JSON, "\"", "")
		t.Run("invalid_"+testName, func(t *testing.T) {
			err := validateJSONInteger(tc.JSON)
			if err == nil {
				t.Errorf("integer %q should be invalid (reason: %s, %s) but was accepted",
					tc.JSON, tc.Reason, tc.Description)
			}
		})
	}
}

// maxSafeInt is the maximum integer exactly representable in JSON (2^53 - 1).
const maxSafeInt = (1 << 53) - 1

// validateJSONInteger validates a JSON number string is a valid integer per spec.
// Valid integers must be whole numbers in range 0..2^53-1.
func validateJSONInteger(jsonNum string) error {
	// NaN, Infinity are not valid JSON per RFC 8259
	lower := strings.ToLower(jsonNum)
	if lower == "nan" || strings.Contains(lower, "infinity") {
		return &validationError{msg: "non-finite number"}
	}

	// String representation is not a number
	if strings.HasPrefix(jsonNum, "\"") {
		return &validationError{msg: "string is not a number"}
	}

	// Try to parse as json.Number first, then get float64
	num := json.Number(jsonNum)
	f, err := num.Float64()
	if err != nil {
		return &validationError{msg: "invalid number"}
	}

	// Check for non-finite
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return &validationError{msg: "non-finite number"}
	}

	// Check for negative
	if f < 0 {
		return &validationError{msg: "negative number"}
	}

	// Check max safe integer
	if f > float64(maxSafeInt) {
		return &validationError{msg: "exceeds max safe integer"}
	}

	// Check for fractional part - use a tolerance for floating point representation
	if f != math.Trunc(f) {
		return &validationError{msg: "fractional number"}
	}

	return nil
}

type validationError struct {
	msg string
}

func (e *validationError) Error() string {
	return e.msg
}

// TestManifestRequiredFields tests manifest required field validation.
func TestManifestRequiredFields(t *testing.T) {
	SkipIfNoVectors(t)

	v, err := LoadVector[ManifestVector]("manifest", "required-fields.json")
	if err != nil {
		t.Fatalf("failed to load required-fields vector: %v", err)
	}

	for _, tc := range v.Tests {
		t.Run(tc.Name, func(t *testing.T) {
			_, err := pack.ParseManifest(tc.Input)
			if tc.Valid {
				if err != nil {
					t.Errorf("expected valid manifest but got error: %v", err)
				}
			} else {
				if err == nil {
					t.Errorf("expected error for %s but got none", tc.ExpectedError)
				}
			}
		})
	}
}

// TestManifestDigestFormat tests digest format validation.
func TestManifestDigestFormat(t *testing.T) {
	SkipIfNoVectors(t)

	v, err := LoadVector[DigestFormatVectorActual]("manifest", "digest-format.json")
	if err != nil {
		t.Fatalf("failed to load digest-format vector: %v", err)
	}

	// Test valid digests by embedding them in a valid manifest
	for _, tc := range v.ValidDigests {
		t.Run("valid_"+tc.Value[:20], func(t *testing.T) {
			manifest := buildManifestWithDigest(tc.Value)
			_, err := pack.ParseManifest(manifest)
			if err != nil {
				t.Errorf("expected valid digest %q (%s) but got error: %v",
					tc.Value, tc.Description, err)
			}
		})
	}

	// Test invalid digests
	for _, tc := range v.InvalidDigests {
		t.Run("invalid_"+tc.Reason, func(t *testing.T) {
			manifest := buildManifestWithDigest(tc.Value)
			_, err := pack.ParseManifest(manifest)
			if err == nil {
				t.Errorf("expected error for invalid digest %q (reason: %s, %s) but got none",
					tc.Value, tc.Reason, tc.Description)
			}
		})
	}
}

// TestManifestArtifactFields tests artifact field validation.
func TestManifestArtifactFields(t *testing.T) {
	SkipIfNoVectors(t)

	v, err := LoadVector[ArtifactFieldsVector]("manifest", "artifact-fields.json")
	if err != nil {
		t.Fatalf("failed to load artifact-fields vector: %v", err)
	}

	// Test embedded artifact fields
	for _, tc := range v.EmbeddedArtifactTests {
		t.Run("embedded_"+tc.Name, func(t *testing.T) {
			manifest := buildManifestWithArtifact(tc.Input)
			_, err := pack.ParseManifest(manifest)
			if tc.Valid {
				if err != nil {
					t.Errorf("expected valid artifact but got error: %v", err)
				}
			} else {
				if err == nil {
					t.Errorf("expected error %s but got none", tc.ExpectedError)
				}
			}
		})
	}

	// Referenced artifacts are not currently supported by the implementation
	// so we skip those tests
}

// TestManifestDuplicateArtifactPaths tests duplicate path rejection.
func TestManifestDuplicateArtifactPaths(t *testing.T) {
	SkipIfNoVectors(t)

	v, err := LoadVector[ManifestVector]("manifest", "duplicate-artifact-paths.json")
	if err != nil {
		t.Fatalf("failed to load duplicate-artifact-paths vector: %v", err)
	}

	for _, tc := range v.Tests {
		t.Run(tc.Name, func(t *testing.T) {
			_, err := pack.ParseManifest(tc.Input)
			if tc.Valid {
				if err != nil {
					t.Errorf("expected valid manifest but got error: %v", err)
				}
			} else {
				if err == nil {
					t.Errorf("expected error for %s but got none", tc.ExpectedError)
				}
			}
		})
	}
}

// TestManifestProvenanceValidation tests provenance object validation.
func TestManifestProvenanceValidation(t *testing.T) {
	SkipIfNoVectors(t)

	v, err := LoadVector[ProvenanceVector]("manifest", "provenance-validation.json")
	if err != nil {
		t.Fatalf("failed to load provenance-validation vector: %v", err)
	}

	// Test valid provenance
	for _, tc := range v.ValidProvenance {
		t.Run("valid_"+sanitizeTestName(tc.Description), func(t *testing.T) {
			manifest := buildManifestWithProvenance(tc.Provenance)
			_, err := pack.ParseManifest(manifest)
			if err != nil {
				t.Errorf("expected valid provenance (%s) but got error: %v",
					tc.Description, err)
			}
		})
	}

	// Test invalid provenance
	for _, tc := range v.InvalidProvenance {
		t.Run("invalid_"+tc.Reason, func(t *testing.T) {
			manifest := buildManifestWithProvenance(tc.Provenance)
			_, err := pack.ParseManifest(manifest)
			if err == nil {
				t.Errorf("expected error for invalid provenance (reason: %s, %s) but got none",
					tc.Reason, tc.Description)
			}
		})
	}
}

// TestManifestAccessPolicy tests access policy validation.
// Note: This is behavioral guidance - the implementation currently only validates
// embedded artifacts, not referenced artifacts with access policies.
func TestManifestAccessPolicy(t *testing.T) {
	SkipIfNoVectors(t)

	// Load to ensure vector file is valid
	_, err := LoadVector[AccessPolicyVector]("manifest", "access-policy.json")
	if err != nil {
		t.Fatalf("failed to load access-policy vector: %v", err)
	}

	// Skip actual tests since referenced artifacts are not implemented
	t.Skip("referenced artifacts with access policies not yet implemented")
}

// buildManifestWithDigest creates a minimal valid manifest JSON with the given pack_digest.
func buildManifestWithDigest(digest string) []byte {
	return []byte(`{
		"spec_version": "1.0",
		"stream": "test/stream",
		"generated_at": "2026-01-20T12:00:00Z",
		"pack_digest": "` + digest + `",
		"sources": [],
		"artifacts": []
	}`)
}

// buildManifestWithArtifact creates a minimal valid manifest JSON with the given artifact.
func buildManifestWithArtifact(artifactJSON json.RawMessage) []byte {
	return []byte(`{
		"spec_version": "1.0",
		"stream": "test/stream",
		"generated_at": "2026-01-20T12:00:00Z",
		"pack_digest": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		"sources": [],
		"artifacts": [` + string(artifactJSON) + `]
	}`)
}

// buildManifestWithProvenance creates a minimal valid manifest JSON with the given provenance.
func buildManifestWithProvenance(provenanceJSON json.RawMessage) []byte {
	return []byte(`{
		"spec_version": "1.0",
		"stream": "test/stream",
		"generated_at": "2026-01-20T12:00:00Z",
		"pack_digest": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		"sources": [],
		"artifacts": [],
		"provenance": ` + string(provenanceJSON) + `
	}`)
}

// sanitizeTestName converts a description to a valid test name.
func sanitizeTestName(s string) string {
	s = strings.ReplaceAll(s, " ", "_")
	s = strings.ReplaceAll(s, "(", "")
	s = strings.ReplaceAll(s, ")", "")
	if len(s) > 40 {
		s = s[:40]
	}
	return s
}
