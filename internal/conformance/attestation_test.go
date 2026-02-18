package conformance

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/locktivity/epack/internal/intoto"
)

func TestAttestationValidBundle(t *testing.T) {
	SkipIfNoVectors(t)

	raw, err := LoadVectorRaw("attestation", "valid-attestation.json")
	if err != nil {
		t.Fatalf("failed to load valid-attestation.json: %v", err)
	}

	var v AttestationVector
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("failed to parse vector: %v", err)
	}

	// Parse the bundle structure
	var bundle struct {
		MediaType            string `json:"mediaType"`
		VerificationMaterial struct {
			X509CertificateChain struct {
				Certificates []struct {
					RawBytes string `json:"rawBytes"`
				} `json:"certificates"`
			} `json:"x509CertificateChain"`
			TlogEntries []struct {
				LogIndex string `json:"logIndex"`
			} `json:"tlogEntries"`
		} `json:"verificationMaterial"`
		DSSEEnvelope struct {
			PayloadType string `json:"payloadType"`
			Payload     string `json:"payload"`
			Signatures  []struct {
				Sig   string `json:"sig"`
				KeyID string `json:"keyid"`
			} `json:"signatures"`
		} `json:"dsseEnvelope"`
	}
	if err := json.Unmarshal(v.Input.Bundle, &bundle); err != nil {
		t.Fatalf("failed to parse bundle: %v", err)
	}

	// Verify expected structure
	t.Run("media_type", func(t *testing.T) {
		expected := "application/vnd.dev.sigstore.bundle.v0.3+json"
		if bundle.MediaType != expected {
			t.Errorf("mediaType = %q, want %q", bundle.MediaType, expected)
		}
	})

	t.Run("verification_material_present", func(t *testing.T) {
		if len(bundle.VerificationMaterial.X509CertificateChain.Certificates) == 0 &&
			len(bundle.VerificationMaterial.TlogEntries) == 0 {
			t.Error("verificationMaterial should have certificate chain or tlog entries")
		}
	})

	t.Run("dsse_envelope_present", func(t *testing.T) {
		if bundle.DSSEEnvelope.PayloadType == "" {
			t.Error("dsseEnvelope.payloadType should be present")
		}
		if bundle.DSSEEnvelope.Payload == "" {
			t.Error("dsseEnvelope.payload should be present")
		}
	})

	t.Run("payload_type", func(t *testing.T) {
		expected := "application/vnd.in-toto+json"
		if bundle.DSSEEnvelope.PayloadType != expected {
			t.Errorf("payloadType = %q, want %q", bundle.DSSEEnvelope.PayloadType, expected)
		}
	})

	t.Run("payload_decodes", func(t *testing.T) {
		decoded, err := base64.StdEncoding.DecodeString(bundle.DSSEEnvelope.Payload)
		if err != nil {
			t.Fatalf("failed to decode payload: %v", err)
		}

		var statement struct {
			Type          string `json:"_type"`
			PredicateType string `json:"predicateType"`
			Subject       []struct {
				Name   string            `json:"name"`
				Digest map[string]string `json:"digest"`
			} `json:"subject"`
			Predicate struct {
				PackDigest string `json:"pack_digest"`
				Stream     string `json:"stream"`
			} `json:"predicate"`
		}
		if err := json.Unmarshal(decoded, &statement); err != nil {
			t.Fatalf("failed to parse in-toto statement: %v", err)
		}

		// Verify statement type
		if statement.Type != intoto.StatementType {
			t.Errorf("statement _type = %q, want %q", statement.Type, intoto.StatementType)
		}

		// Verify predicate type
		if statement.PredicateType != intoto.EvidencePackPredicateType {
			t.Errorf("predicateType = %q, want %q", statement.PredicateType, intoto.EvidencePackPredicateType)
		}

		// Verify subject is present
		if len(statement.Subject) == 0 {
			t.Error("statement should have at least one subject")
		}

		// Verify predicate has pack_digest
		if statement.Predicate.PackDigest == "" {
			t.Error("predicate.pack_digest should be present")
		}
	})
}

func TestAttestationInvalidMediaType(t *testing.T) {
	SkipIfNoVectors(t)

	raw, err := LoadVectorRaw("attestation", "invalid-media-type.json")
	if err != nil {
		t.Skipf("invalid-media-type.json not found: %v", err)
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
			var bundle struct {
				MediaType string `json:"mediaType"`
			}
			if err := json.Unmarshal(tc.Input, &bundle); err != nil {
				t.Fatalf("failed to parse bundle: %v", err)
			}

			// Validate media type
			validMediaType := bundle.MediaType == "application/vnd.dev.sigstore.bundle.v0.3+json" ||
				strings.HasPrefix(bundle.MediaType, "application/vnd.dev.sigstore.bundle")

			if tc.Valid && !validMediaType {
				t.Errorf("expected valid media type but got: %s", bundle.MediaType)
			}
			if !tc.Valid && validMediaType {
				t.Errorf("expected invalid media type (error: %s) but was valid: %s",
					tc.ExpectedError, bundle.MediaType)
			}
		})
	}
}

func TestAttestationMissingVerificationMaterial(t *testing.T) {
	SkipIfNoVectors(t)

	raw, err := LoadVectorRaw("attestation", "missing-verification-material.json")
	if err != nil {
		t.Skipf("missing-verification-material.json not found: %v", err)
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
			var bundle struct {
				VerificationMaterial *json.RawMessage `json:"verificationMaterial"`
			}
			if err := json.Unmarshal(tc.Input, &bundle); err != nil {
				t.Fatalf("failed to parse bundle: %v", err)
			}

			hasVerificationMaterial := bundle.VerificationMaterial != nil

			if tc.Valid && !hasVerificationMaterial {
				t.Errorf("expected valid bundle with verificationMaterial")
			}
			if !tc.Valid && hasVerificationMaterial {
				t.Errorf("expected invalid bundle (error: %s) but has verificationMaterial",
					tc.ExpectedError)
			}
		})
	}
}

func TestAttestationMissingDSSEEnvelope(t *testing.T) {
	SkipIfNoVectors(t)

	raw, err := LoadVectorRaw("attestation", "missing-dsse-envelope.json")
	if err != nil {
		t.Skipf("missing-dsse-envelope.json not found: %v", err)
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
			var bundle struct {
				DSSEEnvelope *json.RawMessage `json:"dsseEnvelope"`
			}
			if err := json.Unmarshal(tc.Input, &bundle); err != nil {
				t.Fatalf("failed to parse bundle: %v", err)
			}

			hasDSSEEnvelope := bundle.DSSEEnvelope != nil

			if tc.Valid && !hasDSSEEnvelope {
				t.Errorf("expected valid bundle with dsseEnvelope")
			}
			if !tc.Valid && hasDSSEEnvelope {
				t.Errorf("expected invalid bundle (error: %s) but has dsseEnvelope",
					tc.ExpectedError)
			}
		})
	}
}

func TestAttestationInvalidType(t *testing.T) {
	SkipIfNoVectors(t)

	raw, err := LoadVectorRaw("attestation", "invalid-type.json")
	if err != nil {
		t.Skipf("invalid-type.json not found: %v", err)
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
			// Parse bundle and decode payload to check statement type
			var bundle struct {
				DSSEEnvelope struct {
					Payload string `json:"payload"`
				} `json:"dsseEnvelope"`
			}
			if err := json.Unmarshal(tc.Input, &bundle); err != nil {
				t.Fatalf("failed to parse bundle: %v", err)
			}

			decoded, err := base64.StdEncoding.DecodeString(bundle.DSSEEnvelope.Payload)
			if err != nil {
				// Can't decode - might be intentionally invalid
				if tc.Valid {
					t.Errorf("expected valid payload but decode failed: %v", err)
				}
				return
			}

			var statement struct {
				Type          string `json:"_type"`
				PredicateType string `json:"predicateType"`
			}
			if err := json.Unmarshal(decoded, &statement); err != nil {
				if tc.Valid {
					t.Errorf("expected valid statement but parse failed: %v", err)
				}
				return
			}

			// Check if types are valid
			validType := statement.Type == intoto.StatementType
			validPredicateType := statement.PredicateType == intoto.EvidencePackPredicateType

			isValid := validType && validPredicateType
			if tc.Valid && !isValid {
				t.Errorf("expected valid types but got _type=%q predicateType=%q",
					statement.Type, statement.PredicateType)
			}
			if !tc.Valid && isValid {
				t.Errorf("expected invalid types (error: %s) but both are valid",
					tc.ExpectedError)
			}
		})
	}
}

func TestAttestationPlacement(t *testing.T) {
	SkipIfNoVectors(t)

	raw, err := LoadVectorRaw("attestation", "attestation-placement.json")
	if err != nil {
		t.Skipf("attestation-placement.json not found: %v", err)
	}

	var v struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		Tests       []struct {
			Name          string   `json:"name"`
			Path          string   `json:"path"`
			Attestations  []string `json:"attestations"` // For multiple_signers test case
			Valid         bool     `json:"valid"`
			ExpectedError string   `json:"expected_error"`
			Description   string   `json:"description"`
		} `json:"tests"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("failed to parse vector: %v", err)
	}

	for _, tc := range v.Tests {
		t.Run(tc.Name, func(t *testing.T) {
			// Collect all paths to validate (either single path or multiple attestations)
			var paths []string
			if tc.Path != "" {
				paths = append(paths, tc.Path)
			}
			paths = append(paths, tc.Attestations...)

			// For empty paths, it's invalid unless the test expects it to be invalid
			if len(paths) == 0 {
				if tc.Valid {
					t.Errorf("test case has no paths to validate but expects valid")
				}
				return
			}

			// Validate all paths
			allValid := true
			for _, path := range paths {
				isValidPath := strings.HasPrefix(path, "attestations/") &&
					strings.HasSuffix(path, ".sigstore.json") &&
					!strings.Contains(strings.TrimPrefix(path, "attestations/"), "/")
				if !isValidPath {
					allValid = false
					break
				}
			}

			if tc.Valid && !allValid {
				t.Errorf("expected valid paths but validation failed: %v", paths)
			}
			if !tc.Valid && allValid {
				t.Errorf("expected invalid path (error: %s) but was valid: %v",
					tc.ExpectedError, paths)
			}
		})
	}
}
