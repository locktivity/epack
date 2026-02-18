package verify

import (
	"encoding/json"
	"testing"
)

// FuzzVerifyStatementSemantics tests that VerifyStatementSemantics handles
// arbitrary statement payloads without panicking and properly validates
// all semantic requirements.
func FuzzVerifyStatementSemantics(f *testing.F) {
	// Seed corpus with various statement patterns
	f.Add(`{}`, "sha256:abc123")
	f.Add(`{"_type":"https://in-toto.io/Statement/v1"}`, "sha256:abc123")
	f.Add(`{"predicateType":"https://evidencepack.org/attestation/v1"}`, "sha256:abc123")
	f.Add(`{"predicate":{}}`, "sha256:abc123")
	f.Add(`{"predicate":{"pack_digest":"sha256:abc123"}}`, "sha256:abc123")
	f.Add(`null`, "sha256:abc123")
	f.Add(`[]`, "sha256:abc123")
	f.Add(`"string"`, "sha256:abc123")
	f.Add(`{"_type":"wrong","predicateType":"wrong"}`, "sha256:abc123")

	// Valid statement structure
	validStatement := `{
		"_type": "https://in-toto.io/Statement/v1",
		"predicateType": "https://evidencepack.org/attestation/v1",
		"subject": [{"name": "pack", "digest": {"sha256": "abc123"}}],
		"predicate": {"pack_digest": "sha256:abc123"}
	}`
	f.Add(validStatement, "sha256:abc123")

	// Attack vectors - wrong types
	f.Add(`{"_type": "https://in-toto.io/Statement/v0.1"}`, "sha256:abc123")
	f.Add(`{"predicateType": "https://slsa.dev/provenance/v1"}`, "sha256:abc123")

	f.Fuzz(func(t *testing.T, statementJSON string, expectedDigest string) {
		// Try to parse as a statement-like structure
		var parsed struct {
			Type          string          `json:"_type"`
			PredicateType string          `json:"predicateType"`
			Subjects      []Subject       `json:"subject"`
			Predicate     json.RawMessage `json:"predicate"`
		}

		if err := json.Unmarshal([]byte(statementJSON), &parsed); err != nil {
			// Invalid JSON - test with nil statement
			result := &Result{Verified: true, Statement: nil}
			err := VerifyStatementSemantics(result, expectedDigest)
			if err == nil {
				t.Error("should reject nil statement")
			}
			return
		}

		// Create result from parsed data
		result := &Result{
			Verified: true,
			Statement: &Statement{
				Type:          parsed.Type,
				PredicateType: parsed.PredicateType,
				Subjects:      parsed.Subjects,
				Predicate:     parsed.Predicate,
			},
		}

		// Call should not panic
		err := VerifyStatementSemantics(result, expectedDigest)

		// Verify security invariants
		if err == nil {
			// If accepted, verify all semantic requirements are met
			if result.Statement.Type != "https://in-toto.io/Statement/v1" {
				t.Errorf("accepted wrong statement type: %s", result.Statement.Type)
			}
			if result.Statement.PredicateType != "https://evidencepack.org/attestation/v1" {
				t.Errorf("accepted wrong predicate type: %s", result.Statement.PredicateType)
			}
			if len(result.Statement.Subjects) == 0 {
				t.Error("accepted empty subjects")
			}

			// Verify predicate pack_digest matches
			var pred struct {
				PackDigest string `json:"pack_digest"`
			}
			if json.Unmarshal(result.Statement.Predicate, &pred) == nil {
				if pred.PackDigest != expectedDigest {
					t.Errorf("accepted mismatched predicate pack_digest: %s vs %s", pred.PackDigest, expectedDigest)
				}
			}

			// Verify at least one subject matches
			matched := false
			for _, subj := range result.Statement.Subjects {
				for algo, digest := range subj.Digest {
					if algo+":"+digest == expectedDigest {
						matched = true
						break
					}
				}
			}
			if !matched {
				t.Errorf("accepted statement without matching subject digest")
			}
		}
	})
}

// FuzzVerifyPredicatePackDigest tests predicate parsing with arbitrary JSON.
func FuzzVerifyPredicatePackDigest(f *testing.F) {
	f.Add([]byte(`{}`), "sha256:abc123")
	f.Add([]byte(`{"pack_digest":"sha256:abc123"}`), "sha256:abc123")
	f.Add([]byte(`{"pack_digest":"sha256:wrong"}`), "sha256:abc123")
	f.Add([]byte(`{"pack_digest":null}`), "sha256:abc123")
	f.Add([]byte(`{"pack_digest":123}`), "sha256:abc123")
	f.Add([]byte(`null`), "sha256:abc123")
	f.Add([]byte(`[]`), "sha256:abc123")
	f.Add([]byte(``), "sha256:abc123")

	f.Fuzz(func(t *testing.T, predicateJSON []byte, expectedDigest string) {
		// Should not panic
		err := verifyPredicatePackDigest(predicateJSON, expectedDigest)

		// If accepted, verify the digest actually matches
		if err == nil {
			var pred struct {
				PackDigest string `json:"pack_digest"`
			}
			if json.Unmarshal(predicateJSON, &pred) == nil {
				if pred.PackDigest != expectedDigest {
					t.Errorf("accepted mismatched pack_digest: got %q, expected %q", pred.PackDigest, expectedDigest)
				}
			}
		}
	})
}

// FuzzVerifySubjectDigest tests subject digest matching with arbitrary subjects.
func FuzzVerifySubjectDigest(f *testing.F) {
	f.Add("sha256", "abc123", "sha256:abc123")
	f.Add("sha256", "wrong", "sha256:abc123")
	f.Add("sha512", "abc123", "sha256:abc123")
	f.Add("", "", "sha256:abc123")

	f.Fuzz(func(t *testing.T, algo, digest, expectedDigest string) {
		subjects := []Subject{
			{
				Name:   "pack",
				Digest: map[string]string{algo: digest},
			},
		}

		// Should not panic
		err := verifySubjectDigest(subjects, expectedDigest)

		// If accepted, verify the digest actually matches
		if err == nil {
			fullDigest := algo + ":" + digest
			if fullDigest != expectedDigest {
				t.Errorf("accepted mismatched subject digest: got %q, expected %q", fullDigest, expectedDigest)
			}
		}
	})
}
