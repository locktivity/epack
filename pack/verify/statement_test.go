package verify

import (
	"testing"

	epkgerrors "github.com/locktivity/epack/errors"
	"github.com/locktivity/epack/internal/intoto"
)

func TestVerifyStatementSemantics_NilStatement(t *testing.T) {
	result := &Result{
		Statement: nil,
	}

	err := VerifyStatementSemantics(result, "sha256:abc123")
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if got := epkgerrors.CodeOf(err); got != epkgerrors.SignatureInvalid {
		t.Fatalf("CodeOf(err) = %q, want %q", got, epkgerrors.SignatureInvalid)
	}
}

func TestVerifyStatementSemantics_WrongStatementType(t *testing.T) {
	result := &Result{
		Statement: &Statement{
			Type:          "https://wrong.type/v1",
			PredicateType: intoto.EvidencePackPredicateType,
			Subjects: []Subject{
				{Name: "manifest.json", Digest: map[string]string{"sha256": "abc123"}},
			},
			Predicate: []byte(`{"pack_digest":"sha256:xyz"}`),
		},
	}

	err := VerifyStatementSemantics(result, "sha256:abc123")
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if got := epkgerrors.CodeOf(err); got != epkgerrors.SignatureInvalid {
		t.Fatalf("CodeOf(err) = %q, want %q", got, epkgerrors.SignatureInvalid)
	}
}

func TestVerifyStatementSemantics_WrongPredicateType(t *testing.T) {
	result := &Result{
		Statement: &Statement{
			Type:          intoto.StatementType,
			PredicateType: "https://wrong.predicate/v1",
			Subjects: []Subject{
				{Name: "manifest.json", Digest: map[string]string{"sha256": "abc123"}},
			},
			Predicate: []byte(`{"pack_digest":"sha256:xyz"}`),
		},
	}

	err := VerifyStatementSemantics(result, "sha256:abc123")
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if got := epkgerrors.CodeOf(err); got != epkgerrors.SignatureInvalid {
		t.Fatalf("CodeOf(err) = %q, want %q", got, epkgerrors.SignatureInvalid)
	}
}

func TestVerifyStatementSemantics_Success(t *testing.T) {
	// manifest digest in subject, empty predicate per spec
	manifestDigest := "sha256:abc123"
	result := &Result{
		Statement: &Statement{
			Type:          intoto.StatementType,
			PredicateType: intoto.EvidencePackPredicateType,
			Subjects: []Subject{
				{Name: "manifest.json", Digest: map[string]string{"sha256": "abc123"}},
			},
			Predicate: []byte(`{}`),
		},
	}

	err := VerifyStatementSemantics(result, manifestDigest)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestVerifyStatementSemantics_NoSubjects(t *testing.T) {
	result := &Result{
		Statement: &Statement{
			Type:          intoto.StatementType,
			PredicateType: intoto.EvidencePackPredicateType,
			Subjects:      []Subject{}, // Empty subjects - spec requires exactly 1
			Predicate:     []byte(`{}`),
		},
	}

	err := VerifyStatementSemantics(result, "sha256:abc123")
	if err == nil {
		t.Fatal("expected error for no subjects, got nil")
	}

	if got := epkgerrors.CodeOf(err); got != epkgerrors.SignatureInvalid {
		t.Fatalf("CodeOf(err) = %q, want %q", got, epkgerrors.SignatureInvalid)
	}
}

func TestVerifyStatementSemantics_SubjectDigestNotMatch(t *testing.T) {
	result := &Result{
		Statement: &Statement{
			Type:          intoto.StatementType,
			PredicateType: intoto.EvidencePackPredicateType,
			Subjects: []Subject{
				// Subject digest is "different" but we expect "abc123"
				{Name: "manifest.json", Digest: map[string]string{"sha256": "different"}},
			},
			Predicate: []byte(`{}`),
		},
	}

	err := VerifyStatementSemantics(result, "sha256:abc123")
	if err == nil {
		t.Fatal("expected error for subject digest mismatch, got nil")
	}

	if got := epkgerrors.CodeOf(err); got != epkgerrors.SignatureInvalid {
		t.Fatalf("CodeOf(err) = %q, want %q", got, epkgerrors.SignatureInvalid)
	}
}

func TestVerifyStatementSemantics_MultipleSubjectsRejected(t *testing.T) {
	// Spec requires exactly 1 subject
	manifestDigest := "sha256:abc123"
	result := &Result{
		Statement: &Statement{
			Type:          intoto.StatementType,
			PredicateType: intoto.EvidencePackPredicateType,
			Subjects: []Subject{
				{Name: "other.json", Digest: map[string]string{"sha256": "other"}},
				{Name: "manifest.json", Digest: map[string]string{"sha256": "abc123"}},
			},
			Predicate: []byte(`{}`),
		},
	}

	err := VerifyStatementSemantics(result, manifestDigest)
	if err == nil {
		t.Fatal("expected error for multiple subjects, got nil")
	}

	if got := epkgerrors.CodeOf(err); got != epkgerrors.SignatureInvalid {
		t.Fatalf("CodeOf(err) = %q, want %q", got, epkgerrors.SignatureInvalid)
	}
}

func TestVerifyStatementSemantics_SubjectWithMultipleDigests(t *testing.T) {
	// Subject can have multiple digests, we only verify sha256
	manifestDigest := "sha256:abc123"
	result := &Result{
		Statement: &Statement{
			Type:          intoto.StatementType,
			PredicateType: intoto.EvidencePackPredicateType,
			Subjects: []Subject{
				{
					Name: "manifest.json",
					Digest: map[string]string{
						"sha256": "abc123",
						"sha512": "def456",
					},
				},
			},
			Predicate: []byte(`{}`),
		},
	}

	err := VerifyStatementSemantics(result, manifestDigest)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestVerifyStatementSemantics_SHA512Rejected(t *testing.T) {
	// Spec requires sha256, not sha512
	hash512 := "a1b2c3d4e5f6a7b8a1b2c3d4e5f6a7b8a1b2c3d4e5f6a7b8a1b2c3d4e5f6a7b8a1b2c3d4e5f6a7b8a1b2c3d4e5f6a7b8a1b2c3d4e5f6a7b8a1b2c3d4e5f6a7b8"
	manifestDigest := "sha512:" + hash512

	result := &Result{
		Statement: &Statement{
			Type:          intoto.StatementType,
			PredicateType: intoto.EvidencePackPredicateType,
			Subjects: []Subject{
				{Name: "manifest.json", Digest: map[string]string{"sha512": hash512}},
			},
			Predicate: []byte(`{}`),
		},
	}

	err := VerifyStatementSemantics(result, manifestDigest)
	if err == nil {
		t.Fatal("expected error for sha512 digest, got nil")
	}

	if got := epkgerrors.CodeOf(err); got != epkgerrors.SignatureInvalid {
		t.Fatalf("CodeOf(err) = %q, want %q", got, epkgerrors.SignatureInvalid)
	}
}

// SECURITY REGRESSION TESTS
// These tests document and prevent algorithm substitution attacks.

// TestVerifySubjectDigest_AlgorithmMatching verifies that subject digest
// matching enforces SHA-256 only per spec.
// SECURITY: An attacker could include a weak algorithm (md5, sha1) alongside
// sha256 in the subject digests. We must only accept sha256.
func TestVerifySubjectDigest_AlgorithmMatching(t *testing.T) {
	tests := []struct {
		name           string
		subject        Subject
		expectedDigest string
		wantErr        bool
		description    string
	}{
		{
			name:           "sha256 matches sha256",
			subject:        Subject{Digest: map[string]string{"sha256": "abc123"}},
			expectedDigest: "sha256:abc123",
			wantErr:        false,
			description:    "Same algorithm and hash should match",
		},
		{
			name:           "sha256 expected but only md5 present",
			subject:        Subject{Digest: map[string]string{"md5": "abc123"}},
			expectedDigest: "sha256:abc123",
			wantErr:        true,
			description:    "SECURITY: Should not accept md5 when sha256 is expected",
		},
		{
			name: "sha256 expected with multiple algorithms present",
			subject: Subject{Digest: map[string]string{
				"md5":    "weakweakweakweakweakweakweakweak",
				"sha256": "abc123",
			}},
			expectedDigest: "sha256:abc123",
			wantErr:        false,
			description:    "Should match sha256 when present among other algorithms",
		},
		{
			name: "sha256 expected with only sha1 collision",
			subject: Subject{Digest: map[string]string{
				"sha1": "abc123", // Same hash value but wrong algorithm
			}},
			expectedDigest: "sha256:abc123",
			wantErr:        true,
			description:    "SECURITY: Should not match sha1 hash against sha256 expectation",
		},
		{
			name:           "empty subject digest map",
			subject:        Subject{Digest: map[string]string{}},
			expectedDigest: "sha256:abc123",
			wantErr:        true,
			description:    "Empty digest map should not match",
		},
		{
			name:           "nil subject digest map",
			subject:        Subject{Digest: nil},
			expectedDigest: "sha256:abc123",
			wantErr:        true,
			description:    "Nil digest map should not match",
		},
		{
			name:           "sha512 not allowed per spec",
			subject:        Subject{Digest: map[string]string{"sha512": "abc123def456"}},
			expectedDigest: "sha512:abc123def456",
			wantErr:        true,
			description:    "SHA-512 is not allowed - spec requires SHA-256 only",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := verifySubjectDigest(tt.subject, tt.expectedDigest)
			if (err != nil) != tt.wantErr {
				t.Errorf("%s: verifySubjectDigest() error = %v, wantErr %v",
					tt.description, err, tt.wantErr)
			}
		})
	}
}

// TestVerifySubjectDigest_WeakAlgorithmIsolation ensures that weak algorithms
// cannot be used to satisfy verification when sha256 is expected.
// SECURITY: This is critical - an attacker could craft a pack where:
// 1. The subject contains md5:attackerhash and sha256:legitimatehash
// 2. A weak parser might accept md5:attackerhash as matching sha256:attackerhash
// This test ensures we ONLY look at the sha256 entry.
func TestVerifySubjectDigest_WeakAlgorithmIsolation(t *testing.T) {
	// Attack scenario: attacker includes their controlled md5 hash alongside
	// the legitimate sha256 hash, hoping the verifier will accept the md5.
	attackerControlledMD5 := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0"
	legitimateSHA256 := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb11"

	subject := Subject{
		Name: "manifest.json",
		Digest: map[string]string{
			"md5":    attackerControlledMD5,
			"sha256": legitimateSHA256,
		},
	}

	// Expected digest is sha256 of the legitimate hash
	expectedDigest := "sha256:" + legitimateSHA256

	// This should succeed - matching the sha256
	err := verifySubjectDigest(subject, expectedDigest)
	if err != nil {
		t.Errorf("should match legitimate sha256: %v", err)
	}

	// Now try to trick verification with the md5 value
	// This MUST fail - the sha256 entry doesn't match
	trickyExpectedDigest := "sha256:" + attackerControlledMD5
	err = verifySubjectDigest(subject, trickyExpectedDigest)
	if err == nil {
		t.Error("SECURITY VULNERABILITY: accepted wrong sha256 hash value")
	}
}
