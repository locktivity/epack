package verify

import (
	stderrors "errors"
	"testing"

	epkgerrors "github.com/locktivity/epack/errors"
	"github.com/locktivity/epack/internal/intoto"
)

func TestVerifyStatementSemantics_InvalidPredicate_PreservesCause(t *testing.T) {
	result := &Result{
		Statement: &Statement{
			Type:          intoto.StatementType,
			PredicateType: intoto.EvidencePackPredicateType,
			Subjects: []Subject{
				{Name: "manifest.json", Digest: map[string]string{"sha256": "abc"}},
			},
			Predicate: []byte(`{"pack_digest":`), // malformed JSON
		},
	}

	err := VerifyStatementSemantics(result, "sha256:abc")
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if got := epkgerrors.CodeOf(err); got != epkgerrors.SignatureInvalid {
		t.Fatalf("CodeOf(err) = %q, want %q", got, epkgerrors.SignatureInvalid)
	}

	// Ensure cause chain is preserved for callers that inspect root failure.
	// The coded error should wrap the JSON parse error.
	var coded *epkgerrors.Error
	if !stderrors.As(err, &coded) {
		t.Fatalf("expected *epkgerrors.Error, got %T", err)
	}
	if coded.Unwrap() == nil {
		t.Fatalf("expected wrapped parse cause, but Unwrap() returned nil")
	}
}

func TestVerifyStatementSemantics_NilStatement(t *testing.T) {
	result := &Result{
		Statement: nil,
	}

	err := VerifyStatementSemantics(result, "sha256:abc")
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
				{Name: "manifest.json", Digest: map[string]string{"sha256": "abc"}},
			},
			Predicate: []byte(`{"pack_digest":"sha256:abc"}`),
		},
	}

	err := VerifyStatementSemantics(result, "sha256:abc")
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
				{Name: "manifest.json", Digest: map[string]string{"sha256": "abc"}},
			},
			Predicate: []byte(`{"pack_digest":"sha256:abc"}`),
		},
	}

	err := VerifyStatementSemantics(result, "sha256:abc")
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if got := epkgerrors.CodeOf(err); got != epkgerrors.SignatureInvalid {
		t.Fatalf("CodeOf(err) = %q, want %q", got, epkgerrors.SignatureInvalid)
	}
}

func TestVerifyStatementSemantics_DigestMismatch(t *testing.T) {
	result := &Result{
		Statement: &Statement{
			Type:          intoto.StatementType,
			PredicateType: intoto.EvidencePackPredicateType,
			Subjects: []Subject{
				{Name: "manifest.json", Digest: map[string]string{"sha256": "abc"}},
			},
			Predicate: []byte(`{"pack_digest":"sha256:different"}`),
		},
	}

	err := VerifyStatementSemantics(result, "sha256:abc")
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if got := epkgerrors.CodeOf(err); got != epkgerrors.SignatureInvalid {
		t.Fatalf("CodeOf(err) = %q, want %q", got, epkgerrors.SignatureInvalid)
	}
}

func TestVerifyStatementSemantics_Success(t *testing.T) {
	result := &Result{
		Statement: &Statement{
			Type:          intoto.StatementType,
			PredicateType: intoto.EvidencePackPredicateType,
			Subjects: []Subject{
				{Name: "manifest.json", Digest: map[string]string{"sha256": "abc123"}},
			},
			Predicate: []byte(`{"pack_digest":"sha256:abc123"}`),
		},
	}

	err := VerifyStatementSemantics(result, "sha256:abc123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestVerifyStatementSemantics_NoSubjects(t *testing.T) {
	result := &Result{
		Statement: &Statement{
			Type:          intoto.StatementType,
			PredicateType: intoto.EvidencePackPredicateType,
			Subjects:      []Subject{}, // Empty subjects
			Predicate:     []byte(`{"pack_digest":"sha256:abc123"}`),
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

func TestVerifyStatementSemantics_EmptyPredicate(t *testing.T) {
	result := &Result{
		Statement: &Statement{
			Type:          intoto.StatementType,
			PredicateType: intoto.EvidencePackPredicateType,
			Subjects: []Subject{
				{Name: "manifest.json", Digest: map[string]string{"sha256": "abc123"}},
			},
			Predicate: []byte{}, // Empty predicate
		},
	}

	err := VerifyStatementSemantics(result, "sha256:abc123")
	if err == nil {
		t.Fatal("expected error for empty predicate, got nil")
	}

	if got := epkgerrors.CodeOf(err); got != epkgerrors.SignatureInvalid {
		t.Fatalf("CodeOf(err) = %q, want %q", got, epkgerrors.SignatureInvalid)
	}
}

func TestVerifyStatementSemantics_PredicateMissingPackDigest(t *testing.T) {
	result := &Result{
		Statement: &Statement{
			Type:          intoto.StatementType,
			PredicateType: intoto.EvidencePackPredicateType,
			Subjects: []Subject{
				{Name: "manifest.json", Digest: map[string]string{"sha256": "abc123"}},
			},
			Predicate: []byte(`{"stream":"test/stream"}`), // Missing pack_digest
		},
	}

	err := VerifyStatementSemantics(result, "sha256:abc123")
	if err == nil {
		t.Fatal("expected error for missing pack_digest in predicate, got nil")
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
			Predicate: []byte(`{"pack_digest":"sha256:abc123"}`),
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

func TestVerifyStatementSemantics_MultipleSubjectsOneMatches(t *testing.T) {
	result := &Result{
		Statement: &Statement{
			Type:          intoto.StatementType,
			PredicateType: intoto.EvidencePackPredicateType,
			Subjects: []Subject{
				{Name: "other.json", Digest: map[string]string{"sha256": "other"}},
				{Name: "manifest.json", Digest: map[string]string{"sha256": "abc123"}}, // This one matches
			},
			Predicate: []byte(`{"pack_digest":"sha256:abc123"}`),
		},
	}

	err := VerifyStatementSemantics(result, "sha256:abc123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestVerifyStatementSemantics_SubjectWithMultipleDigests(t *testing.T) {
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
			Predicate: []byte(`{"pack_digest":"sha256:abc123"}`),
		},
	}

	err := VerifyStatementSemantics(result, "sha256:abc123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestVerifyStatementSemantics_SHA512Digest(t *testing.T) {
	hash512 := "a1b2c3d4e5f6a7b8a1b2c3d4e5f6a7b8a1b2c3d4e5f6a7b8a1b2c3d4e5f6a7b8a1b2c3d4e5f6a7b8a1b2c3d4e5f6a7b8a1b2c3d4e5f6a7b8a1b2c3d4e5f6a7b8"
	expectedDigest := "sha512:" + hash512

	result := &Result{
		Statement: &Statement{
			Type:          intoto.StatementType,
			PredicateType: intoto.EvidencePackPredicateType,
			Subjects: []Subject{
				{Name: "manifest.json", Digest: map[string]string{"sha512": hash512}},
			},
			Predicate: []byte(`{"pack_digest":"` + expectedDigest + `"}`),
		},
	}

	err := VerifyStatementSemantics(result, expectedDigest)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// SECURITY REGRESSION TESTS
// These tests document and prevent algorithm substitution attacks.

// TestVerifySubjectDigest_AlgorithmMatching verifies that subject digest
// matching uses the same algorithm as the expected digest.
// SECURITY: An attacker could include a weak algorithm (md5, sha1) alongside
// sha256 in the subject digests. We must only match the same algorithm.
func TestVerifySubjectDigest_AlgorithmMatching(t *testing.T) {
	tests := []struct {
		name           string
		subjects       []Subject
		expectedDigest string
		wantErr        bool
		description    string
	}{
		{
			name: "sha256 matches sha256",
			subjects: []Subject{
				{Digest: map[string]string{"sha256": "abc123"}},
			},
			expectedDigest: "sha256:abc123",
			wantErr:        false,
			description:    "Same algorithm and hash should match",
		},
		{
			name: "sha256 expected but only md5 present",
			subjects: []Subject{
				{Digest: map[string]string{"md5": "abc123"}},
			},
			expectedDigest: "sha256:abc123",
			wantErr:        true,
			description:    "SECURITY: Should not accept md5 when sha256 is expected",
		},
		{
			name: "sha256 expected with multiple algorithms present",
			subjects: []Subject{
				{Digest: map[string]string{
					"md5":    "weakweakweakweakweakweakweakweak",
					"sha256": "abc123",
				}},
			},
			expectedDigest: "sha256:abc123",
			wantErr:        false,
			description:    "Should match sha256 when present among other algorithms",
		},
		{
			name: "sha256 expected with only sha1 collision",
			subjects: []Subject{
				{Digest: map[string]string{
					"sha1": "abc123", // Same hash value but wrong algorithm
				}},
			},
			expectedDigest: "sha256:abc123",
			wantErr:        true,
			description:    "SECURITY: Should not match sha1 hash against sha256 expectation",
		},
		{
			name: "empty subject digest map",
			subjects: []Subject{
				{Digest: map[string]string{}},
			},
			expectedDigest: "sha256:abc123",
			wantErr:        true,
			description:    "Empty digest map should not match",
		},
		{
			name: "nil subject digest map",
			subjects: []Subject{
				{Digest: nil},
			},
			expectedDigest: "sha256:abc123",
			wantErr:        true,
			description:    "Nil digest map should not match",
		},
		{
			name: "multiple subjects with matching algorithm in second",
			subjects: []Subject{
				{Digest: map[string]string{"sha1": "wrong"}},
				{Digest: map[string]string{"sha256": "abc123"}},
			},
			expectedDigest: "sha256:abc123",
			wantErr:        false,
			description:    "Should find match in any subject",
		},
		{
			name: "sha512 expected and present",
			subjects: []Subject{
				{Digest: map[string]string{"sha512": "abc123def456"}},
			},
			expectedDigest: "sha512:abc123def456",
			wantErr:        false,
			description:    "SHA-512 algorithm matching should work",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := verifySubjectDigest(tt.subjects, tt.expectedDigest)
			if (err != nil) != tt.wantErr {
				t.Errorf("%s: verifySubjectDigest() error = %v, wantErr %v",
					tt.description, err, tt.wantErr)
			}
		})
	}
}

// TestVerifySubjectDigest_WeakAlgorithmIsolation ensures that weak algorithms
// cannot be used to satisfy verification when a strong algorithm is expected.
// SECURITY: This is critical - an attacker could craft a pack where:
// 1. The subject contains md5:attackerhash and sha256:legitimatehash
// 2. A weak parser might accept md5:attackerhash as matching sha256:attackerhash
// This test ensures we ONLY look at the sha256 entry when sha256 is expected.
func TestVerifySubjectDigest_WeakAlgorithmIsolation(t *testing.T) {
	// Attack scenario: attacker includes their controlled md5 hash alongside
	// the legitimate sha256 hash, hoping the verifier will accept the md5.
	attackerControlledMD5 := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0"
	legitimateSHA256 := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb11"

	subjects := []Subject{
		{
			Name: "manifest.json",
			Digest: map[string]string{
				"md5":    attackerControlledMD5,
				"sha256": legitimateSHA256,
			},
		},
	}

	// Expected digest is sha256 of the legitimate hash
	expectedDigest := "sha256:" + legitimateSHA256

	// This should succeed - matching the sha256
	err := verifySubjectDigest(subjects, expectedDigest)
	if err != nil {
		t.Errorf("should match legitimate sha256: %v", err)
	}

	// Now try to trick verification with the md5 value
	// This MUST fail - md5:attackerhash should not match sha256:attackerhash
	trickyExpectedDigest := "sha256:" + attackerControlledMD5
	err = verifySubjectDigest(subjects, trickyExpectedDigest)
	if err == nil {
		t.Error("SECURITY VULNERABILITY: accepted wrong sha256 hash value")
	}

	// Also verify we can't use md5 algorithm at all for sha256 expectation
	// (the subject has md5:aaa..., but we're expecting sha256:aaa...)
	err = verifySubjectDigest(subjects, "sha256:"+attackerControlledMD5)
	if err == nil {
		t.Error("SECURITY VULNERABILITY: matched md5 value against sha256 expectation")
	}
}

// TestVerifyPredicatePackDigest_DuplicateKeys ensures that duplicate keys
// in the predicate JSON are rejected before parsing.
// SECURITY: JSON parsers handle duplicates inconsistently. An attacker could
// craft a predicate with multiple "pack_digest" keys hoping one parser uses
// the first (legitimate) value while another uses the last (malicious) value.
func TestVerifyPredicatePackDigest_DuplicateKeys(t *testing.T) {
	// This predicate has duplicate pack_digest keys
	// The first is legitimate, the second is attacker-controlled
	predicateWithDuplicates := []byte(`{
		"pack_digest": "sha256:legitimate_hash_here",
		"pack_digest": "sha256:attacker_hash_here"
	}`)

	// This should fail due to duplicate key detection
	err := verifyPredicatePackDigest(predicateWithDuplicates, "sha256:legitimate_hash_here")
	if err == nil {
		t.Error("SECURITY: should reject predicate with duplicate keys")
	}
}

// TestVerifyPredicatePackDigest_MalformedJSON ensures malformed JSON is rejected.
func TestVerifyPredicatePackDigest_MalformedJSON(t *testing.T) {
	tests := []struct {
		name      string
		predicate []byte
	}{
		{"empty", []byte{}},
		{"null", []byte("null")},
		{"array", []byte("[]")},
		{"string", []byte(`"not an object"`)},
		{"number", []byte("123")},
		{"unclosed brace", []byte(`{"pack_digest": "sha256:abc`)},
		{"trailing garbage", []byte(`{"pack_digest": "sha256:abc"} garbage`)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := verifyPredicatePackDigest(tt.predicate, "sha256:abc")
			if err == nil {
				t.Errorf("should reject malformed predicate: %s", tt.name)
			}
		})
	}
}
