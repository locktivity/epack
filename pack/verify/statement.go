package verify

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/locktivity/epack/errors"
	"github.com/locktivity/epack/internal/intoto"
	"github.com/locktivity/epack/internal/packpath"
)

// VerifyStatementSemantics validates the in-toto statement structure and content.
// Checks statement type, predicate type, subject shape, and that subject digest matches
// the expected manifest digest. The manifest digest covers the entire manifest including
// pack_digest, so no separate pack_digest verification is needed.
func VerifyStatementSemantics(result *Result, expectedManifestDigest string) error {
	if result.Statement == nil {
		return errors.E(errors.SignatureInvalid, "attestation has no in-toto statement", nil)
	}

	if result.Statement.Type != intoto.StatementType {
		return errors.E(errors.SignatureInvalid,
			fmt.Sprintf("unexpected statement type %q, expected %q",
				result.Statement.Type, intoto.StatementType), nil)
	}

	if result.Statement.PredicateType != intoto.EvidencePackPredicateType {
		return errors.E(errors.SignatureInvalid,
			fmt.Sprintf("unexpected predicate type %q, expected %q",
				result.Statement.PredicateType, intoto.EvidencePackPredicateType), nil)
	}

	// Spec requires exactly one subject
	if len(result.Statement.Subjects) != 1 {
		return errors.E(errors.SignatureInvalid,
			fmt.Sprintf("attestation must have exactly 1 subject, got %d", len(result.Statement.Subjects)), nil)
	}

	// Spec requires subject[0].name == "manifest.json"
	if result.Statement.Subjects[0].Name != packpath.Manifest {
		return errors.E(errors.SignatureInvalid,
			fmt.Sprintf("attestation subject name must be %q, got %q",
				packpath.Manifest, result.Statement.Subjects[0].Name), nil)
	}

	if err := verifySubjectDigest(result.Statement.Subjects[0], expectedManifestDigest); err != nil {
		return err
	}

	// Spec requires predicate to be empty object {}
	if err := verifyEmptyPredicate(result.Statement.Predicate); err != nil {
		return err
	}

	return nil
}

func verifySubjectDigest(subject Subject, expectedManifestDigest string) error {
	// Parse expected digest format (algo:hash)
	parts := strings.SplitN(expectedManifestDigest, ":", 2)
	if len(parts) != 2 {
		return errors.E(errors.SignatureInvalid,
			fmt.Sprintf("invalid digest format: %q", expectedManifestDigest), nil)
	}
	expectedAlgo := parts[0]
	expectedHash := parts[1]

	// Per spec, manifest_digest must be SHA-256
	if expectedAlgo != "sha256" {
		return errors.E(errors.SignatureInvalid,
			fmt.Sprintf("manifest_digest must use sha256, got %q", expectedAlgo), nil)
	}

	// SECURITY: Only check sha256 entry to prevent algorithm substitution attacks
	// (attacker could include weak algorithms like md5/sha1 alongside sha256)
	subjectHash, ok := subject.Digest["sha256"]
	if !ok {
		return errors.E(errors.SignatureInvalid, "attestation subject missing sha256 digest", nil)
	}
	if subjectHash != expectedHash {
		return errors.E(errors.SignatureInvalid,
			fmt.Sprintf("attestation subject sha256 digest %q does not match expected %q",
				subjectHash, expectedHash), nil)
	}
	return nil
}

// verifyEmptyPredicate ensures the predicate is a semantically empty JSON object.
// Uses streaming token parsing to avoid allocating large objects (DoS protection).
// Accepts any valid JSON representation of an empty object (e.g., {}, { }, etc.).
func verifyEmptyPredicate(predicate []byte) error {
	const maxPredicateBytes = 4096 // DoS guard, but allows pretty-printed {}
	if len(predicate) > maxPredicateBytes {
		return errors.E(errors.SignatureInvalid, "predicate too large", nil)
	}

	dec := json.NewDecoder(bytes.NewReader(predicate))
	dec.UseNumber()

	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		return errors.E(errors.SignatureInvalid, "predicate must be JSON object", nil)
	}

	// Empty object must close immediately
	if dec.More() {
		return errors.E(errors.SignatureInvalid, "predicate must be empty object", nil)
	}

	tok, err = dec.Token()
	if err != nil || tok != json.Delim('}') {
		return errors.E(errors.SignatureInvalid, "predicate must be empty object", nil)
	}

	// Ensure no trailing non-whitespace JSON
	if tok, err = dec.Token(); err != io.EOF {
		_ = tok
		return errors.E(errors.SignatureInvalid, "predicate has trailing content", nil)
	}
	return nil
}
