package verify

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/locktivity/epack/errors"
	"github.com/locktivity/epack/internal/intoto"
	"github.com/locktivity/epack/internal/jsonutil"
)

// VerifyStatementSemantics validates the in-toto statement structure and content.
// Checks statement type, predicate type, and that subject/predicate pack_digest match expected.
func VerifyStatementSemantics(result *Result, expectedPackDigest string) error {
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

	if len(result.Statement.Subjects) == 0 {
		return errors.E(errors.SignatureInvalid, "attestation has no subjects", nil)
	}

	if err := verifyPredicatePackDigest(result.Statement.Predicate, expectedPackDigest); err != nil {
		return err
	}

	if err := verifySubjectDigest(result.Statement.Subjects, expectedPackDigest); err != nil {
		return err
	}

	return nil
}

func verifyPredicatePackDigest(predicateJSON []byte, expectedPackDigest string) error {
	if len(predicateJSON) == 0 {
		return errors.E(errors.SignatureInvalid, "attestation has no predicate", nil)
	}

	// SECURITY: Validate no duplicate keys BEFORE parsing.
	// JSON parsers handle duplicates inconsistently (first-wins vs last-wins),
	// which could allow an attacker to craft a predicate where fields like
	// "pack_digest" appear multiple times with different values.
	if err := jsonutil.ValidateNoDuplicateKeys(predicateJSON); err != nil {
		return errors.E(errors.SignatureInvalid, "predicate contains duplicate JSON keys", err)
	}

	var predicate intoto.EvidencePackPayload
	if err := json.Unmarshal(predicateJSON, &predicate); err != nil {
		return errors.E(errors.SignatureInvalid, "failed to parse predicate", err)
	}

	if predicate.PackDigest == "" {
		return errors.E(errors.SignatureInvalid, "predicate missing pack_digest field", nil)
	}

	if predicate.PackDigest != expectedPackDigest {
		return errors.E(errors.SignatureInvalid,
			fmt.Sprintf("predicate pack_digest %q does not match manifest pack_digest %q",
				predicate.PackDigest, expectedPackDigest), nil)
	}

	return nil
}

func verifySubjectDigest(subjects []Subject, expectedPackDigest string) error {
	// SECURITY: Extract algorithm from expected digest to prevent algorithm substitution.
	// An attacker could include weak algorithms (md5, sha1) alongside sha256.
	// We must only match the same algorithm as expected.
	parts := strings.SplitN(expectedPackDigest, ":", 2)
	if len(parts) != 2 {
		return errors.E(errors.SignatureInvalid,
			fmt.Sprintf("invalid digest format: %q", expectedPackDigest), nil)
	}
	expectedAlgo := parts[0]
	expectedHash := parts[1]

	for _, subject := range subjects {
		// Only check the digest entry for the expected algorithm
		if subjectHash, ok := subject.Digest[expectedAlgo]; ok {
			if subjectHash == expectedHash {
				return nil
			}
		}
	}
	return errors.E(errors.SignatureInvalid,
		fmt.Sprintf("attestation subject has no %s digest matching pack_digest %q", expectedAlgo, expectedPackDigest), nil)
}
