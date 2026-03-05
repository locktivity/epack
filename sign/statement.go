package sign

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/locktivity/epack/errors"
	"github.com/locktivity/epack/internal/intoto"
	"github.com/locktivity/epack/internal/packpath"
)

// NewStatement creates an in-toto statement for an evidence pack.
// manifestDigest is the JCS-canonicalized SHA256 of manifest.json (used for subject).
// manifestDigest should be in "algo:hash" format (e.g., "sha256:abc123").
func NewStatement(manifestDigest string) (*intoto.Statement, error) {
	algo, hash, err := parseDigest(manifestDigest)
	if err != nil {
		return nil, fmt.Errorf("invalid manifest_digest format: %w", err)
	}

	return &intoto.Statement{
		Type: intoto.StatementType,
		Subject: []intoto.Subject{
			{
				Name:   packpath.Manifest,
				Digest: map[string]string{algo: hash},
			},
		},
		PredicateType: intoto.EvidencePackPredicateType,
		Predicate:     intoto.EvidencePackPayload{},
	}, nil
}

// parseDigest parses and validates a digest string like "sha256:abc123".
// Per spec, manifest_digest MUST be SHA-256 (64 hex characters).
func parseDigest(digest string) (algo, hash string, err error) {
	parts := strings.SplitN(digest, ":", 2)
	if len(parts) != 2 {
		return "", "", errors.E(errors.InvalidInput,
			fmt.Sprintf("expected format 'algo:hash', got %q", digest), nil)
	}
	algo, hash = parts[0], parts[1]

	// Per spec, manifest_digest must be SHA-256
	if algo != "sha256" {
		return "", "", errors.E(errors.InvalidInput,
			fmt.Sprintf("manifest_digest must use sha256, got %q", algo), nil)
	}

	if len(hash) != 64 {
		return "", "", errors.E(errors.InvalidInput,
			fmt.Sprintf("sha256 hash must be 64 hex characters, got %d", len(hash)), nil)
	}
	if _, err := hex.DecodeString(hash); err != nil {
		return "", "", errors.E(errors.InvalidInput, "invalid hex in hash", err)
	}

	return algo, hash, nil
}
