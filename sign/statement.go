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
// The packDigest should be in "algo:hash" format (e.g., "sha256:abc123").
func NewStatement(packDigest, stream string) (*intoto.Statement, error) {
	algo, hash, err := parseDigest(packDigest)
	if err != nil {
		return nil, fmt.Errorf("invalid pack_digest format: %w", err)
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
		Predicate: intoto.EvidencePackPayload{
			PackDigest: packDigest,
			Stream:     stream,
		},
	}, nil
}

// parseDigest parses and validates a digest string like "sha256:abc123".
// Validates that the algorithm is supported and the hash is valid hex of correct length.
func parseDigest(digest string) (algo, hash string, err error) {
	parts := strings.SplitN(digest, ":", 2)
	if len(parts) != 2 {
		return "", "", errors.E(errors.InvalidInput,
			fmt.Sprintf("expected format 'algo:hash', got %q", digest), nil)
	}
	algo, hash = parts[0], parts[1]

	var expectedLen int
	switch algo {
	case "sha256":
		expectedLen = 64
	case "sha512":
		expectedLen = 128
	default:
		return "", "", errors.E(errors.InvalidInput,
			fmt.Sprintf("unsupported digest algorithm %q (supported: sha256, sha512)", algo), nil)
	}

	if len(hash) != expectedLen {
		return "", "", errors.E(errors.InvalidInput,
			fmt.Sprintf("%s hash must be %d hex characters, got %d", algo, expectedLen, len(hash)), nil)
	}
	if _, err := hex.DecodeString(hash); err != nil {
		return "", "", errors.E(errors.InvalidInput, "invalid hex in hash", err)
	}

	return algo, hash, nil
}
