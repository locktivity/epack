package pack

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/locktivity/epack/errors"
	"github.com/locktivity/epack/pack/verify"
)

// VerifyAttestation verifies a specific attestation against the pack.
// Performs integrity check, signature verification, and statement semantic validation.
func (p *Pack) VerifyAttestation(ctx context.Context, path string, v verify.Verifier) (*verify.Result, error) {
	if v == nil {
		return nil, errors.E(errors.InvalidInput, "verifier cannot be nil", nil)
	}

	if err := p.VerifyIntegrity(); err != nil {
		return nil, fmt.Errorf("pack integrity check failed: %w", err)
	}

	return p.verifyAttestationWithoutIntegrityCheck(ctx, path, v)
}

// VerifyAllAttestations verifies all attestations in the pack.
// Returns a map of path to result.
//
// SECURITY: If any attestation fails verification, returns nil results with an error.
// This "fail closed" design prevents callers from accidentally using partial results
// when some attestations failed. Callers who need individual attestation verification
// should use VerifyAttestation directly.
func (p *Pack) VerifyAllAttestations(ctx context.Context, v verify.Verifier) (map[string]*verify.Result, error) {
	if v == nil {
		return nil, errors.E(errors.InvalidInput, "verifier cannot be nil", nil)
	}

	paths := p.ListAttestations()
	if len(paths) == 0 {
		return map[string]*verify.Result{}, nil
	}

	if err := p.VerifyIntegrity(); err != nil {
		return nil, fmt.Errorf("pack integrity check failed: %w", err)
	}

	results := make(map[string]*verify.Result, len(paths))

	for _, path := range paths {
		result, err := p.verifyAttestationWithoutIntegrityCheck(ctx, path, v)
		if err != nil {
			// SECURITY: Fail closed - return nil results when ANY verification fails.
			// This prevents callers from using partial results when the pack
			// has mixed valid/invalid attestations.
			return nil, err
		}
		results[path] = result
	}

	return results, nil
}

func (p *Pack) verifyAttestationWithoutIntegrityCheck(ctx context.Context, path string, v verify.Verifier) (*verify.Result, error) {
	attestation, err := p.ReadAttestation(path)
	if err != nil {
		return nil, err
	}

	result, err := v.Verify(ctx, attestation)
	if err != nil {
		return nil, fmt.Errorf("verification failed for %q: %w", path, err)
	}
	if result == nil {
		return nil, errors.E(errors.SignatureInvalid, "verifier returned nil result", nil)
	}

	if err := verify.VerifyStatementSemantics(result, p.manifest.PackDigest); err != nil {
		return nil, err
	}

	return result, nil
}

// EmbeddedVerifyResult contains the verification result for an embedded attestation.
type EmbeddedVerifyResult struct {
	// SourcePackIndex is the index of the source pack in provenance.source_packs.
	SourcePackIndex int

	// AttestationIndex is the index of the attestation within the source pack's embedded_attestations.
	AttestationIndex int

	// Stream is the stream identifier of the source pack.
	Stream string

	// Result is the verification result.
	Result *verify.Result
}

// VerifyEmbeddedAttestations verifies all embedded attestations in a merged pack's provenance.
// Returns results for each embedded attestation across all source packs.
// For non-merged packs, returns nil with no error.
//
// SECURITY: This function verifies pack integrity first to ensure artifacts haven't been
// tampered with. Without this check, valid embedded attestations could be returned for
// a pack with modified artifact contents.
func (p *Pack) VerifyEmbeddedAttestations(ctx context.Context, v verify.Verifier) ([]EmbeddedVerifyResult, error) {
	if v == nil {
		return nil, errors.E(errors.InvalidInput, "verifier cannot be nil", nil)
	}

	manifest := p.Manifest()
	if manifest.Provenance == nil || manifest.Provenance.Type != "merged" {
		return nil, nil // Not a merged pack
	}

	// SECURITY: Verify pack integrity before validating embedded attestations.
	// This prevents returning "valid" attestation results for a tampered pack.
	// Without this check, an attacker could modify artifact contents while the
	// embedded attestations (which reference the original pack_digest) would
	// still verify successfully.
	if err := p.VerifyIntegrity(); err != nil {
		return nil, fmt.Errorf("pack integrity check failed: %w", err)
	}

	var results []EmbeddedVerifyResult

	for i, sp := range manifest.Provenance.SourcePacks {
		for j, att := range sp.EmbeddedAttestations {
			// Reconstruct bundle JSON from embedded attestation
			bundleJSON, err := json.Marshal(att)
			if err != nil {
				// SECURITY: Fail closed - return nil results when ANY verification fails.
				return nil, fmt.Errorf("source_pack[%d] (%s) attestation[%d]: failed to marshal: %w", i, sp.Stream, j, err)
			}

			result, err := v.Verify(ctx, bundleJSON)
			if err != nil {
				// SECURITY: Fail closed - return nil results when ANY verification fails.
				return nil, fmt.Errorf("source_pack[%d] (%s) attestation[%d]: verification failed: %w", i, sp.Stream, j, err)
			}

			// Verify statement subject matches source pack's digest
			if err := verify.VerifyStatementSemantics(result, sp.PackDigest); err != nil {
				// SECURITY: Fail closed - return nil results when ANY verification fails.
				return nil, fmt.Errorf("source_pack[%d] (%s) attestation[%d]: %w", i, sp.Stream, j, err)
			}

			results = append(results, EmbeddedVerifyResult{
				SourcePackIndex:  i,
				AttestationIndex: j,
				Stream:           sp.Stream,
				Result:           result,
			})
		}
	}

	return results, nil
}
