package verify

import (
	"context"
	"fmt"
	"os"
	"regexp"

	"github.com/locktivity/epack/pack"
	"github.com/locktivity/epack/pack/verify"
)

// PackOpts configures pack verification workflow.
type PackOpts struct {
	// Identity policy for attestation verification
	Issuer        string
	IssuerRegexp  string
	Subject       string
	SubjectRegexp string

	// TrustRootPath pins a specific Sigstore trust root instead of fetching from TUF.
	TrustRootPath string

	// Offline skips transparency log verification.
	Offline bool

	// IntegrityOnly skips attestation verification, only checking digests.
	IntegrityOnly bool

	// RequireAttestation fails if no attestations are present.
	RequireAttestation bool

	// InsecureSkipIdentityCheck accepts any valid signer without identity verification.
	InsecureSkipIdentityCheck bool

	// InsecureSkipEmbeddedVerify skips verification of embedded attestations in merged packs.
	InsecureSkipEmbeddedVerify bool
}

// PackResult contains the outcomes of pack verification.
type PackResult struct {
	// Verified is true if all checks passed.
	Verified bool

	// Manifest metadata
	Stream     string
	PackDigest string

	// Counts
	ArtifactCount    int
	AttestationCount int

	// Errors from each verification step
	ArtifactErrors    []string
	PackDigestError   string
	AttestationErrors []string
	EmbeddedErrors    []string
}

// HasErrors returns true if any verification step failed.
func (r *PackResult) HasErrors() bool {
	return len(r.ArtifactErrors) > 0 ||
		r.PackDigestError != "" ||
		len(r.AttestationErrors) > 0 ||
		len(r.EmbeddedErrors) > 0
}

// Pack runs the full verification pipeline on a pack.
//
// The verification steps are:
//  1. Artifact integrity - verify all embedded artifact digests
//  2. Pack digest - verify the canonical pack digest
//  3. Attestation verification - verify signatures and identity (unless IntegrityOnly)
//  4. Embedded attestation verification - for merged packs (unless InsecureSkipEmbeddedVerify)
func Pack(ctx context.Context, p *pack.Pack, opts PackOpts) (*PackResult, error) {
	manifest := p.Manifest()
	result := &PackResult{
		Stream:     manifest.Stream,
		PackDigest: manifest.PackDigest,
	}

	// Step 1: Verify artifact integrity
	result.ArtifactErrors = verifyArtifactIntegrity(p, &manifest)
	result.ArtifactCount = len(manifest.Artifacts)

	// Step 2: Verify pack digest using the pack library's canonical implementation.
	// SECURITY: Use p.VerifyPackDigest() rather than reimplementing digest logic.
	// This ensures consistency with the pack library and prevents algorithm drift.
	if err := p.VerifyPackDigest(); err != nil {
		result.PackDigestError = err.Error()
	}

	// Step 3: Verify attestations (unless integrity-only)
	attestations := p.ListAttestations()
	result.AttestationCount = len(attestations)

	if !opts.IntegrityOnly {
		if len(attestations) == 0 {
			if opts.RequireAttestation {
				result.AttestationErrors = append(result.AttestationErrors,
					"no attestations found (RequireAttestation specified)")
			}
		} else {
			result.AttestationErrors = verifyAttestationsWorkflow(ctx, p, &manifest, attestations, opts)
		}
	}

	// Step 4: Verify embedded attestations in provenance (for merged packs)
	if !opts.IntegrityOnly && !opts.InsecureSkipEmbeddedVerify {
		if manifest.Provenance != nil && manifest.Provenance.Type == "merged" {
			result.EmbeddedErrors = verifyEmbeddedAttestationsWorkflow(ctx, p, opts)
		}
	}

	result.Verified = !result.HasErrors()
	return result, nil
}

// verifyArtifactIntegrity checks all embedded artifact digests.
func verifyArtifactIntegrity(p *pack.Pack, manifest *pack.Manifest) []string {
	var errors []string

	// SECURITY: Use a shared budget across all artifacts to prevent DoS.
	// Without this, a malicious pack with many large artifacts could exhaust
	// memory. The budget limits total bytes read across all ReadArtifact calls.
	budget := pack.NewReadBudget()

	for _, artifact := range manifest.Artifacts {
		if artifact.Type != "embedded" {
			continue
		}

		// Use ReadArtifactWithBudget which performs proper integrity verification
		// including size validation with proper error handling for malformed
		// size values (e.g., scientific notation like "1e0").
		_, err := p.ReadArtifactWithBudget(artifact.Path, budget)
		if err != nil {
			// SECURITY: Use %q to escape artifact paths which are untrusted input
			errors = append(errors, fmt.Sprintf("%q: %v", artifact.Path, err))
		}
	}

	return errors
}

// buildVerifierOptions builds verify options from PackOpts.
func buildVerifierOptions(opts PackOpts) ([]verify.Option, error) {
	var vopts []verify.Option

	// Load trust root from explicit path
	if opts.TrustRootPath != "" {
		data, err := os.ReadFile(opts.TrustRootPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read trust root %s: %w", opts.TrustRootPath, err)
		}
		tr, err := verify.LoadTrustedRoot(data)
		if err != nil {
			return nil, fmt.Errorf("failed to parse trust root %s: %w", opts.TrustRootPath, err)
		}
		vopts = append(vopts, verify.WithTrustedRoot(tr))
	}

	// Identity policy
	if opts.Issuer != "" {
		vopts = append(vopts, verify.WithIssuer(opts.Issuer))
	}
	if opts.IssuerRegexp != "" {
		re, err := regexp.Compile(opts.IssuerRegexp)
		if err != nil {
			return nil, fmt.Errorf("invalid issuer-regexp: %w", err)
		}
		vopts = append(vopts, verify.WithIssuerRegexp(re))
	}
	if opts.Subject != "" {
		vopts = append(vopts, verify.WithSubject(opts.Subject))
	}
	if opts.SubjectRegexp != "" {
		re, err := regexp.Compile(opts.SubjectRegexp)
		if err != nil {
			return nil, fmt.Errorf("invalid subject-regexp: %w", err)
		}
		vopts = append(vopts, verify.WithSubjectRegexp(re))
	}

	if opts.Offline {
		vopts = append(vopts, verify.WithOffline())
	}

	if opts.InsecureSkipIdentityCheck {
		vopts = append(vopts, verify.WithInsecureSkipIdentityCheckForTesting())
	}

	return vopts, nil
}

// hasIdentityPolicy returns true if any identity constraint is specified.
func hasIdentityPolicy(opts PackOpts) bool {
	return opts.Issuer != "" || opts.IssuerRegexp != "" || opts.Subject != "" || opts.SubjectRegexp != ""
}

// ErrNoIdentityPolicy is returned when attestation verification is attempted
// without an identity policy and InsecureSkipIdentityCheck is not set.
var ErrNoIdentityPolicy = fmt.Errorf(
	"no identity policy specified: use Issuer/Subject to verify signer identity, " +
		"or InsecureSkipIdentityCheck to accept any valid signature (INSECURE)")

// ValidateIdentityPolicy checks that an identity policy is specified or explicitly skipped.
//
// SECURITY: Attestation verification without identity constraints means "any valid Sigstore
// signature is accepted" - an attacker could sign malicious packs with their own key.
// Callers must either specify identity constraints OR explicitly opt out.
func ValidateIdentityPolicy(opts PackOpts) error {
	if !hasIdentityPolicy(opts) && !opts.InsecureSkipIdentityCheck {
		return ErrNoIdentityPolicy
	}
	return nil
}

// verifyAttestationsWorkflow verifies all attestation signatures and statement semantics.
func verifyAttestationsWorkflow(ctx context.Context, p *pack.Pack, manifest *pack.Manifest, attestations []string, opts PackOpts) []string {
	var errors []string

	// SECURITY: Require identity policy before attestation verification.
	// Uses centralized ValidateIdentityPolicy to ensure consistent enforcement.
	if err := ValidateIdentityPolicy(opts); err != nil {
		return []string{err.Error()}
	}

	vopts, err := buildVerifierOptions(opts)
	if err != nil {
		return []string{fmt.Sprintf("failed to build verifier options: %v", err)}
	}

	verifier, err := verify.NewSigstoreVerifier(vopts...)
	if err != nil {
		return []string{fmt.Sprintf("failed to create verifier: %v", err)}
	}

	for _, attPath := range attestations {
		data, err := p.ReadAttestation(attPath)
		if err != nil {
			// SECURITY: Use %q to escape attestation paths which are untrusted input
			errors = append(errors, fmt.Sprintf("%q: failed to read: %v", attPath, err))
			continue
		}

		result, err := verifier.Verify(ctx, data)
		if err != nil {
			errors = append(errors, fmt.Sprintf("%q: verification failed: %v", attPath, err))
			continue
		}

		// Verify statement semantics: require valid in-toto statement with matching pack digest.
		if err := verify.VerifyStatementSemantics(result, manifest.PackDigest); err != nil {
			errors = append(errors, fmt.Sprintf("%q: %v", attPath, err))
			continue
		}
	}

	return errors
}

// verifyEmbeddedAttestationsWorkflow verifies embedded attestations in merged pack provenance.
func verifyEmbeddedAttestationsWorkflow(ctx context.Context, p *pack.Pack, opts PackOpts) []string {
	// SECURITY: Require identity policy before attestation verification.
	// Uses centralized ValidateIdentityPolicy to ensure consistent enforcement.
	if err := ValidateIdentityPolicy(opts); err != nil {
		return []string{err.Error()}
	}

	vopts, err := buildVerifierOptions(opts)
	if err != nil {
		return []string{fmt.Sprintf("failed to build verifier options: %v", err)}
	}

	verifier, err := verify.NewSigstoreVerifier(vopts...)
	if err != nil {
		return []string{fmt.Sprintf("failed to create verifier: %v", err)}
	}

	_, err = p.VerifyEmbeddedAttestations(ctx, verifier)
	if err != nil {
		return []string{err.Error()}
	}

	return nil
}
