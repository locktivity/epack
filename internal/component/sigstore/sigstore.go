// Package sigstore provides Sigstore signature verification for epack components.
package sigstore

import (
	"fmt"
	"os"

	"github.com/locktivity/epack/internal/digest"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

// DigestPrefix is the hash algorithm prefix for digests.
// Deprecated: Use digest.Parse() for format validation instead.
const DigestPrefix = "sha256:"

// Trusted OIDC issuers for component signature verification.
const (
	// GitHubActionsIssuer is the OIDC issuer for GitHub Actions workflows.
	// This is used by the SLSA builder to sign attestations.
	GitHubActionsIssuer = "https://token.actions.githubusercontent.com"
)

// Trusted SLSA builders for component signature verification.
// Components must be built by one of these builders to be verified.
// The builder signs attestations with its own workflow identity (SAN),
// while the source repository is verified via certificate extensions.
var (
	// TrustedSLSABuilders contains regex patterns for trusted SLSA builder workflows.
	// Each pattern matches the Subject Alternative Name (SAN) in the signing certificate.
	//
	// Currently trusted:
	// - slsa-framework/slsa-github-generator: Official SLSA Level 3 builder for GitHub Actions
	//   https://github.com/slsa-framework/slsa-github-generator
	TrustedSLSABuilders = []string{
		`^https://github\.com/slsa-framework/slsa-github-generator/\.github/workflows/[^@]+@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+$`,
	}
)

// ComputeDigest computes sha256 digest of a file.
// Uses internal/digest package for consistent formatting.
func ComputeDigest(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("opening file: %w", err)
	}
	defer func() { _ = f.Close() }()

	d, err := digest.FromReader(f)
	if err != nil {
		return "", fmt.Errorf("hashing file: %w", err)
	}

	return d.String(), nil
}

// VerifyDigest checks that a file matches the expected digest.
// SECURITY: Uses constant-time comparison via digest.Equal to prevent timing attacks.
func VerifyDigest(path, expected string) error {
	actual, err := ComputeDigest(path)
	if err != nil {
		return err
	}

	actualDigest, err := digest.Parse(actual)
	if err != nil {
		return fmt.Errorf("invalid computed digest: %w", err)
	}
	expectedDigest, err := digest.Parse(expected)
	if err != nil {
		return fmt.Errorf("invalid expected digest format: %w", err)
	}

	if !actualDigest.Equal(expectedDigest) {
		return fmt.Errorf("digest mismatch: expected %s, got %s", expected, actual)
	}
	return nil
}

// Result contains verified signer identity from Sigstore bundle.
type Result struct {
	Issuer              string
	SourceRepositoryURI string
	SourceRepositoryRef string
}

// ExpectedIdentity specifies the expected source identity for signature verification.
// When provided to VerifyBundle, the signature MUST come from this identity.
type ExpectedIdentity struct {
	// SourceRepositoryURI is the expected repository (e.g., "https://github.com/owner/repo")
	SourceRepositoryURI string
	// SourceRepositoryRef is the expected ref (e.g., "refs/tags/v1.0.0")
	SourceRepositoryRef string
}

// LockedSigner captures required source signer identity claims.
type LockedSigner struct {
	Issuer              string `yaml:"issuer"`
	Subject             string `yaml:"subject,omitempty"` // Certificate subject (e.g., workflow path)
	SourceRepositoryURI string `yaml:"source_repository_uri"`
	SourceRepositoryRef string `yaml:"source_repository_ref"`
}

// VerifyBundle verifies a Sigstore bundle against an artifact.
// Returns the verified signer identity claims.
//
// If expected is non-nil, the signature MUST come from the specified source repository
// and ref. This prevents accepting signatures from arbitrary repositories.
//
// If expected is nil, the function verifies signature validity but does NOT enforce
// identity binding. The caller MUST validate the returned claims themselves.
// This mode should only be used when initially locking a component.
func VerifyBundle(bundlePath, artifactPath string, expected *ExpectedIdentity) (*Result, error) {
	b, err := bundle.LoadJSONFromPath(bundlePath)
	if err != nil {
		return nil, fmt.Errorf("loading sigstore bundle: %w", err)
	}
	sev, err := buildSigstoreVerifier()
	if err != nil {
		return nil, err
	}
	artifact, err := os.Open(artifactPath)
	if err != nil {
		return nil, fmt.Errorf("opening artifact: %w", err)
	}
	defer func() { _ = artifact.Close() }()

	policy, err := buildVerificationPolicy(artifact, expected)
	if err != nil {
		return nil, err
	}
	result, err := sev.Verify(b, policy)
	if err != nil {
		return nil, fmt.Errorf("sigstore verification failed: %w", err)
	}
	return extractVerificationResult(result)
}

func buildSigstoreVerifier() (*verify.Verifier, error) {
	trustedRoot, err := root.FetchTrustedRoot()
	if err != nil {
		return nil, fmt.Errorf("fetching trusted root: %w", err)
	}
	sev, err := verify.NewVerifier(
		trustedRoot,
		verify.WithTransparencyLog(1),
		verify.WithIntegratedTimestamps(1),
	)
	if err != nil {
		return nil, fmt.Errorf("creating verifier: %w", err)
	}
	return sev, nil
}

func buildVerificationPolicy(artifact *os.File, expected *ExpectedIdentity) (verify.PolicyBuilder, error) {
	var policy verify.PolicyBuilder
	if expected == nil {
		policy = verify.NewPolicy(
			verify.WithArtifact(artifact),
			verify.WithoutIdentitiesUnsafe(),
		)
		return policy, nil
	}

	if len(TrustedSLSABuilders) == 0 {
		return policy, fmt.Errorf("no trusted SLSA builders configured")
	}
	sanMatcher, err := verify.NewSANMatcher("", TrustedSLSABuilders[0])
	if err != nil {
		return policy, fmt.Errorf("creating SAN matcher: %w", err)
	}
	issuerMatcher, err := verify.NewIssuerMatcher(GitHubActionsIssuer, "")
	if err != nil {
		return policy, fmt.Errorf("creating issuer matcher: %w", err)
	}
	extensions := certificate.Extensions{
		SourceRepositoryURI: expected.SourceRepositoryURI,
		SourceRepositoryRef: expected.SourceRepositoryRef,
	}
	certID, err := verify.NewCertificateIdentity(sanMatcher, issuerMatcher, extensions)
	if err != nil {
		return policy, fmt.Errorf("creating certificate identity: %w", err)
	}

	policy = verify.NewPolicy(
		verify.WithArtifact(artifact),
		verify.WithCertificateIdentity(certID),
	)
	return policy, nil
}

func extractVerificationResult(result *verify.VerificationResult) (*Result, error) {
	cert := result.Signature.Certificate
	if cert == nil {
		return nil, fmt.Errorf("no certificate in verification result")
	}
	if cert.Issuer == "" {
		return nil, fmt.Errorf("certificate missing issuer claim")
	}
	return &Result{
		Issuer:              cert.Issuer,
		SourceRepositoryURI: cert.SourceRepositoryURI,
		SourceRepositoryRef: cert.SourceRepositoryRef,
	}, nil
}

// MatchSigner checks that verification result matches expected signer.
func MatchSigner(result *Result, expected *LockedSigner) error {
	if expected == nil {
		return fmt.Errorf("no expected signer to match against")
	}

	if result.Issuer != expected.Issuer {
		return fmt.Errorf("issuer mismatch: expected %q, got %q", expected.Issuer, result.Issuer)
	}
	if result.SourceRepositoryURI != expected.SourceRepositoryURI {
		return fmt.Errorf("source_repository_uri mismatch: expected %q, got %q",
			expected.SourceRepositoryURI, result.SourceRepositoryURI)
	}
	if result.SourceRepositoryRef != expected.SourceRepositoryRef {
		return fmt.Errorf("source_repository_ref mismatch: expected %q, got %q",
			expected.SourceRepositoryRef, result.SourceRepositoryRef)
	}

	return nil
}
