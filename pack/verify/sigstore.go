package verify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"

	"github.com/locktivity/epack/internal/jsonutil"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

// SigstoreVerifier implements Verifier using sigstore-go.
// It verifies attestations stored as Sigstore bundles.
type SigstoreVerifier struct {
	verifier *verify.Verifier
	cfg      *config
}

// NewStrictVerifier creates a Verifier that requires identity verification.
// This is the recommended constructor for production use - it ensures both
// issuer and subject are checked, preventing impersonation attacks.
//
// Parameters:
//   - issuer: Required OIDC issuer (e.g., "https://accounts.google.com")
//   - subject: Required certificate subject/SAN (e.g., "user@example.com")
//   - opts: Additional options (e.g., WithOffline, WithTrustedRoot)
//
// Example:
//
//	verifier, err := verify.NewStrictVerifier(
//	    "https://accounts.google.com",
//	    "security-team@company.com",
//	)
func NewStrictVerifier(issuer, subject string, opts ...Option) (*SigstoreVerifier, error) {
	if issuer == "" {
		return nil, fmt.Errorf("issuer is required for strict verification")
	}
	if subject == "" {
		return nil, fmt.Errorf("subject is required for strict verification")
	}
	// Prepend identity options so user opts can override if needed
	allOpts := append([]Option{WithIssuer(issuer), WithSubject(subject)}, opts...)
	return NewSigstoreVerifier(allOpts...)
}

// NewSigstoreVerifier creates a new Verifier backed by sigstore-go.
// By default, it uses the Sigstore Public Good instance for trust material
// and requires online verification against the transparency log.
//
// For production use, prefer NewStrictVerifier which enforces identity checks.
// This constructor requires explicit identity configuration or opt-in to
// WithInsecureSkipIdentityCheck for testing.
func NewSigstoreVerifier(opts ...Option) (*SigstoreVerifier, error) {
	cfg := applyOptions(opts)

	trustedMaterial := cfg.trustedRoot
	if cfg.offline && trustedMaterial == nil {
		return nil, fmt.Errorf("offline verification requires a trusted root; use WithTrustedRoot")
	}
	if trustedMaterial == nil {
		// Use Sigstore Public Good instance via LiveTrustedRoot
		liveTrustedRoot, err := root.NewLiveTrustedRoot(tuf.DefaultOptions())
		if err != nil {
			return nil, wrapTrustedRootError(err)
		}
		trustedMaterial = liveTrustedRoot
	}

	// Build verifier options.
	//
	// Offline mode means "do not rely on live services", not "ignore all timestamp
	// evidence". Certificate-signed Sigstore bundles still need observer timestamps
	// to establish certificate validity. For the normal Fulcio+Rekor path, those
	// timestamps come from the embedded Rekor entry in the bundle.
	var verifierOpts []verify.VerifierOption
	if cfg.tlogThreshold > 0 {
		verifierOpts = append(verifierOpts, verify.WithTransparencyLog(cfg.tlogThreshold))
		verifierOpts = append(verifierOpts, verify.WithIntegratedTimestamps(cfg.tlogThreshold))
	}
	if cfg.tsaThreshold > 0 {
		verifierOpts = append(verifierOpts, verify.WithSignedTimestamps(cfg.tsaThreshold))
	}

	v, err := verify.NewVerifier(trustedMaterial, verifierOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create verifier: %w", err)
	}

	return &SigstoreVerifier{
		verifier: v,
		cfg:      cfg,
	}, nil
}

// Verify verifies a Sigstore bundle attestation.
// The attestation parameter should be the raw Sigstore bundle JSON.
// This verifies the cryptographic signature and identity policy.
// Callers should separately verify that the statement's subject digest
// matches the expected pack digest.
//
// Note: The context parameter is accepted for interface compatibility but
// is not currently used by the underlying sigstore-go library. Verification
// is not cancelable once started.
func (v *SigstoreVerifier) Verify(ctx context.Context, attestation []byte) (*Result, error) {
	// Validate size and depth before parsing
	if err := ValidateAttestation(attestation); err != nil {
		return nil, err
	}

	// Parse the Sigstore bundle from JSON
	b := &bundle.Bundle{}
	if err := b.UnmarshalJSON(attestation); err != nil {
		return nil, fmt.Errorf("failed to parse sigstore bundle: %w", err)
	}

	// Build identity policy
	identityOpts, err := v.buildIdentityPolicy()
	if err != nil {
		return nil, err
	}

	// Determine artifact policy based on bundle type
	var artifactOpt verify.ArtifactPolicyOption
	if b.GetDsseEnvelope() != nil {
		// DSSE envelopes contain the statement; no external artifact needed
		artifactOpt = verify.WithoutArtifactUnsafe()
	} else if msgSig := b.GetMessageSignature(); msgSig != nil {
		// Message signatures require the artifact digest for verification
		msgDigest := msgSig.GetMessageDigest()
		if msgDigest != nil && msgDigest.GetDigest() != nil {
			artifactOpt = verify.WithArtifactDigest("sha256", msgDigest.GetDigest())
		} else {
			return nil, fmt.Errorf("message signature bundle missing digest")
		}
	} else {
		// Unknown bundle type, try without artifact
		artifactOpt = verify.WithoutArtifactUnsafe()
	}

	policy := verify.NewPolicy(artifactOpt, identityOpts...)

	// Verify the bundle
	result, err := v.verifier.Verify(b, policy)
	if err != nil {
		return nil, fmt.Errorf("verification failed: %w", err)
	}

	return v.toResult(result, b)
}

// buildIdentityPolicy builds verification policy options from config.
func (v *SigstoreVerifier) buildIdentityPolicy() ([]verify.PolicyOption, error) {
	var opts []verify.PolicyOption

	hasIdentityPolicy := v.cfg.issuer != "" || v.cfg.issuerRegexp != nil ||
		v.cfg.subject != "" || v.cfg.subjectRegexp != nil

	// If no identity requirements, require explicit opt-in to unsafe mode
	if !hasIdentityPolicy {
		if !v.cfg.insecureSkipIdentityCheck {
			return nil, fmt.Errorf("identity policy required: use WithIssuer/WithSubject to specify allowed signers, or WithInsecureSkipIdentityCheck() to explicitly allow any signer (not recommended)")
		}
		opts = append(opts, verify.WithoutIdentitiesUnsafe())
		return opts, nil
	}

	// Build certificate identity matcher
	identity, err := verify.NewShortCertificateIdentity(
		v.cfg.issuer, regexpString(v.cfg.issuerRegexp),
		v.cfg.subject, regexpString(v.cfg.subjectRegexp),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create identity matcher: %w", err)
	}

	opts = append(opts, verify.WithCertificateIdentity(identity))
	return opts, nil
}

// toResult converts sigstore verification result to our Result type.
func (v *SigstoreVerifier) toResult(sr *verify.VerificationResult, b *bundle.Bundle) (*Result, error) {
	result := &Result{
		Verified: true,
	}

	// Extract identity from verified certificate
	if sr.VerifiedIdentity != nil {
		result.Identity = &Identity{
			Issuer:  sr.VerifiedIdentity.Issuer.Issuer,
			Subject: sr.VerifiedIdentity.SubjectAlternativeName.SubjectAlternativeName,
		}
	} else {
		// When using InsecureSkipIdentityCheck, VerifiedIdentity is nil.
		// Extract identity directly from the certificate in the bundle.
		if identity := extractIdentityFromBundle(b); identity != nil {
			result.Identity = identity
		}
	}

	// Extract timestamps
	for _, ts := range sr.VerifiedTimestamps {
		result.Timestamps = append(result.Timestamps, ts.Timestamp)
	}

	// Extract transparency log entry info from bundle
	if tlogEntry := extractTlogEntryFromBundle(b); tlogEntry != nil {
		result.TransparencyLog = tlogEntry
	}

	// Parse in-toto statement from verification result or bundle
	if sr.Statement != nil {
		result.Statement = &Statement{
			Type:          sr.Statement.Type,
			PredicateType: sr.Statement.PredicateType,
		}
		for _, subj := range sr.Statement.Subject {
			result.Statement.Subjects = append(result.Statement.Subjects, Subject{
				Name:   subj.Name,
				Digest: subj.Digest,
			})
		}
		if sr.Statement.Predicate != nil {
			predBytes, err := json.Marshal(sr.Statement.Predicate)
			if err != nil {
				return nil, fmt.Errorf("marshaling statement predicate: %w", err)
			}
			result.Statement.Predicate = predBytes
		}
	} else {
		// Try to extract statement from bundle's DSSE envelope
		if stmt := extractStatementFromBundle(b); stmt != nil {
			result.Statement = stmt
		}
	}

	return result, nil
}

// extractStatementFromBundle extracts the in-toto statement from a bundle's DSSE envelope.
// Returns nil if the bundle is nil, empty, or has no DSSE envelope.
// Returns nil if the payload cannot be parsed as an in-toto statement.
//
// SECURITY: This function validates that the JSON has no duplicate keys to prevent
// predicate shadowing attacks where an attacker includes multiple "predicate" keys
// with different values, exploiting parsers that may handle duplicates differently.
func extractStatementFromBundle(b *bundle.Bundle) *Statement {
	if b == nil || b.Bundle == nil {
		return nil
	}
	envelope := b.GetDsseEnvelope()
	if envelope == nil {
		return nil
	}

	payload := envelope.GetPayload()

	// SECURITY: Validate no duplicate keys BEFORE parsing.
	// JSON parsers handle duplicates inconsistently (first-wins vs last-wins),
	// which could allow an attacker to craft a payload where the "predicate"
	// appears multiple times with different values.
	if err := jsonutil.ValidateNoDuplicateKeys(payload); err != nil {
		return nil
	}

	var stmt inTotoStatement
	if err := json.Unmarshal(payload, &stmt); err != nil {
		return nil
	}

	// SECURITY: Also validate the nested predicate for duplicate keys.
	// The predicate is json.RawMessage, so we need to validate it separately.
	if len(stmt.Predicate) > 0 {
		if err := jsonutil.ValidateNoDuplicateKeys(stmt.Predicate); err != nil {
			return nil
		}
	}

	result := &Statement{
		Type:          stmt.Type,
		PredicateType: stmt.PredicateType,
		Predicate:     stmt.Predicate,
	}
	for _, subj := range stmt.Subject {
		result.Subjects = append(result.Subjects, Subject(subj))
	}

	return result
}

// inTotoStatement represents an in-toto statement structure.
type inTotoStatement struct {
	Type          string          `json:"_type"`
	PredicateType string          `json:"predicateType"`
	Subject       []inTotoSubject `json:"subject"`
	Predicate     json.RawMessage `json:"predicate"`
}

type inTotoSubject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

// Ensure SigstoreVerifier implements Verifier.
var _ Verifier = (*SigstoreVerifier)(nil)

// LoadTrustedRoot loads a trusted root from JSON data.
// This is useful for loading custom trust roots for private Sigstore instances.
func LoadTrustedRoot(jsonData []byte) (root.TrustedMaterial, error) {
	tr, err := root.NewTrustedRootFromJSON(jsonData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse trusted root: %w", err)
	}
	return tr, nil
}

// regexpString returns the pattern string from a regexp, or empty string if nil.
func regexpString(r *regexp.Regexp) string {
	if r == nil {
		return ""
	}
	return r.String()
}

// extractTlogEntryFromBundle extracts transparency log entry info from a bundle.
// Returns nil if the bundle has no tlog entries.
func extractTlogEntryFromBundle(b *bundle.Bundle) *TransparencyLogEntry {
	if b == nil {
		return nil
	}

	entries, err := b.TlogEntries()
	if err != nil || len(entries) == 0 {
		return nil
	}

	// Use the first entry (typically there's only one)
	entry := entries[0]
	return &TransparencyLogEntry{
		LogIndex: entry.LogIndex(),
		LogID:    entry.LogKeyID(),
	}
}

// extractIdentityFromBundle extracts the signer identity from a bundle's certificate.
// Returns nil if the bundle has no certificate or the certificate cannot be parsed.
func extractIdentityFromBundle(b *bundle.Bundle) *Identity {
	if b == nil {
		return nil
	}

	vc, err := b.VerificationContent()
	if err != nil {
		return nil
	}

	cert := vc.Certificate()
	if cert == nil {
		return nil
	}

	summary, err := certificate.SummarizeCertificate(cert)
	if err != nil {
		return nil
	}

	// summary.Issuer is the OIDC issuer (e.g., https://accounts.google.com)
	// summary.CertificateIssuer is the X.509 issuer (Fulcio CA, e.g., sigstore.dev)
	return &Identity{
		Issuer:  summary.Issuer,
		Subject: summary.SubjectAlternativeName,
	}
}

// wrapTrustedRootError wraps TUF/network errors with user-friendly messages.
func wrapTrustedRootError(err error) error {
	errStr := err.Error()

	// Check for DNS resolution failures
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) || strings.Contains(errStr, "no such host") {
		return fmt.Errorf("cannot reach Sigstore trust repository (DNS lookup failed)\n\n"+
			"This typically means:\n"+
			"  - No network connection\n"+
			"  - DNS server issues\n"+
			"  - Firewall blocking sigstore.dev\n"+
			"  - Sigstore service outage (check https://status.sigstore.dev)\n\n"+
			"Workarounds:\n"+
			"  1. Use --trust-root with a local trust root file\n"+
			"  2. Use --integrity-only to skip attestation verification\n\n"+
			"To download a trust root for offline use:\n"+
			"  curl -o trusted_root.json https://raw.githubusercontent.com/sigstore/root-signing/main/targets/trusted_root.json\n"+
			"  epack verify pack.epack --trust-root trusted_root.json ...\n\n"+
			"Original error: %w", err)
	}

	// Check for connection refused/timeout
	var netErr net.Error
	if errors.As(err, &netErr) || strings.Contains(errStr, "connection refused") ||
		strings.Contains(errStr, "connection timed out") || strings.Contains(errStr, "i/o timeout") {
		return fmt.Errorf("cannot connect to Sigstore trust repository (network error)\n\n"+
			"Check Sigstore status: https://status.sigstore.dev\n\n"+
			"Workarounds:\n"+
			"  1. Check your network connection\n"+
			"  2. Use --trust-root with a local trust root file\n"+
			"  3. Use --integrity-only to skip attestation verification\n\n"+
			"Original error: %w", err)
	}

	// Default: pass through with context
	return fmt.Errorf("failed to get Sigstore trusted root: %w", err)
}
