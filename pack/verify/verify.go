// Package verify provides signature verification for attestations in evidence packs.
//
// The package defines a Verifier interface that can be implemented by different
// verification backends. The primary implementation uses sigstore-go for
// Sigstore-based verification.
package verify

import (
	"context"
	"regexp"
	"time"

	"github.com/sigstore/sigstore-go/pkg/root"
)

// Result contains the outcome of attestation verification.
type Result struct {
	// Verified indicates whether the signature was cryptographically valid.
	Verified bool

	// Identity contains information about who signed the attestation.
	Identity *Identity

	// Timestamps contains when the signature was observed/verified.
	Timestamps []time.Time

	// Statement contains the decoded in-toto statement payload, if applicable.
	Statement *Statement

	// TransparencyLog contains info about the transparency log entry, if available.
	TransparencyLog *TransparencyLogEntry
}

// TransparencyLogEntry contains information about a transparency log entry.
type TransparencyLogEntry struct {
	// LogIndex is the index of the entry in the transparency log.
	LogIndex int64

	// LogID is the ID of the transparency log (e.g., Rekor log ID).
	LogID string
}

// Identity represents the verified signer identity from the certificate.
type Identity struct {
	// Issuer is the OIDC issuer that authenticated the signer (e.g., "https://accounts.google.com").
	Issuer string

	// Subject is the subject alternative name from the certificate (e.g., email or URI).
	Subject string

	// SubjectAlternativeNames contains all SANs from the certificate.
	SubjectAlternativeNames []string
}

// Statement represents a decoded in-toto statement from the attestation payload.
type Statement struct {
	// Type is the in-toto statement type (e.g., "https://in-toto.io/Statement/v1").
	Type string

	// PredicateType is the predicate type URI.
	PredicateType string

	// Subjects contains the subjects (artifacts) the statement refers to.
	Subjects []Subject

	// Predicate contains the raw predicate JSON.
	Predicate []byte
}

// Subject represents an in-toto subject (artifact reference).
type Subject struct {
	Name   string
	Digest map[string]string
}

// Verifier verifies attestation signatures.
type Verifier interface {
	// Verify verifies an attestation's cryptographic signature.
	// The attestation parameter should be the raw Sigstore bundle JSON.
	// Returns the verification result including the parsed statement.
	Verify(ctx context.Context, attestation []byte) (*Result, error)
}

// config holds verifier configuration.
type config struct {
	issuer                    string
	issuerRegexp              *regexp.Regexp
	subject                   string
	subjectRegexp             *regexp.Regexp
	offline                   bool
	trustedRoot               root.TrustedMaterial
	tlogThreshold             int
	tsaThreshold              int
	insecureSkipIdentityCheck bool
}

// Option configures a Verifier.
type Option func(*config)

// WithIssuer requires the certificate issuer to match exactly.
func WithIssuer(issuer string) Option {
	return func(c *config) {
		c.issuer = issuer
	}
}

// WithIssuerRegexp requires the certificate issuer to match a regular expression.
func WithIssuerRegexp(pattern *regexp.Regexp) Option {
	return func(c *config) {
		c.issuerRegexp = pattern
	}
}

// WithSubject requires the certificate subject (SAN) to match exactly.
func WithSubject(subject string) Option {
	return func(c *config) {
		c.subject = subject
	}
}

// WithSubjectRegexp requires the certificate subject (SAN) to match a regular expression.
func WithSubjectRegexp(pattern *regexp.Regexp) Option {
	return func(c *config) {
		c.subjectRegexp = pattern
	}
}

// WithOffline disables online transparency log verification.
// When offline, verification relies on embedded timestamps only.
func WithOffline() Option {
	return func(c *config) {
		c.offline = true
	}
}

// WithTrustedRoot uses a custom trusted root instead of Sigstore Public Good.
// This is useful for private Sigstore instances or enterprise PKI.
func WithTrustedRoot(tr root.TrustedMaterial) Option {
	return func(c *config) {
		c.trustedRoot = tr
	}
}

// WithTransparencyLogThreshold sets the minimum number of transparency log entries required.
// Default is 1 when online verification is enabled.
func WithTransparencyLogThreshold(threshold int) Option {
	return func(c *config) {
		c.tlogThreshold = threshold
	}
}

// WithTimestampAuthorityThreshold sets the minimum number of TSA timestamps required.
// Default is 0 (no TSA timestamps required).
func WithTimestampAuthorityThreshold(threshold int) Option {
	return func(c *config) {
		c.tsaThreshold = threshold
	}
}

// WithInsecureSkipIdentityCheck disables certificate identity verification.
// Any certificate chaining to the trusted root is accepted, regardless of issuer
// or subject. Use only for tests; in production, use WithIssuer/WithSubject.
//
// Deprecated: Use WithInsecureSkipIdentityCheckForTesting instead for clearer intent.
func WithInsecureSkipIdentityCheck() Option {
	return func(c *config) {
		c.insecureSkipIdentityCheck = true
	}
}

// WithInsecureSkipIdentityCheckForTesting disables certificate identity verification.
// This accepts ANY valid signature from ANY signer - use ONLY in test code.
//
// In production, always use NewStrictVerifier or configure WithIssuer/WithSubject
// to ensure attestations come from expected signers.
//
// Example (test only):
//
//	verifier, _ := verify.NewSigstoreVerifier(
//	    verify.WithInsecureSkipIdentityCheckForTesting(),
//	)
func WithInsecureSkipIdentityCheckForTesting() Option {
	return WithInsecureSkipIdentityCheck()
}

// defaultConfig returns the default verifier configuration.
func defaultConfig() *config {
	return &config{
		offline:       false,
		tlogThreshold: 1,
		tsaThreshold:  0,
	}
}

// applyOptions applies options to a config.
func applyOptions(opts []Option) *config {
	cfg := defaultConfig()
	for _, opt := range opts {
		opt(cfg)
	}
	return cfg
}
