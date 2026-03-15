// Package sigstore provides shared utilities for Sigstore verification in CLI commands.
package sigstore

import (
	"fmt"
	"os"
	"regexp"

	"github.com/locktivity/epack/pack/verify"
)

// IdentityPolicy holds identity verification requirements.
type IdentityPolicy struct {
	Issuer        string
	IssuerRegexp  string
	Subject       string
	SubjectRegexp string
}

// HasPolicy returns true if any identity constraint is specified.
func (p *IdentityPolicy) HasPolicy() bool {
	return p.Issuer != "" || p.IssuerRegexp != "" || p.Subject != "" || p.SubjectRegexp != ""
}

// VerifierConfig holds all configuration for building a Sigstore verifier.
type VerifierConfig struct {
	// TrustRootPath is the path to a trust root JSON file.
	// If empty, online verification falls back to fetching from TUF.
	TrustRootPath string

	// Identity policy for signer verification.
	Identity IdentityPolicy

	// Offline uses embedded Rekor/TSA timestamps instead of live transparency log lookups.
	// Requires TrustRootPath.
	Offline bool

	// InsecureSkipIdentityCheck allows any valid signature without identity verification.
	InsecureSkipIdentityCheck bool
}

// BuildVerifierOptions builds verify.Option slice from configuration.
// Returns options and any error encountered during setup.
func BuildVerifierOptions(cfg VerifierConfig) ([]verify.Option, error) {
	var opts []verify.Option

	if cfg.Offline && cfg.TrustRootPath == "" {
		return nil, fmt.Errorf("offline verification requires a trust root")
	}

	trOpt, err := LoadTrustRootOption(cfg.TrustRootPath)
	if err != nil {
		return nil, err
	}
	if trOpt != nil {
		opts = append(opts, trOpt)
	}
	if err := appendIdentityOptions(&opts, cfg.Identity); err != nil {
		return nil, err
	}
	if cfg.Offline {
		opts = append(opts, verify.WithOffline())
	}
	if !cfg.Identity.HasPolicy() && cfg.InsecureSkipIdentityCheck {
		opts = append(opts, verify.WithInsecureSkipIdentityCheckForTesting())
	}
	return opts, nil
}

func appendIdentityOptions(opts *[]verify.Option, identity IdentityPolicy) error {
	if identity.Issuer != "" {
		*opts = append(*opts, verify.WithIssuer(identity.Issuer))
	}
	if err := appendIdentityRegexpOption(opts, identity.IssuerRegexp, "issuer-regexp", verify.WithIssuerRegexp); err != nil {
		return err
	}
	if identity.Subject != "" {
		*opts = append(*opts, verify.WithSubject(identity.Subject))
	}
	return appendIdentityRegexpOption(opts, identity.SubjectRegexp, "subject-regexp", verify.WithSubjectRegexp)
}

func appendIdentityRegexpOption(opts *[]verify.Option, pattern, field string, fn func(*regexp.Regexp) verify.Option) error {
	if pattern == "" {
		return nil
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return fmt.Errorf("invalid %s: %w", field, err)
	}
	*opts = append(*opts, fn(re))
	return nil
}

// LoadTrustRootOption loads a trust root from file and returns the option.
// Returns nil option (not error) if no trust root path is specified.
//
// SECURITY: This function only accepts explicit paths, not environment variables.
// Environment variable overrides were removed because they allow hostile CI environments
// to silently redirect trust verification to attacker-controlled roots.
func LoadTrustRootOption(path string) (verify.Option, error) {
	if path == "" {
		return nil, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read trust root %s: %w", path, err)
	}

	tr, err := verify.LoadTrustedRoot(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse trust root %s: %w", path, err)
	}

	return verify.WithTrustedRoot(tr), nil
}

// NewVerifier creates a SigstoreVerifier from configuration.
// This is a convenience function that calls BuildVerifierOptions and NewSigstoreVerifier.
func NewVerifier(cfg VerifierConfig) (verify.Verifier, error) {
	opts, err := BuildVerifierOptions(cfg)
	if err != nil {
		return nil, err
	}
	return verify.NewSigstoreVerifier(opts...)
}
