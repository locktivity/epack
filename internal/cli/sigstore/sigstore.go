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
	// If empty, falls back to fetching from TUF.
	TrustRootPath string

	// Identity policy for signer verification.
	Identity IdentityPolicy

	// Offline skips transparency log verification.
	Offline bool

	// InsecureSkipIdentityCheck allows any valid signature without identity verification.
	InsecureSkipIdentityCheck bool
}

// BuildVerifierOptions builds verify.Option slice from configuration.
// Returns options and any error encountered during setup.
func BuildVerifierOptions(cfg VerifierConfig) ([]verify.Option, error) {
	var opts []verify.Option

	// Load trust root from explicit path only (no env var fallback for security)
	trOpt, err := LoadTrustRootOption(cfg.TrustRootPath)
	if err != nil {
		return nil, err
	}
	if trOpt != nil {
		opts = append(opts, trOpt)
	}

	// Identity policy
	if cfg.Identity.Issuer != "" {
		opts = append(opts, verify.WithIssuer(cfg.Identity.Issuer))
	}
	if cfg.Identity.IssuerRegexp != "" {
		re, err := regexp.Compile(cfg.Identity.IssuerRegexp)
		if err != nil {
			return nil, fmt.Errorf("invalid issuer-regexp: %w", err)
		}
		opts = append(opts, verify.WithIssuerRegexp(re))
	}
	if cfg.Identity.Subject != "" {
		opts = append(opts, verify.WithSubject(cfg.Identity.Subject))
	}
	if cfg.Identity.SubjectRegexp != "" {
		re, err := regexp.Compile(cfg.Identity.SubjectRegexp)
		if err != nil {
			return nil, fmt.Errorf("invalid subject-regexp: %w", err)
		}
		opts = append(opts, verify.WithSubjectRegexp(re))
	}

	if cfg.Offline {
		opts = append(opts, verify.WithOffline())
	}

	// Handle identity policy enforcement
	if !cfg.Identity.HasPolicy() {
		if cfg.InsecureSkipIdentityCheck {
			opts = append(opts, verify.WithInsecureSkipIdentityCheckForTesting())
		}
		// If no policy and no skip flag, caller decides how to handle
	}

	return opts, nil
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
