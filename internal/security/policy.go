// Package security provides security policy types and enforcement for epack operations.
//
// # Quick Start
//
// For most operations, use the default strict policy:
//
//	policy := security.PolicyStrict  // Default, recommended
//
// To enable insecure options (requires explicit "Dangerously" prefix):
//
//	opts := security.DangerouslySkipVerify()  // Skips signature verification
//
// # Naming Convention
//
// All insecure options use the prefix "Dangerously" in code and "--insecure-*" on CLI.
// This makes security-weakening options immediately visible in code review and logs.
//
// # ExecutionPolicy
//
// ExecutionPolicy controls the verification level for component execution.
// Use the most restrictive policy that meets your requirements:
//
//   - Strict: Full verification required (default, recommended)
//   - TrustOnFirstUse: Trust lockfile digest, skip Sigstore on first install
//   - Permissive: Skip all verification (DANGEROUS - development only)
package security

import "fmt"

// ExecutionPolicy controls verification requirements for component operations.
// Higher values indicate more permissive (less secure) policies.
//
// SECURITY: Default to Strict. Only use weaker policies with explicit user consent.
type ExecutionPolicy int

const (
	// PolicyStrict requires full Sigstore verification for all operations.
	// This is the default and recommended policy for production use.
	PolicyStrict ExecutionPolicy = iota

	// PolicyTrustOnFirstUse trusts the lockfile digest without Sigstore verification.
	// NOT RECOMMENDED for production use.
	PolicyTrustOnFirstUse

	// PolicyPermissive skips all verification.
	// DANGEROUS: Only use for local development with trusted components.
	// NEVER use in production.
	PolicyPermissive
)

// String returns the policy name for logging and error messages.
func (p ExecutionPolicy) String() string {
	switch p {
	case PolicyStrict:
		return "strict"
	case PolicyTrustOnFirstUse:
		return "trust-on-first-use"
	case PolicyPermissive:
		return "permissive"
	default:
		return fmt.Sprintf("unknown(%d)", p)
	}
}

// IsInsecure returns true if the policy weakens security guarantees.
func (p ExecutionPolicy) IsInsecure() bool {
	return p > PolicyStrict
}

// RequiresSigstore returns true if the policy requires Sigstore verification.
func (p ExecutionPolicy) RequiresSigstore() bool {
	return p == PolicyStrict
}

// RequiresDigest returns true if the policy requires digest verification.
func (p ExecutionPolicy) RequiresDigest() bool {
	return p < PolicyPermissive
}

// ParsePolicy parses a policy string. Returns an error for unknown values.
// Accepts: "strict", "trust-on-first-use", "tofu", "permissive"
func ParsePolicy(s string) (ExecutionPolicy, error) {
	switch s {
	case "strict", "":
		return PolicyStrict, nil
	case "trust-on-first-use", "tofu":
		return PolicyTrustOnFirstUse, nil
	case "permissive":
		return PolicyPermissive, nil
	default:
		return PolicyStrict, fmt.Errorf("unknown execution policy: %q (valid: strict, trust-on-first-use, permissive)", s)
	}
}

// InsecureOption represents a security-weakening option that must be explicitly enabled.
// Each option requires calling a "Dangerously*" constructor to enable it.
type InsecureOption struct {
	name    string
	enabled bool
}

// String returns the option name for logging.
func (o InsecureOption) String() string {
	return o.name
}

// IsEnabled returns true if this option was enabled.
func (o InsecureOption) IsEnabled() bool {
	return o.enabled
}

// Insecure option constructors. Each requires explicit acknowledgment via "Dangerously" prefix.

// DangerouslySkipVerify returns an option that skips Sigstore signature verification.
// DANGER: Components will run without signature validation.
// CLI equivalent: --insecure-skip-verify
func DangerouslySkipVerify() InsecureOption {
	return InsecureOption{name: "skip-verify", enabled: true}
}

// DangerouslySkipIdentityCheck returns an option that accepts any valid signer.
// DANGER: Components signed by any valid identity will be accepted.
// CLI equivalent: --insecure-skip-identity-check
func DangerouslySkipIdentityCheck() InsecureOption {
	return InsecureOption{name: "skip-identity-check", enabled: true}
}

// DangerouslySkipEmbeddedVerify returns an option that skips embedded attestation verification.
// DANGER: Merged packs will not have their embedded attestations verified.
// CLI equivalent: --insecure-skip-embedded-verify
func DangerouslySkipEmbeddedVerify() InsecureOption {
	return InsecureOption{name: "skip-embedded-verify", enabled: true}
}

// DangerouslyAllowUnverified returns an option that permits running unverified components.
// DANGER: Components may execute without any prior verification.
// CLI equivalent: --insecure-allow-unverified
func DangerouslyAllowUnverified() InsecureOption {
	return InsecureOption{name: "allow-unverified", enabled: true}
}

// DangerouslyAllowCustomEndpoints returns an option that permits custom Sigstore endpoints.
// DANGER: Custom TSA/Fulcio/Rekor endpoints could be malicious.
// CLI equivalent: --insecure-allow-custom-endpoints
func DangerouslyAllowCustomEndpoints() InsecureOption {
	return InsecureOption{name: "allow-custom-endpoints", enabled: true}
}

// DangerouslyAllowHTTP returns an option that permits HTTP (non-TLS) connections.
// DANGER: Traffic may be intercepted or modified.
// CLI equivalent: --insecure-allow-http
func DangerouslyAllowHTTP() InsecureOption {
	return InsecureOption{name: "allow-http", enabled: true}
}

// DangerouslyInheritPath returns an option that inherits PATH from the environment.
// DANGER: Malicious binaries in PATH could be executed.
// CLI equivalent: --insecure-inherit-path
func DangerouslyInheritPath() InsecureOption {
	return InsecureOption{name: "inherit-path", enabled: true}
}

// InsecureOptions collects multiple insecure options for operations that need them.
type InsecureOptions struct {
	SkipVerify           bool
	SkipIdentityCheck    bool
	SkipEmbeddedVerify   bool
	AllowUnverified      bool
	AllowCustomEndpoints bool
	AllowHTTP            bool
	InheritPath          bool
}

// NewInsecureOptions creates InsecureOptions from a list of options.
// Only enabled options are applied.
func NewInsecureOptions(opts ...InsecureOption) *InsecureOptions {
	o := &InsecureOptions{}
	for _, opt := range opts {
		if !opt.enabled {
			continue
		}
		switch opt.name {
		case "skip-verify":
			o.SkipVerify = true
		case "skip-identity-check":
			o.SkipIdentityCheck = true
		case "skip-embedded-verify":
			o.SkipEmbeddedVerify = true
		case "allow-unverified":
			o.AllowUnverified = true
		case "allow-custom-endpoints":
			o.AllowCustomEndpoints = true
		case "allow-http":
			o.AllowHTTP = true
		case "inherit-path":
			o.InheritPath = true
		}
	}
	return o
}

// HasAny returns true if any insecure options are enabled.
func (o *InsecureOptions) HasAny() bool {
	if o == nil {
		return false
	}
	return o.SkipVerify || o.SkipIdentityCheck || o.SkipEmbeddedVerify ||
		o.AllowUnverified || o.AllowCustomEndpoints || o.AllowHTTP || o.InheritPath
}

// String returns a comma-separated list of enabled insecure options.
func (o *InsecureOptions) String() string {
	if o == nil || !o.HasAny() {
		return "(none)"
	}
	var parts []string
	if o.SkipVerify {
		parts = append(parts, "skip-verify")
	}
	if o.SkipIdentityCheck {
		parts = append(parts, "skip-identity-check")
	}
	if o.SkipEmbeddedVerify {
		parts = append(parts, "skip-embedded-verify")
	}
	if o.AllowUnverified {
		parts = append(parts, "allow-unverified")
	}
	if o.AllowCustomEndpoints {
		parts = append(parts, "allow-custom-endpoints")
	}
	if o.AllowHTTP {
		parts = append(parts, "allow-http")
	}
	if o.InheritPath {
		parts = append(parts, "inherit-path")
	}
	result := ""
	for i, p := range parts {
		if i > 0 {
			result += ", "
		}
		result += p
	}
	return result
}
