// Package componenttypes defines shared types for component management.
// This file defines verification options shared across all component types.
package componenttypes

import (
	"fmt"
	"io"

	"github.com/locktivity/epack/errors"
	"github.com/locktivity/epack/internal/exitcode"
)

// VerifyOptions controls component execution security.
// These options are shared across all component types (collectors, tools, remotes, utilities).
//
// The security model follows the collector pattern:
//   - By default, all components must be pinned in lockfile with digest verification
//   - --frozen mode (CI) requires all components to be pinned
//   - --insecure-allow-unverified permits components installed with --insecure-skip-verify
//   - --insecure-allow-unpinned permits components not in lockfile (for development)
type VerifyOptions struct {
	// Frozen requires all components to be pinned with digests (CI mode).
	// When true, any unpinned or unverified component causes an error.
	Frozen bool

	// InsecureAllowUnverified permits execution of components installed with
	// --insecure-skip-verify (signature verification was bypassed at install time).
	// SECURITY WARNING: Use only for development/testing.
	InsecureAllowUnverified bool

	// InsecureAllowUnpinned permits execution of components not pinned in lockfile.
	// This enables PATH discovery for components not configured in epack.yaml.
	// SECURITY WARNING: Use only for development/testing.
	InsecureAllowUnpinned bool
}

// DefaultVerifyOptions returns secure defaults for component verification.
// All security checks are enabled; no insecure modes allowed.
func DefaultVerifyOptions() VerifyOptions {
	return VerifyOptions{
		Frozen:                  false,
		InsecureAllowUnverified: false,
		InsecureAllowUnpinned:   false,
	}
}

// VerifyOptionsFromEnv returns options with environment variable defaults applied.
// Reads EPACK_INSECURE_ALLOW_UNPINNED to set InsecureAllowUnpinned.
func VerifyOptionsFromEnv() VerifyOptions {
	return VerifyOptions{
		InsecureAllowUnpinned: InsecureAllowUnpinnedFromEnv(),
	}
}

// DigestInfo contains information about a component's digest and verification state.
// This is used to determine whether TOCTOU-safe verification is required.
type DigestInfo struct {
	// Digest is the expected SHA256 digest from the lockfile (empty if not pinned).
	Digest string

	// NeedsVerification is true if the component should be verified before execution.
	// Source-based components always need verification; PATH-based do not.
	NeedsVerification bool

	// IsSourceBased is true if this is a source-based component (not external or PATH).
	// Source-based components are installed via epack sync with Sigstore verification.
	IsSourceBased bool

	// MissingDigest is true if the component is in the lockfile but has no digest.
	// This can happen if the lockfile was created before digest pinning was implemented.
	MissingDigest bool

	// IsPATHBased is true if the component was discovered from PATH (unverified).
	// PATH-based components cannot be verified because they're not pinned.
	IsPATHBased bool

	// IsExternal is true if this is an external component (binary path in config).
	// External components can optionally be pinned in lockfile.
	IsExternal bool
}

// CheckSecurity validates that execution is allowed given the digest info and options.
// Returns nil if execution is allowed, or an error describing the security violation.
//
// The check order is:
//  1. PATH-based components: allowed only with InsecureAllowUnpinned, never in frozen mode
//  2. Missing digest: allowed only with InsecureAllowUnpinned, never in frozen mode
//  3. Frozen mode: all components must have a digest
func CheckSecurity(kind ComponentKind, name string, info DigestInfo, opts VerifyOptions) error {
	// PATH-based component checks
	if info.IsPATHBased {
		if opts.Frozen {
			return errors.WithHint(errors.LockfileInvalid, exitcode.LockInvalid,
				fmt.Sprintf("%s %q uses PATH-based discovery (not allowed in --frozen mode)", kind, name),
				fmt.Sprintf("Configure a source for this %s in epack.yaml and run 'epack lock && epack sync'", kind), nil)
		}
		if !opts.InsecureAllowUnpinned {
			return errors.WithHint(errors.LockfileInvalid, exitcode.LockInvalid,
				fmt.Sprintf("%s %q not found in lockfile", kind, name),
				fmt.Sprintf("Run 'epack lock' to pin all %ss, or use --insecure-allow-unpinned for development", kind.Plural()), nil)
		}
		// PATH-based allowed with explicit opt-in
		return nil
	}

	// Source-based component with missing digest
	if info.IsSourceBased && info.MissingDigest {
		if opts.Frozen {
			return errors.WithHint(errors.LockfileInvalid, exitcode.LockInvalid,
				fmt.Sprintf("%s %q missing digest in lockfile (required in --frozen mode)", kind, name),
				"Run 'epack lock' to compute and pin digests", nil)
		}
		if !opts.InsecureAllowUnpinned {
			return errors.WithHint(errors.LockfileInvalid, exitcode.LockInvalid,
				fmt.Sprintf("%s %q missing digest in lockfile", kind, name),
				"Run 'epack lock' to compute and pin digests, or use --insecure-allow-unpinned for development", nil)
		}
	}

	// External component without lockfile pinning
	if info.IsExternal && info.Digest == "" {
		if opts.Frozen {
			return errors.WithHint(errors.LockfileInvalid, exitcode.LockInvalid,
				fmt.Sprintf("external %s %q is not pinned in lockfile (required in --frozen mode)", kind, name),
				fmt.Sprintf("Run 'epack %s lock' to pin external %ss", kind, kind.Plural()), nil)
		}
		if !opts.InsecureAllowUnpinned {
			return errors.WithHint(errors.LockfileInvalid, exitcode.LockInvalid,
				fmt.Sprintf("external %s %q is not pinned in lockfile", kind, name),
				fmt.Sprintf("Run 'epack %s lock' to pin external %ss, or use --insecure-allow-unpinned", kind, kind.Plural()), nil)
		}
	}

	// Frozen mode: all components must be verifiable
	if opts.Frozen && info.NeedsVerification && info.Digest == "" {
		return errors.WithHint(errors.LockfileInvalid, exitcode.LockInvalid,
			fmt.Sprintf("%s %q not pinned in lockfile (required in --frozen mode)", kind, name),
			fmt.Sprintf("Run 'epack lock' to pin all %ss", kind.Plural()), nil)
	}

	return nil
}

// WarnUnpinnedExecution prints a warning when executing an unpinned component.
// This is called when InsecureAllowUnpinned is true and a component is not pinned.
func WarnUnpinnedExecution(w io.Writer, kind ComponentKind, name, path string, fromPATH bool) {
	if fromPATH {
		_, _ = fmt.Fprintf(w, "Warning: executing unverified %s %q from PATH (%s)\n", kind, name, path)
		_, _ = fmt.Fprintf(w, "  Binary is NOT digest-verified.\n")
		_, _ = fmt.Fprintf(w, "  Use --insecure-allow-unpinned to suppress this warning.\n")
	} else {
		_, _ = fmt.Fprintf(w, "Warning: skipping digest verification for %s %q\n", kind, name)
	}
}
