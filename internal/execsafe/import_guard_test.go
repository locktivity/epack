//go:build components

package execsafe

import (
	"testing"

	"github.com/locktivity/epack/internal/testutil/importguard"
)

// TestExecImportGuard_RepoWide scans the ENTIRE codebase for os/exec imports.
//
// SECURITY: This is an ALLOWLIST approach. Any package importing os/exec
// must be explicitly exempted below. New code adding os/exec will FAIL
// this test until reviewed and added to the allowlist.
//
// This prevents security bypasses where exec.Command is used without
// execsafe's environment filtering and binary verification.
//
// Allowed packages (all use execsafe.BuildRestrictedEnvSafe correctly):
//   - internal/execsafe - The implementation itself
//   - internal/procexec - Shared process wrapper implementation
//   - internal/tool - Tool probing (capabilities check)
//   - internal/toolcap - Tool capabilities probing
//   - cmd/epack/utilitycmd - Utility dispatch with TOCTOU verification
//   - cmd/epack/componentcmd - Component scaffolding (lower risk, dev tool)
//   - internal/componentconf - Conformance test runner (build tag: conformance)
//   - internal/detach - Re-executes epack itself for background jobs
func TestExecImportGuard_RepoWide(t *testing.T) {
	importguard.AssertNoImportRepoWide(t, "os/exec",
		importguard.RepoWideOptions{
			// ALLOWLIST: Only these packages may import os/exec.
			// All use execsafe.BuildRestrictedEnvSafe for environment filtering.
			// Adding a new package here requires security review.
			AllowedPackages: []string{
				// The execsafe implementation itself
				"internal/execsafe",

				// Shared process wrapper implementation.
				"internal/procexec",

				// Tool probing - uses BuildRestrictedEnvSafe for capabilities
				"internal/tool",
				"internal/toolcap",

				// Utility dispatch - uses VerifiedBinaryFD + BuildRestrictedEnvSafe
				"cmd/epack/utilitycmd",

				// Component scaffolding - dev tool, uses BuildRestrictedEnvSafe
				"cmd/epack/componentcmd",

				// Conformance test runner - only builds with -tags conformance
				// Tests component binaries for protocol compliance (not production code)
				"internal/componentconf",

				// Detach spawner - re-executes the epack binary itself for background jobs
				// Lower risk: only executes the current binary, not untrusted components
				"internal/detach",

				// Component SDK - dev tooling for building/testing/watching components
				// Lower risk: dev tool, executes go build and developer's own component code
				"internal/componentsdk",
			},
			ExactMatch: true, // Must be exactly "os/exec", not substring
		},
		"SECURITY VIOLATION: Unauthorized os/exec import.\n\n"+
			"Direct exec.Command usage bypasses security controls:\n"+
			"  - No environment filtering (credential exfiltration risk)\n"+
			"  - No safe PATH (PATH injection risk)\n"+
			"  - No proxy credential stripping\n"+
			"  - No TOCTOU-safe binary verification\n\n"+
			"Required pattern for subprocess execution:\n"+
			"  1. Use execsafe.BuildRestrictedEnvSafe for environment filtering\n"+
			"  2. Use execsafe.VerifiedBinaryFD for TOCTOU-safe digest verification\n"+
			"  3. Add to AllowedPackages after security review")
}
