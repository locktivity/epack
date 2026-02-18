package remote

import (
	"testing"

	"github.com/locktivity/epack/internal/testutil/importguard"
)

// TestNoUnsafeExecInRemote ensures the remote package uses execsafe for binary execution.
//
// SECURITY BOUNDARY: The remote package executes adapter binaries which may be:
//   - Unverified (PATH-based adapters)
//   - Verified (source-based with digest checks)
//
// All binary execution must go through execsafe to ensure:
//   - TOCTOU-safe execution for verified binaries
//   - Restricted environment (no credential leakage)
//   - Proper timeout handling
//
// Direct use of exec.Command bypasses these protections.
func TestNoUnsafeExecInRemote(t *testing.T) {
	importguard.AssertRequiresImport(t, "os/exec", "execsafe",
		"When using os/exec, ensure execsafe is also imported for:\n"+
			"  - TOCTOU-safe execution via VerifiedBinaryFD\n"+
			"  - Restricted environment via BuildRestrictedEnvSafe")
}

// TestNoDirectOsFileOps ensures the remote package uses safe file operations.
//
// SECURITY: Remote adapters are executed binaries that could be malicious.
// File operations related to adapter binaries should use safefile to prevent:
//   - Symlink attacks
//   - Path traversal
//   - TOCTOU races
func TestNoDirectOsFileOps(t *testing.T) {
	importguard.AssertNoRiskyCalls(t, []importguard.RiskyCall{
		{
			Package:   "os",
			Functions: []string{"Create", "WriteFile"},
			Reason:    "Consider using safefile functions for symlink protection.",
		},
	})
}

// TestNoCatalogImport ensures the remote package doesn't import catalog.
//
// SECURITY BOUNDARY: The remote package handles adapter execution.
// Catalog data is for discovery/UI only. Execution decisions (which adapter
// to run, what digest to verify) must come from lockfile or explicit user input,
// NOT from the catalog which could be manipulated.
func TestNoCatalogImport(t *testing.T) {
	importguard.AssertNoImport(t, "internal/catalog",
		"The remote package must NOT import internal/catalog.\n"+
			"Catalog data is for discovery only. Adapter execution decisions\n"+
			"must come from the lockfile or explicit user configuration.")
}
