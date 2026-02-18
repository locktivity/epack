// Package security provides security utilities and import guards.
package security

import (
	"testing"

	"github.com/locktivity/epack/internal/testutil/importguard"
)

// TestNoUnsafeFileOps ensures security-sensitive packages use safe file operations.
//
// SECURITY BOUNDARY: Packages that handle untrusted data must use:
//   - safefile.* functions (O_NOFOLLOW, symlink prevention, atomic writes)
//   - execsafe.* functions (TOCTOU-safe execution)
//
// Direct use of these stdlib functions bypasses symlink and TOCTOU protections:
//   - os.Create, os.WriteFile, os.MkdirAll (vulnerable to symlink attacks)
//   - os.Open without O_NOFOLLOW (follows symlinks)
//
// This test flags violations but allows exceptions in test files.
func TestNoUnsafeFileOps(t *testing.T) {
	importguard.AssertNoRiskyCallsInPackages(t,
		[]string{
			"internal/dispatch",
			"internal/collector",
			"internal/component/sync",
			"pack/extract",
		},
		[]importguard.RiskyCall{
			{
				Package:   "os",
				Functions: []string{"Create", "WriteFile"},
				Reason:    "This function doesn't use O_NOFOLLOW and is vulnerable to symlink attacks.\nUse safefile functions instead.",
			},
		},
		importguard.PackageScanOptions{},
	)
}

// TestNoCatalogImportInExecution ensures execution packages don't import catalog.
//
// SECURITY BOUNDARY: The catalog package is for DISCOVERY ONLY.
// Execution decisions (which binary to run, what digest to verify) must come
// from the lockfile, not the catalog. Importing catalog in execution packages
// creates a risk that untrusted catalog data influences security decisions.
func TestNoCatalogImportInExecution(t *testing.T) {
	importguard.AssertNoImportsInPackages(t,
		[]string{
			"internal/dispatch",
			"internal/collector",
			"internal/component/sync",
		},
		[]string{"internal/catalog"},
		importguard.PackageScanOptions{},
		"Execution packages must NOT import internal/catalog.\n"+
			"Catalog data is for discovery/display only.\n"+
			"Execution decisions must come from the lockfile.")
}
