package safefile

import (
	"testing"

	"github.com/locktivity/epack/internal/testutil/importguard"
)

// TestFileIOImportGuard ensures raw os file operations are not used in security-sensitive packages.
//
// SECURITY BOUNDARY: Direct os.WriteFile, os.MkdirAll, etc. can follow symlinks,
// creating TOCTOU race conditions and symlink attacks. Security-sensitive packages
// must use safefile for filesystem operations.
//
// This test scans security-boundary packages for dangerous raw file operations.
//
// Security-boundary packages that should use safefile:
//   - internal/component (downloads and installs untrusted components)
//   - internal/collector (executes and stores untrusted output)
//   - pack (extracts archives from untrusted sources)
//   - sign (writes attestations and signed packs)
//
// Exempted usages:
//   - internal/safefile (this package - the safe wrapper)
func TestFileIOImportGuard(t *testing.T) {
	// Check for direct os.WriteFile, os.MkdirAll usage in security-sensitive packages
	importguard.AssertNoRiskyCallsInPackages(t,
		[]string{
			"internal/component",
			"internal/collector",
			"pack",
			"sign",
		},
		[]importguard.RiskyCall{
			{
				Package:   "os",
				Functions: []string{"WriteFile", "MkdirAll", "Create"},
				Reason:    "Use safefile.WriteFile or safefile.MkdirAll instead to prevent symlink attacks.",
			},
		},
		importguard.PackageScanOptions{
			Recursive: true,
			ExemptPackages: []string{
				"internal/safefile",
			},
		},
	)
}
