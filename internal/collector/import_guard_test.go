package collector

import (
	"testing"

	"github.com/locktivity/epack/internal/testutil/importguard"
)

// TestImportGuard ensures the collector package never imports internal/catalog.
//
// SECURITY BOUNDARY: The collector package handles collector execution and must only
// trust the lockfile for execution decisions. Catalog data is for discovery/display
// only and must never influence which binary to run, what digest to verify, or
// what signer to trust.
func TestImportGuard(t *testing.T) {
	importguard.AssertNoImport(t, "internal/catalog",
		"The collector package must NOT import internal/catalog.\n"+
			"Catalog data is for discovery/display only.\n"+
			"Collector execution decisions must come exclusively from the lockfile.")
}
