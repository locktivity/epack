package component

import (
	"testing"

	"github.com/locktivity/epack/internal/testutil/importguard"
)

// TestImportGuard ensures the component package never imports internal/catalog.
//
// SECURITY BOUNDARY: The component package handles component resolution, locking,
// syncing, and verification. It must only trust the lockfile for security decisions.
// Catalog data is for discovery/display only and must never influence which binary
// to download, what digest to verify, or what signer to trust.
func TestImportGuard(t *testing.T) {
	importguard.AssertNoImport(t, "internal/catalog",
		"The component package must NOT import internal/catalog.\n"+
			"Catalog data is for discovery/display only.\n"+
			"Component resolution and verification must come exclusively from the lockfile.")
}
