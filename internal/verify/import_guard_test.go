package verify

import (
	"testing"

	"github.com/locktivity/epack/internal/testutil/importguard"
)

// TestImportGuard ensures the verify package never imports execution-layer packages.
//
// SECURITY BOUNDARY: The verify package handles pack verification and must remain
// independent of the component/execution layer. Pack verification should work with
// just a pack file and verification options - it should never need to know about
// collectors, tools, or component configuration.
func TestImportGuard(t *testing.T) {
	importguard.AssertNoImports(t, []string{
		"internal/component",
		"internal/collector",
		"internal/tool",
		"internal/dispatch",
		"internal/catalog",
		"internal/cli",
	}, "The verify package must NOT import execution-layer packages.\n"+
		"Pack verification should be independent of component configuration,\n"+
		"collectors, tools, and dispatch logic.")
}
