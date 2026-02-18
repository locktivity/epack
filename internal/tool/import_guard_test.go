//go:build components

package tool_test

import (
	"testing"

	"github.com/locktivity/epack/internal/testutil/importguard"
)

// TestImportGuard ensures that the tool package does not import internal/catalog.
// Tool execution decisions (which binary to run, what digest to verify) come
// exclusively from the lockfile. Catalog data is for discovery/display only
// and is handled at the CLI layer.
func TestImportGuard(t *testing.T) {
	importguard.AssertNoImports(t, []string{
		"internal/catalog",
		"internal/cli",
	}, "Tool package must NOT import catalog or CLI packages.\n"+
		"Tool execution decisions come from lockfile only.")
}
