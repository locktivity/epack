package safejson

import (
	"testing"

	"github.com/locktivity/epack/internal/testutil/importguard"
)

// TestJSONImportGuard ensures encoding/json is only used safely in security-sensitive packages.
//
// SECURITY BOUNDARY: Direct JSON parsing without size limits can lead to memory exhaustion
// attacks. Security-sensitive packages must use safejson for untrusted input parsing.
//
// This test scans security-boundary packages for direct json.Unmarshal usage and logs
// potential issues. Unlike YAML (which has alias bombs), JSON is safer but still needs
// size limits for untrusted input.
//
// Security-boundary packages that should prefer safejson:
//   - internal/remote (adapter responses are untrusted)
//   - internal/dispatch (tool output is untrusted)
//   - internal/collector (collector output is untrusted)
//
// Exempted usages (validated separately or internal):
//   - internal/safejson (this package - the safe wrapper)
//   - internal/jsonutil (provides validation helpers)
func TestJSONImportGuard(t *testing.T) {
	importguard.AssertNoImportRepoWide(t, "encoding/json", importguard.RepoWideOptions{
		AllowedPackages: []string{
			"internal/safejson",
			"internal/jsonutil",
		},
		OnlyPackages: []string{
			"internal/remote",
			"internal/dispatch",
			"internal/collector",
		},
		ExactMatch: true,
		WarnOnly:   true,
	}, "Ensure these files validate input size before json.Unmarshal calls.\n"+
		"Consider using safejson.Unmarshal() for untrusted input parsing.")
}
