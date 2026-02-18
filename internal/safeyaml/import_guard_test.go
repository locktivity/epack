package safeyaml

import (
	"testing"

	"github.com/locktivity/epack/internal/testutil/importguard"
)

// TestYAMLImportGuard ensures gopkg.in/yaml.v3 is only imported by authorized packages.
//
// SECURITY BOUNDARY: Direct YAML parsing is dangerous due to alias bombs and
// memory exhaustion attacks. All YAML parsing must go through the safeyaml
// package which enforces pre-parse validation.
//
// Authorized packages:
//   - internal/safeyaml (this package - the safe wrapper)
//   - internal/yamlpolicy (provides validation logic used by safeyaml)
//
// This test scans all Go files in the repository (including test files) and
// fails if any other package imports gopkg.in/yaml.v3 directly.
func TestYAMLImportGuard(t *testing.T) {
	importguard.AssertNoImportRepoWide(t, "gopkg.in/yaml.v3", importguard.RepoWideOptions{
		AllowedPackages: []string{
			"internal/safeyaml",
			"internal/yamlpolicy",
		},
		IncludeTests: true,
		ExactMatch:   true,
	}, "YAML parsing must go through internal/safeyaml to ensure pre-parse validation.\n"+
		"Use safeyaml.Unmarshal() instead of yaml.Unmarshal().")
}
