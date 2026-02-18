//go:build conformance

package componentsdk_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/locktivity/epack/internal/componentconf"
	"github.com/locktivity/epack/internal/componenttypes"
)

// TestSDKFixturesConformance builds SDK fixtures and runs conformance tests.
// This ensures the SDK produces compliant components.
//
// Run with: go test -tags conformance ./componentsdk -v
func TestSDKFixturesConformance(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping conformance tests in short mode")
	}

	// Create temp directory for binaries
	tmpDir, err := os.MkdirTemp("", "sdk-conformance-*")
	if err != nil {
		t.Fatalf("creating temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Get module root (where go.mod is)
	moduleRoot := findModuleRoot(t)

	tests := []struct {
		name       string
		kind       componenttypes.ComponentKind
		fixture    string
		binaryName string
	}{
		{
			name:       "tool",
			kind:       componenttypes.KindTool,
			fixture:    "componentsdk/fixtures/tool",
			binaryName: "epack-tool-sdk-fixture",
		},
		{
			name:       "collector",
			kind:       componenttypes.KindCollector,
			fixture:    "componentsdk/fixtures/collector",
			binaryName: "epack-collector-sdk-fixture",
		},
		{
			name:       "remote",
			kind:       componenttypes.KindRemote,
			fixture:    "componentsdk/fixtures/remote",
			binaryName: "epack-remote-sdk-fixture",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Build fixture
			binaryPath := filepath.Join(tmpDir, tt.binaryName)
			fixturePath := filepath.Join(moduleRoot, tt.fixture)

			cmd := exec.Command("go", "build", "-o", binaryPath, ".")
			cmd.Dir = fixturePath
			cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
			output, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("building fixture: %v\n%s", err, output)
			}

			// Run conformance tests
			runner := componentconf.NewRunner(binaryPath, tt.kind)
			report, err := runner.Run(context.Background())
			if err != nil {
				t.Fatalf("running conformance: %v", err)
			}

			// Check results
			t.Logf("Conformance level: %s", report.Level)
			t.Logf("MUST:   %d pass, %d fail, %d skip",
				report.Summary.Must.Pass, report.Summary.Must.Fail, report.Summary.Must.Skip)
			t.Logf("SHOULD: %d pass, %d fail, %d skip",
				report.Summary.Should.Pass, report.Summary.Should.Fail, report.Summary.Should.Skip)

			// Log failures
			for _, r := range report.Results {
				if r.Status == componentconf.StatusFail {
					t.Errorf("FAIL %s [%s]: %s", r.ID, r.Level, r.Message)
				}
			}

			// SDK fixtures should achieve at least "standard" conformance
			if report.Summary.Must.Fail > 0 {
				t.Errorf("SDK fixture failed %d MUST requirements", report.Summary.Must.Fail)
			}
			if report.Summary.Should.Fail > 0 {
				t.Errorf("SDK fixture failed %d SHOULD requirements", report.Summary.Should.Fail)
			}
		})
	}
}

func findModuleRoot(t *testing.T) string {
	t.Helper()

	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getting working directory: %v", err)
	}

	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not find module root (go.mod)")
		}
		dir = parent
	}
}
