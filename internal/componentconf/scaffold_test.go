//go:build conformance

package componentconf

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/locktivity/epack/internal/componentsdk"
	"github.com/locktivity/epack/internal/componenttypes"
)

// TestScaffoldedCollectorConforms builds what `epack sdk new collector`
// generates against this checkout and runs the harness on it, so a template
// that drifts from the SDK or from the protocol fails here.
func TestScaffoldedCollectorConforms(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a scaffolded collector")
	}
	if runtime.GOOS == "windows" {
		t.Skip("the collector build depends on internal/execsafe")
	}
	repoRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "epack-collector-demo")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	result, err := componentsdk.Scaffold(componentsdk.ScaffoldOptions{
		TargetDir:  dir,
		Name:       "demo",
		Kind:       componenttypes.KindCollector,
		ModulePath: "example.com/epack-collector-demo",
	})
	if err != nil {
		t.Fatalf("Scaffold() = %v", err)
	}
	useCheckout(t, dir, repoRoot)

	goCmd(t, dir, "test", "./...")
	binary := filepath.Join(dir, result.BinaryName)
	goCmd(t, dir, "build", "-o", binary, result.MainPackage)

	runner := NewRunner(binary, componenttypes.KindCollector)
	runner.CollectorConfig = filepath.Join(dir, "testdata", "conformance.json")
	runner.Timeout = 30 * time.Second
	report, err := runner.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() = %v", err)
	}
	results := make(map[string]TestResult, len(report.Results))
	for _, r := range report.Results {
		results[r.ID] = r
		if r.Status == StatusFail {
			t.Errorf("%s failed: %s", r.ID, r.Message)
		}
	}
	for _, id := range append(outputChecks, "COL-024", "COL-031", "COL-042") {
		if got := results[id]; got.Status != StatusPass {
			t.Errorf("%s = %s (%s), want pass", id, got.Status, got.Reason)
		}
	}
}

// useCheckout points the scaffold's epack requirement at this checkout,
// with this checkout's go.sum for the dependencies they share.
func useCheckout(t *testing.T, dir, repoRoot string) {
	t.Helper()
	goMod := filepath.Join(dir, "go.mod")
	data, err := os.ReadFile(goMod)
	if err != nil {
		t.Fatal(err)
	}
	mod := strings.TrimRight(string(data), "\n")
	if !strings.Contains(mod, "require github.com/locktivity/epack") {
		mod += "\n\nrequire github.com/locktivity/epack v0.0.0"
	}
	mod += "\n\nreplace github.com/locktivity/epack => " + repoRoot + "\n"
	if err := os.WriteFile(goMod, []byte(mod), 0o644); err != nil {
		t.Fatal(err)
	}
	sum, err := os.ReadFile(filepath.Join(repoRoot, "go.sum"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "go.sum"), sum, 0o644); err != nil {
		t.Fatal(err)
	}
}

func goCmd(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("go", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOWORK=off", "GOFLAGS=-mod=mod")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go %s: %v\n%s", strings.Join(args, " "), err, out)
	}
}
