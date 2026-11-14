//go:build conformance

package componentconf

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/locktivity/epack/internal/componentsdk"
	"github.com/locktivity/epack/internal/componenttypes"
	"github.com/locktivity/epack/internal/tracemap"
)

var updateTraceMap = flag.Bool("update-trace-map", false, "rewrite the collector scaffold's trace map template from a build of the scaffold")

// TestScaffoldedCollectorConforms builds what `epack sdk new collector`
// generates against this checkout, runs its tests, which include the
// collectortest suite, and runs the harness on it, so a template that drifts
// from the SDK or from the protocol fails here. The scaffold signs in to an
// API this test cannot reach, so the harness checks its configuration and
// exit codes, and the suite checks its output.
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
	goCmd(t, dir, "vet", "-tags", "record", "./...")
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
		// A fresh scaffold has no recording of a sandbox yet, which COL-113
		// says until the developer records one.
		if r.Status == StatusFail && r.ID != "COL-113" {
			t.Errorf("%s failed: %s", r.ID, r.Message)
		}
	}
	for _, id := range []string{"COL-024", "COL-042", "COL-060", "COL-061", "COL-062", "COL-063", "COL-110", "COL-114"} {
		if got := results[id]; got.Status != StatusPass {
			t.Errorf("%s = %s (%s%s), want pass", id, got.Status, got.Message, got.Reason)
		}
	}
	if got := results["COL-113"]; got.Status != StatusFail || !strings.Contains(got.Message, "no test kit suite replays a recording") {
		t.Errorf("COL-113 = %s (%s), want the failure that says to record the sandbox", got.Status, got.Message)
	}
}

// TestScaffoldedToolConforms builds what epack sdk new tool generates and
// runs the harness against it. The scaffold requires a pack, so the harness
// builds one, and nothing may fail.
func TestScaffoldedToolConforms(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a scaffolded tool")
	}
	if runtime.GOOS == "windows" {
		t.Skip("the harness runs the binary by the name go build was given, without .exe")
	}
	repoRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "epack-tool-demo")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	result, err := componentsdk.Scaffold(componentsdk.ScaffoldOptions{
		TargetDir:  dir,
		Name:       "demo",
		Kind:       componenttypes.KindTool,
		ModulePath: "example.com/epack-tool-demo",
	})
	if err != nil {
		t.Fatalf("Scaffold() = %v", err)
	}
	useCheckout(t, dir, repoRoot)
	goCmd(t, dir, "vet", "./...")
	binary := filepath.Join(dir, result.BinaryName)
	goCmd(t, dir, "build", "-o", binary, result.MainPackage)

	runner := NewRunner(binary, componenttypes.KindTool)
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
	for _, id := range []string{"TOOL-010", "C-020", "TOOL-014", "TOOL-015", "TOOL-060", "TOOL-061"} {
		if got := results[id]; got.Status != StatusPass {
			t.Errorf("%s = %s (%s%s), want pass", id, got.Status, got.Message, got.Reason)
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

// TestScaffoldTraceMapIsCurrent builds the trace map of what `epack sdk new
// collector` generates, as `epack sdk map` would, and compares it with the
// map the scaffold ships. With -update-trace-map it rewrites the template
// instead, from a scaffold whose names are distinct enough to put back as
// template actions.
func TestScaffoldTraceMapIsCurrent(t *testing.T) {
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
	dir := filepath.Join(t.TempDir(), "epack-collector-zz-name")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := componentsdk.Scaffold(componentsdk.ScaffoldOptions{
		TargetDir: dir, Name: "zz-name", Kind: componenttypes.KindCollector, ModulePath: "github.com/OWNER/epack-collector-zz-name",
	}); err != nil {
		t.Fatalf("Scaffold() = %v", err)
	}
	useCheckout(t, dir, repoRoot)
	t.Setenv("GOWORK", "off")
	t.Setenv("GOFLAGS", "-mod=mod")
	var output bytes.Buffer
	m, _, err := tracemap.Build(context.Background(), tracemap.Options{Dir: dir, Output: &output})
	if err != nil {
		t.Fatalf("building the scaffold's trace map: %v\n%s", err, output.String())
	}
	built, err := tracemap.Encode(m)
	if err != nil {
		t.Fatal(err)
	}
	if *updateTraceMap {
		template := string(built)
		for _, r := range []struct{ value, action string }{
			{"ZZ_NAME_API_TOKEN", "{{.TokenEnv}}"},
			{"epack-collector-zz-name", "{{.BinaryName}}"},
			{"zz-name", "{{.Name}}"},
			{"zzname", "{{.VendorPackage}}"},
		} {
			template = strings.ReplaceAll(template, r.value, r.action)
		}
		if strings.Contains(template, "github.com/OWNER") || strings.Contains(template, "zz") {
			t.Fatal("the map holds a name the template cannot fill in")
		}
		path := filepath.Join(repoRoot, "internal", "componentsdk", "templates", "collector.trace-map.json.tmpl")
		if err := os.WriteFile(path, []byte(template), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	shipped, err := os.ReadFile(filepath.Join(dir, "docs", "schema", "trace-map.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(shipped, built) {
		var old tracemap.Map
		_ = json.Unmarshal(shipped, &old)
		t.Errorf("the scaffold's trace map is stale (%s); rewrite it with go test -tags conformance ./internal/componentconf -run TestScaffoldTraceMapIsCurrent -update-trace-map", tracemap.Diff(&old, m))
	}
}
