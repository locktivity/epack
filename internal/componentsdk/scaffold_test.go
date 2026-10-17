package componentsdk

import (
	"encoding/json"
	"go/format"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/locktivity/epack/internal/componenttypes"
	"github.com/locktivity/epack/internal/limits"
	"github.com/locktivity/epack/internal/safeyaml"
)

func TestScaffold_EveryKindRendersValidFiles(t *testing.T) {
	for _, kind := range SupportedKinds() {
		t.Run(string(kind), func(t *testing.T) {
			dir := t.TempDir()
			result, err := Scaffold(ScaffoldOptions{TargetDir: dir, Name: "demo", Kind: kind})
			if err != nil {
				t.Fatalf("Scaffold() = %v", err)
			}
			for _, file := range result.FilesCreated {
				data, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(file)))
				if err != nil {
					t.Fatalf("%s: %v", file, err)
				}
				switch {
				case strings.HasSuffix(file, ".go"):
					formatted, err := format.Source(data)
					if err != nil {
						t.Errorf("%s does not parse: %v", file, err)
					} else if string(formatted) != string(data) {
						t.Errorf("%s is not gofmt-clean", file)
					}
				case strings.HasSuffix(file, ".yaml"), strings.HasSuffix(file, ".yml"):
					var doc map[string]any
					if err := safeyaml.Unmarshal(data, limits.ConfigFile, &doc); err != nil || len(doc) == 0 {
						t.Errorf("%s is not a YAML document: %v", file, err)
					}
				case strings.HasSuffix(file, ".json"):
					if !json.Valid(data) {
						t.Errorf("%s is not JSON", file)
					}
				}
				if strings.Contains(string(data), "{{") && !strings.HasSuffix(file, ".yaml") && !strings.HasSuffix(file, ".yml") && file != "Makefile" && file != "README.md" {
					t.Errorf("%s has an unrendered template action", file)
				}
			}
		})
	}
}

func TestScaffold_CollectorUsesTheSharedLayout(t *testing.T) {
	dir := t.TempDir()
	result, err := Scaffold(ScaffoldOptions{TargetDir: dir, Name: "demo", Kind: componenttypes.KindCollector, ModulePath: "github.com/acme/epack-collector-demo"})
	if err != nil {
		t.Fatalf("Scaffold() = %v", err)
	}
	if result.MainPackage != "./cmd/epack-collector-demo" {
		t.Errorf("MainPackage = %q", result.MainPackage)
	}
	for _, file := range []string{"cmd/epack-collector-demo/main.go", "internal/collector/collector.go", "internal/collector/collector_test.go", "testdata/conformance.json", "Makefile"} {
		if _, err := os.Stat(filepath.Join(dir, filepath.FromSlash(file))); err != nil {
			t.Errorf("missing %s", file)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "main.go")); err == nil {
		t.Error("a collector keeps its entrypoint under cmd/")
	}

	main := readFile(t, dir, "cmd/epack-collector-demo/main.go")
	if !strings.Contains(main, `"github.com/acme/epack-collector-demo/internal/collector"`) {
		t.Error("main.go should import internal/collector by the module path")
	}
	makefile := readFile(t, dir, "Makefile")
	if !strings.Contains(makefile, "\n\tgo build -ldflags \"$(LDFLAGS)\" -o $(BINARY_NAME) $(MAIN)\n") {
		t.Error("Makefile recipes must be indented with tabs")
	}
	for _, want := range []string{
		"go list -m -f '{{.Version}}' github.com/locktivity/epack",
		"--config testdata/conformance.json",
		"$(foreach s,$(CONFORMANCE_SECRETS),--secret $(s))",
	} {
		if !strings.Contains(makefile, want) {
			t.Errorf("Makefile conformance target lacks %q", want)
		}
	}
	for _, workflow := range []string{".github/workflows/ci.yaml", ".github/workflows/release.yaml"} {
		if got := readFile(t, dir, workflow); !strings.Contains(got, "run: make conformance") || strings.Contains(got, "@latest") {
			t.Errorf("%s should run conformance through the Makefile:\n%s", workflow, got)
		}
	}
	slsa := readFile(t, dir, ".slsa-goreleaser/epack-collector-demo-linux-amd64.yml")
	if !strings.Contains(slsa, "main: ./cmd/epack-collector-demo") || !strings.Contains(slsa, "-X main.Commit={{ .Env.COMMIT }}") {
		t.Errorf("SLSA config should build cmd/ and stamp the commit:\n%s", slsa)
	}
}

func TestScaffold_OtherKindsKeepMainAtTheRoot(t *testing.T) {
	dir := t.TempDir()
	result, err := Scaffold(ScaffoldOptions{TargetDir: dir, Name: "demo", Kind: componenttypes.KindTool})
	if err != nil {
		t.Fatalf("Scaffold() = %v", err)
	}
	if result.MainPackage != "." || result.ModulePath != "github.com/OWNER/epack-tool-demo" {
		t.Errorf("result = %+v", result)
	}
	if _, err := os.Stat(filepath.Join(dir, "main.go")); err != nil {
		t.Error("a tool keeps main.go at the root")
	}
	if ci := readFile(t, dir, ".github/workflows/ci.yaml"); !strings.Contains(ci, "epack-conformance tool ./epack-tool-demo --level standard") || strings.Contains(ci, "make conformance") {
		t.Errorf("a tool installs and runs the pinned harness itself:\n%s", ci)
	}
}

func TestEpackModuleVersion(t *testing.T) {
	for version, want := range map[string]string{
		"0.5.3":            "v0.5.3",
		"v0.5.3":           "v0.5.3",
		"0.6.0-rc.1":       "v0.6.0-rc.1",
		"dev":              "",
		"0.5.3-4-gabc1234": "",
		"0.5.3-dirty":      "",
		"":                 "",
	} {
		if got := epackModuleVersion(version); got != want {
			t.Errorf("epackModuleVersion(%q) = %q, want %q", version, got, want)
		}
	}
}

func TestGenerateGoMod_PinsOnlyAReleaseVersion(t *testing.T) {
	data := newTemplateData("demo", componenttypes.KindTool, "github.com/acme/epack-tool-demo")
	data.EpackVersion = "v0.5.3"
	pinned, err := renderTemplate("go.mod.tmpl", data)
	if err != nil {
		t.Fatal(err)
	}
	if pinned != "module github.com/acme/epack-tool-demo\n\ngo 1.26.0\n\nrequire github.com/locktivity/epack v0.5.3\n" {
		t.Errorf("go.mod = %q", pinned)
	}
	data.EpackVersion = ""
	unpinned, err := renderTemplate("go.mod.tmpl", data)
	if err != nil {
		t.Fatal(err)
	}
	if unpinned != "module github.com/acme/epack-tool-demo\n\ngo 1.26.0\n" {
		t.Errorf("go.mod = %q", unpinned)
	}
}

func TestMainPackage(t *testing.T) {
	project := filepath.Join(t.TempDir(), "epack-collector-demo")
	if got := MainPackage(project); got != "." {
		t.Errorf("no cmd/: MainPackage() = %q, want .", got)
	}
	mkdir(t, project, "cmd/demo-collector")
	if got := MainPackage(project); got != "./cmd/demo-collector" {
		t.Errorf("one cmd/ package: MainPackage() = %q", got)
	}
	mkdir(t, project, "cmd/tool")
	if got := MainPackage(project); got != "." {
		t.Errorf("two cmd/ packages: MainPackage() = %q, want .", got)
	}
	mkdir(t, project, "cmd/epack-collector-demo")
	if got := MainPackage(project); got != "./cmd/epack-collector-demo" {
		t.Errorf("cmd/<project>: MainPackage() = %q", got)
	}
}

func TestProjectConformanceConfig(t *testing.T) {
	project := t.TempDir()
	if got := projectConformanceConfig(project); got != "" {
		t.Errorf("without the file: %q", got)
	}
	mkdir(t, project, "testdata")
	config := filepath.Join(project, "testdata", "conformance.json")
	if err := os.WriteFile(config, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := projectConformanceConfig(project); got != config {
		t.Errorf("projectConformanceConfig() = %q, want %q", got, config)
	}
	if got := projectConformanceConfig(config); got != "" {
		t.Errorf("a file path is a binary, not a project: %q", got)
	}
}

func TestGenerateMocks_CollectorFollowsTheProtocol(t *testing.T) {
	dir := t.TempDir()
	result, err := GenerateMocks(MockOptions{OutputDir: dir, Kind: componenttypes.KindCollector})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.FilesCreated) != 2 {
		t.Fatalf("files = %v", result.FilesCreated)
	}
	if !json.Valid([]byte(readFile(t, dir, "config.json"))) {
		t.Error("config.json is not JSON")
	}
	script := readFile(t, dir, "run-collector.sh")
	for _, want := range []string{"EPACK_COLLECTOR_CONFIG=", "EPACK_COLLECTOR_NAME=", "EPACK_PROTOCOL_VERSION=1", "< /dev/null"} {
		if !strings.Contains(script, want) {
			t.Errorf("run-collector.sh lacks %q", want)
		}
	}
}

func readFile(t *testing.T, dir, rel string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(rel)))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func mkdir(t *testing.T, dir, rel string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(dir, filepath.FromSlash(rel)), 0o755); err != nil {
		t.Fatal(err)
	}
}
