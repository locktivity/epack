package componentsdk

import (
	"encoding/json"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
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
	for _, file := range []string{
		"cmd/epack-collector-demo/main.go",
		"internal/collector/handler.go",
		"internal/collector/config.go",
		"internal/collector/collector.go",
		"internal/collector/gaps.go",
		"internal/collector/collectortest_test.go",
		"internal/collector/fixtures_test.go",
		"internal/collector/record_test.go",
		"internal/collector/recording_scrub_test.go",
		"internal/demo/client.go",
		"docs/schema/v1.0.0.json",
		"docs/schema/embed.go",
		"docs/schema/trace-map.json",
		"docs/levels.md",
		"testdata/conformance.json",
		"Makefile",
		"LICENSE",
		".github/workflows/publish.yaml",
	} {
		if _, err := os.Stat(filepath.Join(dir, filepath.FromSlash(file))); err != nil {
			t.Errorf("missing %s", file)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "main.go")); err == nil {
		t.Error("a collector keeps its entrypoint under cmd/")
	}

	main := readFile(t, dir, "cmd/epack-collector-demo/main.go")
	if !strings.Contains(main, `"github.com/acme/epack-collector-demo/internal/collector"`) ||
		!strings.Contains(main, "componentsdk.RunCollector(collector.Spec(Version, Commit), collector.Run)") {
		t.Errorf("main.go should only run the handler from internal/collector:\n%s", main)
	}
	handler := readFile(t, dir, "internal/collector/handler.go")
	for _, want := range []string{
		`"github.com/acme/epack-collector-demo/docs/schema"`,
		`"github.com/acme/epack-collector-demo/internal/demo"`,
		`tokenEnv = "DEMO_API_TOKEN"`,
		"Timeout:     5 * time.Minute,",
		"Schemas:     map[string][]byte{artifactPath: schema.Artifact},",
		"TraceMap:    schema.TraceMap,",
		"CredentialHosts: []string{demo.Host},",
		"VendorCode:      demo.VendorCode,",
	} {
		if !strings.Contains(handler, want) {
			t.Errorf("handler.go lacks %q", want)
		}
	}
	client := readFile(t, dir, "internal/demo/client.go")
	if !strings.Contains(client, "package demo\n") || !strings.Contains(client, "componentsdk.WithOperation(ctx, componentsdk.Operation{Name: op})") {
		t.Error("client.go should name each call it makes")
	}
	if !strings.Contains(client, "componentsdk.ResponseError(resp, &APIError{") || !strings.Contains(client, "func VendorCode(_ *http.Response, body []byte) string {") {
		t.Error("client.go should give its errors their call and read the vendor's error code")
	}
	collector := readFile(t, dir, "internal/collector/collector.go")
	if strings.Count(collector, "componentsdk.StartCollectorStep(ctx, ") != 2 || !strings.Contains(collector, "AuthMethod: componentsdk.AuthAPIToken") {
		t.Error("collector.go should run its parts in steps and record how it signed in")
	}
	for _, op := range []string{`"demo.organization.get"`, `"demo.users.list"`, `"demo.users.factors.list"`} {
		if !strings.Contains(client, op) {
			t.Errorf("client.go lacks the operation %s", op)
		}
	}
	gaps := readFile(t, dir, "internal/collector/gaps.go")
	if !strings.Contains(gaps, "l.rec.NotCollected(") || !strings.Contains(gaps, "l.rec.Partial(") || strings.Count(gaps, "l.rec.Helper()") != 2 {
		t.Error("gaps.go should record values left out as not collected or partial, as a helper")
	}
	kit := readFile(t, dir, "internal/collector/collectortest_test.go")
	if !strings.Contains(kit, "collectortest.Run(t, collectortest.Suite{") || !strings.Contains(kit, "Operations: []string{") || !strings.Contains(kit, "GapOperations: true,") {
		t.Error("collectortest_test.go should run a kit suite that lists every operation and checks each gap names its call")
	}
	if !strings.Contains(kit, `}, kitRecordings(t, "demo")...),`) || !strings.Contains(kit, "func TestConformanceListsEveryCredential(") {
		t.Error("collectortest_test.go should load the sandbox's recording and check that conformance lists every credential")
	}
	var traceMap struct {
		Artifacts map[string]map[string]struct {
			Operations []string `json:"operations"`
		} `json:"artifacts"`
		Lines map[string]string `json:"lines"`
	}
	if err := json.Unmarshal([]byte(readFile(t, dir, "docs/schema/trace-map.json")), &traceMap); err != nil {
		t.Fatal(err)
	}
	if ops := traceMap.Artifacts["artifacts/demo.json"]["/users/mfa_enabled_pct"].Operations; strings.Join(ops, ",") != "demo.users.factors.list,demo.users.list" || len(traceMap.Lines) == 0 {
		t.Errorf("the trace map should name the scaffold's calls behind each field, got %v with %d lines", ops, len(traceMap.Lines))
	}
	record := readFile(t, dir, "internal/collector/record_test.go")
	if !strings.HasPrefix(record, "//go:build record\n") || !strings.Contains(record, "collectortest.Record(") {
		t.Error("record_test.go should call collectortest.Record behind the record build tag")
	}
	for _, want := range []string{
		`t.Run("demo", func(t *testing.T) {`,
		`os.Getenv("SANDBOX_DEMO_ORGANIZATION")`,
		`collectortest.EnvIdentifiers("SANDBOX_", map[string]string{"SANDBOX_DEMO_ORGANIZATION": kitOrganization})`,
		`Out:     "testdata/recordings/demo.json",`,
		"Patterns:    recordScrubPatterns,",
	} {
		if !strings.Contains(record, want) {
			t.Errorf("record_test.go lacks %q", want)
		}
	}
	if scrub := readFile(t, dir, "internal/collector/recording_scrub_test.go"); !strings.HasPrefix(scrub, "package collector\n") || !strings.Contains(scrub, "func TestRecordingsScrubbed(t *testing.T) {") {
		t.Error("recording_scrub_test.go should check the committed recordings without a build tag")
	}

	var schema map[string]any
	if err := json.Unmarshal([]byte(readFile(t, dir, "docs/schema/v1.0.0.json")), &schema); err != nil {
		t.Fatal(err)
	}
	if schema["$id"] != "epack-collector-demo/v1.0.0.json" {
		t.Errorf("$id = %v", schema["$id"])
	}
	for _, keyword := range []string{"x-epack-level", "x-epack-denominator", "x-epack-numerator", "x-epack-rounding", "x-epack-rollup"} {
		if !schemaHasKeyword(schema, keyword) {
			t.Errorf("schema has no %s annotation", keyword)
		}
	}

	makefile := readFile(t, dir, "Makefile")
	if !strings.Contains(makefile, "\n\tgo build -ldflags \"$(LDFLAGS)\" -o $(BINARY_NAME) $(MAIN)\n") {
		t.Error("Makefile recipes must be indented with tabs")
	}
	for _, want := range []string{
		"go list -m -f '{{.Version}}' github.com/locktivity/epack",
		"--config testdata/conformance.json",
		"$(foreach s,$(CONFORMANCE_SECRETS),--secret $(s))",
		"CONFORMANCE_SECRETS := DEMO_API_TOKEN\n",
		"\tgo test -tags record -run '^TestRecord$$/^demo$$' -count=1 -v ./internal/collector/\n",
		"\tgo run -tags components github.com/locktivity/epack/cmd/epack@$(EPACK_VERSION) sdk map\n",
	} {
		if !strings.Contains(makefile, want) {
			t.Errorf("Makefile lacks %q", want)
		}
	}

	var ci struct {
		On   map[string]any `yaml:"on"`
		Jobs map[string]struct {
			Uses string            `yaml:"uses"`
			With map[string]string `yaml:"with"`
		} `yaml:"jobs"`
	}
	if err := safeyaml.Unmarshal([]byte(readFile(t, dir, ".github/workflows/ci.yaml")), limits.ConfigFile, &ci); err != nil {
		t.Fatal(err)
	}
	if _, ok := ci.On["workflow_call"]; !ok {
		t.Error("ci.yaml needs a workflow_call trigger so the release workflow can run it")
	}
	job := ci.Jobs["collector"]
	if job.Uses != "locktivity/epack/.github/workflows/collector-ci.yaml@main" || job.With["name"] != "demo" || job.With["conformance-secrets"] != "DEMO_API_TOKEN" {
		t.Errorf("ci.yaml should call the shared collector workflow: %+v", ci.Jobs)
	}
	release := readFile(t, dir, ".github/workflows/release.yaml")
	if !strings.Contains(release, "  test:\n    uses: ./.github/workflows/ci.yaml\n") || !strings.Contains(release, "needs: [test, args]") {
		t.Errorf("release.yaml should run ci.yaml before the SLSA builds:\n%s", release)
	}
	if !regexp.MustCompile(`\n    uses: slsa-framework/slsa-github-generator/\.github/workflows/builder_go_slsa3\.yml@v\d+\.\d+\.\d+\n`).MatchString(release) {
		t.Error("release.yaml should call the SLSA builder by its full release tag")
	}
	for _, want := range []string{
		"      upload-assets: false\n",
		"          draft: ${{ vars.SANDBOX_RELEASE_CHECK == 'true' }}\n",
		"      - name: Publish if the sandbox check already passed\n",
	} {
		if !strings.Contains(release, want) {
			t.Errorf("release.yaml should leave a draft for the sandbox check: it lacks %q", want)
		}
	}
	var publish struct {
		On   map[string]any `yaml:"on"`
		Jobs map[string]struct {
			If string `yaml:"if"`
		} `yaml:"jobs"`
	}
	if err := safeyaml.Unmarshal([]byte(readFile(t, dir, ".github/workflows/publish.yaml")), limits.ConfigFile, &publish); err != nil {
		t.Fatal(err)
	}
	if _, ok := publish.On["status"]; !ok || !strings.Contains(publish.Jobs["publish"].If, "github.event.context == 'sandboxes'") {
		t.Errorf("publish.yaml should publish the drafts when the sandboxes status passes: %+v", publish)
	}

	if readFile(t, dir, "LICENSE") != readEpackFile(t, "LICENSE") {
		t.Error("LICENSE should be epack's own")
	}
	if readme := readFile(t, dir, "README.md"); strings.Contains(readme, "TODO: Add license") || !strings.Contains(readme, "See [LICENSE](LICENSE).") {
		t.Error("README.md should name the license")
	}
	for _, file := range []string{"docs/configuration.md", "docs/examples.md"} {
		if docs := readFile(t, dir, file); !strings.Contains(docs, "    source: acme/epack-collector-demo@^0.1\n") || strings.Contains(docs, "@v1") {
			t.Errorf("%s should name the repository with a constraint the first release meets", file)
		}
	}
	if !strings.Contains(readFile(t, dir, "docs/configuration.md"), "(https://github.com/acme/epack-collector-demo/blob/main/docs/levels.md)") {
		t.Error("docs/configuration.md should link to levels.md")
	}
	slsa := readFile(t, dir, ".slsa-goreleaser/epack-collector-demo-linux-amd64.yml")
	if !strings.Contains(slsa, "main: ./cmd/epack-collector-demo") || !strings.Contains(slsa, "-X main.Commit={{ .Env.COMMIT }}") {
		t.Errorf("SLSA config should build cmd/ and stamp the commit:\n%s", slsa)
	}
}

func TestScaffold_CollectorPinsTheSharedWorkflowToTheRelease(t *testing.T) {
	data := newTemplateData("demo", componenttypes.KindCollector, "github.com/acme/epack-collector-demo")
	data.EpackVersion = "v0.6.1"
	data.EpackCommit = "0123456789abcdef0123456789abcdef01234567"
	pinned, err := renderTemplate("collector.ci.yaml.tmpl", data)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(pinned, "    uses: locktivity/epack/.github/workflows/collector-ci.yaml@0123456789abcdef0123456789abcdef01234567 # v0.6.1\n") {
		t.Errorf("a release build should pin its own commit:\n%s", pinned)
	}
	data.EpackVersion, data.EpackCommit = "", ""
	unpinned, err := renderTemplate("collector.ci.yaml.tmpl", data)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(unpinned, "    uses: locktivity/epack/.github/workflows/collector-ci.yaml@main\n") {
		t.Errorf("a source build has no release commit to pin:\n%s", unpinned)
	}
}

// TestScaffold_CollectorLintsAsCIDoes checks that make lint runs the
// golangci-lint version collector-ci.yaml defaults to, under go.mod's
// toolchain line, the Go release CI installs. golangci-lint panics on a Go
// release newer than the one it was built with.
func TestScaffold_CollectorLintsAsCIDoes(t *testing.T) {
	var workflow struct {
		On struct {
			WorkflowCall struct {
				Inputs map[string]struct {
					Default string `yaml:"default"`
				} `yaml:"inputs"`
			} `yaml:"workflow_call"`
		} `yaml:"on"`
	}
	if err := safeyaml.Unmarshal([]byte(readEpackFile(t, ".github/workflows/collector-ci.yaml")), limits.ConfigFile, &workflow); err != nil {
		t.Fatal(err)
	}
	version := workflow.On.WorkflowCall.Inputs["golangci-lint-version"].Default
	if version == "" {
		t.Fatal("collector-ci.yaml has no golangci-lint-version default")
	}

	dir := t.TempDir()
	if _, err := Scaffold(ScaffoldOptions{TargetDir: dir, Name: "demo", Kind: componenttypes.KindCollector}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(readFile(t, dir, "Makefile"), "\nGOLANGCI_LINT_VERSION := "+version+"\n") {
		t.Errorf("the Makefile should install golangci-lint %s, as CI does", version)
	}
	if runtime.GOOS == "windows" {
		t.Skip("the Makefile's recipes run under sh")
	}
	if _, err := exec.LookPath("make"); err != nil {
		t.Skip("make is not installed")
	}
	toolchain := regexp.MustCompile(`(?m)^toolchain (\S+)$`).FindStringSubmatch(readFile(t, dir, "go.mod"))
	if toolchain == nil {
		t.Fatal("the scaffold's go.mod has no toolchain line")
	}
	cmd := exec.Command("make", "-n", "lint")
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("make -n lint: %v\n%s", err, out)
	}
	if want := "\nGOTOOLCHAIN=" + toolchain[1] + " ./bin/golangci-lint run ./...\n"; !strings.Contains(string(out), want) {
		t.Errorf("make lint should run golangci-lint under %s:\n%s", toolchain[1], out)
	}
}

func TestEpackReleaseCommit(t *testing.T) {
	sha := "0123456789abcdef0123456789abcdef01234567"
	for _, tc := range []struct{ version, commit, want string }{
		{"0.6.1", sha, sha},
		{"v0.6.1-rc.1", sha, sha},
		{"dev", sha, ""},
		{"0.6.1", "unknown", ""},
		{"0.6.1", "0123456", ""},
	} {
		if got := epackReleaseCommit(tc.version, tc.commit); got != tc.want {
			t.Errorf("epackReleaseCommit(%q, %q) = %q, want %q", tc.version, tc.commit, got, tc.want)
		}
	}
}

func TestVendorPackageAndTokenEnv(t *testing.T) {
	for _, tc := range []struct{ name, pkg, env string }{
		{"github", "github", "GITHUB_API_TOKEN"},
		{"google-workspace", "googleworkspace", "GOOGLE_WORKSPACE_API_TOKEN"},
		{"email.dns_v2", "emaildnsv2", "EMAIL_DNS_V2_API_TOKEN"},
		{"1password", "api", "API_TOKEN"},
		{"go", "api", "GO_API_TOKEN"},
		{"time", "api", "TIME_API_TOKEN"},
		{"collector", "api", "COLLECTOR_API_TOKEN"},
		{"collect", "api", "COLLECT_API_TOKEN"},
		{"error", "api", "ERROR_API_TOKEN"},
		{"epack-stats", "epackstats", "API_TOKEN"},
		{"ld-audit", "ldaudit", "API_TOKEN"},
	} {
		if got := vendorPackage(tc.name); got != tc.pkg {
			t.Errorf("vendorPackage(%q) = %q, want %q", tc.name, got, tc.pkg)
		}
		if got := tokenEnv(tc.name); got != tc.env {
			t.Errorf("tokenEnv(%q) = %q, want %q", tc.name, got, tc.env)
		}
	}
}

func TestSandboxEnvKeepsTheName(t *testing.T) {
	for name, want := range map[string]string{
		"github":           "SANDBOX_GITHUB_ORGANIZATION",
		"google-workspace": "SANDBOX_GOOGLE_WORKSPACE_ORGANIZATION",
		"email.dns_v2":     "SANDBOX_EMAIL_DNS_V2_ORGANIZATION",
		"1password":        "SANDBOX_1PASSWORD_ORGANIZATION",
		"epack-stats":      "SANDBOX_EPACK_STATS_ORGANIZATION",
	} {
		if got := newTemplateData(name, componenttypes.KindCollector, "").SandboxEnv; got != want {
			t.Errorf("SandboxEnv for %q = %q, want %q", name, got, want)
		}
	}
}

func TestGithubRepository(t *testing.T) {
	for modulePath, want := range map[string]string{
		"github.com/acme/epack-collector-demo":            "acme/epack-collector-demo",
		"github.com/acme/collectors/epack-collector-demo": "acme/collectors",
		"github.com/OWNER/epack-collector-demo":           "OWNER/epack-collector-demo",
		"example.com/epack-collector-demo":                "OWNER/epack-collector-demo",
		"github.com/acme":                                 "OWNER/epack-collector-demo",
	} {
		if got := githubRepository(modulePath, "epack-collector-demo"); got != want {
			t.Errorf("githubRepository(%q) = %q, want %q", modulePath, got, want)
		}
	}
}

// TestScaffold_CollectorDocsLinkByURL checks that every link in a
// collector's docs/ pages is a full URL. registry.epack.dev shows those pages
// and resolves a relative link from the repository's root, so a link to
// levels.md from docs/configuration.md would not be found there.
func TestScaffold_CollectorDocsLinkByURL(t *testing.T) {
	dir := t.TempDir()
	result, err := Scaffold(ScaffoldOptions{TargetDir: dir, Name: "demo", Kind: componenttypes.KindCollector, ModulePath: "github.com/acme/epack-collector-demo"})
	if err != nil {
		t.Fatal(err)
	}
	link := regexp.MustCompile(`\]\(([^)]*)\)`)
	for _, file := range result.FilesCreated {
		if !strings.HasPrefix(file, "docs/") || !strings.HasSuffix(file, ".md") {
			continue
		}
		for _, m := range link.FindAllStringSubmatch(readFile(t, dir, file), -1) {
			if !strings.HasPrefix(m[1], "https://") {
				t.Errorf("%s links to %s, which the registry cannot resolve", file, m[1])
			}
		}
	}
}

// TestVendorPackageNeverSharesAName checks every collector file that imports
// the vendor client, and the names its package declares: a collector named
// after one of the file's other imports, its package, or a function, type,
// variable, or constant of that package must get the fallback package name,
// or the scaffold would not compile.
func TestVendorPackageNeverSharesAName(t *testing.T) {
	dir := t.TempDir()
	if _, err := Scaffold(ScaffoldOptions{TargetDir: dir, Name: "demo", Kind: componenttypes.KindCollector, ModulePath: "example.com/epack-collector-demo"}); err != nil {
		t.Fatal(err)
	}
	declared := map[string][]string{}
	importers := map[string]bool{}
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") {
			return err
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		pkg := filepath.Dir(path)
		declared[pkg] = append(declared[pkg], declaredNames(file)...)
		importsVendor := false
		names := []string{file.Name.Name}
		for _, spec := range file.Imports {
			importPath, _ := strconv.Unquote(spec.Path.Value)
			if importPath == "example.com/epack-collector-demo/internal/demo" {
				importsVendor = true
				continue
			}
			name := importPath[strings.LastIndex(importPath, "/")+1:]
			if spec.Name != nil {
				name = spec.Name.Name
			}
			names = append(names, name)
		}
		if !importsVendor {
			return nil
		}
		importers[pkg] = true
		for _, name := range names {
			if vendorPackage(name) == name {
				t.Errorf("%s names %q beside the vendor client: add it to takenPackageNames", path, name)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for pkg := range importers {
		for _, name := range declared[pkg] {
			if vendorPackage(name) == name {
				t.Errorf("%s declares %q, which a vendor client of that name would clash with: add it to takenPackageNames", pkg, name)
			}
		}
	}
}

// declaredNames lists the functions, types, variables, and constants file
// declares at package level.
func declaredNames(file *ast.File) []string {
	var names []string
	for _, decl := range file.Decls {
		switch d := decl.(type) {
		case *ast.FuncDecl:
			if d.Recv == nil {
				names = append(names, d.Name.Name)
			}
		case *ast.GenDecl:
			for _, spec := range d.Specs {
				switch s := spec.(type) {
				case *ast.TypeSpec:
					names = append(names, s.Name.Name)
				case *ast.ValueSpec:
					for _, n := range s.Names {
						names = append(names, n.Name)
					}
				}
			}
		}
	}
	return names
}

func schemaHasKeyword(node any, keyword string) bool {
	switch n := node.(type) {
	case map[string]any:
		if _, ok := n[keyword]; ok {
			return true
		}
		for _, child := range n {
			if schemaHasKeyword(child, keyword) {
				return true
			}
		}
	case []any:
		for _, child := range n {
			if schemaHasKeyword(child, keyword) {
				return true
			}
		}
	}
	return false
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
	if pinned != "module github.com/acme/epack-tool-demo\n\ngo 1.26.0\n\ntoolchain go1.26.10\n\nrequire github.com/locktivity/epack v0.5.3\n" {
		t.Errorf("go.mod = %q", pinned)
	}
	data.EpackVersion = ""
	unpinned, err := renderTemplate("go.mod.tmpl", data)
	if err != nil {
		t.Fatal(err)
	}
	if unpinned != "module github.com/acme/epack-tool-demo\n\ngo 1.26.0\n\ntoolchain go1.26.10\n" {
		t.Errorf("go.mod = %q", unpinned)
	}
}

// TestGenerateGoMod_UsesEpacksGoVersions checks that a scaffold's go and
// toolchain lines match epack's own go.mod. CI and release builds use the
// Go version in go.mod, and without the toolchain line that is the older
// release the go line names.
func TestGenerateGoMod_UsesEpacksGoVersions(t *testing.T) {
	epack := readEpackFile(t, "go.mod")
	scaffold, err := renderTemplate("go.mod.tmpl", newTemplateData("demo", componenttypes.KindCollector, "github.com/acme/epack-collector-demo"))
	if err != nil {
		t.Fatal(err)
	}
	for _, directive := range []string{"go", "toolchain"} {
		line := regexp.MustCompile(`(?m)^` + directive + ` \S+$`)
		want := line.FindString(epack)
		if want == "" {
			t.Fatalf("epack's go.mod has no %s line", directive)
		}
		if got := line.FindString(scaffold); got != want {
			t.Errorf("the scaffold's go.mod has %q, want %q from epack's go.mod", got, want)
		}
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

// readEpackFile reads one of epack's own files from the repository root, with
// LF line endings. A Windows checkout can give the file CRLF endings, while
// .gitattributes keeps the templates LF.
func readEpackFile(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", name))
	if err != nil {
		t.Fatal(err)
	}
	return strings.ReplaceAll(string(data), "\r\n", "\n")
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
