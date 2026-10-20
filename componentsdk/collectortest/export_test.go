package collectortest

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/locktivity/epack/componentsdk"
)

func readIndex(t *testing.T, path string) exportIndex {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var index exportIndex
	if err := json.Unmarshal(raw, &index); err != nil {
		t.Fatal(err)
	}
	return index
}

func listDir(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, len(entries))
	for i, e := range entries {
		names[i] = e.Name()
	}
	sort.Strings(names)
	return names
}

func TestScenarioRunsWriteTheirOutputUnderCollectortestOut(t *testing.T) {
	out := t.TempDir()
	t.Setenv(outEnv, out)
	s := demoSuite(demo{})
	s.Scenarios = append(s.Scenarios, Scenario{
		Name: "Token rejected!", ExpectFailure: componentsdk.CodeAuthFailed,
		Responses: []Response{{URL: demoHost + "/me", Status: 401, Body: `{}`}},
	})
	for _, v := range checkSuite(t, s).Violations {
		t.Errorf("%s/%s: %s", v.Check, v.Case, v.Message)
	}
	if got := strings.Join(listDir(t, filepath.Join(out, "demo")), " "); got != "clean lagged-total no-users scenarios.json token-rejected" {
		t.Errorf("the suite's directory holds %s, want one directory for each scenario run and none for the other checks", got)
	}
	index := readIndex(t, filepath.Join(out, "demo", "scenarios.json"))
	raw, _ := json.Marshal(index)
	sdk := `{"path":"artifacts/demo.collector-build.json","schema":"evidencepack/collector-build@v1"},{"path":"artifacts/demo.collector-result.json","schema":"evidencepack/collector-result@v1"}`
	want := `{"suite":"demo","scenarios":[` +
		`{"name":"clean","dir":"clean","exit_code":0,"artifacts":[{"path":"artifacts/demo.json","schema":""},` + sdk + `]},` +
		`{"name":"no users","dir":"no-users","exit_code":0,"artifacts":[{"path":"artifacts/demo.json","schema":""},` + sdk + `]},` +
		`{"name":"lagged total","dir":"lagged-total","exit_code":0,"artifacts":[{"path":"artifacts/demo.json","schema":""},` + sdk + `]},` +
		`{"name":"Token rejected!","dir":"token-rejected","exit_code":3,"failure":{"code":"auth_failed","message":"signing in: demo API returned 401"},"artifacts":[]}]}`
	if string(raw) != want {
		t.Errorf("index = %s\nwant    %s", raw, want)
	}
	data, err := os.ReadFile(filepath.Join(out, "demo", "clean", "artifacts", "demo.json"))
	if err != nil {
		t.Fatal(err)
	}
	var art map[string]any
	if err := json.Unmarshal(data, &art); err != nil || art["users"] != float64(4) || art["score"] != float64(72) {
		t.Errorf("the clean scenario's artifact is %s (%v)", data, err)
	}
	result, err := os.ReadFile(filepath.Join(out, "demo", "lagged-total", "artifacts", "demo.collector-result.json"))
	if err != nil || !strings.Contains(string(result), `"outcome"`) {
		t.Errorf("the collector result was not written: %v", err)
	}
	if got := listDir(t, filepath.Join(out, "demo", "token-rejected")); len(got) != 0 {
		t.Errorf("a failed run emits nothing, yet its directory holds %v", got)
	}
}

func TestScenarioOutputCopiesFileArtifacts(t *testing.T) {
	out := t.TempDir()
	t.Setenv(outEnv, out)
	checkSuite(t, stagerSuite(stager{}))
	data, err := os.ReadFile(filepath.Join(out, "stager", "clean", "artifacts", "policy.txt"))
	if err != nil || string(data) != "Passwords rotate yearly." {
		t.Errorf("the staged file was copied as %q (%v)", data, err)
	}
	index := readIndex(t, filepath.Join(out, "stager", "scenarios.json"))
	if got := index.Scenarios[0].Artifacts; len(got) != 4 || got[1] != (exportArtifact{Path: stagerFile, File: true}) {
		t.Errorf("artifacts = %+v, want the file artifact marked as a file", got)
	}
}

func TestSuiteNamesKeepScenarioOutputApart(t *testing.T) {
	out := t.TempDir()
	t.Setenv(outEnv, out)
	stale := filepath.Join(out, "demo-org", "renamed")
	if err := os.MkdirAll(stale, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"demo-org", "Demo Enterprise"} {
		s := demoSuite(demo{})
		s.Name = name
		s.Scenarios = []Scenario{s.Scenarios[0], {Name: "Clean", Responses: demoScenario().Responses}}
		checkSuite(t, s)
	}
	for dir, suite := range map[string]string{"demo-org": "demo-org", "demo-enterprise": "Demo Enterprise"} {
		if got := strings.Join(listDir(t, filepath.Join(out, dir)), " "); got != "clean clean-2 scenarios.json" {
			t.Errorf("%s holds %s, want a directory for each scenario, the second numbered, and nothing left from before", dir, got)
		}
		index := readIndex(t, filepath.Join(out, dir, "scenarios.json"))
		if index.Suite != suite || index.Scenarios[1].Dir != "clean-2" || index.Scenarios[1].Artifacts[2].Path != "artifacts/"+suite+".collector-result.json" {
			t.Errorf("%s index = %+v", dir, index)
		}
	}
}

func TestSlug(t *testing.T) {
	for in, want := range map[string]string{
		"clean": "clean", "No users": "no-users", "  DMARC lookup fails (SERVFAIL)  ": "dmarc-lookup-fails-servfail",
		"a/b..c": "a-b-c", "é": "", "": "",
	} {
		if got := slug(in); got != want {
			t.Errorf("slug(%q) = %q, want %q", in, got, want)
		}
	}
	t.Setenv(outEnv, "")
	if e, err := newExporter(demoSuite(demo{})); e != nil || err != nil {
		t.Errorf("with %s empty, newExporter = %v, %v", outEnv, e, err)
	}
}
