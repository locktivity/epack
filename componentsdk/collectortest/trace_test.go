package collectortest

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/locktivity/epack/componentsdk"
	"github.com/locktivity/epack/internal/tracemap"
)

func TestGapOperationsCheckNamesTheFaultedOperation(t *testing.T) {
	s := demoSuite(demo{callErrors: true})
	s.GapOperations = true
	for _, v := range checkSuite(t, s).Violations {
		t.Errorf("%s/%s: %s", v.Check, v.Case, v.Message)
	}

	s = demoSuite(demo{})
	s.GapOperations = true
	report := checkSuite(t, s)
	expectViolation(t, report, "faults", "names no operation, want demo.score.get")
	for _, v := range violationsOf(report, "faults") {
		if strings.Contains(v.Case, "/timeout/") || strings.Contains(v.Case, "/reset/") {
			t.Errorf("%s: %s; an error the SDK's client returned names its call already", v.Case, v.Message)
		}
	}

	off := checkSuite(t, demoSuite(demo{}))
	for _, v := range violationsOf(off, "faults") {
		t.Errorf("without GapOperations: %s: %s", v.Case, v.Message)
	}
}

func TestMisnamedGap(t *testing.T) {
	g := componentsdk.Gap{Path: "artifacts/okta.json", Pointer: "/system_log", Operation: "okta.users.list"}
	if got := misnamedGap(g, "okta.logs.list"); got != "the gap at artifacts/okta.json /system_log names operation okta.users.list, want okta.logs.list, whose fault left it" {
		t.Errorf("message = %q", got)
	}
}

// suiteTraces runs s with COLLECTORTEST_MAP set and returns what it wrote.
func suiteTraces(t *testing.T, s Suite) []tracemap.SuiteTrace {
	t.Helper()
	dir := t.TempDir()
	t.Setenv(tracemap.Env, dir)
	for _, v := range checkSuite(t, s).Violations {
		t.Errorf("%s/%s: %s", v.Check, v.Case, v.Message)
	}
	files, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	var out []tracemap.SuiteTrace
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var st tracemap.SuiteTrace
		if err := json.Unmarshal(raw, &st); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		out = append(out, st)
	}
	return out
}

func TestSuiteTraceListsWhatEachFieldDependsOn(t *testing.T) {
	traces := suiteTraces(t, demoSuite(demo{normalized: true}))
	if len(traces) != 1 {
		t.Fatalf("traces = %+v, want one for the suite", traces)
	}
	st := traces[0]
	if st.Suite != "demo" || strings.Join(st.Operations, ",") != "demo.me.get,demo.score.get,demo.users.list" || strings.Join(st.Insensitive, ",") != "demo.me.get" {
		t.Errorf("suite = %q, operations = %v, insensitive = %v", st.Suite, st.Operations, st.Insensitive)
	}
	fields := st.Artifacts["artifacts/demo.json"]
	for pattern, want := range map[string][]string{
		"/org":            nil,
		"/mfa_enforced":   nil,
		"/score":          {"demo.score.get"},
		"/users":          {"demo.users.list"},
		"/mfa_pct":        {"demo.users.list"},
		"/user_mfa":       {"demo.users.list"},
		"/user_mfa/*/mfa": {"demo.users.list"},
	} {
		f := fields[pattern]
		if f == nil {
			t.Errorf("no field %s in %v", pattern, sortedKeys(fields))
			continue
		}
		if !reflect.DeepEqual(f.Operations, want) {
			t.Errorf("%s operations = %v, want %v", pattern, f.Operations, want)
		}
	}
	if _, ok := fields["/user_mfa/0/mfa"]; ok {
		t.Error("fields should write array indices as *")
	}
	source, err := os.ReadFile("collectortest_test.go")
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(source), "\n")
	for _, ref := range fields["/score"].Gaps {
		file, n, ok := tracemap.SplitLine(ref)
		if !ok || file != "componentsdk/collectortest/collectortest_test.go" || n > len(lines) || !strings.Contains(lines[n-1], `record("/score"`) {
			t.Errorf("gap line %q does not name the demo's call that records the score's gap", ref)
		}
	}
	if len(fields["/score"].Gaps) != 2 {
		t.Errorf("/score gap lines = %v, want both lines that record its gap", fields["/score"].Gaps)
	}
	normalized := st.Artifacts[demoNormalized]["/security/score_pct"]
	if normalized == nil || !reflect.DeepEqual(normalized.Copies, []tracemap.Copy{{Path: "artifacts/demo.json", Pointer: "/score"}}) || !reflect.DeepEqual(normalized.Operations, []string{"demo.score.get"}) {
		t.Errorf("normalized score = %+v, want the copied field and the operation behind it", normalized)
	}
}

// traceMapOf turns a suite's trace into the map `epack sdk map` would write
// from it, with no source lines.
func traceMapOf(st tracemap.SuiteTrace) tracemap.Map {
	m := tracemap.Map{Artifacts: map[string]map[string]*tracemap.Field{}, Lines: tracemap.Lines{}}
	for path, fields := range st.Artifacts {
		m.Artifacts[path] = map[string]*tracemap.Field{}
		for pattern, f := range fields {
			m.Artifacts[path][pattern] = &tracemap.Field{Operations: f.Operations, Gaps: f.Gaps, Copies: f.Copies}
		}
	}
	return m
}

func TestKitChecksTheCommittedTraceMap(t *testing.T) {
	st := suiteTraces(t, demoSuite(demo{}))[0]
	t.Setenv(tracemap.Env, "")
	withMap := func(m tracemap.Map) Suite {
		raw, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		s := demoSuite(demo{})
		s.Spec.TraceMap = raw
		return s
	}

	current := checkSuite(t, withMap(traceMapOf(st)))
	for _, v := range current.Violations {
		t.Errorf("a current map: %s/%s: %s", v.Check, v.Case, v.Message)
	}

	stale := traceMapOf(st)
	stale.Artifacts["artifacts/demo.json"]["/score"].Operations = nil
	delete(stale.Artifacts["artifacts/demo.json"], "/org")
	report := checkSuite(t, withMap(stale))
	expectViolation(t, report, "tracemap", "artifacts/demo.json /org is missing")
	expectViolation(t, report, "tracemap", "/score does not list demo.score.get, whose faults change it")
	expectViolation(t, report, "tracemap", "Run epack sdk map")

	broken := demoSuite(demo{})
	broken.Spec.TraceMap = []byte(`{"artifacts": [], "lines": {}}`)
	report = checkSuite(t, broken)
	expectViolation(t, report, "tracemap", "is not a trace map")
	expectViolation(t, report, "schema", "collector-build.json")

	skipped := withMap(stale)
	skipped.SkipChecks = []string{"tracemap"}
	if got := violationsOf(checkSuite(t, skipped), "tracemap"); len(got) != 0 {
		t.Errorf("SkipChecks tracemap still reported %+v", got)
	}

	t.Setenv(tracemap.Env, t.TempDir())
	if got := violationsOf(checkSuite(t, withMap(stale)), "tracemap"); len(got) != 0 {
		t.Errorf("while epack sdk map rebuilds the map, the old one is not checked, got %+v", got)
	}
}

func TestStaleMapViolationIsBounded(t *testing.T) {
	st := suiteTraces(t, demoSuite(demo{}))[0]
	t.Setenv(tracemap.Env, "")
	s := demoSuite(demo{})
	s.Spec.TraceMap = []byte(`{"artifacts": {}, "lines": {}}`)
	report := checkSuite(t, s)
	got := violationsOf(report, "tracemap")
	fields := len(st.Artifacts["artifacts/demo.json"])
	if len(got) != 1 || !strings.Contains(got[0].Message, "and "+strconv.Itoa(fields-maxStale)+" more") {
		t.Errorf("violations = %+v, want one listing %d of the %d missing fields", got, maxStale, fields)
	}
}

func TestOnlyScenarioRunsCarryTheTraceMap(t *testing.T) {
	s := demoSuite(demo{})
	s.Spec.TraceMap = []byte(`{"artifacts": {}, "lines": {}}`)
	k := &kit{suite: s, report: &Report{}, seen: map[string]bool{}, reported: map[Violation]bool{}}
	if err := k.loadSchemas(); err != nil {
		t.Fatal(err)
	}
	ca, err := newTestCA(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	k.ca = ca
	// The fault matrix's runs leave the map's bytes out of their build files,
	// which nothing compares, while the scenario runs' build files keep it.
	for check, want := range map[string]bool{"scenario": true, "faults": false, "determinism": false} {
		res, _ := k.runWith(check, "clean", s.Scenarios[0], nil, s.Config)
		if res.Build == nil {
			t.Fatalf("%s: no build file", check)
		}
		if got := len(res.Build.TraceMap) > 0; got != want {
			t.Errorf("%s: the build file carries the trace map = %t, want %t", check, got, want)
		}
	}
}
