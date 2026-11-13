package componentsdk

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/locktivity/epack/internal/outputcheck"
)

const demoTraceMap = `{
  "artifacts": {
    "artifacts/demo.json": {
      "/users/mfa_pct": {
        "operations": ["demo.users.factors.list", "demo.users.list"],
        "code": [
          {"role": "assign", "line": "internal/collector/collector.go:88"},
          {"role": "helper", "line": "internal/collector/collector.go:120", "end": 126}
        ],
        "gaps": ["internal/collector/collector.go:95"]
      },
      "/users/inventory/*/id": {"operations": ["demo.users.list"]}
    },
    "artifacts/demo.idp-posture.json": {
      "/mfa_coverage_pct": {"copies": [{"path": "artifacts/demo.json", "pointer": "/users/mfa_pct"}]}
    }
  },
  "lines": {
    "internal/collector/collector.go:88": "\tout.MFAPct = percent(enrolled, total)",
    "internal/collector/collector.go:95": "\t\tgaps.partial(unmeasured, firstErr, \"/users/mfa_pct\")"
  }
}`

var demoBuildSpec = CollectorSpec{
	Name:     "demo",
	Version:  "v0.4.0",
	Commit:   "5d0c1e7f2a9b4c3d8e6f1a0b2c4d6e8f0a1b3c5d",
	Schemas:  map[string][]byte{"artifacts/demo.json": []byte(`{"type": "object", "description": "a < b && c"}`)},
	TraceMap: []byte(demoTraceMap),
}

func emitDemo(ctx CollectorContext) error {
	data := map[string]any{"collected_at": Now(ctx).Format(time.RFC3339)}
	if ctx.Level().AtLeast(LevelInternal) {
		data["inventory"] = []any{}
	}
	return ctx.Emit([]CollectedArtifact{{Data: data, Path: "artifacts/demo.json"}})
}

func buildArtifact(t *testing.T, res InProcessResult) EmittedArtifact {
	t.Helper()
	for _, a := range res.Artifacts {
		if a.Schema == BuildSchema {
			return a
		}
	}
	t.Fatalf("no build file in %+v (stderr %s)", res.Artifacts, res.Stderr)
	return EmittedArtifact{}
}

func TestBuildFileIsTheSameForEveryRunOfABuild(t *testing.T) {
	var first []byte
	for i, opts := range []InProcessOptions{
		{Config: map[string]any{"level": "trust"}, RunID: "run-1"},
		{Config: map[string]any{"level": "audit"}, RunID: "run-2", Clock: func() time.Time { return time.Unix(1e9, 0) }},
		{Config: map[string]any{"level": "internal"}},
	} {
		res := RunInProcess(demoBuildSpec, emitDemo, opts)
		if res.ExitCode != 0 {
			t.Fatalf("exit = %d stderr = %s", res.ExitCode, res.Stderr)
		}
		build := buildArtifact(t, res)
		if i == 0 {
			first = build.Data
		} else if !bytes.Equal(build.Data, first) {
			t.Errorf("run %d wrote another build file:\n%s\nwant\n%s", i, build.Data, first)
		}
		if build.Path != "artifacts/demo.collector-build.json" {
			t.Errorf("build file path = %q", build.Path)
		}
	}

	// A run configured under another name writes its files under that name,
	// and its build file names them by those paths.
	prod := RunInProcess(demoBuildSpec, emitDemo, InProcessOptions{Name: "demo-prod"})
	if prod.ExitCode != 0 || prod.Build == nil {
		t.Fatalf("exit = %d stderr = %s", prod.ExitCode, prod.Stderr)
	}
	renamed := strings.ReplaceAll(string(first), "artifacts/demo.", "artifacts/demo-prod.")
	var want, got any
	if err := json.Unmarshal([]byte(renamed), &want); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(buildArtifact(t, prod).Data, &got); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("the demo-prod build file = %s\nwant the demo one with each artifacts/demo. path under artifacts/demo-prod.", buildArtifact(t, prod).Data)
	}
	for _, a := range prod.Artifacts {
		if !strings.HasPrefix(a.Path, "artifacts/demo-prod.") {
			t.Errorf("the demo-prod run wrote %s", a.Path)
		}
	}
	res := RunInProcess(demoBuildSpec, emitDemo, InProcessOptions{})
	b := res.Build
	if b == nil || b.Collector != (ResultCollector{Name: "demo", Version: "v0.4.0", Commit: demoBuildSpec.Commit}) || len(b.Schemas) != 1 || len(b.TraceMap) == 0 {
		t.Fatalf("build = %+v", b)
	}
	sch, err := outputcheck.Compile(BuildSchemaJSON())
	if err != nil {
		t.Fatal(err)
	}
	doc, err := outputcheck.Decode(buildArtifact(t, res).Data)
	if err != nil {
		t.Fatal(err)
	}
	if found := outputcheck.Validate(sch, "build", doc); len(found) > 0 {
		t.Errorf("the build file does not match its schema: %+v", found)
	}
}

func TestBuildSchemaChecksTheTraceMap(t *testing.T) {
	sch, err := outputcheck.Compile(BuildSchemaJSON())
	if err != nil {
		t.Fatal(err)
	}
	for name, traceMap := range map[string]string{
		"unknown role":             `{"artifacts": {"a.json": {"/x": {"code": [{"role": "guess", "line": "a.go:1"}]}}}, "lines": {}}`,
		"line without file":        `{"artifacts": {}, "lines": {"12": "x := 1"}}`,
		"extra member":             `{"artifacts": {}, "lines": {}, "steps": []}`,
		"suite without a name":     `{"artifacts": {}, "lines": {}, "suites": [{"operations": [], "scenarios": 1, "recordings": 0}]}`,
		"waiver without expiry":    `{"artifacts": {}, "lines": {}, "suites": [{"name": "demo", "operations": ["demo.me.get"], "scenarios": 1, "recordings": 0, "waivers": [{"check": "faults", "reason": "r"}]}]}`,
		"waiver with a loose date": `{"artifacts": {}, "lines": {}, "suites": [{"name": "demo", "operations": ["demo.me.get"], "scenarios": 1, "recordings": 0, "waivers": [{"check": "faults", "reason": "r", "expires": "next year"}]}]}`,
	} {
		doc, err := outputcheck.Decode([]byte(`{"collector": {"name": "demo"}, "schemas": {}, "trace_map": ` + traceMap + `}`))
		if err != nil {
			t.Fatal(err)
		}
		if found := outputcheck.Validate(sch, "build", doc); len(found) == 0 {
			t.Errorf("%s: the build schema accepted %s", name, traceMap)
		}
	}
}

func TestBuildSchemaAcceptsTheSuitesAMapKeeps(t *testing.T) {
	sch, err := outputcheck.Compile(BuildSchemaJSON())
	if err != nil {
		t.Fatal(err)
	}
	doc, err := outputcheck.Decode([]byte(`{"collector": {"name": "demo"}, "schemas": {}, "trace_map": {"artifacts": {}, "lines": {}, "suites": [
		{"name": "demo", "operations": ["demo.me.get", "demo.users.list"], "scenarios": 3, "recordings": 1,
		 "waivers": [{"check": "insensitive", "subject": "demo.me.get", "reason": "The sign-in feeds no value.", "expires": "2027-03-01"}]},
		{"name": "demo-token", "operations": ["demo.users.list"], "scenarios": 1, "recordings": 0}]}}`))
	if err != nil {
		t.Fatal(err)
	}
	if found := outputcheck.Validate(sch, "build", doc); len(found) > 0 {
		t.Errorf("the build schema rejects a map with suites: %+v", found)
	}
}

func TestBuildFileLeavesOutWhatIsNotJSON(t *testing.T) {
	spec := CollectorSpec{
		Name:     "demo",
		Schemas:  map[string][]byte{"artifacts/demo.json": []byte(`{"type":`), "evidencepack/idp-posture@v1": []byte(`true`)},
		TraceMap: []byte(`["not", "a", "map"]`),
	}
	res := RunInProcess(spec, emitDemo, InProcessOptions{})
	if res.ExitCode != 0 || res.Build == nil {
		t.Fatalf("exit = %d build = %+v stderr = %s", res.ExitCode, res.Build, res.Stderr)
	}
	if _, ok := res.Build.Schemas["artifacts/demo.json"]; ok || len(res.Build.Schemas) != 1 || res.Build.TraceMap != nil {
		t.Errorf("build = %+v, want the broken schema and the trace map left out", res.Build)
	}
	if !strings.Contains(res.Stderr, "CollectorSpec.TraceMap is not a JSON object") {
		t.Errorf("stderr = %q, want a warning about the trace map", res.Stderr)
	}
}

func TestBuildFileCarriesTheNormalizedSchemaWithTheCollectorsMethods(t *testing.T) {
	spec := CollectorSpec{Name: "tls", Version: "1.0.0", Writes: []string{"evidencepack/tls@v1"},
		Methods: map[string]map[string]string{"evidencepack/tls@v1": {"/summary/reachable_pct": "Connects to each endpoint once."}}}
	data := map[string]any{"schema_version": "1.0.0", "collected_at": "2026-01-01T00:00:00Z", "summary": map[string]any{"total_endpoints": 0}, "endpoints": []any{}}
	res := RunInProcess(spec, func(ctx CollectorContext) error {
		return ctx.Emit([]CollectedArtifact{{Data: data, Path: "artifacts/tls.json", Schema: "evidencepack/tls@v1"}})
	}, InProcessOptions{})
	if res.ExitCode != 0 || res.Build == nil {
		t.Fatalf("exit %d: %s", res.ExitCode, res.Stderr)
	}
	sch, err := outputcheck.Compile(res.Build.Schemas["evidencepack/tls@v1"])
	if err != nil {
		t.Fatal(err)
	}
	if got := outputcheck.MethodAt(sch, "/summary/reachable_pct"); got != "Connects to each endpoint once." {
		t.Errorf("the build file's tls schema gives the method %q", got)
	}
	for _, f := range res.Result.Checks {
		if f.Check == CheckSchema {
			t.Errorf("the artifact was checked against a schema it does not match: %+v", f)
		}
	}
}

func TestEmitRefusesAnArtifactAtTheBuildFilesPath(t *testing.T) {
	res := RunInProcess(CollectorSpec{Name: "demo"}, func(ctx CollectorContext) error {
		return ctx.Emit([]CollectedArtifact{{Data: map[string]any{}, Path: "artifacts/demo.collector-build.json"}})
	}, InProcessOptions{})
	if res.ExitCode == 0 || res.Failure == nil || !strings.Contains(res.Failure.Message, "the path of the build file") {
		t.Errorf("run = exit %d failure %+v, want Emit to refuse the build file's path", res.ExitCode, res.Failure)
	}
}
