package componentsdk

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/locktivity/epack/componentsdk/internal/outputcheck"
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
		{Config: map[string]any{"level": "internal"}, Name: "demo-prod"},
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
		if want := "artifacts/" + map[bool]string{true: "demo-prod", false: "demo"}[opts.Name != ""] + ".collector-build.json"; build.Path != want {
			t.Errorf("build file path = %q, want %q", build.Path, want)
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
		"unknown role":      `{"artifacts": {"a.json": {"/x": {"code": [{"role": "guess", "line": "a.go:1"}]}}}, "lines": {}}`,
		"line without file": `{"artifacts": {}, "lines": {"12": "x := 1"}}`,
		"extra member":      `{"artifacts": {}, "lines": {}, "steps": []}`,
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

func TestEmitRefusesAnArtifactAtTheBuildFilesPath(t *testing.T) {
	res := RunInProcess(CollectorSpec{Name: "demo"}, func(ctx CollectorContext) error {
		return ctx.Emit([]CollectedArtifact{{Data: map[string]any{}, Path: "artifacts/demo.collector-build.json"}})
	}, InProcessOptions{})
	if res.ExitCode == 0 || res.Failure == nil || !strings.Contains(res.Failure.Message, "the path of the build file") {
		t.Errorf("run = exit %d failure %+v, want Emit to refuse the build file's path", res.ExitCode, res.Failure)
	}
}
