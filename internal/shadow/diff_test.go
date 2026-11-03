package shadow

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// demoRun parses a demo collector run that writes the demo file and records
// gaps, each a gap as the result artifact lists it.
func demoRun(t *testing.T, gaps ...string) RunOutput {
	t.Helper()
	build, _ := json.Marshal(map[string]any{
		"collector": map[string]string{"name": "demo"},
		"schemas":   map[string]json.RawMessage{"artifacts/demo.json": json.RawMessage(strings.Replace(demoSchema, "%s", "", 1))},
	})
	output := `{"type":"epack_result","protocol_version":1,"artifacts":[
{"path":"artifacts/demo.json","data":{"regions":{"us-east-1":{"enabled":true},"eu-west-1":{"enabled":true}}}},
{"path":"artifacts/demo.collector-build.json","schema":"evidencepack/collector-build@v1","data":` + string(build) + `},
{"path":"artifacts/demo.collector-result.json","schema":"evidencepack/collector-result@v1","data":{"collector":{"name":"demo"},"outcome":{"status":"collected"},"gaps":[` + strings.Join(gaps, ",") + `],"calls":{},"run":{}}}
]}`
	r := ParseRun("demo", []byte(output), true)
	if r.Failed {
		t.Fatalf("the demo run did not parse")
	}
	return r
}

func TestGapNoiseIsListedApart(t *testing.T) {
	flaky := `{"path":"artifacts/demo.json","pointer":"/regions","status":"partial","code":"rate_limited","owner":"vendor"}`
	rep, _ := Compare("demo", "trust", demoRun(t, flaky), demoRun(t), demoRun(t, flaky))
	if len(rep.Gaps) != 0 {
		t.Errorf("gaps = %+v, want none: the gap differs between the locked runs", rep.Gaps)
	}
	want := GapRef{FieldRef: FieldRef{Kind: "demo", File: "artifacts/demo.json", Pointer: "/regions"}, Status: "partial", Code: "rate_limited"}
	if len(rep.GapNoise) != 1 || rep.GapNoise[0] != want {
		t.Errorf("gap noise = %+v, want the rate_limited gap that one locked run recorded", rep.GapNoise)
	}
}

func TestGapsAreReportedInAStableOrder(t *testing.T) {
	denied := func(region, permission string) string {
		return `{"path":"artifacts/demo.json","pointer":"/regions/` + region + `/enabled","status":"not_collected","code":"permission_denied","owner":"customer","missing_permission":"` + permission + `"}`
	}
	candidate := demoRun(t, denied("us-east-1", "demo:ReadUS"), denied("eu-west-1", "demo:ReadEU"))
	for range 20 {
		rep, _ := Compare("demo", "trust", demoRun(t), demoRun(t), candidate)
		var got []string
		for _, g := range rep.Gaps {
			got = append(got, g.MissingPermission)
		}
		if strings.Join(got, " ") != "demo:ReadEU demo:ReadUS" {
			t.Fatalf("gap permissions = %v, want them sorted, since both gaps share a pattern and a code", got)
		}
	}
}

// artifact is one artifact as a run's output lists it, with no schema when
// schema is "".
func artifact(path, schema, data string) string {
	a := map[string]any{"path": path, "data": json.RawMessage(data)}
	if schema != "" {
		a["schema"] = schema
	}
	raw, _ := json.Marshal(a)
	return string(raw)
}

// buildArtifact is a build file with schemas keyed by path or schema ID,
// and the schema IDs the collector writes.
func buildArtifact(collectorName string, schemas map[string]string, writes ...string) string {
	raw := map[string]json.RawMessage{}
	for key, s := range schemas {
		raw[key] = json.RawMessage(s)
	}
	data, _ := json.Marshal(map[string]any{"collector": map[string]string{"name": collectorName}, "schemas": raw, "writes": writes})
	return artifact("artifacts/"+collectorName+".collector-build.json", "evidencepack/collector-build@v1", string(data))
}

// resultSpec is what a run's result artifact records.
type resultSpec struct {
	outcome    string
	gaps       []string
	operations []string
	leftOut    []string
}

func resultArtifact(collectorName string, r resultSpec) string {
	outcome := r.outcome
	if outcome == "" {
		outcome = `{"status":"collected"}`
	}
	data := `{"collector":{"name":"` + collectorName + `"},"outcome":` + outcome +
		`,"gaps":[` + strings.Join(r.gaps, ",") + `],"calls":{"operations":[` + strings.Join(r.operations, ",") + `]},"run":{}`
	if r.leftOut != nil {
		listed, _ := json.Marshal(r.leftOut)
		data += `,"collect":{"listed":[],"left_out":` + string(listed) + `}`
	}
	return artifact("artifacts/"+collectorName+".collector-result.json", "evidencepack/collector-result@v1", data+"}")
}

// parsedRun parses a run that wrote artifacts.
func parsedRun(t *testing.T, collectorName string, artifacts ...string) RunOutput {
	t.Helper()
	output := `{"type":"epack_result","protocol_version":1,"artifacts":[` + strings.Join(artifacts, ",") + `]}`
	r := ParseRun(collectorName, []byte(output), true)
	if r.Failed {
		t.Fatalf("the run did not parse: %s", output)
	}
	return r
}

func TestCompareKinds(t *testing.T) {
	file := func(name, schema string) string { return artifact("artifacts/"+name, schema, `{}`) }
	users := file("acme.users.json", "acme/users@v1")
	plain := file("acme.json", "")
	old := file("acme.old.json", "acme/old@v1")
	posture := file("acme.posture.json", "acme/posture@v1")
	locked := func(extra ...string) RunOutput {
		return parsedRun(t, "acme", append([]string{users, plain, old, posture,
			file("acme.repos.json", "acme/repos@v1"),
			file("documents/3f2a9c1e-7b4d-4e8a-9c1f-2b3d4e5f6a7b.json", "acme/document@v1"),
		}, extra...)...)
	}
	candidate := parsedRun(t, "acme", users, plain,
		file("acme.repos.json", "acme/repos@v2"),
		file("acme.audit.json", "acme/audit@v1"),
		file("acme.blip.json", "acme/blip@v1"),
		file("documents/9a8b7c6d-1111-2222-3333-444455556666.json", "acme/document@v1"),
		buildArtifact("acme", nil, "acme/network@v1", "acme/users@v1"),
		resultArtifact("acme", resultSpec{leftOut: []string{"posture", "network"}}),
	)
	// flaky is in the first locked run only, and blip in the second locked
	// run and the candidate's.
	rep, _ := Compare("acme", "trust", locked(file("acme.flaky.json", "acme/flaky@v1")), locked(file("acme.blip.json", "acme/blip@v1")), candidate)
	want := []KindChange{
		{Kind: "acme", File: "artifacts/acme.json", Change: "unchanged"},
		{Kind: "audit", File: "artifacts/acme.audit.json", Change: "added", Candidate: "acme/audit@v1"},
		// One document gone and another new read as unchanged, since both
		// paths share a pattern.
		{Kind: "document", File: "artifacts/documents/{id}", Change: "unchanged", Locked: "acme/document@v1", Candidate: "acme/document@v1"},
		{Kind: "network", Change: "left out", Candidate: "acme/network@v1"},
		{Kind: "old", File: "artifacts/acme.old.json", Change: "removed", Locked: "acme/old@v1"},
		{Kind: "posture", File: "artifacts/acme.posture.json", Change: "left out", Locked: "acme/posture@v1"},
		{Kind: "repos", File: "artifacts/acme.repos.json", Change: "schema changed", Locked: "acme/repos@v1", Candidate: "acme/repos@v2"},
		{Kind: "users", File: "artifacts/acme.users.json", Change: "unchanged", Locked: "acme/users@v1", Candidate: "acme/users@v1"},
	}
	if !reflect.DeepEqual(rep.Kinds, want) {
		t.Errorf("kinds =\n%s\nwant\n%s", jsonOf(rep.Kinds), jsonOf(want))
	}
	// A file only one locked run wrote is noise, whether or not the
	// candidate writes it.
	wantNoise := []FieldRef{{Kind: "blip", File: "artifacts/acme.blip.json"}, {Kind: "flaky", File: "artifacts/acme.flaky.json"}}
	if len(rep.Fields) != 0 || !reflect.DeepEqual(rep.Noise, wantNoise) {
		t.Errorf("fields = %+v, noise = %+v, want no fields and %+v", rep.Fields, rep.Noise, wantNoise)
	}
}

func TestCompareFields(t *testing.T) {
	run := func(schema, data string) RunOutput {
		return parsedRun(t, "demo",
			artifact("artifacts/demo.json", "", data),
			buildArtifact("demo", map[string]string{"artifacts/demo.json": schema}),
		)
	}
	lockedSchema := strings.Replace(demoSchema, "%s", "", 1)
	candidateSchema := strings.Replace(demoSchema, "%s", `, "x-epack-level": "audit"`, 1)
	locked := func(collectedAt string) RunOutput {
		return run(lockedSchema, `{"collected_at":"`+collectedAt+`","mfa_pct":50,"user_count":2,"users":[{"name":"alice","mfa":true},{"name":"bob","mfa":false}],"regions":{"us-east-1":{"enabled":true}}}`)
	}
	candidate := run(candidateSchema, `{"collected_at":"t3","mfa_pct":100,"users_present":true,"users":[{"name":"bob","mfa":true},{"name":"alice","mfa":true}]}`)

	at := func(pointer string) FieldRef {
		return FieldRef{Kind: "demo", File: "artifacts/demo.json", Pointer: pointer}
	}
	rep, preview := Compare("demo", "trust", locked("t1"), locked("t2"), candidate)
	wantFields := []FieldChange{
		{FieldRef: at("/mfa_pct"), Change: "changed"},
		{FieldRef: at("/regions/{key}/enabled"), Change: "removed"},
		{FieldRef: at("/user_count"), Change: "removed", Level: "audit"},
		{FieldRef: at("/users/*/mfa"), Change: "changed"},
		{FieldRef: at("/users/*/name"), Change: "reordered"},
		{FieldRef: at("/users_present"), Change: "added"},
	}
	if !reflect.DeepEqual(rep.Fields, wantFields) {
		t.Errorf("fields =\n%s\nwant\n%s", jsonOf(rep.Fields), jsonOf(wantFields))
	}
	if want := []FieldRef{at("/collected_at")}; !reflect.DeepEqual(rep.Noise, want) {
		t.Errorf("noise = %+v, want %+v", rep.Noise, want)
	}
	if want := []KindChange{{Kind: "demo", File: "artifacts/demo.json", Change: "unchanged"}}; !reflect.DeepEqual(rep.Kinds, want) {
		t.Errorf("kinds = %+v, want %+v", rep.Kinds, want)
	}
	value := func(pointer, field, from, to string) ValueChange {
		return ValueChange{Kind: "demo", File: "artifacts/demo.json", Pointer: pointer, Field: field, From: from, To: to}
	}
	wantValues := []ValueChange{
		value("/mfa_pct", "/mfa_pct", "50", "100"),
		value("/regions/us-east-1/enabled", "/regions/{key}/enabled", "true", ""),
		value("/user_count", "/user_count", "2", ""),
		value("/users/1/mfa", "/users/*/mfa", "false", "true"),
		value("/users/0/name", "/users/*/name", `"alice"`, `"bob"`),
		value("/users/1/name", "/users/*/name", `"bob"`, `"alice"`),
		value("/users_present", "/users_present", "", "true"),
	}
	if !reflect.DeepEqual(preview.Values, wantValues) {
		t.Errorf("preview =\n%s\nwant\n%s", jsonOf(preview.Values), jsonOf(wantValues))
	}

	// At the audit level, user_count is no longer above the run's level.
	rep, _ = Compare("demo", "audit", locked("t1"), locked("t2"), candidate)
	for _, f := range rep.Fields {
		if f.Pointer == "/user_count" && f.Level != "" {
			t.Errorf("at the audit level, user_count = %+v, want no level", f)
		}
	}
}

// TestCompareFieldsAcrossFilesOfOnePattern pins how files that share a
// pattern combine: a field one file adds and another removes reads as
// changed, and a field can be noise in one file and changed in another.
func TestCompareFieldsAcrossFilesOfOnePattern(t *testing.T) {
	build := buildArtifact("acme", map[string]string{"acme/doc@v1": `{"type":"object","properties":{"title":{"type":"string"},"size":{"type":"integer"}}}`})
	run := func(a, b string) RunOutput {
		return parsedRun(t, "acme",
			artifact("artifacts/docs/0000000a.json", "acme/doc@v1", a),
			artifact("artifacts/docs/0000000b.json", "acme/doc@v1", b),
			build,
		)
	}
	rep, preview := Compare("acme", "trust",
		run(`{"title":"a"}`, `{"title":"b","size":2}`),
		run(`{"title":"a-again"}`, `{"title":"b","size":2}`),
		run(`{"title":"a","size":1}`, `{"title":"B"}`),
	)
	at := func(pointer string) FieldRef {
		return FieldRef{Kind: "doc", File: "artifacts/docs/{id}", Pointer: pointer}
	}
	wantFields := []FieldChange{
		{FieldRef: at("/size"), Change: "changed"},
		{FieldRef: at("/title"), Change: "changed"},
	}
	if !reflect.DeepEqual(rep.Fields, wantFields) {
		t.Errorf("fields =\n%s\nwant\n%s", jsonOf(rep.Fields), jsonOf(wantFields))
	}
	if want := []FieldRef{at("/title")}; !reflect.DeepEqual(rep.Noise, want) {
		t.Errorf("noise = %+v, want %+v", rep.Noise, want)
	}
	wantValues := []ValueChange{
		{Kind: "doc", File: "artifacts/docs/0000000a.json", Pointer: "/size", Field: "/size", To: "1"},
		{Kind: "doc", File: "artifacts/docs/0000000b.json", Pointer: "/size", Field: "/size", From: "2"},
		{Kind: "doc", File: "artifacts/docs/0000000b.json", Pointer: "/title", Field: "/title", From: `"b"`, To: `"B"`},
	}
	if !reflect.DeepEqual(preview.Values, wantValues) {
		t.Errorf("preview =\n%s\nwant\n%s", jsonOf(preview.Values), jsonOf(wantValues))
	}
}

func TestCompareGaps(t *testing.T) {
	gap := func(pointer, status, code, extra string) string {
		return `{"path":"artifacts/demo.json","pointer":"` + pointer + `","status":"` + status + `","code":"` + code + `","owner":"vendor"` + extra + `}`
	}
	stay := gap("/regions/eu-west-1", "partial", "timeout", "")
	gone := gap("/regions", "partial", "vendor_error", "")
	fresh := gap("/regions/us-east-1/enabled", "not_collected", "permission_denied", `,"missing_permission":"demo:ReadRegions"`)
	flakyA := gap("/users", "partial", "rate_limited", "")
	flakyB := gap("/mfa_pct", "not_collected", "rate_limited", "")
	notShared := gap("/user_count", "not_collected", "not_shared", "")
	noPath := `{"pointer":"","status":"partial","code":"vendor_error","owner":"vendor"}`

	// flakyA is in the first locked run and the candidate's, and flakyB in
	// the second locked run only.
	rep, _ := Compare("demo", "trust",
		demoRun(t, stay, gone, flakyA),
		demoRun(t, stay, gone, flakyB),
		demoRun(t, stay, fresh, flakyA, notShared, noPath),
	)
	at := func(pointer string) FieldRef {
		return FieldRef{Kind: "demo", File: "artifacts/demo.json", Pointer: pointer}
	}
	wantGaps := []GapChange{
		{GapRef: GapRef{FieldRef: FieldRef{Kind: "demo"}, Status: "partial", Code: "vendor_error"}, Change: "added"},
		{GapRef: GapRef{FieldRef: at("/regions"), Status: "partial", Code: "vendor_error"}, Change: "removed"},
		{GapRef: GapRef{FieldRef: at("/regions/{key}/enabled"), Status: "not_collected", Code: "permission_denied", MissingPermission: "demo:ReadRegions"}, Change: "added"},
	}
	if !reflect.DeepEqual(rep.Gaps, wantGaps) {
		t.Errorf("gaps =\n%s\nwant\n%s", jsonOf(rep.Gaps), jsonOf(wantGaps))
	}
	wantNoise := []GapRef{
		{FieldRef: at("/mfa_pct"), Status: "not_collected", Code: "rate_limited"},
		{FieldRef: at("/users"), Status: "partial", Code: "rate_limited"},
	}
	if !reflect.DeepEqual(rep.GapNoise, wantNoise) {
		t.Errorf("gap noise =\n%s\nwant\n%s", jsonOf(rep.GapNoise), jsonOf(wantNoise))
	}
}

func TestCompareOperationsAndCalls(t *testing.T) {
	op := func(name string, calls int, permission string, codes ...string) string {
		raw, _ := json.Marshal(map[string]any{"name": name, "calls": calls, "attempts": calls, "retries": 0, "retried": false, "permission": permission, "error_codes": codes})
		return string(raw)
	}
	run := func(ops ...string) RunOutput {
		return parsedRun(t, "acme", artifact("artifacts/acme.json", "", `{}`), resultArtifact("acme", resultSpec{operations: ops}))
	}
	rep, _ := Compare("acme", "trust",
		run(
			op("acme.users.list", 4, ""),
			op("acme.old.get", 3, "acme:Old"),
			op("acme.repos.list", 3, "acme:ReadRepos", "rate_limited"),
			op("acme.teams.list", 0, "", "timeout"),
			op("acme.flaky.get", 2, ""),
		),
		run(
			op("acme.users.list", 4000, ""),
			op("acme.old.get", 3, "acme:Old"),
			op("acme.repos.list", 3, "acme:ReadRepos", "timeout"),
			op("acme.teams.list", 0, ""),
			op("acme.blip.get", 1, ""),
		),
		run(
			op("acme.users.list", 600, ""),
			op("acme.audit.list", 500, "acme:ReadAudit"),
			op("acme.repos.list", 100, "acme:ReadRepos", "not_found", "permission_denied", "rate_limited", "timeout"),
			op("acme.teams.list", 0, "", "timeout"),
			op("acme.flaky.get", 0, "", "timeout"),
		),
	)
	want := []OperationChange{
		{Name: "acme.audit.list", Change: "added", Permission: "acme:ReadAudit"},
		{Name: "acme.old.get", Change: "removed"},
		{Name: "acme.repos.list", Change: "now fails", Permission: "acme:ReadRepos", Codes: []string{"not_found", "permission_denied"}},
	}
	if !reflect.DeepEqual(rep.Operations, want) {
		t.Errorf("operations =\n%s\nwant\n%s", jsonOf(rep.Operations), jsonOf(want))
	}
	// Calls count the first locked run and the candidate's.
	if want := (&Calls{Locked: "10-99", Candidate: "1,000-9,999"}); !reflect.DeepEqual(rep.Calls, want) {
		t.Errorf("calls = %+v, want %+v", rep.Calls, want)
	}

	rep, _ = Compare("acme", "trust", run(op("acme.users.list", 0, "")), run(op("acme.users.list", 7, "")), run(op("acme.users.list", 0, "")))
	if rep.Calls != nil || len(rep.Operations) != 0 {
		t.Errorf("calls = %+v, operations = %+v, want none", rep.Calls, rep.Operations)
	}
}

func TestCallRange(t *testing.T) {
	for n, want := range map[int]string{
		0: "0", 1: "1-9", 9: "1-9", 10: "10-99", 99: "10-99", 100: "100-999", 999: "100-999",
		1000: "1,000-9,999", 9999: "1,000-9,999", 10000: "10,000 or more",
	} {
		if got := callRange(n); got != want {
			t.Errorf("callRange(%d) = %q, want %q", n, got, want)
		}
	}
}

// TestCompareSortsOperationsByNameAndChange pins the order of operations:
// by name and change run together, so acme.get.all sorts before acme.get.
func TestCompareSortsOperationsByNameAndChange(t *testing.T) {
	op := func(name string) string {
		return `{"name":"` + name + `","calls":0,"attempts":0,"retries":0,"retried":false}`
	}
	run := func(ops ...string) RunOutput {
		return parsedRun(t, "acme", resultArtifact("acme", resultSpec{operations: ops}))
	}
	for range 10 {
		rep, _ := Compare("acme", "trust", run(op("acme.get")), run(op("acme.get")), run(op("acme.get.all"), op("acme.a")))
		var got []string
		for _, o := range rep.Operations {
			got = append(got, o.Name+" "+o.Change)
		}
		if want := "acme.a added,acme.get removed,acme.get.all added"; strings.Join(got, ",") != want {
			t.Fatalf("operations = %v, want %s", got, want)
		}
	}
}

func TestCompareStopsAtAFailedRun(t *testing.T) {
	partial := parsedRun(t, "demo", resultArtifact("demo", resultSpec{outcome: `{"status":"partial","code":"rate_limited"}`}))
	failed := ParseRun("demo", []byte(`not json`), true)
	rep, preview := Compare("demo", "trust", demoRun(t), partial, failed)
	want := Report{
		SchemaVersion: ReportSchemaVersion,
		Collector:     "demo",
		Level:         "trust",
		Locked:        LockedRuns{Runs: []Outcome{{Status: "collected"}, {Status: "partial", Code: "rate_limited"}}},
		Candidate:     CandidateRun{Outcome: Outcome{Status: "failed"}},
	}
	if !reflect.DeepEqual(rep, want) {
		t.Errorf("report =\n%s\nwant\n%s", jsonOf(rep), jsonOf(want))
	}
	if want := (Preview{Collector: "demo", Values: []ValueChange{}}); !reflect.DeepEqual(preview, want) {
		t.Errorf("preview = %+v, want %+v", preview, want)
	}
}

func jsonOf(v any) string {
	raw, _ := json.MarshalIndent(v, "", "  ")
	return string(raw)
}

// TestCompareFieldsWhenTheSecondLockedRunStagedTheFile pins that only the
// first locked run's file and the candidate's must be inline. A file the
// second locked run staged reads as null, so every field is noise.
func TestCompareFieldsWhenTheSecondLockedRunStagedTheFile(t *testing.T) {
	inline := parsedRun(t, "acme", artifact("artifacts/acme.json", "", `{"a":1}`))
	staged := parsedRun(t, "acme", `{"path":"artifacts/acme.json","file":"staged/acme.json"}`)
	candidate := parsedRun(t, "acme", artifact("artifacts/acme.json", "", `{"a":2}`))
	// A file staged in any run has no fields to compare, so none is noise.
	rep, preview := Compare("acme", "trust", inline, staged, candidate)
	if len(rep.Fields) != 0 || len(rep.Noise) != 0 || len(preview.Values) != 0 {
		t.Errorf("fields = %+v, noise = %+v, values = %+v, want none", rep.Fields, rep.Noise, preview.Values)
	}
	// With the candidate's file staged, no field is compared.
	rep, _ = Compare("acme", "trust", inline, inline, staged)
	if len(rep.Fields) != 0 || len(rep.Noise) != 0 {
		t.Errorf("fields = %+v, noise = %+v, want none", rep.Fields, rep.Noise)
	}
}

func TestTheReportHidesFileNamesNothingDeclares(t *testing.T) {
	doc := func(title, body string) string {
		return artifact("artifacts/documents/"+title+".json", "", `{"approved":`+body+`}`)
	}
	locked := func() RunOutput { return parsedRun(t, "acme", doc("Northwind Merger Plan", "true")) }
	rep, _ := Compare("acme", "trust", locked(), locked(), parsedRun(t, "acme", doc("Northwind Merger Plan", "false")))
	if strings.Contains(jsonOf(rep), "Northwind") {
		t.Errorf("report = %s, want no file name that no build file or schema declares", jsonOf(rep))
	}
	if len(rep.Fields) != 1 || rep.Fields[0].File != "artifacts/documents/{file}.json" {
		t.Errorf("fields = %+v, want the change named by its directory and extension", rep.Fields)
	}
}
