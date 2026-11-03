package componentsdk

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestCollectOf(t *testing.T) {
	cases := []struct {
		name   string
		config map[string]any
		want   []string
		set    bool
		bad    bool
	}{
		{"absent", map[string]any{"level": "trust"}, nil, false, false},
		{"decoded JSON", map[string]any{"collect": []any{"tls", "demo"}}, []string{"tls", "demo"}, true, false},
		{"strings", map[string]any{"collect": []string{"tls"}}, []string{"tls"}, true, false},
		{"empty list", map[string]any{"collect": []any{}}, []string{}, true, false},
		{"not a list", map[string]any{"collect": "tls"}, nil, true, true},
		{"not a string", map[string]any{"collect": []any{"tls", 3}}, nil, true, true},
		{"empty name", map[string]any{"collect": []any{""}}, nil, true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, set, err := CollectOf(tc.config)
			if set != tc.set || (err != nil) != tc.bad || (!tc.bad && !reflect.DeepEqual(got, tc.want)) {
				t.Errorf("CollectOf = %v, %v, %v; want %v, %v, error %v", got, set, err, tc.want, tc.set, tc.bad)
			}
		})
	}
}

func TestKindOf(t *testing.T) {
	for schemaID, want := range map[string]string{
		"evidencepack/vuln-scanning@v1": "vuln-scanning",
		"demo/posture@v2":               "posture",
		"":                              "github",
		"odd schema":                    "odd schema",
	} {
		if got := KindOf(schemaID, "github"); got != want {
			t.Errorf("KindOf(%q) = %q, want %q", schemaID, got, want)
		}
	}
}

func TestACollectKeyThatIsNotAListOfKindsIsAConfigError(t *testing.T) {
	for name, value := range map[string]any{"not a list": "tls", "not a kind": []any{"Cloud Posture"}} {
		res := RunInProcess(CollectorSpec{Name: "demo"}, func(ctx CollectorContext) error {
			t.Errorf("%s: the handler ran with an unusable collect key", name)
			return nil
		}, InProcessOptions{Config: map[string]any{"collect": value}})
		if res.ExitCode != 2 || res.Failure == nil || res.Failure.Code != CodeConfigInvalid {
			t.Errorf("%s: exit %d, failure %+v; want a config_invalid failure", name, res.ExitCode, res.Failure)
		}
	}
}

func TestTheResultListsKindsTheRunNeverWrote(t *testing.T) {
	res := RunInProcess(CollectorSpec{Name: "demo"}, func(ctx CollectorContext) error {
		return ctx.Emit([]CollectedArtifact{{Data: map[string]any{}}, {Schema: "evidencepack/tls@v1", Data: map[string]any{}}})
	}, InProcessOptions{Name: "demo-prod", Config: map[string]any{"collect": []any{"demo", "tls", "vuln-scaning"}}})
	if res.ExitCode != 0 {
		t.Fatalf("exit %d: %s", res.ExitCode, res.Stderr)
	}
	if got := res.Result.Collect; got == nil || !reflect.DeepEqual(got.Unmatched, []string{"vuln-scaning"}) || len(got.LeftOut) != 0 {
		t.Errorf("collect = %+v, want only the misspelled kind unmatched, and the collector's own file kept under its published name", got)
	}
}

// selectionRun emits detailed and normalized as a collector with both would,
// at the level and with the artifacts key config gives.
func selectionRun(spec CollectorSpec, config map[string]any, handler func(CollectorContext) []CollectedArtifact) InProcessResult {
	if spec.Name == "" {
		spec.Name = "demo"
	}
	return RunInProcess(spec, func(ctx CollectorContext) error {
		return ctx.Emit(handler(ctx))
	}, InProcessOptions{Config: config})
}

func paths(res InProcessResult) []string {
	var out []string
	for _, a := range res.Artifacts {
		out = append(out, a.Path)
	}
	return out
}

func dataOf(t *testing.T, res InProcessResult, path string) map[string]any {
	t.Helper()
	for _, a := range res.Artifacts {
		if a.Path == path {
			var doc map[string]any
			if err := json.Unmarshal(a.Data, &doc); err != nil {
				t.Fatalf("%s: %v", path, err)
			}
			return doc
		}
	}
	t.Fatalf("no artifact %s in %v", path, paths(res))
	return nil
}

// gapAt finds the gap at at's path and pointer, or with no path, at its
// schema. The SDK fills in a gap's schema from the artifact at its path.
func gapAt(res InProcessResult, at Location) *Gap {
	for i, g := range res.Result.Gaps {
		if g.Pointer == at.Pointer && at.names(g.Path, g.Schema) && (at.Path != "" || g.Path == "") {
			return &res.Result.Gaps[i]
		}
	}
	return nil
}

func TestTheCollectKeyLeavesOutKindsItDoesNotList(t *testing.T) {
	res := selectionRun(CollectorSpec{}, map[string]any{"collect": []any{"tls"}}, func(CollectorContext) []CollectedArtifact {
		return []CollectedArtifact{
			{Data: map[string]any{"x": 1}},
			{Schema: "evidencepack/tls@v1", Data: map[string]any{"y": 2}},
		}
	})
	if res.ExitCode != 0 {
		t.Fatalf("exit %d: %s", res.ExitCode, res.Stderr)
	}
	want := []string{"artifacts/demo_1.json", "artifacts/demo.collector-build.json", "artifacts/demo.collector-result.json"}
	if got := paths(res); !reflect.DeepEqual(got, want) {
		t.Errorf("paths = %v, want %v: the normalized artifact keeps the path its place gave it", got, want)
	}
	if g := gapAt(res, Location{Path: "artifacts/demo.json"}); g == nil || g.Code != CodeNotShared || g.Owner != OwnerNobody || g.Status != GapNotCollected {
		t.Errorf("gap on the detailed artifact = %+v, want not_shared", g)
	}
	if got := res.Result.Collect; got == nil || !reflect.DeepEqual(*got, ResultCollect{Listed: []string{"tls"}, LeftOut: []string{"demo"}}) {
		t.Errorf("collect = %+v, want the detailed file left out under the collector's name", got)
	}
	if res.Result.Outcome.Status != OutcomeCollected {
		t.Errorf("outcome = %+v, want collected, since leaving an artifact out is the customer's choice", res.Result.Outcome)
	}
}

func TestTheCollectKeyAppliesAtEveryLevel(t *testing.T) {
	res := selectionRun(CollectorSpec{}, map[string]any{"level": "internal", "collect": []any{"tls"}}, func(CollectorContext) []CollectedArtifact {
		return []CollectedArtifact{
			{Data: map[string]any{"x": 1}},
			{Schema: "evidencepack/tls@v1", Data: map[string]any{"y": 2}},
		}
	})
	if got := len(res.Artifacts); got != 3 || res.Result.Collect == nil {
		t.Errorf("%d artifacts, collect %+v; want the detailed file left out of an internal run too", got, res.Result.Collect)
	}
}

func TestACollectorsOwnFileGoesByEitherName(t *testing.T) {
	res := RunInProcess(CollectorSpec{Name: "github"}, func(ctx CollectorContext) error {
		return ctx.Emit([]CollectedArtifact{{Data: map[string]any{}}})
	}, InProcessOptions{Name: "github-prod", Config: map[string]any{"collect": []any{"github"}}})
	if res.ExitCode != 0 || len(res.Artifacts) != 3 || res.Result.Collect == nil || len(res.Result.Collect.LeftOut) != 0 {
		t.Errorf("exit %d, %d artifacts, collect %+v; want the file kept under the published name", res.ExitCode, len(res.Artifacts), res.Result.Collect)
	}
}

func TestLeavingOutANormalizedArtifactRemovesWhatWasCopiedFromIt(t *testing.T) {
	spec := CollectorSpec{Schemas: map[string][]byte{"demo/posture@v1": []byte(`{}`)}}
	res := selectionRun(spec, map[string]any{"collect": []any{"posture"}}, func(ctx CollectorContext) []CollectedArtifact {
		Records(ctx).Mirror(Location{Path: "artifacts/scan.json", Pointer: "/enabled"}, Location{Path: "artifacts/posture.json", Pointer: "/scan_enabled"})
		return []CollectedArtifact{
			{Path: "artifacts/scan.json", Schema: "evidencepack/tls@v1", Data: map[string]any{"enabled": true}},
			{Path: "artifacts/posture.json", Schema: "demo/posture@v1", Data: map[string]any{"scan_enabled": true, "other": 1}},
		}
	})
	if res.ExitCode != 0 {
		t.Fatalf("exit %d: %s", res.ExitCode, res.Stderr)
	}
	doc := dataOf(t, res, "artifacts/posture.json")
	if _, ok := doc["scan_enabled"]; ok || doc["other"] != float64(1) {
		t.Errorf("posture = %v, want the copy removed and the rest kept", doc)
	}
	if g := gapAt(res, Location{Path: "artifacts/posture.json", Pointer: "/scan_enabled"}); g == nil || g.Code != CodeNotShared {
		t.Errorf("gap on the copy = %+v, want not_shared", g)
	}
	if g := gapAt(res, Location{Schema: "evidencepack/tls@v1"}); g == nil || g.Code != CodeNotShared {
		t.Errorf("gap on the normalized artifact = %+v, want not_shared", g)
	}
}

func TestLeavingOutADetailedArtifactKeepsWhatWasCopiedFromIt(t *testing.T) {
	res := selectionRun(CollectorSpec{}, map[string]any{"collect": []any{"tls"}}, func(ctx CollectorContext) []CollectedArtifact {
		rec := Records(ctx)
		rec.NotCollectedCode(Location{Path: "artifacts/detail.json", Pointer: "/lost"}, CodeVendorError, "unavailable")
		rec.Mirror(Location{Path: "artifacts/detail.json", Pointer: "/lost"}, Location{Path: "artifacts/tls.json", Pointer: "/lost"})
		rec.Mirror(Location{Path: "artifacts/detail.json", Pointer: "/kept"}, Location{Path: "artifacts/tls.json", Pointer: "/kept"})
		return []CollectedArtifact{
			{Path: "artifacts/detail.json", Schema: "demo/detail@v1", Data: map[string]any{"kept": 1}},
			{Path: "artifacts/tls.json", Schema: "evidencepack/tls@v1", Data: map[string]any{"kept": 1}},
		}
	})
	if res.ExitCode != 0 {
		t.Fatalf("exit %d: %s", res.ExitCode, res.Stderr)
	}
	if doc := dataOf(t, res, "artifacts/tls.json"); doc["kept"] != float64(1) {
		t.Errorf("normalized = %v, want the copied value kept", doc)
	}
	if g := gapAt(res, Location{Path: "artifacts/detail.json", Pointer: "/lost"}); g != nil {
		t.Errorf("gap %+v points into an artifact the pack does not hold", g)
	}
	if g := gapAt(res, Location{Path: "artifacts/tls.json", Pointer: "/lost"}); g == nil || g.Code != CodeVendorError {
		t.Errorf("mirrored gap = %+v, want the vendor_error gap carried to the normalized value", g)
	}
	if res.Result.Outcome.Status != OutcomePartial || res.Result.Outcome.Code != CodeVendorError {
		t.Errorf("outcome = %+v, want partial with the vendor_error code, passing over not_shared", res.Result.Outcome)
	}
}

const auditOnlySchema = `{"type": "object", "x-epack-level": "audit", "properties": {"kept": {"type": "integer"}}}`

func TestAnArtifactMarkedAboveTheRunLevelIsNotWritten(t *testing.T) {
	spec := CollectorSpec{Schemas: map[string][]byte{"artifacts/detail.json": []byte(auditOnlySchema)}}
	run := func(level string) InProcessResult {
		return selectionRun(spec, map[string]any{"level": level}, func(ctx CollectorContext) []CollectedArtifact {
			rec := Records(ctx)
			rec.NotCollectedCode(Location{Path: "artifacts/detail.json", Pointer: "/lost"}, CodeVendorError, "unavailable")
			rec.Mirror(Location{Path: "artifacts/detail.json", Pointer: "/lost"}, Location{Path: "artifacts/tls.json", Pointer: "/lost"})
			return []CollectedArtifact{
				{Path: "artifacts/detail.json", Schema: "demo/detail@v1", Data: map[string]any{"kept": 1}},
				{Path: "artifacts/tls.json", Schema: "evidencepack/tls@v1", Data: map[string]any{}},
			}
		})
	}
	trust := run("trust")
	if got := paths(trust); len(got) != 3 || got[0] != "artifacts/tls.json" {
		t.Errorf("trust paths = %v, want the detailed artifact left out", got)
	}
	if trust.Result.Collect != nil || gapAt(trust, Location{Path: "artifacts/detail.json", Pointer: "/lost"}) != nil {
		t.Errorf("trust collect %+v, gaps %+v; want no collect record and no gap inside the artifact left out", trust.Result.Collect, trust.Result.Gaps)
	}
	if g := gapAt(trust, Location{Path: "artifacts/tls.json", Pointer: "/lost"}); g == nil || g.Code != CodeVendorError {
		t.Errorf("mirrored gap = %+v, want it kept on the normalized value", g)
	}
	if got := paths(run("audit")); len(got) != 4 {
		t.Errorf("audit paths = %v, want the detailed artifact written", got)
	}
}

func TestAFieldMarkedAboveTheRunLevelIsLeftOutAndReported(t *testing.T) {
	schema := `{"type": "object", "properties": {"present": {"type": "boolean"}, "count": {"type": "integer", "x-epack-level": "audit"}}}`
	spec := CollectorSpec{Schemas: map[string][]byte{"artifacts/detail.json": []byte(schema)}}
	run := func(level string) InProcessResult {
		return selectionRun(spec, map[string]any{"level": level}, func(CollectorContext) []CollectedArtifact {
			return []CollectedArtifact{{Path: "artifacts/detail.json", Data: map[string]any{"present": true, "count": 3}}}
		})
	}
	trust := run("trust")
	if doc := dataOf(t, trust, "artifacts/detail.json"); doc["count"] != nil || doc["present"] != true {
		t.Errorf("trust data = %v, want the audit-level count left out and the rest kept", doc)
	}
	found := false
	for _, f := range trust.Result.Checks {
		found = found || (f.Check == CheckLevels && f.Path == "artifacts/detail.json" && f.Pointer == "/count")
	}
	if !found {
		t.Errorf("checks = %+v, want a levels finding for the count the collector wrote at trust", trust.Result.Checks)
	}
	audit := run("audit")
	if doc := dataOf(t, audit, "artifacts/detail.json"); doc["count"] == nil {
		t.Errorf("audit data = %v, want the count kept", doc)
	}
	if len(audit.Result.Checks) != 0 {
		t.Errorf("audit checks = %+v, want none", audit.Result.Checks)
	}
}

func TestSelectedSaysWhetherToCollectAnArtifact(t *testing.T) {
	spec := CollectorSpec{Name: "demo", Schemas: map[string][]byte{
		"artifacts/detail.json": []byte(auditOnlySchema),
		"demo/other@v1":         []byte(`{}`),
	}}
	for _, level := range []string{"trust", "internal"} {
		var got []bool
		res := RunInProcess(spec, func(ctx CollectorContext) error {
			got = append(got,
				Selected(ctx, Location{Schema: "evidencepack/tls@v1"}),
				Selected(ctx, Location{Path: "artifacts/detail.json"}),
				Selected(ctx, Location{Schema: "demo/other@v1"}))
			return ctx.Emit(nil)
		}, InProcessOptions{Config: map[string]any{"level": level, "collect": []any{"other", "demo"}}})
		want := []bool{false, level == "internal", true}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s: Selected = %v, want %v: the unlisted kind is ruled out, and the audit-only file below audit", level, got, want)
		}
		if res.ExitCode != 0 {
			t.Fatalf("%s: exit %d: %s; Emit takes no artifacts when the key left them out", level, res.ExitCode, res.Stderr)
		}
		if res.Result.Collect == nil || !reflect.DeepEqual(res.Result.Collect.LeftOut, []string{"tls"}) {
			t.Errorf("%s: collect = %+v, want only the unlisted kind left out", level, res.Result.Collect)
		}
		if g := gapAt(res, Location{Schema: "evidencepack/tls@v1"}); g == nil || g.Code != CodeNotShared {
			t.Errorf("%s: gap = %+v, want not_shared", level, g)
		}
	}
}

func TestAnArtifactLeftOutTwiceGetsOneGap(t *testing.T) {
	at := Location{Schema: "evidencepack/tls@v1", Path: "artifacts/tls.json"}
	res := RunInProcess(CollectorSpec{Name: "demo"}, func(ctx CollectorContext) error {
		if Selected(ctx, at) {
			t.Errorf("Selected(%+v) = true, want the unlisted kind ruled out", at)
		}
		return ctx.Emit([]CollectedArtifact{
			{Schema: at.Schema, Path: at.Path, Data: map[string]any{}},
			{Path: "artifacts/demo.json", Data: map[string]any{"ok": true}},
		})
	}, InProcessOptions{Config: map[string]any{"level": "audit", "collect": []any{"demo"}}})
	if res.ExitCode != 0 {
		t.Fatalf("exit %d: %s", res.ExitCode, res.Stderr)
	}
	var notShared []Location
	for _, g := range res.Result.Gaps {
		if g.Code == CodeNotShared {
			notShared = append(notShared, g.Location)
		}
	}
	if len(notShared) != 1 {
		t.Errorf("not_shared gaps at %+v, want one: Selected and Emit both left out the same artifact", notShared)
	}
}

func TestOnlyTheSDKRecordsNotShared(t *testing.T) {
	rec := &Recorder{}
	rec.NotCollectedCode(Location{Path: "a.json", Pointer: "/x"}, CodeNotShared, "chose to")
	if got := rec.Gaps(); len(got) != 1 || got[0].Code != CodeInternal {
		t.Errorf("gaps = %+v, want the collector's not_shared recorded as internal", got)
	}
}

func TestCapabilitiesAndTheBuildFileListWhatACollectorWrites(t *testing.T) {
	spec := CollectorSpec{Name: "demo", Version: "1.0.0", Writes: []string{"evidencepack/vcs-posture@v1", "evidencepack/tls@v1", "evidencepack/tls@v1"}}
	var out, errOut bytes.Buffer
	if code := writeCollectorCapabilities(&out, &errOut, spec); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	var caps struct {
		Writes []string `json:"writes"`
	}
	if err := json.Unmarshal(out.Bytes(), &caps); err != nil {
		t.Fatal(err)
	}
	want := []string{"evidencepack/tls@v1", "evidencepack/vcs-posture@v1"}
	if !reflect.DeepEqual(caps.Writes, want) {
		t.Errorf("capabilities writes = %v, want %v, sorted and each once", caps.Writes, want)
	}
	if got := newBuild(spec, &errOut).Writes; !reflect.DeepEqual(got, want) {
		t.Errorf("build file writes = %v, want %v", got, want)
	}
	out.Reset()
	writeCollectorCapabilities(&out, &errOut, CollectorSpec{Name: "demo"})
	if strings.Contains(out.String(), "writes") {
		t.Errorf("capabilities = %s, want no writes for a collector that lists none", out.String())
	}
}
