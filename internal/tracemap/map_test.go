package tracemap

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func fixtureTraces() []SuiteTrace {
	return []SuiteTrace{
		{
			Suite:       "fixture",
			Operations:  []string{"fixture.org.get", "fixture.people.list"},
			Insensitive: []string{"fixture.org.get"},
			Schemas:     map[string]string{"fixture.normalized.json": "evidencepack/fixture@v1"},
			Artifacts: map[string]map[string]*FieldTrace{
				"artifacts/fixture.json": {
					"/org":                {},
					"/users/mfa_coverage": {Operations: []string{"fixture.people.list"}, Gaps: []string{"internal/collector/gaps.go:12"}},
				},
				"fixture.normalized.json": {
					"/mfa_coverage_pct": {Copies: []Copy{{Path: "artifacts/fixture.json", Pointer: "/users/mfa_coverage"}}},
				},
			},
		},
		{
			Suite:      "fixture-oauth",
			Operations: []string{"fixture.people.list", "fixture.token.create"},
			Artifacts: map[string]map[string]*FieldTrace{
				"artifacts/fixture.json": {
					"/users/mfa_coverage": {Operations: []string{"fixture.token.create"}},
				},
			},
		},
	}
}

func TestFromTracesMergesSuitesWithTheSource(t *testing.T) {
	if testing.Short() {
		t.Skip("loads a module, which compiles the SDK")
	}
	m, err := FromTraces(context.Background(), fixtureDir, fixtureTraces())
	if err != nil {
		t.Fatal(err)
	}
	f := m.Artifacts["artifacts/fixture.json"]["/users/mfa_coverage"]
	if !reflect.DeepEqual(f.Operations, []string{"fixture.people.list", "fixture.token.create"}) || !reflect.DeepEqual(f.Gaps, []string{"internal/collector/gaps.go:12"}) {
		t.Errorf("merged field = %+v", f)
	}
	var assign string
	for _, c := range f.Code {
		if c.Role == RoleAssign {
			assign = c.Line
		}
		file, n, _ := SplitLine(c.Line)
		for last := max(n, c.End); n <= last; n++ {
			if _, ok := m.Lines[LineRef(file, n)]; !ok {
				t.Errorf("line %s:%d has no text in the map", file, n)
			}
		}
	}
	if !strings.Contains(m.Lines[assign], "out.CoveragePct = percent(") {
		t.Errorf("the assignment is %s %q", assign, m.Lines[assign])
	}
	normalized := m.Artifacts["fixture.normalized.json"]["/mfa_coverage_pct"]
	if len(normalized.Copies) != 1 || len(normalized.Code) == 0 {
		t.Errorf("normalized field = %+v, want its copy and its code", normalized)
	}
	if org := m.Artifacts["artifacts/fixture.json"]["/org"]; org == nil || len(org.Operations) != 0 {
		t.Errorf("/org = %+v, want the field with no operations", org)
	}

	encoded, err := Encode(m)
	if err != nil {
		t.Fatal(err)
	}
	again, _ := FromTraces(context.Background(), fixtureDir, fixtureTraces())
	if second, _ := Encode(again); !bytes.Equal(encoded, second) {
		t.Error("two builds of one map encode differently")
	}
	var decoded Map
	if err := json.Unmarshal(encoded, &decoded); err != nil || Diff(&decoded, m) != "" {
		t.Errorf("an encoded map reads back with differences: %v %q", err, Diff(&decoded, m))
	}
}

func TestFromTracesFailsForAnOperationThatFeedsNothing(t *testing.T) {
	traces := fixtureTraces()
	traces[0].Operations = append(traces[0].Operations, "fixture.groups.list")
	_, err := FromTraces(context.Background(), fixtureDir, traces)
	if err == nil || !strings.Contains(err.Error(), "no fault on fixture.groups.list changed or left out any field") || !strings.Contains(err.Error(), "Suite.Insensitive") {
		t.Errorf("err = %v, want one naming the operation and Suite.Insensitive", err)
	}
	traces[1].Required = []string{"fixture.groups.list"}
	if err := unfed(traces); err != nil {
		t.Errorf("a required operation, whose faults fail the run, should need no field: %v", err)
	}
}

func TestDiffCountsFieldsAndLines(t *testing.T) {
	old := &Map{Artifacts: map[string]map[string]*Field{"a.json": {"/x": {Operations: []string{"op"}}, "/y": {}}}, Lines: Lines{"a.go:1": "x"}}
	current := &Map{Artifacts: map[string]map[string]*Field{"a.json": {"/x": {}, "/z": {}}}, Lines: Lines{"a.go:1": "y"}}
	if got := Diff(old, current); got != "1 field added, 1 field removed, 1 field changed, source lines changed" {
		t.Errorf("Diff = %q", got)
	}
	if got := Diff(old, old); got != "" {
		t.Errorf("Diff of a map with itself = %q", got)
	}
}

func TestBuildRunsTheSuitesAndMapsTheFixture(t *testing.T) {
	if testing.Short() {
		t.Skip("runs the fixture's collectortest suite")
	}
	var output bytes.Buffer
	m, root, err := Build(context.Background(), Options{Dir: fixtureDir, Output: &output})
	if err != nil {
		t.Fatalf("Build: %v\n%s", err, output.String())
	}
	if root == "" {
		t.Error("Build returned no module root")
	}
	f := m.Artifacts["artifacts/fixture.json"]["/users/mfa_coverage"]
	if f == nil || !reflect.DeepEqual(f.Operations, []string{"fixture.people.list"}) {
		t.Fatalf("/users/mfa_coverage = %+v, want the people list behind it", f)
	}
	if len(f.Gaps) != 1 || !strings.Contains(m.Lines[f.Gaps[0]], `gaps.notCollected(err, "/users")`) {
		t.Errorf("gap lines = %v (%q), want the line that called the gap helper", f.Gaps, m.Lines[f.Gaps[0]])
	}
	if c := m.Artifacts["fixture.normalized.json"]["/mfa_coverage_pct"]; c == nil || len(c.Copies) != 1 || c.Copies[0].Pointer != "/users/mfa_coverage" {
		t.Errorf("normalized copy = %+v", c)
	}
	if _, ok := m.Artifacts["artifacts/fixture.json"]["/users/inventory/*/login"]; !ok {
		t.Error("the map has no entry for the rows' fields")
	}
}
