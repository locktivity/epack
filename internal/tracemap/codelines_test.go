package tracemap

import (
	"sort"
	"strings"
	"testing"
)

// linesOf returns the role and trimmed text of each line the analysis finds
// for a field, sorted.
func linesOf(t *testing.T, a *analysis, path, schema, pattern string) []string {
	t.Helper()
	text := fixtureLines(t)
	var out []string
	for _, l := range a.fieldLines(path, schema, pattern) {
		file, n, ok := a.prog.relative(l.pos)
		if !ok || file != "internal/collector/collector.go" {
			t.Fatalf("line %v is in %s", l, file)
		}
		entry := l.role + " " + strings.TrimSpace(text[n])
		if l.end.IsValid() {
			_, end, _ := a.prog.relative(l.end)
			entry += " ... " + strings.TrimSpace(text[end])
		}
		out = append(out, entry)
	}
	sort.Strings(out)
	return out
}

func TestFieldLinesFollowAPercentageToItsCounts(t *testing.T) {
	a := fixtureAnalysis(t)
	got := linesOf(t, a, "artifacts/fixture.json", "", "/users/mfa_coverage")
	want := []string{
		"assign out.CoveragePct = percent(m.enrolled, m.total)",
		"condition for _, f := range p.Factors {",
		"condition for _, p := range people {",
		"condition if active {",
		`condition if f.Status != "ACTIVE" {`,
		`condition if p.Status == "DEPROVISIONED" {`,
		"helper func percent(n, total int) *int { ... }",
		"input active := false",
		"input active = true",
		"input m.enrolled++",
		"input m.total++",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("lines =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func TestFieldLinesFindLiteralsCasesAndRows(t *testing.T) {
	a := fixtureAnalysis(t)
	for pattern, want := range map[string][]string{
		"/users/suspended_count": {
			"assign out := &Users{Total: m.total, Suspended: m.suspended}",
			`condition case "SUSPENDED":`,
			"condition for _, p := range people {",
			`condition if p.Status == "DEPROVISIONED" {`,
			"condition switch p.Status {",
			"input m.suspended++",
		},
		"/users/inventory/*/has_active_mfa": {
			"assign out.Inventory = append(out.Inventory, User{Login: p.Login, MFA: &on})",
			"condition for _, p := range people {",
			"input on := len(p.Factors) > 0",
		},
		"/collected_at": {
			`assign out := &Output{Meta: Meta{CollectedAt: componentsdk.Now(ctx).UTC().Format("2006-01-02")}, Org: org.Name}`,
			"condition if err := get(opOrg, \"/org\", &org); err != nil {",
			`condition if org.Name == "" {`,
		},
	} {
		got := linesOf(t, a, "artifacts/fixture.json", "", pattern)
		if strings.Join(got, "\n") != strings.Join(want, "\n") {
			t.Errorf("%s lines =\n%s\nwant\n%s", pattern, strings.Join(got, "\n"), strings.Join(want, "\n"))
		}
	}
}

func TestFieldLinesFindAnArtifactByItsSchema(t *testing.T) {
	a := fixtureAnalysis(t)
	got := linesOf(t, a, "fixture.normalized.json", "evidencepack/fixture@v1", "/mfa_coverage_pct")
	for _, want := range []string{
		"assign n.CoveragePct = &v",
		"condition if o.Users != nil && o.Users.CoveragePct != nil {",
		"input v := float64(*o.Users.CoveragePct)",
		"input out.CoveragePct = percent(m.enrolled, m.total)",
		"input m.enrolled++",
	} {
		if !contains(got, want) {
			t.Errorf("lines lack %q:\n%s", want, strings.Join(got, "\n"))
		}
	}
	if got := a.fieldLines("fixture.normalized.json", "", "/mfa_coverage_pct"); got != nil {
		t.Errorf("without its schema, an artifact whose path is not a constant has no root, got %v", got)
	}
}

func TestFieldAtStopsWhereTheJSONIsNotTheFields(t *testing.T) {
	a := fixtureAnalysis(t)
	for _, pattern := range []string{"/raw", "/raw/v", "/Hidden", "/hidden", "/users/inventory/0/login", "/users/nothing", ""} {
		if got := a.fieldLines("artifacts/fixture.json", "", pattern); len(got) != 0 {
			t.Errorf("%q: lines %v, want none", pattern, got)
		}
	}
	if len(a.fieldsAt(a.roots["artifacts/fixture.json"][0], "/raw/v")) != 0 {
		t.Error("a type that encodes itself other than as one of its fields has no fields to follow")
	}
	if got := a.fieldLines("artifacts/other.json", "", "/users/total_count"); got != nil {
		t.Errorf("an artifact no code emits has no lines, got %v", got)
	}
}

func TestFieldLinesFollowAMarshalerThatEncodesOneField(t *testing.T) {
	a := fixtureAnalysis(t)
	want := []string{
		"assign out.Plan.Record = &Plan{Name: org.Name}",
		`condition if err := get(opOrg, "/org", &org); err != nil {`,
		`condition if org.Name == "" {`,
	}
	for _, pattern := range []string{"/plan", "/plan/name"} {
		got := linesOf(t, a, "artifacts/fixture.json", "", pattern)
		if strings.Join(got, "\n") != strings.Join(want, "\n") {
			t.Errorf("%s lines =\n%s\nwant\n%s", pattern, strings.Join(got, "\n"), strings.Join(want, "\n"))
		}
	}
}

func TestFieldLinesFollowAGenericTypeInstantiatedInTwoPackages(t *testing.T) {
	a := fixtureAnalysis(t)
	got := linesOf(t, a, "artifacts/fixture.json", "", "/billing/owner")
	want := []string{
		"assign out.Billing.Owner = owner",
		"assign owner.Value = &billing.Owner{Name: org.Name}",
		`condition if err := get(opOrg, "/org", &org); err != nil {`,
		`condition if org.Name == "" {`,
		"input var owner billing.Optional[billing.Owner]",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("lines =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
