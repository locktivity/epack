package outputcheck

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func mustCompile(t *testing.T, raw string) *Schema {
	t.Helper()
	s, err := Compile([]byte(raw))
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return s
}

func mustDecode(t *testing.T, raw string) any {
	t.Helper()
	doc, err := Decode([]byte(raw))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	return doc
}

// annotationsOnly builds a schema for lookups alone, for documents that do
// not compile, such as one with a remote ref.
func annotationsOnly(t *testing.T, raw string) *Schema {
	t.Helper()
	return &Schema{root: mustDecode(t, raw)}
}

// lookup walks the view along a path of member names and item indexes.
func lookup(s *Schema, steps ...any) view {
	v := s.rootView()
	for _, step := range steps {
		switch st := step.(type) {
		case string:
			v = s.member(v, st)
		case int:
			v = s.item(v, st)
		}
	}
	return v
}

func TestLookupFollowsTheSchema(t *testing.T) {
	s := annotationsOnly(t, `{
		"$schema": "https://json-schema.org/draft/2020-12/schema",
		"$id": "https://example.test/schema.json",
		"type": "object",
		"properties": {
			"direct": {"x-epack-null": "direct"},
			"viaDefs": {"$ref": "#/$defs/noted"},
			"viaID": {"$ref": "https://example.test/schema.json#/$defs/noted"},
			"remote": {"$ref": "https://elsewhere.test/schema.json#/$defs/noted"},
			"anchor": {"$ref": "#noted"},
			"tuple": {"prefixItems": [{"x-epack-null": "first"}], "items": {"x-epack-null": "rest"}},
			"own": {"x-epack-null": "own", "allOf": [{"x-epack-null": "branch", "x-epack-denominator": "n"}]},
			"loop": {"$ref": "#/properties/loop"}
		},
		"patternProperties": {"^p_": {"x-epack-null": "pattern"}, "(?<=q)z": {"x-epack-null": "lookbehind"}},
		"additionalProperties": {"x-epack-null": "additional"},
		"allOf": [{"properties": {"fromAllOf": {"x-epack-null": "allOf"}, "direct": {"x-epack-denominator": "users"}}}],
		"anyOf": [{"properties": {"fromAnyOf": {"x-epack-null": "anyOf"}}}],
		"oneOf": [{"$ref": "#/$defs/branch"}],
		"$defs": {
			"noted": {"x-epack-null": "def"},
			"branch": {"properties": {"fromOneOf": {"x-epack-null": "oneOf"}}}
		}
	}`)
	cases := []struct {
		name  string
		steps []any
		key   string
		want  string
	}{
		{"properties", []any{"direct"}, "x-epack-null", "direct"},
		{"a branch adds keywords the member lacks", []any{"direct"}, "x-epack-denominator", "users"},
		{"$defs ref", []any{"viaDefs"}, "x-epack-null", "def"},
		{"ref through the schema's own $id", []any{"viaID"}, "x-epack-null", "def"},
		{"remote refs are not followed", []any{"remote"}, "x-epack-null", ""},
		{"anchors are not followed", []any{"anchor"}, "x-epack-null", ""},
		{"prefixItems", []any{"tuple", 0}, "x-epack-null", "first"},
		{"items after prefixItems", []any{"tuple", 3}, "x-epack-null", "rest"},
		{"the first value wins", []any{"own"}, "x-epack-null", "own"},
		{"branch keywords still count", []any{"own"}, "x-epack-denominator", "n"},
		{"patternProperties", []any{"p_count"}, "x-epack-null", "pattern"},
		{"additionalProperties", []any{"other"}, "x-epack-null", "additional"},
		{"a pattern Go cannot compile matches nothing", []any{"qz"}, "x-epack-null", "additional"},
		{"allOf names the member before additionalProperties", []any{"fromAllOf"}, "x-epack-null", "allOf"},
		{"anyOf", []any{"fromAnyOf"}, "x-epack-null", "anyOf"},
		{"oneOf through a ref", []any{"fromOneOf"}, "x-epack-null", "oneOf"},
		{"a ref cycle ends", []any{"loop"}, "x-epack-null", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := lookup(s, tc.steps...).text(tc.key); got != tc.want {
				t.Errorf("%s = %q, want %q", tc.key, got, tc.want)
			}
		})
	}
}

func TestLookupReadsDraft07Items(t *testing.T) {
	s := annotationsOnly(t, `{
		"$schema": "http://json-schema.org/draft-07/schema#",
		"properties": {
			"tuple": {"items": [{"x-epack-null": "first"}], "additionalItems": {"x-epack-null": "rest"}},
			"list": {"items": {"$ref": "#/definitions/row"}}
		},
		"definitions": {"row": {"properties": {"mfa": {"x-epack-null": "row"}}}}
	}`)
	if got := lookup(s, "tuple", 0).text("x-epack-null"); got != "first" {
		t.Errorf("items array: %q", got)
	}
	if got := lookup(s, "tuple", 1).text("x-epack-null"); got != "rest" {
		t.Errorf("additionalItems: %q", got)
	}
	if got := lookup(s, "list", 7, "mfa").text("x-epack-null"); got != "row" {
		t.Errorf("items object through definitions: %q", got)
	}
}

func TestLookupCollectsTypes(t *testing.T) {
	s := annotationsOnly(t, `{"properties": {
		"a": {"type": ["boolean", "null"]},
		"b": {"anyOf": [{"type": "null"}, {"$ref": "#/$defs/n"}]},
		"c": {"type": ["string", "integer", "null"]}
	}, "$defs": {"n": {"type": "number"}}}`)
	for name, want := range map[string]string{"a": "boolean", "b": "number", "c": "string,integer"} {
		if got := strings.Join(lookup(s, name).types(), ","); got != want {
			t.Errorf("types of %s = %q, want %q", name, got, want)
		}
	}
}

func TestTarget(t *testing.T) {
	at := []string{"accounts", "0", "iam", "mfa_pct"}
	cases := []struct {
		ref, want string
		ok        bool
	}{
		{"users", "/accounts/0/iam/users", true},
		{"/summary/total", "/summary/total", true},
		{"0/users", "/accounts/0/iam/users", true},
		{"1/users_count", "/accounts/0/users_count", true},
		{"3/total", "/total", true},
		{"0", "/accounts/0/iam", true},
		{"4/total", "", false},
		{"2fa_users", "/accounts/0/iam/2fa_users", true},
		{"01/x", "/accounts/0/iam/01~1x", true},
		{"a/b", "/accounts/0/iam/a~1b", true},
		{"", "", false},
	}
	for _, tc := range cases {
		got, ok := target(tc.ref, at)
		if got != tc.want || ok != tc.ok {
			t.Errorf("target(%q) = %q, %v; want %q, %v", tc.ref, got, ok, tc.want, tc.ok)
		}
	}
}

func TestResolve(t *testing.T) {
	doc := mustDecode(t, `{"a/b": 1, "m~n": [10, {"x": null}]}`)
	cases := []struct {
		ptr   string
		found bool
	}{
		{"", true}, {"/a~1b", true}, {"/m~0n/1/x", true}, {"/m~0n/2", false},
		{"/m~0n/01", false}, {"/m~0n/x", false}, {"/missing", false}, {"/m~0n/1/x/deeper", false}, {"no-slash", false},
	}
	for _, tc := range cases {
		if _, found := Resolve(doc, tc.ptr); found != tc.found {
			t.Errorf("Resolve(%q) found = %v, want %v", tc.ptr, found, tc.found)
		}
	}
}

func TestCompile(t *testing.T) {
	if _, err := Compile([]byte(`{"type": 5}`)); err == nil {
		t.Error("a schema with a bad keyword value should not compile")
	}
	if _, err := Compile([]byte(`{"properties": {"a": {"$ref": "https://elsewhere.test/s.json"}}}`)); err == nil {
		t.Error("a remote ref should not load")
	}
	if _, err := Compile([]byte(`{`)); err == nil {
		t.Error("invalid JSON should not compile")
	}
	a := mustCompile(t, `{"type": "object"}`)
	b := mustCompile(t, `{"type": "object"}`)
	if a != b {
		t.Error("the same schema should compile once")
	}
}

func TestCompileFileFollowsLocalRefs(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "defs.json"), []byte(`{"$defs": {"pct": {"type": "integer", "maximum": 100}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	main := filepath.Join(dir, "main.json")
	if err := os.WriteFile(main, []byte(`{"properties": {"p": {"$ref": "defs.json#/$defs/pct"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := CompileFile(main)
	if err != nil {
		t.Fatal(err)
	}
	if got := Validate(s, "a.json", mustDecode(t, `{"p": 101}`)); len(got) != 1 || got[0].Pointer != "/p" {
		t.Errorf("findings = %+v", got)
	}
}

func TestValidate(t *testing.T) {
	s := mustCompile(t, `{
		"$schema": "https://json-schema.org/draft/2020-12/schema",
		"type": "object",
		"required": ["provider"],
		"properties": {
			"accounts": {"type": "array", "items": {"$ref": "#/$defs/account"}}
		},
		"$defs": {"account": {"type": "object", "properties": {"mfa_pct": {"type": ["number", "null"], "maximum": 100}}}}
	}`)
	if got := Validate(s, "a.json", mustDecode(t, `{"provider": "x", "accounts": [{"mfa_pct": null}]}`)); len(got) != 0 {
		t.Errorf("a valid artifact got %+v", got)
	}
	got := Validate(s, "a.json", mustDecode(t, `{"accounts": [{"mfa_pct": 50}, {"mfa_pct": 120}]}`))
	if len(got) != 2 {
		t.Fatalf("findings = %+v", got)
	}
	if got[0].Pointer != "" || !strings.Contains(got[0].Message, "provider") {
		t.Errorf("first finding = %+v, want the missing provider at the root", got[0])
	}
	if got[1].Pointer != "/accounts/1/mfa_pct" || got[1].Check != CheckSchema || got[1].Path != "a.json" {
		t.Errorf("second finding = %+v", got[1])
	}
}

const metricsSchema = `{
	"$schema": "https://json-schema.org/draft/2020-12/schema",
	"type": "object",
	"properties": {
		"users": {"type": ["integer", "null"]},
		"mfa_pct": {"type": ["integer", "null"], "x-epack-denominator": "users"},
		"session_hours": {"type": ["integer", "null"], "x-epack-null": "No policy sets a lifetime"},
		"enforced": {"type": ["boolean", "null"]},
		"name": {"type": ["string", "null"]},
		"anything": {},
		"summary": {
			"type": ["object", "null"],
			"properties": {
				"admins_pct": {"type": ["number", "null"], "x-epack-denominator": "1/admins_total"},
				"weak_pct": {"type": ["number", "null"], "x-epack-denominator": "/totals/weak"}
			}
		},
		"admins_total": {"type": "integer"},
		"totals": {"type": "object", "properties": {"weak": {"type": "integer"}}},
		"flags": {"type": "array", "items": {"type": ["boolean", "null"]}}
	}
}`

func findingsOf(t *testing.T, schema, doc string, gaps ...Gap) []Finding {
	t.Helper()
	return Check(mustCompile(t, schema), "a.json", mustDecode(t, doc), gaps)
}

func pointersOf(findings []Finding, check string) []string {
	var out []string
	for _, f := range findings {
		if f.Check == check {
			out = append(out, f.Pointer)
		}
	}
	return out
}

func TestPopulation(t *testing.T) {
	got := findingsOf(t, metricsSchema, `{
		"users": 0, "mfa_pct": 100,
		"summary": {"admins_pct": 50, "weak_pct": 0},
		"admins_total": 0, "totals": {"weak": 0}
	}`)
	if strings.Join(pointersOf(got, CheckPopulation), ",") != "/mfa_pct,/summary/admins_pct,/summary/weak_pct" {
		t.Errorf("population findings = %+v", got)
	}
	if !strings.Contains(got[0].Message, "value 100") || !strings.Contains(got[0].Message, "/users is 0") {
		t.Errorf("message = %q", got[0].Message)
	}
	quiet := []string{
		`{"users": 0, "mfa_pct": null}`,
		`{"users": 0}`,
		`{"users": 3, "mfa_pct": 100}`,
		`{"mfa_pct": 100}`,
	}
	for _, doc := range quiet {
		if got := pointersOf(findingsOf(t, metricsSchema, doc), CheckPopulation); len(got) != 0 {
			t.Errorf("%s: population findings %v", doc, got)
		}
	}
	if got := findingsOf(t, metricsSchema, `{"users": 0, "mfa_pct": 100}`, Gap{Path: "a.json", Pointer: "/users"}); len(got) != 0 {
		t.Errorf("a denominator a gap covers is skipped, got %+v", got)
	}
	if got := findingsOf(t, metricsSchema, `{"users": 0, "mfa_pct": 100}`, Gap{Path: "other.json", Pointer: "/users"}); len(got) != 1 {
		t.Errorf("a gap in another artifact covers nothing here, got %+v", got)
	}
}

func TestNulls(t *testing.T) {
	doc := `{
		"users": null, "enforced": null, "name": null, "anything": null, "session_hours": null,
		"flags": [true, null], "summary": null
	}`
	got := findingsOf(t, metricsSchema, doc)
	if strings.Join(pointersOf(got, CheckNulls), ",") != "/enforced,/flags/1,/users" {
		t.Errorf("nulls findings = %+v", got)
	}
	explained := findingsOf(t, metricsSchema, doc,
		Gap{Path: "a.json", Pointer: "/users"},
		Gap{Path: "a.json", Pointer: "/enforced"},
		Gap{Path: "a.json", Pointer: "/flags"},
	)
	if len(explained) != 0 {
		t.Errorf("gaps at the value or an ancestor explain a null, got %+v", explained)
	}
	if got := findingsOf(t, metricsSchema, doc, Gap{Path: "a.json", Pointer: ""}); len(got) != 0 {
		t.Errorf("a gap for the whole artifact explains every null, got %+v", got)
	}
	if got := findingsOf(t, metricsSchema, `{"users": 0, "mfa_pct": null}`); len(got) != 0 {
		t.Errorf("a denominator of 0 explains a null, got %+v", got)
	}
	if got := findingsOf(t, metricsSchema, `{"users": 4, "mfa_pct": null}`); strings.Join(pointersOf(got, CheckNulls), ",") != "/mfa_pct" {
		t.Errorf("a denominator above 0 does not explain a null, got %+v", got)
	}
}

const rollupSchema = `{
	"$schema": "https://json-schema.org/draft/2020-12/schema",
	"type": "object",
	"properties": {
		"users": {"type": "array", "items": {"type": "object"}},
		"users_count": {"type": "integer", "x-epack-rollup": {"rows": "users"}},
		"admins_count": {"type": "integer", "x-epack-rollup": {"rows": "/users", "where": "/role", "equals": "admin", "as": "count"}},
		"mfa_count": {"type": "integer", "x-epack-rollup": {"rows": "users", "where": "/mfa"}},
		"mfa_pct": {"type": "number", "x-epack-rollup": {"rows": "users", "where": "/mfa", "as": "pct"}},
		"reported_count": {"type": "integer", "x-epack-rollup": {"rows": "users", "as": "count"}, "x-epack-as-of": "report_time"},
		"report_time": {"type": ["string", "null"]},
		"odd_count": {"type": "integer", "x-epack-rollup": {"rows": "users", "as": "median"}},
		"name": {"type": "string", "x-epack-rollup": {"rows": "users"}},
		"nested": {"type": "object", "properties": {"total": {"type": "integer", "x-epack-rollup": {"rows": "1/users"}}}}
	}
}`

const threeUsers = `[{"mfa": true, "role": "admin"}, {"mfa": false, "role": "user"}, {"mfa": true, "role": "user"}]`

func TestRollups(t *testing.T) {
	good := findingsOf(t, rollupSchema, `{
		"users": `+threeUsers+`,
		"users_count": 3, "admins_count": 1, "mfa_count": 2, "mfa_pct": 66, "nested": {"total": 3},
		"reported_count": 9, "report_time": "2026-01-01T00:00:00Z", "odd_count": 7, "name": "x"
	}`)
	if len(good) != 0 {
		t.Errorf("matching rollups got %+v", good)
	}
	bad := findingsOf(t, rollupSchema, `{
		"users": `+threeUsers+`,
		"users_count": 4, "admins_count": 2, "mfa_count": 3, "mfa_pct": 64.5, "nested": {"total": 2},
		"reported_count": 9, "report_time": null
	}`)
	if strings.Join(pointersOf(bad, CheckRollups), ",") != "/admins_count,/mfa_count,/mfa_pct,/nested/total,/reported_count,/users_count" {
		t.Fatalf("rollups findings = %+v", bad)
	}
	messages := map[string]string{}
	for _, f := range bad {
		messages[f.Pointer] = f.Message
	}
	if want := `value 2, but 1 of the 3 rows at /users have /role equal to "admin"`; messages["/admins_count"] != want {
		t.Errorf("admins message = %q, want %q", messages["/admins_count"], want)
	}
	if want := "value 64.5, but 2 of the 3 rows at /users have /mfa equal to true, which is 66.67"; messages["/mfa_pct"] != want {
		t.Errorf("pct message = %q, want %q", messages["/mfa_pct"], want)
	}
	if want := "value 4, but there are 3 rows at /users"; messages["/users_count"] != want {
		t.Errorf("count message = %q, want %q", messages["/users_count"], want)
	}
}

func TestRollupsSkipWhatTheyCannotRecompute(t *testing.T) {
	doc := `{"users": ` + threeUsers + `, "users_count": 4}`
	if got := findingsOf(t, rollupSchema, doc, Gap{Path: "a.json", Pointer: "/users"}); len(got) != 0 {
		t.Errorf("rows a gap covers are skipped, got %+v", got)
	}
	if got := findingsOf(t, rollupSchema, doc, Gap{Path: "a.json", Pointer: "/users/1"}); len(got) != 1 {
		t.Errorf("a gap inside the rows does not skip the rollup, got %+v", got)
	}
	if got := findingsOf(t, rollupSchema, `{"users": {"not": "rows"}, "users_count": 4}`); len(got) != 0 {
		t.Errorf("rows that are not an array are skipped, got %+v", got)
	}
	if got := findingsOf(t, rollupSchema, `{"users_count": 4}`); len(got) != 0 {
		t.Errorf("missing rows are skipped, got %+v", got)
	}
	if got := findingsOf(t, rollupSchema, `{"users": [], "mfa_pct": 100}`); len(got) != 0 {
		t.Errorf("a percentage over no rows is skipped, got %+v", got)
	}
}

const cappedSchema = `{
	"$schema": "https://json-schema.org/draft/2020-12/schema",
	"type": "object",
	"properties": {
		"users": {"$ref": "#/$defs/capped"},
		"users_count": {"type": "integer", "x-epack-rollup": {"rows": "users"}},
		"repos": {"type": "array", "maxItems": 1000, "items": {"type": "object"}},
		"repos_truncated": {"type": ["boolean", "null"]},
		"repo_count": {"type": "integer", "x-epack-rollup": {"rows": "repos", "truncated": "repos_truncated"}},
		"summary": {"type": "object", "properties": {
			"private_pct": {"type": "number", "x-epack-rollup": {"rows": "/repos", "where": "/private", "as": "pct", "truncated": "1/repos_truncated"}}
		}},
		"accounts": {"type": "array", "items": {"type": "object", "properties": {
			"members": {"type": "array", "maxItems": 2},
			"member_count": {"type": "integer", "x-epack-rollup": {"rows": "members"}}
		}}}
	},
	"$defs": {"capped": {"type": "array", "maxItems": 3}}
}`

func TestRollupsSkipRowsCutShort(t *testing.T) {
	const threeRepos = `[{"private": true}, {"private": false}, {"private": true}]`
	skipped := []string{
		`{"users": [{}, {}, {}], "users_count": 1200}`,
		`{"accounts": [{"members": [{}, {}], "member_count": 40}]}`,
		`{"repos": ` + threeRepos + `, "repos_truncated": true, "repo_count": 500, "summary": {"private_pct": 10}}`,
	}
	for _, doc := range skipped {
		if got := findingsOf(t, cappedSchema, doc); len(got) != 0 {
			t.Errorf("%s: rows cut short should skip the rollup, got %+v", doc, got)
		}
	}
	checked := map[string]string{
		`{"users": [{}, {}], "users_count": 1200}`:                                                                   "/users_count",
		`{"accounts": [{"members": [{}], "member_count": 40}]}`:                                                      "/accounts/0/member_count",
		`{"repos": ` + threeRepos + `, "repos_truncated": false, "repo_count": 500, "summary": {"private_pct": 10}}`: "/repo_count,/summary/private_pct",
		`{"repos": ` + threeRepos + `, "repos_truncated": null, "repo_count": 500}`:                                  "/repo_count",
		`{"repos": ` + threeRepos + `, "repo_count": 500}`:                                                           "/repo_count",
	}
	for doc, want := range checked {
		if got := strings.Join(pointersOf(findingsOf(t, cappedSchema, doc), CheckRollups), ","); got != want {
			t.Errorf("%s: rollups findings at %q, want %q", doc, got, want)
		}
	}
}

func TestAboveLevel(t *testing.T) {
	s := mustCompile(t, `{
		"type": "object",
		"properties": {
			"summary": {"type": "integer"},
			"users": {"type": "array", "x-epack-level": "audit", "items": {"properties": {"id": {"x-epack-level": "trust"}, "email": {"x-epack-level": "internal"}}}},
			"detail": {"$ref": "#/$defs/internal"}
		},
		"$defs": {"internal": {"x-epack-level": "internal"}}
	}`)
	doc := mustDecode(t, `{"summary": 1, "users": [{"id": "u1", "email": "a@example.test"}], "detail": null}`)
	cases := map[string]string{
		"trust":    "/detail,/users",
		"audit":    "/detail,/users/0/email",
		"internal": "",
	}
	for level, want := range cases {
		var got []string
		for _, f := range AboveLevel(s, "a.json", doc, level) {
			got = append(got, f.Pointer)
		}
		if strings.Join(got, ",") != want {
			t.Errorf("%s: %v, want %s", level, got, want)
		}
	}
	whole := mustCompile(t, `{"x-epack-level": "audit"}`)
	if got := AboveLevel(whole, "a.json", mustDecode(t, `{}`), "trust"); len(got) != 1 || got[0].Pointer != "" || got[0].Message != "present at trust, but its schema marks it audit" {
		t.Errorf("an artifact marked audit at trust: %+v", got)
	}
}
