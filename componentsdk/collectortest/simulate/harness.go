package simulate

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"math"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/locktivity/epack/componentsdk"
	"github.com/locktivity/epack/componentsdk/collectortest"
	"github.com/locktivity/epack/componentsdk/collectortest/roster"
	"github.com/locktivity/epack/internal/outputcheck"
)

// Verdict says why a collector's value differs from the derived one.
type Verdict string

const (
	// Known is a difference the collector's docs describe, such as a share
	// taken over the users a report lists.
	Known Verdict = "known"
	// Bug is a value the collector gets wrong by its own docs and the
	// schema's. It gets fixed, and is listed only until then.
	Bug Verdict = "bug"
	// Definition is a difference in what a schema field means, which the
	// schema or the collector settles.
	Definition Verdict = "definition"
	// Gap is a value the collector leaves out with a gap that says why,
	// where the roster determines it.
	Gap Verdict = "gap"
	// Unwritten is a value the roster determines that the collector never
	// writes, and leaves out with no gap.
	Unwritten Verdict = "unwritten"
	// Unmodeled is a difference the roster or Derive cannot express, such
	// as a vendor setting with no normalized term, so the derived value is
	// the one in doubt.
	Unmodeled Verdict = "unmodeled"
)

// Difference is a listed difference: its verdict, and a note that says
// where in the collector's code it was checked.
type Difference struct {
	Verdict Verdict
	Note    string
}

// Differences lists differences by pointer. A pointer is bare for the
// first artifact a Harness names, and the artifact's Prefix and then the
// pointer for the others.
type Differences map[string]Difference

// Same lists pointers that differ for one reason.
func Same(v Verdict, note string, pointers ...string) Differences {
	out := Differences{}
	for _, p := range pointers {
		out[p] = Difference{v, note}
	}
	return out
}

// With returns d and more together, later entries winning.
func (d Differences) With(more ...Differences) Differences {
	out := maps.Clone(d)
	if out == nil {
		out = Differences{}
	}
	for _, m := range more {
		maps.Copy(out, m)
	}
	return out
}

// Without returns d less pointers, for a scenario where some of a shared
// list happen to match.
func (d Differences) Without(pointers ...string) Differences {
	out := maps.Clone(d)
	for _, p := range pointers {
		delete(out, p)
	}
	return out
}

// Artifact names a normalized artifact the collector writes, by the schema
// Derive gives values for and the path the collector writes it to. Prefix
// goes before its pointers in rows and differences, such as
// "access-posture:"; the first artifact usually has none.
type Artifact struct {
	Schema, Prefix, Path string
}

// Harness runs a collector against a simulator and compares its normalized
// artifacts with the derived values.
type Harness struct {
	// Simulate answers for r, with every list paged at pageSize when it is
	// above zero.
	Simulate func(r *roster.Roster, pageSize int) []collectortest.Response
	// Collect runs the collector against responses, as InProcess does.
	Collect   func(t *testing.T, responses []collectortest.Response) componentsdk.InProcessResult
	Artifacts []Artifact
	// Recorded is the sandbox's recording. When set, every answer Simulate
	// gives must keep the shape of the recorded answers to its operation
	// (see Recorded.Check), and a run fails on each difference Unrecorded
	// doesn't list.
	Recorded *Recorded
	// Unrecorded lists, by ShapeDifference.Key, the answers the recording
	// can't vouch for, with why, such as a call the sandbox never makes or
	// a setting it doesn't have. CheckRecorded fails on a listing no roster
	// needs.
	Unrecorded map[string]string
	// Standing are differences that hold wherever the collector reads the
	// value. A tenant can still match one by chance, such as a share of 100
	// over either population, so they are not reported when they match. An
	// Unwritten one accounts only for a value left out with no gap, and a
	// Gap one only for a value left out with a gap.
	Standing Differences
	// Coverage turns on the coverage check: Tenants also fails on a field an
	// artifact writes that the derived values don't reach, as
	// roster.Uncovered finds them, unless Uncompared lists it, and on a
	// listing every scenario now compares.
	Coverage bool
	// Uncompared lists, by the artifact's Prefix and the field, with * for
	// any index or member of an object keyed by name, the fields the
	// collector writes that the scenarios' rosters give no value for, with
	// why.
	Uncompared map[string]string
}

// Scenario is a roster with the differences listed for it.
type Scenario struct {
	Name        string
	Roster      *roster.Roster
	Differences Differences
}

// Realizations returns a scenario for each way r's unsettled attributes
// could turn out, named name and the choices.
func Realizations(t testing.TB, name string, r *roster.Roster, diffs Differences) []Scenario {
	t.Helper()
	reals, err := r.Realizations()
	if err != nil {
		t.Fatal(err)
	}
	var out []Scenario
	for _, real := range reals {
		n := name
		if real.Name != "" {
			n += " " + real.Name
		}
		out = append(out, Scenario{Name: n, Roster: real.Roster, Differences: diffs})
	}
	return out
}

// Row is one derived value beside what the collector reported.
type Row struct {
	Pointer string
	Want    any
	Got     any
	Written bool
	// Gap is the code of the gap the collector left on the value, when it
	// left the value out.
	Gap string
}

// Matches reports whether the collector wrote the derived value.
func (row Row) Matches() bool { return row.Written && sameJSON(row.Want, row.Got) }

// GotString describes what the collector reported.
func (row Row) GotString() string {
	switch {
	case row.Written:
		return show(row.Got, true)
	case row.Gap != "":
		return "absent, " + row.Gap
	default:
		return "absent, no gap"
	}
}

// sameJSON reports whether want and got encode to the same JSON, so a
// derived int matches the float64 decoded from an artifact, and a derived
// list or count by name matches the decoded one.
func sameJSON(want, got any) bool {
	w, errW := json.Marshal(want)
	g, errG := json.Marshal(got)
	return errW == nil && errG == nil && bytes.Equal(w, g)
}

// shapeLog keeps, for one test, the shape differences reported and the
// Unrecorded listings met.
type shapeLog struct{ reported, met map[string]bool }

func newShapeLog() *shapeLog { return &shapeLog{reported: map[string]bool{}, met: map[string]bool{}} }

// Rows derives r's values, runs the collector against the simulator for
// it, and lines its artifacts up with them.
func (h Harness) Rows(t *testing.T, r *roster.Roster) []Row {
	t.Helper()
	rows, _ := h.rows(t, r, newShapeLog(), false)
	return rows
}

// rows also gives, when cover is set, the fields the artifacts write that
// the derived values don't reach.
func (h Harness) rows(t *testing.T, r *roster.Roster, log *shapeLog, cover bool) ([]Row, []string) {
	t.Helper()
	derived, err := roster.Derive(r)
	if err != nil {
		t.Fatal(err)
	}
	res := h.run(t, r, 0, log)
	var rows []Row
	var uncompared []string
	for _, a := range h.Artifacts {
		doc := artifactDoc(t, res, a.Path)
		values := derived[a.Schema]
		for _, pointer := range slices.Sorted(maps.Keys(values)) {
			row := Row{Pointer: a.Prefix + pointer, Want: values[pointer]}
			row.Got, row.Written = lookup(doc, pointer)
			if !row.Written {
				row.Gap = gapAt(res.Result.Gaps, a.Path, pointer)
			}
			rows = append(rows, row)
		}
		if data := artifactData(res, a.Path); cover && data != nil {
			fields, err := uncoveredFields(a, data, values)
			if err != nil {
				t.Fatal(err)
			}
			uncompared = append(uncompared, fields...)
		}
	}
	return rows, uncompared
}

// uncoveredFields lists, by the artifact's Prefix and the field, the fields
// data writes that values don't reach.
func uncoveredFields(a Artifact, data []byte, values map[string]any) ([]string, error) {
	pointers, err := roster.Uncovered(a.Schema, data, values)
	if err != nil || len(pointers) == 0 {
		return nil, err
	}
	s, err := outputcheck.Compile(componentsdk.NormalizedSchemaJSON(a.Schema))
	if err != nil {
		return nil, err
	}
	var out []string
	for _, p := range pointers {
		out = append(out, a.Prefix+outputcheck.FieldOf(s, p))
	}
	slices.Sort(out)
	return slices.Compact(out), nil
}

func (h Harness) run(t *testing.T, r *roster.Roster, pageSize int, log *shapeLog) componentsdk.InProcessResult {
	t.Helper()
	responses := h.Simulate(r, pageSize)
	checkShapes(t, h.Recorded, responses, h.Unrecorded, log.met, log.reported)
	res := h.Collect(t, responses)
	if res.ExitCode != 0 || res.Result == nil {
		t.Fatalf("run failed with exit %d: %s", res.ExitCode, res.Stderr)
	}
	return res
}

func artifactDoc(t *testing.T, res componentsdk.InProcessResult, path string) any {
	t.Helper()
	data := artifactData(res, path)
	if data == nil {
		return nil
	}
	var doc any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

func artifactData(res componentsdk.InProcessResult, path string) []byte {
	for _, a := range res.Artifacts {
		if a.Path == path {
			return a.Data
		}
	}
	return nil
}

// Tenants runs each scenario and fails on a value that differs from the
// derived one unless the scenario or Standing lists it, and on a listed
// difference, other than a standing one, whose value now matches. With
// Coverage on, it also fails on a field no derived value reaches that
// Uncompared doesn't list, and, once every scenario has run, on a listing
// none of them needs. It logs each scenario's table of pointer, derived
// value, collector value, and verdict.
func (h Harness) Tenants(t *testing.T, scenarios []Scenario) {
	log := newShapeLog()
	met := map[string]bool{}
	ran := 0
	for _, sc := range scenarios {
		t.Run(sc.Name, func(t *testing.T) {
			rows, uncompared := h.rows(t, sc.Roster, log, h.Coverage)
			table, failures := judge(rows, sc.Differences, h.Standing)
			for _, f := range failures {
				t.Error(f)
			}
			checkCompared(t, uncompared, h.Uncompared, met)
			t.Logf("%s\n%s", sc.Name, table)
			ran++
		})
	}
	if h.Coverage && ran == len(scenarios) {
		staleUncompared(t, h.Uncompared, met)
	}
}

// checkCompared fails on each field in uncompared that listed doesn't hold,
// and marks the listings it meets.
func checkCompared(t interface{ Errorf(string, ...any) }, uncompared []string, listed map[string]string, met map[string]bool) {
	for _, field := range uncompared {
		if _, ok := listed[field]; ok {
			met[field] = true
			continue
		}
		t.Errorf("%s: the collector writes it, and the roster gives no value to compare it with", field)
	}
}

// staleUncompared fails on each listing no scenario met.
func staleUncompared(t interface{ Errorf(string, ...any) }, listed map[string]string, met map[string]bool) {
	for _, field := range slices.Sorted(maps.Keys(listed)) {
		if !met[field] {
			t.Errorf("listed as uncompared (%s), but every scenario now compares it: %s", listed[field], field)
		}
	}
}

// judge lines rows up with the listed and standing differences. It returns
// the table and a failure for each unlisted difference and each listed one
// that now matches.
func judge(rows []Row, listed, standing Differences) (string, []string) {
	var table strings.Builder
	var failures []string
	for _, row := range rows {
		diff, isListed := listed[row.Pointer]
		stand, isStanding := standing[row.Pointer]
		isStanding = isStanding && stand.accounts(row)
		if !isListed && isStanding {
			diff, isListed = standing[row.Pointer]
		}
		mark := "ok"
		switch {
		case !row.Matches() && !isListed && !isStanding:
			mark = "NEW"
			failures = append(failures, fmt.Sprintf("%s: derived %s, collector %s", row.Pointer, show(row.Want, true), row.GotString()))
		case !row.Matches():
			mark = string(diff.Verdict)
		case isListed && !isStanding:
			failures = append(failures, fmt.Sprintf("%s: listed as %s (%s), but the collector now reports the derived %s", row.Pointer, diff.Verdict, diff.Note, show(row.Want, true)))
		}
		fmt.Fprintf(&table, "  %-62s %-10s %-34s %s\n", row.Pointer, show(row.Want, true), row.GotString(), mark)
	}
	return table.String(), failures
}

// accounts reports whether a standing difference accounts for row: an
// Unwritten one only for a value left out with no gap, a Gap one only for a
// value left out with a gap, and any other for any value.
func (d Difference) accounts(row Row) bool {
	switch d.Verdict {
	case Unwritten:
		return !row.Written && row.Gap == ""
	case Gap:
		return !row.Written && row.Gap != ""
	}
	return true
}

// Expect returns a scenario's derived values, less its listed and the
// standing differences, by artifact path, as a collectortest.Scenario's
// Expect takes them.
func (h Harness) Expect(t testing.TB, sc Scenario) map[string]map[string]any {
	t.Helper()
	derived, err := roster.Derive(sc.Roster)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]map[string]any{}
	for _, a := range h.Artifacts {
		expect := map[string]any{}
		for pointer, value := range derived[a.Schema] {
			_, listed := sc.Differences[a.Prefix+pointer]
			_, standing := h.Standing[a.Prefix+pointer]
			if !listed && !standing {
				expect[pointer] = value
			}
		}
		out[a.Path] = expect
	}
	return out
}

// Output runs the collector for r with lists paged at pageSize, and returns
// every leaf value of its normalized artifacts but collected_at, keyed by
// the schema's short name and the pointer, as in
// idp-posture:/user_security/user_count.
func (h Harness) Output(t *testing.T, r *roster.Roster, pageSize int) map[string]any {
	t.Helper()
	return h.output(t, r, pageSize, newShapeLog())
}

func (h Harness) output(t *testing.T, r *roster.Roster, pageSize int, log *shapeLog) map[string]any {
	t.Helper()
	res := h.run(t, r, pageSize, log)
	out := map[string]any{}
	for _, a := range h.Artifacts {
		flatten(artifactDoc(t, res, a.Path), ShortName(a.Schema)+":", out)
	}
	return out
}

// CheckRecorded checks the shape of the simulator's answers for each roster
// against the recording, as every run does, and fails on an Unrecorded
// listing none of them needs. Pass every roster the tests answer for, the
// scenarios' and each matrix row's, so a listing one of them needs is not
// stale. Each roster is answered in the vendor's pages and in pages of two,
// as Rules may page, since a sandbox's lists often fit one page and its
// recording then holds no next page's link.
func (h Harness) CheckRecorded(t *testing.T, rosters ...*roster.Roster) {
	t.Helper()
	if h.Recorded == nil {
		t.Fatal("the harness has no recording")
	}
	log := newShapeLog()
	for _, r := range rosters {
		for _, pageSize := range []int{0, 2} {
			checkShapes(t, h.Recorded, h.Simulate(r, pageSize), h.Unrecorded, log.met, log.reported)
		}
	}
	for _, key := range slices.Sorted(maps.Keys(h.Unrecorded)) {
		if !log.met[key] {
			t.Errorf("listed as unrecorded (%s), but no simulated answer needs it now: %s", h.Unrecorded[key], key)
		}
	}
}

// ShortName is a schema's name without its namespace and version, such as
// idp-posture for evidencepack/idp-posture@v1.
func ShortName(schema string) string {
	name := schema[strings.LastIndex(schema, "/")+1:]
	name, _, _ = strings.Cut(name, "@")
	return name
}

func flatten(node any, at string, out map[string]any) {
	switch n := node.(type) {
	case nil:
		if !strings.HasSuffix(at, ":") {
			out[at] = nil
		}
	case map[string]any:
		for k, v := range n {
			if k != "collected_at" {
				flatten(v, at+"/"+k, out)
			}
		}
	case []any:
		for i, v := range n {
			flatten(v, fmt.Sprintf("%s/%d", at, i), out)
		}
	default:
		out[at] = n
	}
}

func lookup(doc any, pointer string) (any, bool) {
	node := doc
	if node == nil {
		return nil, false
	}
	for _, part := range strings.Split(strings.TrimPrefix(pointer, "/"), "/") {
		switch n := node.(type) {
		case map[string]any:
			var ok bool
			if node, ok = n[part]; !ok {
				return nil, false
			}
		case []any:
			i, err := strconv.Atoi(part)
			if err != nil || i < 0 || i >= len(n) {
				return nil, false
			}
			node = n[i]
		default:
			return nil, false
		}
	}
	return node, true
}

// gapAt is the code of the gap on path at pointer or above it, with the
// missing permission when the gap names one.
func gapAt(gaps []componentsdk.Gap, path, pointer string) string {
	for _, g := range gaps {
		if g.Path == path && (g.Pointer == "" || g.Pointer == pointer || strings.HasPrefix(pointer, g.Pointer+"/")) {
			if g.MissingPermission != "" {
				return string(g.Code) + " (" + g.MissingPermission + ")"
			}
			return string(g.Code)
		}
	}
	return ""
}

func show(v any, written bool) string {
	switch {
	case !written:
		return "absent"
	case v == nil:
		return "null"
	}
	if f, ok := v.(float64); ok && f == math.Trunc(f) {
		return fmt.Sprint(int(f))
	}
	return fmt.Sprint(v)
}

// InProcess runs a collector in process against responses, with no waits
// and a fixed clock and seed unless opts sets them, and fails on each
// request no response answers.
func InProcess(t testing.TB, spec componentsdk.CollectorSpec, handler componentsdk.CollectorHandler, opts componentsdk.InProcessOptions, responses []collectortest.Response) componentsdk.InProcessResult {
	t.Helper()
	replay, err := collectortest.NewReplay(collectortest.Scenario{Responses: responses})
	if err != nil {
		t.Fatal(err)
	}
	opts.Transport = replay
	if opts.Seed == 0 {
		opts.Seed = 1
	}
	if opts.Sleep == nil {
		opts.Sleep = func(ctx context.Context, _ time.Duration) error { return ctx.Err() }
	}
	res := componentsdk.RunInProcess(spec, handler, opts)
	for _, request := range replay.Unmatched() {
		t.Errorf("no canned response for %s", request)
	}
	return res
}
