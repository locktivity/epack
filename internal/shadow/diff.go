package shadow

import (
	"bytes"
	"encoding/json"
	"maps"
	pathpkg "path"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/locktivity/epack/componentsdk"
	"github.com/locktivity/epack/internal/collector"
	"github.com/locktivity/epack/internal/jsonpointer"
)

// ReportSchemaVersion is the version of the report's format.
const ReportSchemaVersion = "1.0.0"

// Report is what a shadow run found. It holds no value from the account:
// fields are named by pattern, errors by code, and call counts by range.
type Report struct {
	SchemaVersion string            `json:"schema_version"`
	Collector     string            `json:"collector"`
	Level         string            `json:"level"`
	Locked        LockedRuns        `json:"locked"`
	Candidate     CandidateRun      `json:"candidate"`
	Kinds         []KindChange      `json:"kinds,omitempty"`
	Fields        []FieldChange     `json:"fields,omitempty"`
	Noise         []FieldRef        `json:"noise,omitempty"`
	Gaps          []GapChange       `json:"gaps,omitempty"`
	Operations    []OperationChange `json:"operations,omitempty"`
	Calls         *Calls            `json:"calls,omitempty"`
	// GapNoise lists each gap that one locked run records and the other
	// does not. Gaps leaves these out.
	GapNoise []GapRef `json:"gap_noise,omitempty"`
	// Controls lists each requirement whose result the candidate changes,
	// from the project's validate tool. ControlNoise names requirements
	// whose result also differs between the two locked runs.
	// ControlsSkipped says why there are no control results.
	Controls        []ControlChange `json:"controls,omitempty"`
	ControlNoise    []string        `json:"control_noise,omitempty"`
	ControlsSkipped string          `json:"controls_skipped,omitempty"`
}

// Outcome is how one run ended: collected, partial, or failed, with the
// code of a partial run's first gap.
type Outcome struct {
	Status string `json:"status"`
	Code   string `json:"code,omitempty"`
}

// LockedRuns describes the two runs of the locked version.
type LockedRuns struct {
	Version string    `json:"version,omitempty"`
	Runs    []Outcome `json:"runs"`
}

// CandidateRun describes the run of the candidate version.
type CandidateRun struct {
	Version string `json:"version,omitempty"`
	Outcome
}

// KindChange lists one kind of evidence either version wrote, with its
// schema ID in each. Change is unchanged, schema changed, added, removed,
// or left out when the collect config key left it out of the candidate's
// run.
type KindChange struct {
	Kind      string `json:"kind"`
	File      string `json:"file,omitempty"`
	Change    string `json:"change"`
	Locked    string `json:"locked,omitempty"`
	Candidate string `json:"candidate,omitempty"`
}

// FieldRef names a field by its kind, file, and pattern.
type FieldRef struct {
	Kind    string `json:"kind"`
	File    string `json:"file"`
	Pointer string `json:"pointer"`
}

// FieldChange is a field whose values differ between the versions: added,
// removed, changed, or reordered when the same values sit in other rows.
// Level is the candidate schema's level for a field it no longer writes at
// this run's level.
type FieldChange struct {
	FieldRef
	Change string `json:"change"`
	Level  string `json:"level,omitempty"`
}

// GapChange is a gap the candidate records that the locked version does
// not, or the reverse. It names the code and the permission a gap asks
// for, never the gap's detail.
type GapChange struct {
	GapRef
	Change string `json:"change"`
}

// GapRef names a gap by its field, status, and code, and the permission it
// asks for.
type GapRef struct {
	FieldRef
	Status            string `json:"status"`
	Code              string `json:"code"`
	MissingPermission string `json:"missing_permission,omitempty"`
}

// OperationChange is an API operation the candidate calls that the locked
// version does not, or the reverse, or one that now fails with codes it did
// not fail with before.
type OperationChange struct {
	Name       string   `json:"name"`
	Change     string   `json:"change"`
	Permission string   `json:"permission,omitempty"`
	Codes      []string `json:"codes,omitempty"`
}

// Preview holds the values behind a report's field changes: for each field
// that changed, what the locked run wrote and what the candidate wrote. It
// names real files and pointers and holds real values, so it stays on the
// machine that ran the shadow and never goes into a Report.
type Preview struct {
	Collector string         `json:"collector"`
	Values    []ValueChange  `json:"values"`
	Controls  []ControlValue `json:"controls,omitempty"`
}

// ValueChange is one field's value in the locked run and in the candidate's
// run, as JSON. From is empty for a field the candidate added, and To for
// one it removed.
type ValueChange struct {
	Kind    string `json:"kind"`
	File    string `json:"file"`
	Pointer string `json:"pointer"`
	Field   string `json:"field"`
	From    string `json:"from,omitempty"`
	To      string `json:"to,omitempty"`
}

// maxValuesPerField is the most values a preview keeps for one field, such
// as one per row of a long list.
const maxValuesPerField = 50

// Calls holds each version's total API calls as a range. Results record
// call counts at the audit and internal levels only.
type Calls struct {
	Locked    string `json:"locked"`
	Candidate string `json:"candidate"`
}

// Run is one collector run's output, parsed.
type RunOutput struct {
	Failed bool
	files  map[string]file
	result *componentsdk.CollectorResult
	build  *componentsdk.CollectorBuild
}

type file struct {
	path, schema string
	doc          any
	staged       bool
}

// ParseRun parses one run's output. A run with no usable output reads as
// failed.
func ParseRun(collectorName string, output []byte, ok bool) RunOutput {
	r := RunOutput{files: map[string]file{}}
	parsed, err := collector.ParseCollectorOutput(output)
	if !ok || err != nil {
		r.Failed = true
		return r
	}
	for i, a := range parsed.Artifacts {
		path := a.PathOrDefault(collectorName, i)
		switch a.Schema {
		case componentsdk.ResultSchema:
			var res componentsdk.CollectorResult
			if json.Unmarshal(a.RawData, &res) == nil {
				r.result = &res
			}
			continue
		case componentsdk.BuildSchema:
			var b componentsdk.CollectorBuild
			if json.Unmarshal(a.RawData, &b) == nil {
				r.build = &b
			}
			continue
		}
		f := file{path: path, schema: a.Schema, staged: a.File != ""}
		if !f.staged {
			dec := json.NewDecoder(bytes.NewReader(a.RawData))
			dec.UseNumber()
			if dec.Decode(&f.doc) != nil {
				f.doc = nil
			}
		}
		r.files[path] = f
	}
	return r
}

func (r RunOutput) outcome() Outcome {
	switch {
	case r.Failed:
		return Outcome{Status: "failed"}
	case r.result == nil:
		return Outcome{Status: "collected"}
	}
	return Outcome{Status: r.result.Outcome.Status, Code: string(r.result.Outcome.Code)}
}

// schemaFor returns the schema the run checked a file against: its build
// file's, by path and then by schema ID, then the SDK's normalized one.
func (r RunOutput) schemaFor(path, schemaID string) *schema {
	if r.build != nil {
		if raw, ok := r.build.Schemas[path]; ok {
			return parseSchema(raw)
		}
		if raw, ok := r.build.Schemas[schemaID]; ok && schemaID != "" {
			return parseSchema(raw)
		}
	}
	return parseSchema(componentsdk.NormalizedSchemaJSON(schemaID))
}

// Compare compares the candidate's run with the locked version's two runs.
// A field or gap that differs between the two locked runs is noise, which
// the report lists apart and leaves out of its changes. The preview holds
// the values behind each field change, for the person running the shadow.
func Compare(collectorName, level string, locked1, locked2, candidate RunOutput) (Report, Preview) {
	rep := Report{
		SchemaVersion: ReportSchemaVersion,
		Collector:     collectorName,
		Level:         level,
		Locked:        LockedRuns{Runs: []Outcome{locked1.outcome(), locked2.outcome()}},
		Candidate:     CandidateRun{Outcome: candidate.outcome()},
	}
	preview := Preview{Collector: collectorName, Values: []ValueChange{}}
	runs := trio[RunOutput]{Locked1: locked1, Locked2: locked2, Candidate: candidate}
	if anyFailed(runs) {
		return rep, preview
	}
	c := comparison{collector: collectorName, level: level, runs: runs}
	c.compareFiles(&rep, &preview)
	c.compareGaps(&rep)
	c.compareOperations(&rep)
	rep.Calls = c.calls()
	sortReport(&rep)
	return rep, preview
}

type comparison struct {
	collector, level string
	runs             trio[RunOutput]
}

// fileRef names an artifact's file for the report, with identifiers hidden
// as filePattern hides them. A file keeps its name when a build file
// declares its path, when it has a schema ID, or when it is named for the
// collector, as the SDK names files. Any other name can name something in
// the account, such as a document's title, so the report gives only the
// file's directory and extension.
func (c comparison) fileRef(path, schemaID string) string {
	dir, name := pathpkg.Split(path)
	switch {
	case path == "", schemaID != "", c.declares(path), name == c.collector+pathpkg.Ext(name),
		strings.HasPrefix(name, c.collector+"."), strings.HasPrefix(name, c.collector+"_"):
		return filePattern(path)
	}
	return filePattern(dir) + "{file}" + pathpkg.Ext(name)
}

// declares reports whether any run's build file declares a schema for the
// artifact at path.
func (c comparison) declares(path string) bool {
	for _, r := range []RunOutput{c.runs.Locked1, c.runs.Locked2, c.runs.Candidate} {
		if r.build != nil {
			if _, ok := r.build.Schemas[path]; ok {
				return true
			}
		}
	}
	return false
}

func (c comparison) kind(schemaID string) string {
	return componentsdk.KindOf(schemaID, c.collector)
}

func (c comparison) leftOut(kind string) bool {
	b := c.runs.Candidate
	return b.result != nil && b.result.Collect != nil && slices.Contains(b.result.Collect.LeftOut, kind)
}

// compareFiles compares the files the runs wrote: the kinds of evidence
// each version wrote, and the fields of each file every run wrote.
func (c comparison) compareFiles(rep *Report, preview *Preview) {
	files := mapTrio(c.runs, func(r RunOutput) map[string]file { return r.files })
	paths := threeWay(files, nil)
	c.compareKinds(rep, files, paths)
	c.compareFields(rep, preview, files, paths)
}

// compareKinds lists each kind of evidence either version wrote. It lists
// no noise: a file only one locked run wrote counts as the candidate's
// alone when the candidate wrote it too, and is left out when it did not.
func (c comparison) compareKinds(rep *Report, files trio[map[string]file], paths map[string]verdict) {
	type kindSeen struct {
		change      KindChange
		inLocked    bool
		inCandidate bool
	}
	kinds := map[[2]string]*kindSeen{}
	for _, path := range sortedKeys(paths) {
		f1, in1 := files.Locked1[path]
		f2 := files.Locked2[path]
		fb, inCandidate := files.Candidate[path]
		v := paths[path]
		ref := f1
		if !in1 {
			ref = f2
		}
		if v == noisy {
			// Only one locked run wrote the file, so whether the candidate
			// writes it says nothing about the candidate.
			rep.Noise = append(rep.Noise, FieldRef{Kind: c.kind(ref.schema), File: c.fileRef(path, ref.schema)})
			continue
		}
		inLocked := v == kept || v == removed
		if !inLocked && !inCandidate {
			continue
		}
		if !in1 {
			ref = fb
		}
		kind := c.kind(ref.schema)
		key := [2]string{kind, c.fileRef(path, ref.schema)}
		k := kinds[key]
		if k == nil {
			k = &kindSeen{change: KindChange{Kind: kind, File: key[1]}}
			kinds[key] = k
		}
		if inLocked {
			k.inLocked, k.change.Locked = true, f1.schema
		}
		if inCandidate {
			k.inCandidate, k.change.Candidate = true, fb.schema
		}
	}
	for _, k := range kinds {
		ch := k.change
		switch {
		case k.inLocked && k.inCandidate && ch.Locked == ch.Candidate:
			ch.Change = "unchanged"
		case k.inLocked && k.inCandidate:
			ch.Change = "schema changed"
		case k.inCandidate:
			ch.Change = "added"
		case c.leftOut(ch.Kind):
			ch.Change = "left out"
		default:
			ch.Change = "removed"
		}
		rep.Kinds = append(rep.Kinds, ch)
	}
	if b := c.runs.Candidate; b.result != nil && b.result.Collect != nil {
		for _, kind := range b.result.Collect.LeftOut {
			if !slices.ContainsFunc(rep.Kinds, func(k KindChange) bool { return k.Kind == kind }) {
				rep.Kinds = append(rep.Kinds, KindChange{Kind: kind, Change: "left out", Candidate: c.written(kind)})
			}
		}
	}
}

// compareFields compares the fields of each file every run wrote, by the
// patterns its schemas name. A field whose values differ between the two
// locked runs is noise. Only the first locked run's file and the
// candidate's must be inline.
func (c comparison) compareFields(rep *Report, preview *Preview, files trio[map[string]file], paths map[string]verdict) {
	fields := map[FieldRef]FieldChange{}
	noise := map[FieldRef]bool{}
	for _, path := range sortedKeys(paths) {
		f := trio[file]{Locked1: files.Locked1[path], Locked2: files.Locked2[path], Candidate: files.Candidate[path]}
		// A file staged in any run has no fields to compare.
		if paths[path] != kept || !inline(f.Locked1) || !inline(f.Locked2) || !inline(f.Candidate) {
			continue
		}
		kind, pathPattern := c.kind(f.Locked1.schema), c.fileRef(path, f.Locked1.schema)
		w := newWalker(c.runs.Locked1.schemaFor(path, f.Locked1.schema), c.runs.Candidate.schemaFor(path, f.Candidate.schema))
		values := mapTrio(f, func(f file) map[string]map[string]string { return leaves(f.doc, w).values })
		patterns := threeWay(values, func(a, b map[string]string) bool { return maps.Equal(a, b) })
		for _, pattern := range sortedKeys(patterns) {
			at := FieldRef{Kind: kind, File: pathPattern, Pointer: pattern}
			switch patterns[pattern] {
			case kept:
				continue
			case noisy:
				noise[at] = true
				continue
			}
			from, to := values.Locked1[pattern], values.Candidate[pattern]
			change := classify(from, to)
			fc := FieldChange{FieldRef: at, Change: change}
			if change == "removed" {
				if level := w.levelAt(pattern); above(level, c.level) {
					fc.Level = level
				}
			}
			if prev, ok := fields[at]; ok && prev.Change != fc.Change {
				fc.Change = "changed"
			}
			fields[at] = fc
			shown := 0
			for _, concrete := range sortedKeys(unionKeys(from, to)) {
				if from[concrete] == to[concrete] || shown == maxValuesPerField {
					continue
				}
				shown++
				preview.Values = append(preview.Values, ValueChange{
					Kind: kind, File: path, Pointer: concrete, Field: pattern, From: from[concrete], To: to[concrete],
				})
			}
		}
	}
	for _, fc := range fields {
		rep.Fields = append(rep.Fields, fc)
	}
	for ref := range noise {
		rep.Noise = append(rep.Noise, ref)
	}
}

// inline reports whether a run wrote a file's document into its output,
// rather than staging it, so its fields can be compared.
func inline(f file) bool {
	return !f.staged && f.doc != nil
}

// written returns the schema ID the candidate's build says it writes for
// kind, or "".
func (c comparison) written(kind string) string {
	build := c.runs.Candidate.build
	if build == nil {
		return ""
	}
	for _, id := range build.Writes {
		if c.kind(id) == kind {
			return id
		}
	}
	return ""
}

// classify says how one pattern's values changed between the locked run and
// the candidate's, or "" when they did not.
func classify(locked, candidate map[string]string) string {
	switch {
	case reflect.DeepEqual(locked, candidate):
		return ""
	case len(locked) == 0:
		return "added"
	case len(candidate) == 0:
		return "removed"
	}
	if slices.Equal(sortedValues(locked), sortedValues(candidate)) && slices.Equal(sortedKeys(locked), sortedKeys(candidate)) {
		return "reordered"
	}
	return "changed"
}

// leafSet maps each pattern in a document to its values by concrete
// pointer. The concrete pointers and values stay in memory for the
// comparison and the preview, and never reach the report.
type leafSet struct {
	values map[string]map[string]string
}

func leaves(doc any, w walker) leafSet {
	ls := leafSet{values: map[string]map[string]string{}}
	var walk func(node any, w walker, pattern, concrete string)
	add := func(pattern, concrete, value string) {
		if ls.values[pattern] == nil {
			ls.values[pattern] = map[string]string{}
		}
		ls.values[pattern][concrete] = value
	}
	walk = func(node any, w walker, pattern, concrete string) {
		switch n := node.(type) {
		case map[string]any:
			if len(n) == 0 {
				add(pattern, concrete, "{}")
			}
			for _, key := range sortedKeys(n) {
				next, token := w.key(key)
				walk(n[key], next, pattern+"/"+token, concrete+"/"+jsonpointer.Escape(key))
			}
		case []any:
			if len(n) == 0 {
				add(pattern, concrete, "[]")
			}
			for i, item := range n {
				walk(item, w.index(i), pattern+"/*", concrete+"/"+strconv.Itoa(i))
			}
		default:
			raw, _ := json.Marshal(n)
			add(pattern, concrete, string(raw))
		}
	}
	walk(doc, w, "", "")
	return ls
}

func (c comparison) gapKeys(r RunOutput) map[GapRef]bool {
	out := map[GapRef]bool{}
	if r.result == nil {
		return out
	}
	for _, g := range r.result.Gaps {
		if g.Code == componentsdk.CodeNotShared {
			continue
		}
		schemaID, path := g.Schema, g.Path
		if f, ok := r.files[path]; ok && schemaID == "" {
			schemaID = f.schema
		}
		w := newWalker(c.runs.Locked1.schemaFor(path, schemaID), c.runs.Candidate.schemaFor(path, schemaID))
		out[GapRef{
			FieldRef:          FieldRef{Kind: c.kind(schemaID), File: c.fileRef(path, schemaID), Pointer: w.pointerPattern(g.Pointer)},
			Status:            g.Status,
			Code:              string(g.Code),
			MissingPermission: g.MissingPermission,
		}] = true
	}
	return out
}

// compareGaps lists each gap the candidate records that the locked runs do
// not, or the reverse. A gap only one locked run records is noise.
func (c comparison) compareGaps(rep *Report) {
	for k, v := range threeWay(mapTrio(c.runs, c.gapKeys), nil) {
		switch v {
		case added:
			rep.Gaps = append(rep.Gaps, GapChange{GapRef: k, Change: "added"})
		case removed:
			rep.Gaps = append(rep.Gaps, GapChange{GapRef: k, Change: "removed"})
		case noisy:
			rep.GapNoise = append(rep.GapNoise, k)
		}
	}
}

func operations(r RunOutput) map[string]componentsdk.OperationCalls {
	out := map[string]componentsdk.OperationCalls{}
	if r.result == nil {
		return out
	}
	for _, op := range r.result.Calls.Operations {
		out[op.Name] = op
	}
	return out
}

// compareOperations lists each operation the candidate calls that the
// locked runs do not, or the reverse, and each one every run calls that the
// candidate's run fails with a code neither locked run did. It lists no
// noise: an operation only one locked run calls is left out.
func (c comparison) compareOperations(rep *Report) {
	ops := mapTrio(c.runs, operations)
	for name, v := range threeWay(ops, nil) {
		op := ops.Candidate[name]
		switch v {
		case added:
			rep.Operations = append(rep.Operations, OperationChange{Name: name, Change: "added", Permission: op.Permission})
		case removed:
			rep.Operations = append(rep.Operations, OperationChange{Name: name, Change: "removed"})
		case kept:
			var fresh []string
			for _, code := range op.ErrorCodes {
				if !slices.Contains(ops.Locked1[name].ErrorCodes, code) && !slices.Contains(ops.Locked2[name].ErrorCodes, code) {
					fresh = append(fresh, string(code))
				}
			}
			if len(fresh) > 0 {
				sort.Strings(fresh)
				rep.Operations = append(rep.Operations, OperationChange{Name: name, Change: "now fails", Permission: op.Permission, Codes: fresh})
			}
		}
	}
}

func (c comparison) calls() *Calls {
	total := func(r RunOutput) int {
		n := 0
		for _, op := range operations(r) {
			n += op.Calls
		}
		return n
	}
	locked, candidate := total(c.runs.Locked1), total(c.runs.Candidate)
	if locked == 0 && candidate == 0 {
		return nil
	}
	return &Calls{Locked: callRange(locked), Candidate: callRange(candidate)}
}

// callRange puts a call count in a range, so the report does not give the
// exact size of the account.
func callRange(n int) string {
	switch {
	case n == 0:
		return "0"
	case n < 10:
		return "1-9"
	case n < 100:
		return "10-99"
	case n < 1000:
		return "100-999"
	case n < 10000:
		return "1,000-9,999"
	}
	return "10,000 or more"
}

func sortReport(rep *Report) {
	ref := func(r FieldRef) string { return r.Kind + "\x00" + r.File + "\x00" + r.Pointer }
	sort.Slice(rep.Kinds, func(i, j int) bool {
		return rep.Kinds[i].Kind+"\x00"+rep.Kinds[i].File < rep.Kinds[j].Kind+"\x00"+rep.Kinds[j].File
	})
	sort.Slice(rep.Fields, func(i, j int) bool { return ref(rep.Fields[i].FieldRef) < ref(rep.Fields[j].FieldRef) })
	sort.Slice(rep.Noise, func(i, j int) bool { return ref(rep.Noise[i]) < ref(rep.Noise[j]) })
	rep.Noise = slices.Compact(rep.Noise)
	// gap orders gaps that share a field and change by every other part, so
	// the order does not depend on map iteration.
	gap := func(g GapRef, change string) string {
		return ref(g.FieldRef) + "\x00" + change + "\x00" + g.Code + "\x00" + g.Status + "\x00" + g.MissingPermission
	}
	sort.Slice(rep.Gaps, func(i, j int) bool {
		return gap(rep.Gaps[i].GapRef, rep.Gaps[i].Change) < gap(rep.Gaps[j].GapRef, rep.Gaps[j].Change)
	})
	sort.Slice(rep.GapNoise, func(i, j int) bool { return gap(rep.GapNoise[i], "") < gap(rep.GapNoise[j], "") })
	sort.Slice(rep.Operations, func(i, j int) bool {
		return rep.Operations[i].Name+"\x00"+rep.Operations[i].Change < rep.Operations[j].Name+"\x00"+rep.Operations[j].Change
	})
}

func unionKeys(a, b map[string]string) map[string]bool {
	out := map[string]bool{}
	for k := range a {
		out[k] = true
	}
	for k := range b {
		out[k] = true
	}
	return out
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func sortedValues(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for _, v := range m {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}
