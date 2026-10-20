package collectortest

import (
	"cmp"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"slices"
	"strings"

	"github.com/locktivity/epack/componentsdk"
	"github.com/locktivity/epack/componentsdk/internal/outputcheck"
	"github.com/locktivity/epack/internal/tracemap"
)

// tracer collects what a suite's runs find about each field of the
// collector's artifacts: the operations whose faults leave it out or change
// it, the lines that record its gaps, and the fields it copies. With
// COLLECTORTEST_MAP set, the kit writes it out for `epack sdk map`, which
// builds the trace map from every suite's. Otherwise the kit checks the
// collector's committed map against it.
type tracer struct {
	fields map[string]map[string]*tracemap.FieldTrace
	// base is the clean run's result, and clean what it emitted, which the
	// faulted runs are compared with.
	base    *componentsdk.CollectorResult
	clean   snapshot
	schemas map[string]string
}

func newTracer() *tracer {
	return &tracer{
		fields: map[string]map[string]*tracemap.FieldTrace{},
		clean:  snapshot{docs: map[string]any{}, leaves: map[string]map[string]any{}},
	}
}

// tracing reports whether the suite's runs need a tracer: `epack sdk map`
// is building a map, or the collector has one to check.
func tracing(s Suite) bool {
	return os.Getenv(tracemap.Env) != "" || len(s.Spec.TraceMap) > 0
}

func (t *tracer) field(path, pattern string) *tracemap.FieldTrace {
	byPattern := t.fields[path]
	if byPattern == nil {
		byPattern = map[string]*tracemap.FieldTrace{}
		t.fields[path] = byPattern
	}
	f := byPattern[pattern]
	if f == nil {
		f = &tracemap.FieldTrace{}
		byPattern[pattern] = f
	}
	return f
}

// snapshot is what a run emitted, as the tracer compares runs: each data
// artifact's document and its leaves, and each file artifact, by path.
type snapshot struct {
	docs   map[string]any
	leaves map[string]map[string]any
	files  map[string]componentsdk.EmittedArtifact
}

func snapshotOf(artifacts []componentsdk.EmittedArtifact) snapshot {
	s := snapshot{docs: map[string]any{}, leaves: map[string]map[string]any{}, files: filesByPath(artifacts)}
	for path, a := range artifactsByPath(artifacts) {
		doc, err := outputcheck.Decode(a.Data)
		if err != nil {
			continue
		}
		flat, err := flatten(a.Data)
		if err != nil {
			continue
		}
		s.docs[path], s.leaves[path] = doc, flat
	}
	return s
}

// changed calls fn with the path and pattern of each field that differs
// between the clean snapshot c and faulted: each clean value faulted lost or
// changed, each value it added, and each file it changed.
func (c snapshot) changed(faulted snapshot, fn func(path, pattern string)) {
	for path, clean := range c.leaves {
		got := faulted.leaves[path]
		for p, want := range clean {
			v, present := got[p]
			if (present && reflect.DeepEqual(v, want)) || ((!present || v == nil) && want == nil) {
				continue
			}
			fn(path, tracemap.Pattern(p, c.docs[path], faulted.docs[path]))
		}
	}
	for path, leaves := range faulted.leaves {
		clean := c.leaves[path]
		for p, v := range leaves {
			if _, ok := clean[p]; ok || v == nil || emptied(clean, p, v) {
				continue
			}
			fn(path, tracemap.Pattern(p, faulted.docs[path], c.docs[path]))
		}
	}
	for path, want := range c.files {
		if got, ok := faulted.files[path]; !ok || got.SHA256 != want.SHA256 || got.Size != want.Size {
			fn(path, "")
		}
	}
}

// addFields notes every field a successful run emitted.
func (t *tracer) addFields(res componentsdk.InProcessResult) {
	t.noteFields(snapshotOf(res.Artifacts))
}

func (t *tracer) noteFields(s snapshot) {
	for path, flat := range s.leaves {
		for p := range flat {
			t.field(path, tracemap.Pattern(p, s.docs[path]))
		}
	}
	for path := range s.files {
		t.field(path, "")
	}
}

// setBaseline keeps the clean run, which the faulted runs are compared with,
// and notes its fields, the sources of its own gaps, and its Mirror calls.
func (t *tracer) setBaseline(res componentsdk.InProcessResult) {
	t.base = res.Result
	t.clean = snapshotOf(res.Artifacts)
	t.schemas = map[string]string{}
	for _, a := range res.Artifacts {
		if a.Schema != "" && !sdkArtifact(a) {
			t.schemas[a.Path] = a.Schema
		}
	}
	t.noteFields(t.clean)
	for _, g := range gapsOf(res.Result) {
		t.addGap("", g, nil)
	}
	for _, m := range res.Mirrors {
		from, okFrom := locate(m.From, res.Artifacts)
		to, okTo := locate(m.To, res.Artifacts)
		if !okFrom || !okTo {
			continue
		}
		copied := tracemap.Copy{Path: from, Pointer: tracemap.Pattern(m.From.Pointer, t.clean.docs[from])}
		t.field(to, tracemap.Pattern(m.To.Pointer, t.clean.docs[to])).AddCopy(copied)
	}
}

// locate returns the path of the artifact a location names, by its path or
// by the schema of the one artifact that has it.
func locate(at componentsdk.Location, artifacts []componentsdk.EmittedArtifact) (string, bool) {
	if at.Path != "" {
		return at.Path, true
	}
	found := ""
	for _, a := range artifacts {
		if a.Schema != at.Schema || at.Schema == "" {
			continue
		}
		if found != "" {
			return "", false
		}
		found = a.Path
	}
	return found, found != ""
}

// addFault notes what a run with a fault injected into op left out or
// changed: each field that differs from the clean run, and each gap it left,
// with the line that recorded the gap. A run that failed says nothing about
// any one field, so it is passed over.
func (t *tracer) addFault(op string, res componentsdk.InProcessResult) {
	if res.ExitCode != 0 || res.Result == nil {
		return
	}
	faulted := snapshotOf(res.Artifacts)
	t.clean.changed(faulted, func(path, pattern string) {
		t.field(path, pattern).AddOperation(op)
	})
	for _, g := range newGaps(t.base, res.Result) {
		t.addGap(op, g, faulted.docs[g.Path])
	}
}

// addGap notes a gap: at its own field, and with its source at every clean
// field it covers. A gap from a fault also names the faulted operation.
func (t *tracer) addGap(op string, g componentsdk.Gap, doc any) {
	if g.Path == "" {
		return
	}
	f := t.field(g.Path, tracemap.Pattern(g.Pointer, doc, t.clean.docs[g.Path]))
	if op != "" {
		f.AddOperation(op)
	}
	if g.Source == "" {
		return
	}
	f.AddGap(g.Source)
	for p := range t.clean.leaves[g.Path] {
		if tracemap.Covers(g.Pointer, p) {
			t.field(g.Path, tracemap.Pattern(p, t.clean.docs[g.Path])).AddGap(g.Source)
		}
	}
	if _, ok := t.clean.files[g.Path]; ok && g.Pointer == "" {
		t.field(g.Path, "").AddGap(g.Source)
	}
}

// suiteTrace is the tracer's findings as `epack sdk map` reads them.
func (t *tracer) suiteTrace(s Suite, called []componentsdk.OperationCalls) tracemap.SuiteTrace {
	ops := slices.Sorted(slices.Values(s.Operations))
	if len(ops) == 0 {
		for _, op := range called {
			if op.Name != componentsdk.UnnamedOperation {
				ops = append(ops, op.Name)
			}
		}
		slices.Sort(ops)
	}
	return tracemap.SuiteTrace{
		Suite:       cmp.Or(s.Name, s.Spec.Name),
		Operations:  ops,
		Insensitive: slices.Sorted(slices.Values(s.Insensitive)),
		Required:    slices.Sorted(slices.Values(s.Required)),
		Artifacts:   t.fields,
		Schemas:     t.schemas,
	}
}

// writeTrace writes the suite's trace to a file of its own under dir, since
// suites in other packages may share a name and run at the same time.
func (k *kit) writeTrace(dir string) error {
	called := k.baseline.Result.Calls.Operations
	raw, err := json.MarshalIndent(k.trace.suiteTrace(k.suite, called), "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, cmp.Or(slug(cmp.Or(k.suite.Name, k.suite.Spec.Name)), "suite")+"-*.json")
	if err != nil {
		return err
	}
	if _, err := f.Write(append(raw, '\n')); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// maxStale bounds the stale entries a tracemap violation lists.
const maxStale = 5

// checkTraceMap reports a committed trace map that lacks a field the suite's
// runs emitted, or an operation whose faults the fault matrix found
// changing a field. The map merges every suite's runs, so it may list more
// than one suite finds.
func (k *kit) checkTraceMap() {
	var committed tracemap.Map
	if err := json.Unmarshal(k.suite.Spec.TraceMap, &committed); err != nil {
		k.violate("tracemap", "", "CollectorSpec.TraceMap is not a trace map (%v); run epack sdk map and commit the map it writes", err)
		return
	}
	var stale []string
	for _, path := range sortedKeys(k.trace.fields) {
		for _, pattern := range sortedKeys(k.trace.fields[path]) {
			have := committed.Artifacts[path][pattern]
			if have == nil {
				stale = append(stale, fmt.Sprintf("%s %s is missing", path, pointerLabel(pattern)))
				continue
			}
			for _, op := range k.trace.fields[path][pattern].Operations {
				if !containsString(have.Operations, op) {
					stale = append(stale, fmt.Sprintf("%s %s does not list %s, whose faults change it", path, pointerLabel(pattern), op))
				}
			}
		}
	}
	if len(stale) == 0 {
		return
	}
	shown := stale
	more := ""
	if len(shown) > maxStale {
		shown, more = shown[:maxStale], fmt.Sprintf("; and %d more", len(stale)-maxStale)
	}
	k.violate("tracemap", "", "the committed trace map is stale: %s%s. Run epack sdk map and commit the map it writes", strings.Join(shown, "; "), more)
}
