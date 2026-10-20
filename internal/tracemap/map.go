package tracemap

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/locktivity/epack/internal/procexec"
)

// DefaultFile is where a collector commits its trace map, beside its
// schema, relative to the module root.
const DefaultFile = "docs/schema/trace-map.json"

// Options configures Build.
type Options struct {
	// Dir is a directory in the collector's module.
	Dir string
	// Output receives the output of the go test run of the suites.
	Output io.Writer
}

// Build runs the module's tests, which run its collectortest suites, with
// COLLECTORTEST_MAP set so each suite writes what its runs found. It merges
// the suites' traces with what static analysis finds in the module's source.
// It returns the map and the module's root.
func Build(ctx context.Context, opts Options) (*Map, string, error) {
	root, err := moduleRoot(ctx, opts.Dir)
	if err != nil {
		return nil, "", err
	}
	traces, err := runSuites(ctx, root, opts.Output)
	if err != nil {
		return nil, root, err
	}
	m, err := FromTraces(ctx, root, traces)
	return m, root, err
}

// moduleRoot returns the root of the module dir is in.
func moduleRoot(ctx context.Context, dir string) (string, error) {
	out, err := procexec.Output(ctx, procexec.Spec{Path: "go", Args: []string{"env", "GOMOD"}, Dir: dir})
	if err != nil {
		return "", fmt.Errorf("go env GOMOD: %w", err)
	}
	gomod := strings.TrimSpace(string(out))
	if gomod == "" || gomod == os.DevNull {
		return "", fmt.Errorf("%s is not in a Go module", dir)
	}
	return filepath.Dir(gomod), nil
}

// runSuites runs go test across the module, with each suite writing its
// trace to a directory of its own, and reads the traces back.
func runSuites(ctx context.Context, root string, output io.Writer) ([]SuiteTrace, error) {
	dir, err := os.MkdirTemp("", "epack-trace-map-")
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.RemoveAll(dir) }()
	if output == nil {
		output = io.Discard
	}
	var log bytes.Buffer
	err = procexec.Run(ctx, procexec.Spec{
		Path:   "go",
		Args:   []string{"test", "-count=1", "./..."},
		Dir:    root,
		Env:    append(os.Environ(), Env+"="+dir),
		Stdout: io.MultiWriter(output, &log),
		Stderr: io.MultiWriter(output, &log),
	})
	if err != nil {
		return nil, fmt.Errorf("the tests failed, so the map would not be one they prove: %w\n%s", err, tail(log.String(), 40))
	}
	files, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	var traces []SuiteTrace
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		var st SuiteTrace
		if err := json.Unmarshal(raw, &st); err != nil {
			return nil, fmt.Errorf("reading %s: %w", filepath.Base(f), err)
		}
		traces = append(traces, st)
	}
	if len(traces) == 0 {
		return nil, errors.New("no collectortest suite wrote a trace: run the suites with collectortest.Run from a Go test, on an epack version that has the trace map")
	}
	return traces, nil
}

func tail(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

// FromTraces builds the map from suites' traces and the source of the
// module at root. It fails when an operation a suite lists feeds no field
// in any suite's runs, unless a suite marks it as changing no value or as
// required, whose faults fail the whole run.
func FromTraces(ctx context.Context, root string, traces []SuiteTrace) (*Map, error) {
	if err := unfed(traces); err != nil {
		return nil, err
	}
	prog, err := loadProgram(ctx, root)
	if err != nil {
		return nil, fmt.Errorf("loading the module's source: %w", err)
	}
	a := newAnalysis(prog)
	src := newSource(prog.root)
	m := &Map{Artifacts: map[string]map[string]*Field{}, Lines: Lines{}}
	for path, patterns := range merged(traces) {
		schema := schemaOf(traces, path)
		fields := map[string]*Field{}
		for pattern, found := range patterns {
			f := &Field{}
			for _, ft := range found {
				for _, op := range ft.Operations {
					f.Operations = addString(f.Operations, op)
				}
				for _, c := range ft.Copies {
					f.Copies = addCopy(f.Copies, c)
				}
			}
			if f.Gaps, err = gapLines(found, src, m.Lines); err != nil {
				return nil, fmt.Errorf("%s %s: %w", path, pattern, err)
			}
			if f.Code, err = codeLines(a, src, m.Lines, path, schema, pattern); err != nil {
				return nil, fmt.Errorf("%s %s: %w", path, pattern, err)
			}
			fields[pattern] = f
		}
		m.Artifacts[path] = fields
	}
	return m, nil
}

// merged groups every suite's findings by artifact path and field.
func merged(traces []SuiteTrace) map[string]map[string][]*FieldTrace {
	out := map[string]map[string][]*FieldTrace{}
	for _, st := range traces {
		for path, fields := range st.Artifacts {
			if out[path] == nil {
				out[path] = map[string][]*FieldTrace{}
			}
			for pattern, ft := range fields {
				if ft == nil {
					ft = &FieldTrace{}
				}
				out[path][pattern] = append(out[path][pattern], ft)
			}
		}
	}
	return out
}

func schemaOf(traces []SuiteTrace, path string) string {
	for _, st := range traces {
		if s := st.Schemas[path]; s != "" {
			return s
		}
	}
	return ""
}

// unfed reports each operation a suite lists that no suite's runs found
// feeding a field, and that no suite marks as changing no value or as
// required.
func unfed(traces []SuiteTrace) error {
	feeds, exempt := map[string]bool{}, map[string]bool{}
	for _, st := range traces {
		for _, op := range append(append([]string(nil), st.Insensitive...), st.Required...) {
			exempt[op] = true
		}
		for _, fields := range st.Artifacts {
			for _, ft := range fields {
				if ft == nil {
					continue
				}
				for _, op := range ft.Operations {
					feeds[op] = true
				}
			}
		}
	}
	var missing []string
	for _, st := range traces {
		for _, op := range st.Operations {
			if !feeds[op] && !exempt[op] {
				missing = addString(missing, op)
			}
		}
	}
	if len(missing) == 0 {
		return nil
	}
	return fmt.Errorf("no fault on %s changed or left out any field, so the map cannot say what they feed. "+
		"An operation whose answers change no value, such as the sign-in, belongs in Suite.Insensitive; "+
		"otherwise make the first scenario one where its answer decides a value", strings.Join(missing, ", "))
}

// Encode writes a map as a collector commits it: indented, with every list
// and key in order, and a final newline.
func Encode(m *Map) ([]byte, error) {
	m.sort()
	raw, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(raw, '\n'), nil
}

// Canonical decodes an encoded map and encodes it again in Encode's order,
// such as one written from a template whose values change how it sorts.
func Canonical(raw []byte) ([]byte, error) {
	var m Map
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	if m.Artifacts == nil {
		m.Artifacts = map[string]map[string]*Field{}
	}
	if m.Lines == nil {
		m.Lines = Lines{}
	}
	return Encode(&m)
}

// sort puts each field's lists in the order Build gives them.
func (m *Map) sort() {
	for _, fields := range m.Artifacts {
		for _, f := range fields {
			if f == nil {
				continue
			}
			sort.Strings(f.Operations)
			sort.SliceStable(f.Code, func(i, j int) bool { return lineLess(f.Code[i].Line, f.Code[j].Line) })
			sort.Slice(f.Gaps, func(i, j int) bool { return lineLess(f.Gaps[i], f.Gaps[j]) })
			slices.SortFunc(f.Copies, compareCopies)
		}
	}
}

// Diff describes how two maps differ, field by field, or returns "" when
// they hold the same fields with the same entries.
func Diff(old, current *Map) string {
	var added, removed, changed int
	for path, fields := range current.Artifacts {
		for pattern, f := range fields {
			was, ok := old.Artifacts[path][pattern]
			switch {
			case !ok:
				added++
			case !sameField(was, f):
				changed++
			}
		}
	}
	for path, fields := range old.Artifacts {
		for pattern := range fields {
			if _, ok := current.Artifacts[path][pattern]; !ok {
				removed++
			}
		}
	}
	linesChanged := !maps.Equal(old.Lines, current.Lines)
	if added+removed+changed == 0 && !linesChanged {
		return ""
	}
	var parts []string
	for _, p := range []struct {
		n    int
		what string
	}{{added, "added"}, {removed, "removed"}, {changed, "changed"}} {
		if p.n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s %s", p.n, plural(p.n, "field", "fields"), p.what))
		}
	}
	if linesChanged {
		parts = append(parts, "source lines changed")
	}
	return strings.Join(parts, ", ")
}

// Summary counts the map's fields, artifacts, and source lines, such as
// "12 fields in 1 artifact, 30 source lines".
func (m *Map) Summary() string {
	fields := 0
	for _, f := range m.Artifacts {
		fields += len(f)
	}
	count := func(n int, one, many string) string { return strconv.Itoa(n) + " " + plural(n, one, many) }
	return count(fields, "field", "fields") + " in " + count(len(m.Artifacts), "artifact", "artifacts") + ", " + count(len(m.Lines), "source line", "source lines")
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

func sameField(a, b *Field) bool {
	ra, _ := json.Marshal(a)
	rb, _ := json.Marshal(b)
	return bytes.Equal(ra, rb)
}
