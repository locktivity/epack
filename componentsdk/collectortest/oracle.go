package collectortest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"

	"github.com/locktivity/epack/componentsdk"
	"github.com/locktivity/epack/componentsdk/internal/outputcheck"
)

// emptyObject and emptyArray stand in for empty containers, which are leaves
// of a flattened document.
var (
	emptyObject = struct{ emptyObject bool }{true}
	emptyArray  = struct{ emptyArray bool }{true}
)

// flatten maps every leaf of a JSON document to its pointer.
func flatten(raw json.RawMessage) (map[string]any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var doc any
	if err := dec.Decode(&doc); err != nil {
		return nil, err
	}
	out := map[string]any{}
	var walk func(pointer string, v any)
	walk = func(pointer string, v any) {
		switch node := v.(type) {
		case map[string]any:
			if len(node) == 0 {
				out[pointer] = emptyObject
				return
			}
			for k, child := range node {
				walk(pointer+"/"+escapeToken(k), child)
			}
		case []any:
			if len(node) == 0 {
				out[pointer] = emptyArray
				return
			}
			for i, child := range node {
				walk(fmt.Sprintf("%s/%d", pointer, i), child)
			}
		default:
			out[pointer] = node
		}
	}
	walk("", doc)
	return out, nil
}

func escapeToken(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "~", "~0"), "/", "~1")
}

// artifactsByPath indexes data artifacts by path, leaving out the result
// artifact.
func artifactsByPath(artifacts []componentsdk.EmittedArtifact) map[string]componentsdk.EmittedArtifact {
	out := map[string]componentsdk.EmittedArtifact{}
	for _, a := range artifacts {
		if a.Schema == componentsdk.ResultSchema || a.File != "" {
			continue
		}
		out[a.Path] = a
	}
	return out
}

// filesByPath indexes file artifacts by path.
func filesByPath(artifacts []componentsdk.EmittedArtifact) map[string]componentsdk.EmittedArtifact {
	out := map[string]componentsdk.EmittedArtifact{}
	for _, a := range artifacts {
		if a.File != "" {
			out[a.Path] = a
		}
	}
	return out
}

func covered(gaps []componentsdk.Gap, path, pointer string) bool {
	for _, g := range gaps {
		if g.Path != path {
			continue
		}
		if g.Pointer == "" || pointer == g.Pointer || strings.HasPrefix(pointer, g.Pointer+"/") {
			return true
		}
	}
	return false
}

// ignoreSet holds Suite.Ignore's pointer prefixes by artifact path. A lookup
// walks the pointer's ancestors, so its cost follows the pointer's depth
// rather than the number of prefixes.
type ignoreSet map[string]map[string]bool

func newIgnoreSet(ignore map[string][]string) ignoreSet {
	out := ignoreSet{}
	for path, prefixes := range ignore {
		set := map[string]bool{}
		for _, p := range prefixes {
			set[p] = true
		}
		out[path] = set
	}
	return out
}

func (s ignoreSet) has(path, pointer string) bool {
	prefixes := s[path]
	if len(prefixes) == 0 {
		return false
	}
	for p := pointer; ; {
		if prefixes[p] {
			return true
		}
		i := strings.LastIndexByte(p, '/')
		if i < 0 {
			return false
		}
		p = p[:i]
	}
}

// compareRuns applies the outcome rule to a faulted run: every value keeps
// its clean value, or is absent or null with a gap that covers it. Nothing
// may change to a different value or appear, except under a gap, which can
// be a partial gap at a list emitted with the items that were read. A file
// artifact's bytes are one value, compared by digest.
func compareRuns(clean, faulted []componentsdk.EmittedArtifact, gaps []componentsdk.Gap, ignore ignoreSet) []string {
	var problems []string
	cleanByPath := artifactsByPath(clean)
	faultedByPath := artifactsByPath(faulted)
	paths := make([]string, 0, len(cleanByPath))
	for p := range cleanByPath {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, path := range paths {
		cleanLeaves, err := flatten(cleanByPath[path].Data)
		if err != nil {
			problems = append(problems, fmt.Sprintf("%s: clean artifact is not JSON: %v", path, err))
			continue
		}
		fa, ok := faultedByPath[path]
		if !ok {
			if !covered(gaps, path, "") {
				problems = append(problems, fmt.Sprintf("%s: artifact left out without a gap for the whole artifact", path))
			}
			continue
		}
		faultedLeaves, err := flatten(fa.Data)
		if err != nil {
			problems = append(problems, fmt.Sprintf("%s: artifact is not JSON: %v", path, err))
			continue
		}
		problems = append(problems, compareLeaves(path, cleanLeaves, faultedLeaves, gaps, ignore)...)
	}
	for path := range faultedByPath {
		if _, ok := cleanByPath[path]; !ok {
			problems = append(problems, fmt.Sprintf("%s: artifact appeared only under the fault", path))
		}
	}
	return append(problems, compareFiles(filesByPath(clean), filesByPath(faulted), gaps, ignore)...)
}

// compareFiles applies the outcome rule to file artifacts: each keeps its
// clean bytes, or is left out or changed under a gap for the whole artifact.
func compareFiles(clean, faulted map[string]componentsdk.EmittedArtifact, gaps []componentsdk.Gap, ignore ignoreSet) []string {
	var problems []string
	for _, path := range sortedKeys(clean) {
		want := clean[path]
		got, ok := faulted[path]
		switch {
		case ignore.has(path, "") || covered(gaps, path, ""):
		case !ok:
			problems = append(problems, fmt.Sprintf("%s: file artifact left out without a gap for the whole artifact", path))
		case got.SHA256 != want.SHA256 || got.Size != want.Size:
			problems = append(problems, fmt.Sprintf("%s: file changed from %s to %s", path, describeFile(want), describeFile(got)))
		}
	}
	for _, path := range sortedKeys(faulted) {
		if _, ok := clean[path]; !ok && !ignore.has(path, "") {
			problems = append(problems, fmt.Sprintf("%s: artifact appeared only under the fault", path))
		}
	}
	return problems
}

// describeFile names a file artifact's bytes by size and digest prefix.
func describeFile(a componentsdk.EmittedArtifact) string {
	if a.SHA256 == "" {
		return "unreadable bytes"
	}
	return fmt.Sprintf("%d bytes with sha256 %s", a.Size, a.SHA256[:12])
}

func compareLeaves(path string, clean, faulted map[string]any, gaps []componentsdk.Gap, ignore ignoreSet) []string {
	var problems []string
	pointers := make([]string, 0, len(clean))
	for p := range clean {
		pointers = append(pointers, p)
	}
	sort.Strings(pointers)
	for _, p := range pointers {
		if ignore.has(path, p) {
			continue
		}
		want := clean[p]
		got, present := faulted[p]
		switch {
		case present && reflect.DeepEqual(got, want):
		case (!present || got == nil) && want == nil:
		case covered(gaps, path, p):
		case !present || got == nil:
			problems = append(problems, fmt.Sprintf("%s %s: value %s left out without a gap", path, pointerLabel(p), show(want)))
		default:
			problems = append(problems, fmt.Sprintf("%s %s: value changed from %s to %s", path, pointerLabel(p), show(want), show(got)))
		}
	}
	extra := make([]string, 0)
	for p, v := range faulted {
		if _, ok := clean[p]; ok || v == nil || ignore.has(path, p) || covered(gaps, path, p) || emptied(clean, p, v) {
			continue
		}
		extra = append(extra, p)
	}
	sort.Strings(extra)
	for _, p := range extra {
		problems = append(problems, fmt.Sprintf("%s %s: value %s appeared under the fault", path, pointerLabel(p), show(faulted[p])))
	}
	return problems
}

// emptied reports whether v, the faulted run's value at p, is an empty
// object or array that held members in the clean run. It did not appear:
// the members' own comparisons say whether gaps cover their absence.
func emptied(clean map[string]any, p string, v any) bool {
	if v != emptyObject && v != emptyArray {
		return false
	}
	for q := range clean {
		if strings.HasPrefix(q, p+"/") {
			return true
		}
	}
	return false
}

func pointerLabel(p string) string {
	if p == "" {
		return "/"
	}
	return p
}

func show(v any) string {
	switch v {
	case emptyObject:
		return "{}"
	case emptyArray:
		return "[]"
	case nil:
		return "null"
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprint(v)
	}
	return string(raw)
}

// Absent pins a value as absent in Scenario.Expect or Semantic.Expect: not
// even null. A pinned nil matches null and absent alike.
var Absent = absentValue{}

type absentValue struct{}

// pinned compares the values expect pins, by artifact path and JSON pointer,
// with the values the artifacts hold, as JSON. A pinned null also matches an
// absent value, and Absent matches only an absent one. It returns one
// problem per value that differs.
func pinned(artifacts []componentsdk.EmittedArtifact, expect map[string]map[string]any) []string {
	var problems []string
	for _, path := range sortedKeys(expect) {
		var art *componentsdk.EmittedArtifact
		for i := range artifacts {
			if artifacts[i].Path == path && artifacts[i].File == "" {
				art = &artifacts[i]
			}
		}
		if art == nil {
			problems = append(problems, fmt.Sprintf("artifact %s was not emitted", path))
			continue
		}
		doc, err := outputcheck.Decode(art.Data)
		if err != nil {
			problems = append(problems, fmt.Sprintf("%s: %v", path, err))
			continue
		}
		for _, pointer := range sortedKeys(expect[path]) {
			value, found := outputcheck.Resolve(doc, pointer)
			if _, absent := expect[path][pointer].(absentValue); absent {
				if found {
					got, _ := json.Marshal(value)
					problems = append(problems, fmt.Sprintf("%s %s is %s, want it absent", path, pointerLabel(pointer), got))
				}
				continue
			}
			want, err := json.Marshal(expect[path][pointer])
			if err != nil {
				problems = append(problems, fmt.Sprintf("%s %s: the pinned value is not JSON: %v", path, pointerLabel(pointer), err))
				continue
			}
			if !found {
				if string(want) != "null" {
					problems = append(problems, fmt.Sprintf("%s %s is absent, want %s", path, pointerLabel(pointer), want))
				}
				continue
			}
			if got, _ := json.Marshal(value); string(got) != string(want) {
				problems = append(problems, fmt.Sprintf("%s %s is %s, want %s", path, pointerLabel(pointer), got, want))
			}
		}
	}
	return problems
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// newGaps returns the gaps in faulted that the clean run did not have.
func newGaps(clean, faulted *componentsdk.CollectorResult) []componentsdk.Gap {
	if faulted == nil {
		return nil
	}
	seen := map[string]bool{}
	if clean != nil {
		for _, g := range clean.Gaps {
			seen[g.Path+"\x00"+g.Pointer] = true
		}
	}
	var out []componentsdk.Gap
	for _, g := range faulted.Gaps {
		if !seen[g.Path+"\x00"+g.Pointer] {
			out = append(out, g)
		}
	}
	return out
}

func gapsOf(r *componentsdk.CollectorResult) []componentsdk.Gap {
	if r == nil {
		return nil
	}
	return r.Gaps
}
