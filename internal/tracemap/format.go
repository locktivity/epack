// Package tracemap builds a collector's trace map, which links each field of
// its artifacts to the operations whose failure leaves the field out or
// changes it, to the source lines behind it, and to the lines that record
// its gaps. The collectortest kit exports what its fault matrix finds for
// each suite, and Build merges the suites and adds what static analysis of
// the collector's source finds. A collector commits the map, embeds it in
// its binary, and the SDK writes it into the build file in every pack.
package tracemap

import (
	"bytes"
	"cmp"
	"encoding/json"
	"slices"
	"sort"
	"strconv"
	"strings"
)

// Env names the directory a collectortest suite writes its SuiteTrace
// under, as `epack sdk map` sets it.
const Env = "COLLECTORTEST_MAP"

// SuiteTrace is what one collectortest suite's runs found.
type SuiteTrace struct {
	Suite string `json:"suite"`
	// Operations lists the operations the suite declares in
	// Suite.Operations, or those its clean scenario called when it
	// declares none.
	Operations []string `json:"operations"`
	// Insensitive lists the operations the suite marks as changing no
	// value, such as the sign-in.
	Insensitive []string `json:"insensitive,omitempty"`
	// Required lists the operations whose failure may fail the whole run.
	// Their faults fail it, so the fault matrix cannot say what they feed.
	Required []string `json:"required,omitempty"`
	// Artifacts holds every field the suite's runs emitted, by artifact path
	// and pointer pattern.
	Artifacts map[string]map[string]*FieldTrace `json:"artifacts"`
	// Schemas holds the schema ID of each artifact the clean run emitted
	// with one, by path, for finding the code that emits an artifact whose
	// path is not a constant.
	Schemas map[string]string `json:"schemas,omitempty"`
}

// FieldTrace is what a suite's runs found for one field.
type FieldTrace struct {
	// Operations lists the operations whose faults left the field out or
	// changed it.
	Operations []string `json:"operations,omitempty"`
	// Gaps lists the source lines that recorded a gap covering the field.
	Gaps []string `json:"gaps,omitempty"`
	// Copies lists the fields a normalized field copies.
	Copies []Copy `json:"copies,omitempty"`
}

// Copy names a field another copies, by artifact path and pointer pattern.
type Copy struct {
	Path    string `json:"path"`
	Pointer string `json:"pointer"`
}

// Map is a trace map, the trace_map of evidencepack/collector-build@v1.
type Map struct {
	// Artifacts holds each field, by artifact path and then by pointer
	// pattern, with each array index written as *.
	Artifacts map[string]map[string]*Field `json:"artifacts"`
	// Lines holds the text of every line the fields name.
	Lines Lines `json:"lines"`
}

// Field is one field of a trace map.
type Field struct {
	Operations []string   `json:"operations,omitempty"`
	Code       []CodeLine `json:"code,omitempty"`
	Gaps       []string   `json:"gaps,omitempty"`
	Copies     []Copy     `json:"copies,omitempty"`
}

// CodeLine is one source line behind a field, named as file:line relative to
// the module root. A helper's End is the last line of its function.
type CodeLine struct {
	Role string `json:"role"`
	Line string `json:"line"`
	End  int    `json:"end,omitempty"`
}

// Code line roles, in the order a field lists lines with the same position.
const (
	RoleAssign    = "assign"
	RoleHelper    = "helper"
	RoleInput     = "input"
	RoleCondition = "condition"
)

// Lines maps file:line to the line's text. It encodes in file order and then
// line order, so a committed map's diff stays near the code that moved.
type Lines map[string]string

// MarshalJSON writes the lines in file and line order.
func (l Lines) MarshalJSON() ([]byte, error) {
	keys := make([]string, 0, len(l))
	for k := range l {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return lineLess(keys[i], keys[j]) })
	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			buf.WriteByte(',')
		}
		key, err := json.Marshal(k)
		if err != nil {
			return nil, err
		}
		value, err := json.Marshal(l[k])
		if err != nil {
			return nil, err
		}
		buf.Write(key)
		buf.WriteByte(':')
		buf.Write(value)
	}
	buf.WriteByte('}')
	return buf.Bytes(), nil
}

// SplitLine splits file:line. It reports false for anything else.
func SplitLine(ref string) (string, int, bool) {
	i := strings.LastIndexByte(ref, ':')
	if i <= 0 {
		return "", 0, false
	}
	n, err := strconv.Atoi(ref[i+1:])
	if err != nil || n < 1 {
		return "", 0, false
	}
	return ref[:i], n, true
}

// LineRef joins a file and a line as file:line.
func LineRef(file string, line int) string {
	return file + ":" + strconv.Itoa(line)
}

// lineLess orders file:line references by file, then by line number.
func lineLess(a, b string) bool {
	fa, la, okA := SplitLine(a)
	fb, lb, okB := SplitLine(b)
	if !okA || !okB || fa != fb {
		return a < b
	}
	return la < lb
}

// Pattern returns pointer with each token that indexes an array written as
// *, the form a trace map keys fields by. It walks the first of docs that
// holds every container on the pointer's path, and failing that writes
// every all-digit token as *.
func Pattern(pointer string, docs ...any) string {
	if pointer == "" {
		return ""
	}
	tokens := strings.Split(pointer[1:], "/")
	for _, doc := range docs {
		if out, ok := walkPattern(doc, tokens); ok {
			return out
		}
	}
	for i, t := range tokens {
		if allDigits(t) {
			tokens[i] = "*"
		}
	}
	return "/" + strings.Join(tokens, "/")
}

func walkPattern(doc any, tokens []string) (string, bool) {
	out := make([]string, len(tokens))
	cur := doc
	for i, t := range tokens {
		switch node := cur.(type) {
		case map[string]any:
			out[i] = t
			cur = node[unescapeToken(t)]
		case []any:
			idx, err := strconv.Atoi(t)
			if err != nil || idx < 0 {
				return "", false
			}
			out[i] = "*"
			if idx < len(node) {
				cur = node[idx]
			} else {
				cur = nil
			}
		default:
			return "", false
		}
	}
	return "/" + strings.Join(out, "/"), true
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// Covers reports whether the field at pattern is the one at prefix or
// inside it, where both are patterns or both are pointers.
func Covers(prefix, pattern string) bool {
	return prefix == "" || pattern == prefix || strings.HasPrefix(pattern, prefix+"/")
}

// addString adds s to a sorted list of distinct strings.
func addString(list []string, s string) []string {
	i := sort.SearchStrings(list, s)
	if i < len(list) && list[i] == s {
		return list
	}
	list = append(list, "")
	copy(list[i+1:], list[i:])
	list[i] = s
	return list
}

// AddOperation adds op to the field's operations, kept sorted.
func (f *FieldTrace) AddOperation(op string) { f.Operations = addString(f.Operations, op) }

// AddGap adds a gap's source line to the field, kept sorted.
func (f *FieldTrace) AddGap(line string) { f.Gaps = addString(f.Gaps, line) }

// AddCopy adds a copied field, kept sorted.
func (f *FieldTrace) AddCopy(c Copy) { f.Copies = addCopy(f.Copies, c) }

// addCopy adds c to a sorted list of distinct copies.
func addCopy(list []Copy, c Copy) []Copy {
	if slices.Contains(list, c) {
		return list
	}
	list = append(list, c)
	slices.SortFunc(list, compareCopies)
	return list
}

// compareCopies orders copies by artifact path, then by pointer.
func compareCopies(a, b Copy) int {
	return cmp.Or(cmp.Compare(a.Path, b.Path), cmp.Compare(a.Pointer, b.Pointer))
}
