package outputcheck

import (
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"sort"
	"strconv"
	"strings"
)

// Check runs the population, nulls, and rollups checks on doc, the artifact
// at path, with gaps saying which values were left out on purpose.
func Check(s *Schema, path string, doc any, gaps []Gap) []Finding {
	w := &walker{schema: s, path: path, doc: doc}
	for _, g := range gaps {
		if g.Path == path {
			w.gaps = append(w.gaps, g.Pointer)
		}
	}
	w.walk(doc, s.rootView(), nil)
	rank := map[string]int{CheckPopulation: 0, CheckNulls: 1, CheckRollups: 2}
	sort.SliceStable(w.findings, func(i, j int) bool {
		return rank[w.findings[i].Check] < rank[w.findings[j].Check]
	})
	return w.findings
}

type walker struct {
	schema   *Schema
	path     string
	doc      any
	gaps     []string
	findings []Finding
}

func (w *walker) walk(node any, v view, tokens []string) {
	switch n := node.(type) {
	case map[string]any:
		for _, key := range sortedKeys(n) {
			w.child(n[key], w.schema.member(v, key), tokens, key)
		}
	case []any:
		for i, item := range n {
			w.child(item, w.schema.item(v, i), tokens, strconv.Itoa(i))
		}
	}
}

func (w *walker) child(value any, v view, parent []string, token string) {
	if len(v) == 0 {
		return
	}
	tokens := append(append(make([]string, 0, len(parent)+1), parent...), token)
	w.visit(value, v, tokens)
	w.walk(value, v, tokens)
}

func (w *walker) visit(value any, v view, tokens []string) {
	at := pointer(tokens)
	den, hasDen := w.reference(v, "x-epack-denominator", tokens)
	denZero := hasDen && den.found && isZero(den.value)
	if value == nil {
		if scalar(v.types()) && !w.covered(at) && v.text("x-epack-null") == "" && !denZero {
			w.add(CheckNulls, at, "null with no gap, no x-epack-null note, and no denominator of 0")
		}
		return
	}
	if denZero && !w.covered(den.pointer) {
		w.add(CheckPopulation, at, fmt.Sprintf("value %s, but its denominator %s is 0; a value over no population must be null", show(value), den.pointer))
	}
	if got, ok := number(value); ok {
		w.rollup(v, tokens, at, got, value)
	}
}

// rollup recomputes a count or percentage from the rows it covers. It skips
// rollups taken at another time, rows or rollups a gap covers, and rows that
// were cut short: those a "truncated" reference marks, and those as long as
// their schema's maxItems.
func (w *walker) rollup(v view, tokens []string, at string, got float64, value any) {
	raw, _ := v.keyword("x-epack-rollup")
	spec, ok := raw.(map[string]any)
	if !ok {
		return
	}
	rowsRef, _ := spec["rows"].(string)
	as := "count"
	if name, ok := spec["as"].(string); ok {
		as = name
	}
	if as != "count" && as != "pct" {
		return
	}
	where, _ := spec["where"].(string)
	equals, ok := spec["equals"]
	if !ok {
		equals = true
	}
	if asOf, ok := w.reference(v, "x-epack-as-of", tokens); ok && asOf.found && asOf.value != nil {
		return
	}
	rowsAt, ok := target(rowsRef, tokens)
	if !ok {
		return
	}
	found, _ := Resolve(w.doc, rowsAt)
	rows, ok := found.([]any)
	if !ok || w.covered(rowsAt) || w.covered(at) || w.truncated(spec, tokens, rowsAt, len(rows)) {
		return
	}
	matching := 0
	for _, row := range rows {
		if where == "" {
			matching++
			continue
		}
		if field, ok := Resolve(row, where); ok && jsonEqual(field, equals) {
			matching++
		}
	}
	rowsText := fmt.Sprintf("there are %d rows at %s", len(rows), rowsAt)
	if where != "" {
		rowsText = fmt.Sprintf("%d of the %d rows at %s have %s equal to %s", matching, len(rows), rowsAt, where, show(equals))
	}
	switch as {
	case "count":
		if got != float64(matching) {
			w.add(CheckRollups, at, fmt.Sprintf("value %s, but %s", show(value), rowsText))
		}
	case "pct":
		if len(rows) == 0 {
			return
		}
		want := 100 * float64(matching) / float64(len(rows))
		if math.Abs(got-want) > 1 {
			w.add(CheckRollups, at, fmt.Sprintf("value %s, but %s, which is %s", show(value), rowsText, strconv.FormatFloat(math.Round(want*100)/100, 'f', -1, 64)))
		}
	}
}

// truncated reports whether the rows at rowsAt, n of them, stop short of all
// there are: the rollup's "truncated" reference resolves to true, or the
// rows' schema caps them at n with maxItems.
func (w *walker) truncated(spec map[string]any, tokens []string, rowsAt string, n int) bool {
	if ref, ok := spec["truncated"].(string); ok {
		if flagAt, ok := target(ref, tokens); ok {
			flag, _ := Resolve(w.doc, flagAt)
			if cut, _ := flag.(bool); cut {
				return true
			}
		}
	}
	limit, ok := w.schema.viewAt(w.doc, rowsAt).keyword("maxItems")
	if !ok {
		return false
	}
	maxItems, ok := number(limit)
	return ok && maxItems == float64(n)
}

type resolved struct {
	pointer string
	value   any
	found   bool
}

// reference resolves the reference an annotation holds, from the value at
// tokens. It reports false when the annotation is absent or unusable.
func (w *walker) reference(v view, keyword string, tokens []string) (resolved, bool) {
	ref := v.text(keyword)
	at, ok := target(ref, tokens)
	if !ok {
		return resolved{}, false
	}
	value, found := Resolve(w.doc, at)
	return resolved{pointer: at, value: value, found: found}, true
}

// covered reports whether a gap sits at at or at one of its ancestors.
func (w *walker) covered(at string) bool {
	for _, g := range w.gaps {
		if g == "" || at == g || strings.HasPrefix(at, g+"/") {
			return true
		}
	}
	return false
}

func (w *walker) add(check, at, message string) {
	w.findings = append(w.findings, Finding{Check: check, Path: w.path, Pointer: at, Message: message})
}

var levelRank = map[string]int{"trust": 0, "audit": 1, "internal": 2}

var levelNames = []string{"trust", "audit", "internal"}

// AboveLevel reports each value in doc, the artifact at path as emitted at
// level, that its schema places at a higher level with x-epack-level. A value
// takes the highest level named on it or on any ancestor. Values inside one
// already reported are not reported again.
func AboveLevel(s *Schema, path string, doc any, level string) []Finding {
	ran := levelRank[level]
	var out []Finding
	var walk func(node any, v view, tokens []string, inherited int)
	visit := func(node any, v view, tokens []string, inherited int) {
		at := inherited
		if r, ok := levelRank[v.text("x-epack-level")]; ok && r > at {
			at = r
		}
		if at > ran {
			out = append(out, Finding{Check: CheckLevels, Path: path, Pointer: pointer(tokens), Message: fmt.Sprintf("present at %s, but its schema marks it %s", level, levelNames[at])})
			return
		}
		if len(v) > 0 {
			walk(node, v, tokens, at)
		}
	}
	walk = func(node any, v view, tokens []string, inherited int) {
		switch n := node.(type) {
		case map[string]any:
			for _, key := range sortedKeys(n) {
				visit(n[key], s.member(v, key), append(append([]string(nil), tokens...), key), inherited)
			}
		case []any:
			for i, item := range n {
				visit(item, s.item(v, i), append(append([]string(nil), tokens...), strconv.Itoa(i)), inherited)
			}
		}
	}
	visit(doc, s.rootView(), nil, 0)
	return out
}

// scalar reports whether the only types besides null are number, integer,
// and boolean.
func scalar(types []string) bool {
	if len(types) == 0 {
		return false
	}
	for _, t := range types {
		if t != "number" && t != "integer" && t != "boolean" {
			return false
		}
	}
	return true
}

func number(v any) (float64, bool) {
	switch n := v.(type) {
	case json.Number:
		f, err := n.Float64()
		return f, err == nil
	case float64:
		return n, true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	}
	return 0, false
}

func isZero(v any) bool {
	n, ok := number(v)
	return ok && n == 0
}

func jsonEqual(a, b any) bool {
	if x, ok := number(a); ok {
		y, ok := number(b)
		return ok && x == y
	}
	return reflect.DeepEqual(a, b)
}

func show(v any) string {
	raw, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprint(v)
	}
	return string(raw)
}
