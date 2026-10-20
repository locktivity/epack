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

// Check runs the population, nulls, rollups, and ratios checks on doc, the
// artifact at path as emitted at level, with gaps saying which values were
// left out on purpose. An unknown level counts as trust.
func Check(s *Schema, path string, doc any, gaps []Gap, level string) []Finding {
	w := &walker{schema: s, path: path, doc: doc, level: levelRank[level]}
	for _, g := range gaps {
		if g.Path == path {
			w.gaps = append(w.gaps, g.Pointer)
		}
	}
	w.walk(doc, s.rootView(), nil)
	rank := map[string]int{CheckPopulation: 0, CheckNulls: 1, CheckRollups: 2, CheckRatios: 3}
	sort.SliceStable(w.findings, func(i, j int) bool {
		return rank[w.findings[i].Check] < rank[w.findings[j].Check]
	})
	return w.findings
}

type walker struct {
	schema   *Schema
	path     string
	doc      any
	level    int
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
	if num, ok := w.reference(v, "x-epack-numerator", tokens); ok && hasDen {
		w.ratio(v, at, value, num, den)
	}
}

// Roundings x-epack-rounding names. Nearest rounds halves up.
const (
	roundFloor   = "floor"
	roundCeil    = "ceil"
	roundNearest = "nearest"
)

// ratio checks a value against its numerator and denominator, where all
// three are present and the denominator is above 0. A percentage must be
// 100 * numerator / denominator, rounded as x-epack-rounding says, or within
// 1 of it when the schema states no rounding. A boolean must be true exactly
// when the numerator equals the denominator, its count of "all of them".
// A numerator above its denominator is a finding either way.
func (w *walker) ratio(v view, at string, value any, num, den resolved) {
	n, okN := number(num.value)
	d, okD := number(den.value)
	if !num.found || !den.found || !okN || !okD || d <= 0 {
		return
	}
	if n > d {
		w.add(CheckRatios, at, fmt.Sprintf("numerator %s at %s is larger than denominator %s at %s", show(num.value), num.pointer, show(den.value), den.pointer))
		return
	}
	if all, ok := value.(bool); ok {
		if all != (n == d) {
			relation := "is not"
			if n == d {
				relation = "equals"
			}
			w.add(CheckRatios, at, fmt.Sprintf("value %t, but numerator %s at %s %s denominator %s at %s", all, show(num.value), num.pointer, relation, show(den.value), den.pointer))
		}
		return
	}
	got, ok := number(value)
	if !ok {
		return
	}
	exact := 100 * n / d
	rounding := v.text("x-epack-rounding")
	want, ok := expectedPercent(exact, rounding)
	if !ok {
		w.add(CheckRatios, at, fmt.Sprintf("x-epack-rounding %q is not floor, ceil, or nearest", rounding))
		return
	}
	if math.Abs(got-want.value) <= want.tolerance {
		return
	}
	message := fmt.Sprintf("value %s, but 100 * %s / %s is %s", show(value), show(num.value), show(den.value), strconv.FormatFloat(math.Round(exact*100)/100, 'f', -1, 64))
	if want.rule != "" {
		message += fmt.Sprintf(", %s to %s", want.rule, strconv.FormatFloat(want.value, 'f', -1, 64))
	}
	w.add(CheckRatios, at, message+fmt.Sprintf(" (numerator %s, denominator %s)", num.pointer, den.pointer))
}

// percent is the percentage a ratio check expects: a value, how far from it
// a percentage may sit, and the name of the rounding that gave it, if any.
type percent struct {
	value, tolerance float64
	rule             string
}

// expectedPercent returns the percentage x-epack-rounding asks for from the
// exact one: exact itself within 1 when there is no rounding, and exactly
// the rounded value otherwise. It reports false for a rounding it does not
// know.
func expectedPercent(exact float64, rounding string) (percent, bool) {
	switch rounding {
	case "":
		return percent{value: exact, tolerance: 1}, true
	case roundFloor:
		return percent{value: math.Floor(exact), rule: "rounded down"}, true
	case roundCeil:
		return percent{value: math.Ceil(exact), rule: "rounded up"}, true
	case roundNearest:
		return percent{value: math.Floor(exact + 0.5), rule: "rounded to nearest"}, true
	}
	return percent{}, false
}

// rollup recomputes a count or percentage from the rows it covers. It skips
// rollups taken at another time, rows or rollups a gap covers, rows that
// were cut short, which are those a "truncated" reference marks and those as
// long as their schema's maxItems, and rows or a where field the schema
// places above the level the artifact was emitted at, where they are absent.
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
	if !ok || w.covered(rowsAt) || w.covered(at) || w.truncated(spec, tokens, rowsAt, len(rows)) || w.aboveLevel(rowsAt, where) {
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

// aboveLevel reports whether the schema places the rows at rowsAt, or the
// field where names in each of them, above the walker's level with
// x-epack-level, on the value itself or on one that holds it.
func (w *walker) aboveLevel(rowsAt, where string) bool {
	rows, rank, ok := w.schema.levelAt(w.doc, rowsAt)
	if !ok {
		return false
	}
	if rank > w.level {
		return true
	}
	if where == "" || !strings.HasPrefix(where, "/") {
		return false
	}
	v := w.schema.item(rows, 0)
	rank = max(rank, levelOf(v))
	for _, token := range strings.Split(where[1:], "/") {
		token = unescape(token)
		if idx, err := strconv.Atoi(token); err == nil && idx >= 0 {
			v = append(w.schema.member(v, token), w.schema.item(v, idx)...)
		} else {
			v = w.schema.member(v, token)
		}
		rank = max(rank, levelOf(v))
	}
	return rank > w.level
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

// levelOf is the rank of the level a view names with x-epack-level, or 0.
func levelOf(v view) int {
	return levelRank[v.text("x-epack-level")]
}

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
