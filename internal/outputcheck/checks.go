package outputcheck

import (
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"github.com/locktivity/epack/internal/componenttypes"
	"github.com/locktivity/epack/internal/jsonpointer"
)

// Check runs the population, nulls, rollups, and ratios checks on doc, the
// artifact at path as emitted at level, with gaps saying which values were
// left out on purpose. An unknown level counts as trust.
func Check(s *Schema, path string, doc any, gaps []Gap, level string) []Finding {
	w := &walker{schema: s, path: path, doc: doc, level: rankOf(level)}
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
		for _, key := range declared(v) {
			if _, ok := n[key]; !ok {
				w.absent(w.schema.member(v, key), append(append(make([]string, 0, len(tokens)+1), tokens...), key))
			}
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
	at := jsonpointer.Format(tokens)
	pop := w.population(v, tokens)
	if value == nil {
		if scalar(v.types()) && !w.covered(at) && v.text("x-epack-null") == "" && !pop.explainsNull() {
			w.add(CheckNulls, at, "null with no gap, no x-epack-null note, no denominator of 0 or unread, and no x-epack-present of false or unread")
		}
		return
	}
	for _, reason := range w.emptyReasons(pop) {
		w.add(CheckPopulation, at, fmt.Sprintf("value %s, but %s. A value over no population must be null", show(value), reason))
	}
	if pop.unread != "" && !w.covered(at) {
		w.add(CheckPopulation, at, fmt.Sprintf("value %s, but %s was not read. A value over a population that was not read must be left out too", show(value), pop.unread))
	}
	if got, ok := number(value); ok {
		w.rollup(v, tokens, at, got, value)
	}
	if num, ok := w.reference(v, "x-epack-numerator", tokens); ok && pop.hasDen {
		w.ratio(v, at, value, num, pop.den)
	}
}

// absent checks a value left out of its object. The value must be written as
// null when the artifact shows its population is empty, with a denominator
// of 0 or an x-epack-present of false. A value left out looks like one the
// collector could not read. absent skips a value a gap covers, since it was
// not read. It also skips a value the schema places above the level, since
// the level leaves it out.
func (w *walker) absent(v view, tokens []string) {
	if len(v) == 0 || !scalar(v.types()) {
		return
	}
	at := jsonpointer.Format(tokens)
	if w.covered(at) || levelOf(v) > w.level {
		return
	}
	if reasons := w.emptyReasons(w.population(v, tokens)); len(reasons) > 0 {
		w.add(CheckPopulation, at, fmt.Sprintf("left out, but %s. Write null for a value over no population. A value left out looks like one the collector could not read", reasons[0]))
	}
}

// population describes what a value counts. It holds the denominator and
// present flag that the value's annotations point to, with their values in
// the artifact.
type population struct {
	den, present       resolved
	hasDen, hasPresent bool
	// zero is true when the denominator is 0, and none is true when the
	// present flag is false. Either makes the population empty.
	zero, none bool
	// unread is the pointer of the denominator or present flag that was not
	// read, or "".
	unread string
}

func (w *walker) population(v view, tokens []string) population {
	var p population
	p.den, p.hasDen = w.reference(v, "x-epack-denominator", tokens)
	p.present, p.hasPresent = w.reference(v, "x-epack-present", tokens)
	p.zero = p.hasDen && p.den.found && isZero(p.den.value)
	p.none = p.present.found && p.present.value == false
	switch {
	case p.hasDen && w.unread(p.den):
		p.unread = p.den.pointer
	case p.hasPresent && w.unread(p.present):
		p.unread = p.present.pointer
	}
	return p
}

// explainsNull reports whether the population explains a null value. It
// does when the population is empty or was not read.
func (p population) explainsNull() bool {
	return p.zero || p.none || p.unread != ""
}

// emptyReasons returns the reason for each reference that makes the
// population empty and that no gap covers.
func (w *walker) emptyReasons(p population) []string {
	var out []string
	if p.zero && !w.covered(p.den.pointer) {
		out = append(out, fmt.Sprintf("its denominator %s is 0", p.den.pointer))
	}
	if p.none && !w.covered(p.present.pointer) {
		out = append(out, fmt.Sprintf("its present flag %s is false", p.present.pointer))
	}
	return out
}

// declared returns the sorted names of the properties the schemas in v
// define.
func declared(v view) []string {
	seen := map[string]bool{}
	for _, obj := range v {
		if p, ok := obj["properties"].(map[string]any); ok {
			for name := range p {
				seen[name] = true
			}
		}
	}
	return sortedKeys(seen)
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
// long as their schema's maxItems, and rows or a condition's field the
// schema places above the level the artifact was emitted at, where they are
// absent.
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
	among, ok := rollupConditions(spec["among"])
	if !ok {
		return
	}
	var match []condition
	if where, ok := spec["where"].(string); ok && where != "" {
		equals, ok := spec["equals"]
		if !ok {
			equals = true
		}
		match = []condition{{where: where, value: equals}}
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
	if !ok || w.covered(rowsAt) || w.covered(at) || w.truncated(spec, tokens, rowsAt, len(rows)) || w.aboveLevel(rowsAt, append(among, match...)) {
		return
	}
	covered, matching := 0, 0
	for _, row := range rows {
		if !meets(row, among) {
			continue
		}
		covered++
		if meets(row, match) {
			matching++
		}
	}
	rowsText := fmt.Sprintf("there are %d rows at %s", len(rows), rowsAt)
	if len(among) > 0 {
		rowsText = fmt.Sprintf("%d of the %d rows at %s have %s", covered, len(rows), rowsAt, describe(among))
	}
	if len(match) > 0 {
		of := fmt.Sprintf("the %d rows at %s", len(rows), rowsAt)
		if len(among) > 0 {
			of = fmt.Sprintf("the %d rows at %s with %s", covered, rowsAt, describe(among))
		}
		rowsText = fmt.Sprintf("%d of %s have %s", matching, of, describe(match))
	}
	switch as {
	case "count":
		want := covered
		if len(match) > 0 {
			want = matching
		}
		if got != float64(want) {
			w.add(CheckRollups, at, fmt.Sprintf("value %s, but %s", show(value), rowsText))
		}
	case "pct":
		if covered == 0 {
			return
		}
		want := 100 * float64(matching) / float64(covered)
		if math.Abs(got-want) > 1 {
			w.add(CheckRollups, at, fmt.Sprintf("value %s, but %s, which is %s", show(value), rowsText, strconv.FormatFloat(math.Round(want*100)/100, 'f', -1, 64)))
		}
	}
}

// condition is one test a rollup puts to each row: the field at where, a
// pointer within the row, equals value, or with not set, differs from it.
type condition struct {
	where string
	value any
	not   bool
}

// rollupConditions reads a rollup's "among" list. Each entry names a field
// with "where" and gives "equals" or "not_equals", with equals true by
// default. It reports false for a list it cannot read, so the rollup is
// skipped rather than checked against the wrong rows.
func rollupConditions(raw any) ([]condition, bool) {
	if raw == nil {
		return nil, true
	}
	list, ok := raw.([]any)
	if !ok {
		return nil, false
	}
	out := make([]condition, 0, len(list))
	for _, entry := range list {
		obj, ok := entry.(map[string]any)
		where, _ := obj["where"].(string)
		if !ok || where == "" {
			return nil, false
		}
		c := condition{where: where, value: true}
		if v, ok := obj["equals"]; ok {
			c.value = v
		}
		if v, ok := obj["not_equals"]; ok {
			c.value, c.not = v, true
		}
		out = append(out, c)
	}
	return out, true
}

// meets reports whether row passes every condition. A row without the field
// fails an equals condition and passes a not_equals one.
func meets(row any, conditions []condition) bool {
	for _, c := range conditions {
		field, ok := Resolve(row, c.where)
		if (ok && jsonEqual(field, c.value)) == c.not {
			return false
		}
	}
	return true
}

// describe names conditions in a finding, such as "/status equal to
// "ACTIVE" and /sso equal to true".
func describe(conditions []condition) string {
	parts := make([]string, len(conditions))
	for i, c := range conditions {
		relation := "equal to"
		if c.not {
			relation = "other than"
		}
		parts[i] = fmt.Sprintf("%s %s %s", c.where, relation, show(c.value))
	}
	return strings.Join(parts, " and ")
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

// aboveLevel reports whether the schema places the rows at rowsAt, or a
// field a condition names in each of them, above the walker's level with
// x-epack-level, on the value itself or on one that holds it.
func (w *walker) aboveLevel(rowsAt string, conditions []condition) bool {
	rows, rank, ok := w.schema.levelAt(w.doc, rowsAt)
	if !ok {
		return false
	}
	if rank > w.level {
		return true
	}
	for _, c := range conditions {
		if !strings.HasPrefix(c.where, "/") {
			continue
		}
		v := w.schema.item(rows, 0)
		fieldRank := max(rank, levelOf(v))
		for _, token := range jsonpointer.Tokens(c.where) {
			if idx, err := strconv.Atoi(token); err == nil && idx >= 0 {
				v = append(w.schema.member(v, token), w.schema.item(v, idx)...)
			} else {
				v = w.schema.member(v, token)
			}
			fieldRank = max(fieldRank, levelOf(v))
		}
		if fieldRank > w.level {
			return true
		}
	}
	return false
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

// unread reports whether a population reference was not read. That is the
// case when it is null, or when it is absent and a gap covers it. A
// reference absent with no gap was left out on purpose, such as a count the
// level leaves out. unread returns false for it.
func (w *walker) unread(r resolved) bool {
	if r.found {
		return r.value == nil
	}
	return w.covered(r.pointer)
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

// rankOf is the rank of a level, or 0 for a string that names none.
func rankOf(level string) int {
	rank, _ := componenttypes.Level(level).Rank()
	return rank
}

// levelOf is the rank of the level a view names with x-epack-level, or 0.
func levelOf(v view) int {
	return rankOf(v.text("x-epack-level"))
}

// WholeAbove reports whether s sets x-epack-level at its root, on the whole
// artifact, to a level above level.
func WholeAbove(s *Schema, level string) bool {
	whole := s.rootView().text("x-epack-level")
	return whole != "" && !componenttypes.Level(level).AtLeast(componenttypes.Level(whole))
}

// AboveLevel reports each value in doc, the artifact at path as emitted at
// level, that its schema places at a higher level with x-epack-level. A value
// takes the highest level named on it or on any ancestor. Values inside one
// already reported are not reported again.
func AboveLevel(s *Schema, path string, doc any, level string) []Finding {
	ran := rankOf(level)
	var out []Finding
	var walk func(node any, v view, tokens []string, inherited int)
	visit := func(node any, v view, tokens []string, inherited int) {
		at := inherited
		if r, ok := componenttypes.Level(v.text("x-epack-level")).Rank(); ok && r > at {
			at = r
		}
		if at > ran {
			out = append(out, Finding{Check: CheckLevels, Path: path, Pointer: jsonpointer.Format(tokens), Message: fmt.Sprintf("present at %s, but its schema marks it %s", level, componenttypes.LevelAt(at))})
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
