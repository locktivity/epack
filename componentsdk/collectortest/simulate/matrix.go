package simulate

import (
	"fmt"
	"maps"
	"math/rand/v2"
	"slices"
	"strings"
	"testing"

	"github.com/locktivity/epack/componentsdk/collectortest/roster"
)

// Together lists differences that show only when settings meet. A row
// that picks every one of Settings, each as axis=value, may differ on its
// pointers. When Match is set, a row meets the rule when Match accepts the
// row's choices instead, for a difference that any of several values
// shows, such as any admin role together with one state.
type Together struct {
	Settings    []string
	Match       func(choices []string) bool
	Differences Differences
}

// Any reports whether choices pick one of settings, each as axis=value.
func Any(choices []string, settings ...string) bool {
	return slices.ContainsFunc(settings, func(s string) bool { return slices.Contains(choices, s) })
}

// Matrix varies base along axes. Each one-at-a-time row changes one
// setting, so a difference it shows belongs to that setting and must be in
// alone under the setting's axis=value. The pairwise rows put every two
// settings together at least once, and a difference that none of a row's
// settings shows alone must be in a Together rule the row meets.
func (h Harness) Matrix(t *testing.T, base *roster.Roster, axes []roster.Axis, alone map[string]Differences, together []Together) {
	log := newShapeLog()
	observed := map[string][]string{}
	for _, row := range roster.OneAtATime(axes) {
		v, err := roster.Build(base, axes, row)
		if err != nil {
			t.Fatal(err)
		}
		t.Run("alone/"+v.Name, func(t *testing.T) {
			differs, rows := h.differing(t, v.Roster, log)
			observed[v.Name] = differs
			listed := alone[v.Name]
			var table strings.Builder
			for _, pointer := range differs {
				mark := string(listed[pointer].Verdict)
				if _, ok := listed[pointer]; !ok {
					mark = "NEW"
					t.Errorf("%s: derived %s, collector %s", pointer, show(rows[pointer].Want, true), rows[pointer].GotString())
				}
				fmt.Fprintf(&table, "  %-62s %-10s %-34s %s\n", pointer, show(rows[pointer].Want, true), rows[pointer].GotString(), mark)
			}
			for _, pointer := range slices.Sorted(maps.Keys(listed)) {
				if !slices.Contains(differs, pointer) {
					t.Errorf("%s: listed as %s (%s), but the collector now reports the derived %s", pointer, listed[pointer].Verdict, listed[pointer].Note, show(rows[pointer].Want, true))
				}
			}
			if table.Len() > 0 {
				t.Logf("%s\n%s", v.Name, table.String())
			}
		})
	}
	for name := range alone {
		if _, ok := observed[name]; !ok {
			t.Errorf("alone lists %s, which is no one-at-a-time row", name)
		}
	}

	pairwise := roster.Pairwise(axes)
	explainedTogether := 0
	for i, row := range pairwise {
		v, err := roster.Build(base, axes, row)
		if err != nil {
			t.Fatal(err)
		}
		t.Run(fmt.Sprintf("together/%03d", i), func(t *testing.T) {
			differs, rows := h.differing(t, v.Roster, log)
			choices := row.Choices(axes)
			for _, pointer := range roster.Unexplained(axes, row, differs, observed) {
				if explains(together, choices, pointer) {
					explainedTogether++
					continue
				}
				t.Errorf("%s: derived %s, collector %s, with %s", pointer, show(rows[pointer].Want, true), rows[pointer].GotString(), v.Name)
			}
		})
	}
	t.Logf("%d one-at-a-time rows, %d pairwise rows, %d differences explained only together", len(roster.OneAtATime(axes)), len(pairwise), explainedTogether)
}

func explains(together []Together, choices []string, pointer string) bool {
	return slices.ContainsFunc(together, func(rule Together) bool {
		if _, listed := rule.Differences[pointer]; !listed {
			return false
		}
		if rule.Match != nil {
			return rule.Match(choices)
		}
		return !slices.ContainsFunc(rule.Settings, func(s string) bool { return !slices.Contains(choices, s) })
	})
}

// differing returns the pointers whose collector value differs from the
// derived one, less the standing differences, and the rows by pointer.
func (h Harness) differing(t *testing.T, r *roster.Roster, log *shapeLog) ([]string, map[string]Row) {
	var out []string
	byPointer := map[string]Row{}
	rows, _ := h.rows(t, r, log, false)
	for _, row := range rows {
		byPointer[row.Pointer] = row
		if stand, standing := h.Standing[row.Pointer]; (!standing || !stand.accounts(row)) && !row.Matches() {
			out = append(out, row.Pointer)
		}
	}
	return out, byPointer
}

// Rule is a property that holds whatever the right values are: a change to
// a roster that must leave some values as they are, or move them one way
// only. Change returns a page size to answer with, or 0 for the vendor's
// own. Check compares the outputs before and after, as Output gives them,
// and lists what broke.
type Rule struct {
	Name   string
	Change func(*roster.Roster, *rand.Rand) int
	Check  func(before, after map[string]any) []string
}

// Rules runs each rule on n random rosters built from axes. The seed is
// fixed, so a failure names a roster that can be built again.
func (h Harness) Rules(t *testing.T, base *roster.Roster, axes []roster.Axis, rules []Rule, n int, seed uint64) {
	log := newShapeLog()
	rng := rand.New(rand.NewPCG(seed, 1))
	for i := range n {
		row := make(roster.Row, len(axes))
		for j := range axes {
			row[j] = rng.IntN(len(axes[j].Values))
		}
		v, err := roster.Build(base, axes, row)
		if err != nil {
			t.Fatal(err)
		}
		t.Run(fmt.Sprintf("%02d", i), func(t *testing.T) {
			t.Logf("roster: %s", v.Name)
			before := h.output(t, v.Roster, 0, log)
			for _, rule := range rules {
				changed := v.Roster.Clone()
				pageSize := rule.Change(changed, rng)
				if err := changed.Validate(); err != nil {
					t.Fatalf("%s: %v", rule.Name, err)
				}
				for _, broken := range rule.Check(before, h.output(t, changed, pageSize, log)) {
					t.Errorf("%s: %s", rule.Name, broken)
				}
			}
		})
	}
}

// Unchanged lists the keys keep accepts whose values differ between two
// outputs, a value written in one and absent in the other included. A nil
// keep accepts every key.
func Unchanged(before, after map[string]any, keep func(string) bool) []string {
	keys := map[string]bool{}
	for k := range before {
		keys[k] = true
	}
	for k := range after {
		keys[k] = true
	}
	var out []string
	for _, key := range slices.Sorted(maps.Keys(keys)) {
		if keep != nil && !keep(key) {
			continue
		}
		b, inBefore := before[key]
		a, inAfter := after[key]
		if inBefore != inAfter || !sameJSON(b, a) {
			out = append(out, fmt.Sprintf("%s was %s and is %s", key, show(b, inBefore), show(a, inAfter)))
		}
	}
	return out
}

// NeverLower lists the keys whose numbers fell, or that were numbers and
// are no longer.
func NeverLower(before, after map[string]any, keys ...string) []string {
	return compareNumbers(before, after, keys, func(b, a float64) bool { return a < b }, "fell")
}

// NeverHigher lists the keys whose numbers rose, or that were numbers and
// are no longer.
func NeverHigher(before, after map[string]any, keys ...string) []string {
	return compareNumbers(before, after, keys, func(b, a float64) bool { return a > b }, "rose")
}

func compareNumbers(before, after map[string]any, keys []string, wrong func(b, a float64) bool, verb string) []string {
	var out []string
	for _, key := range keys {
		b, ok := before[key].(float64)
		if !ok {
			continue
		}
		v, written := after[key]
		a, ok := v.(float64)
		switch {
		case !ok:
			out = append(out, fmt.Sprintf("%s was %s and is %s", key, show(b, true), show(v, written)))
		case wrong(b, a):
			out = append(out, fmt.Sprintf("%s %s from %s to %s", key, verb, show(b, true), show(a, true)))
		}
	}
	return out
}
