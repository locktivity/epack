package roster

import (
	"fmt"
	"slices"
	"strings"
)

// Axis is one way a roster can vary, such as the methods an account has
// registered or the apps a sign-in policy covers. Its first value is the
// base roster's own setting.
type Axis struct {
	Name   string
	Values []Value
}

// Value is one setting of an axis, as a change to a roster. A nil Change
// leaves the roster as it is.
type Value struct {
	Name   string
	Change func(*Roster)
}

// Row picks one value of each axis, by index.
type Row []int

// Choices names the values a row picks other than each axis's first, as
// axis=value.
func (row Row) Choices(axes []Axis) []string {
	var out []string
	for i, v := range row {
		if v != 0 {
			out = append(out, axes[i].Name+"="+axes[i].Values[v].Name)
		}
	}
	return out
}

// Variant is a base roster with one row's changes made.
type Variant struct {
	Row Row
	// Name lists the row's choices, or is "base" for a row of first values.
	Name   string
	Roster *Roster
}

// Build makes the variant of base that row picks. The changes run in axis
// order on a clone of base, and the result must validate.
func Build(base *Roster, axes []Axis, row Row) (Variant, error) {
	r := base.Clone()
	for i, v := range row {
		if change := axes[i].Values[v].Change; change != nil {
			change(r)
		}
	}
	name := strings.Join(row.Choices(axes), ",")
	if name == "" {
		name = "base"
	}
	if err := r.Validate(); err != nil {
		return Variant{}, fmt.Errorf("%s: %w", name, err)
	}
	return Variant{Row: row, Name: name, Roster: r}, nil
}

// OneAtATime returns the row of first values, then a row for each other
// value of each axis with every other axis at its first value. A difference
// such a row shows belongs to its one value.
func OneAtATime(axes []Axis) []Row {
	rows := []Row{make(Row, len(axes))}
	for i, axis := range axes {
		for v := 1; v < len(axis.Values); v++ {
			row := make(Row, len(axes))
			row[i] = v
			rows = append(rows, row)
		}
	}
	return rows
}

// Pairwise returns rows in which every value of each axis appears beside
// every value of each other axis at least once, so a difference that needs
// two settings together shows in some row. It builds each row greedily from
// the first pair no row has yet, and gives the same rows every time.
func Pairwise(axes []Axis) []Row {
	type pair struct{ i, a, j, b int }
	key := func(i, a, j, b int) pair {
		if i > j {
			return pair{j, b, i, a}
		}
		return pair{i, a, j, b}
	}
	var order []pair
	covered := map[pair]bool{}
	for i := range axes {
		for j := i + 1; j < len(axes); j++ {
			for a := range axes[i].Values {
				for b := range axes[j].Values {
					order = append(order, pair{i, a, j, b})
				}
			}
		}
	}
	var rows []Row
	for _, seed := range order {
		if covered[seed] {
			continue
		}
		row := make(Row, len(axes))
		for k := range row {
			row[k] = -1
		}
		row[seed.i], row[seed.j] = seed.a, seed.b
		for k := range axes {
			if row[k] >= 0 {
				continue
			}
			best, bestGain := 0, -1
			for v := range axes[k].Values {
				gain := 0
				for m, w := range row {
					if m != k && w >= 0 && !covered[key(k, v, m, w)] {
						gain++
					}
				}
				if gain > bestGain {
					best, bestGain = v, gain
				}
			}
			row[k] = best
		}
		for i := range row {
			for j := i + 1; j < len(row); j++ {
				covered[pair{i, row[i], j, row[j]}] = true
			}
		}
		rows = append(rows, row)
	}
	return rows
}

// Unexplained returns the pointers in differs that none of row's choices
// accounts for alone. alone maps each choice, as axis=value, to the pointers
// its one-at-a-time row differs on. A pointer it returns differs only when
// two or more of the row's settings meet.
func Unexplained(axes []Axis, row Row, differs []string, alone map[string][]string) []string {
	var out []string
	for _, pointer := range differs {
		if !slices.ContainsFunc(row.Choices(axes), func(choice string) bool { return slices.Contains(alone[choice], pointer) }) {
			out = append(out, pointer)
		}
	}
	return out
}
