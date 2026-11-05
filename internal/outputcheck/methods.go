package outputcheck

import (
	"fmt"
	"slices"
	"strconv"

	"github.com/locktivity/epack/internal/jsonpointer"
)

// Measured is a number or true-or-false value in a document, or a null whose
// schema allows one, with the annotations that say what it means.
type Measured struct {
	Pointer string
	Method  string
	Label   string
	Summary string
	// Goal is the value's x-epack-goal, and Rounding its x-epack-rounding.
	Goal     any
	Rounding string
	// Boolean is true for a true-or-false value, and for a null whose schema
	// allows a boolean and no number.
	Boolean bool
}

// MeasuredValues lists the numbers and true-or-false values in doc, and the
// nulls whose schema allows a number or boolean, each with its annotations.
// Strings, objects, and arrays are not listed, though the values inside
// objects and arrays are.
func MeasuredValues(s *Schema, doc any) []Measured {
	var out []Measured
	var walk func(node any, v view, tokens []string)
	walk = func(node any, v view, tokens []string) {
		switch n := node.(type) {
		case map[string]any:
			for _, key := range sortedKeys(n) {
				walk(n[key], s.member(v, key), append(append([]string(nil), tokens...), key))
			}
		case []any:
			for i, item := range n {
				walk(item, s.item(v, i), append(append([]string(nil), tokens...), strconv.Itoa(i)))
			}
		case string:
		case nil:
			if scalar(v.types()) {
				out = append(out, measured(v, tokens, !numeric(v.types())))
			}
		case bool:
			out = append(out, measured(v, tokens, true))
		default:
			out = append(out, measured(v, tokens, false))
		}
	}
	walk(doc, s.rootView(), nil)
	return out
}

func measured(v view, tokens []string, boolean bool) Measured {
	goal, _ := v.keyword("x-epack-goal")
	return Measured{
		Pointer: jsonpointer.Format(tokens), Method: v.text("x-epack-method"),
		Label: v.text("x-epack-label"), Summary: v.text("x-epack-summary"),
		Goal: goal, Rounding: v.text("x-epack-rounding"), Boolean: boolean,
	}
}

func numeric(types []string) bool {
	return slices.Contains(types, "number") || slices.Contains(types, "integer")
}

// GoalProblem reports what is wrong with a value's x-epack-goal, or "" when
// it fits. A true-or-false value's goal is true or false. A number's goal is
// higher or lower. A percentage's goal follows its x-epack-rounding, floor
// for higher and ceil for lower, so a goal it sets must agree with it.
func GoalProblem(m Measured) string {
	if m.Goal == nil {
		return ""
	}
	if m.Boolean {
		if _, ok := m.Goal.(bool); !ok {
			return fmt.Sprintf("x-epack-goal %s on a true-or-false value, want true or false", show(m.Goal))
		}
		return ""
	}
	goal, _ := m.Goal.(string)
	if goal != "higher" && goal != "lower" {
		return fmt.Sprintf("x-epack-goal %s on a number, want higher or lower", show(m.Goal))
	}
	if want := map[string]string{"floor": "higher", "ceil": "lower"}[m.Rounding]; want != "" && goal != want {
		return fmt.Sprintf("x-epack-goal %s disagrees with x-epack-rounding %s, which means %s", goal, m.Rounding, want)
	}
	return ""
}

// MethodAt returns the x-epack-method that s gives the value at pointer,
// read from the schema alone, so the artifact need not have been written.
func MethodAt(s *Schema, pointer string) string {
	v := s.rootView()
	if pointer == "" {
		return v.text("x-epack-method")
	}
	for _, token := range jsonpointer.Tokens(pointer) {
		if i, err := strconv.Atoi(token); err == nil && slices.Contains(v.types(), "array") {
			v = s.item(v, i)
		} else {
			v = s.member(v, token)
		}
	}
	return v.text("x-epack-method")
}
