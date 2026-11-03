package outputcheck

import (
	"slices"
	"strconv"

	"github.com/locktivity/epack/internal/jsonpointer"
)

// Measured is a number or true-or-false value in a document, or a null whose
// schema allows one, with the value's x-epack-method.
type Measured struct {
	Pointer string
	Method  string
}

// MeasuredValues lists the numbers and true-or-false values in doc, and the
// nulls whose schema allows a number or boolean, each with its
// x-epack-method. Strings, objects, and arrays are not listed, though the
// values inside objects and arrays are.
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
				out = append(out, Measured{Pointer: jsonpointer.Format(tokens), Method: v.text("x-epack-method")})
			}
		default:
			out = append(out, Measured{Pointer: jsonpointer.Format(tokens), Method: v.text("x-epack-method")})
		}
	}
	walk(doc, s.rootView(), nil)
	return out
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
