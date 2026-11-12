package outputcheck

import (
	"strconv"
	"strings"

	"github.com/locktivity/epack/internal/jsonpointer"
)

// Fields lists every field the schema allows, by JSON pointer with * for any
// array index or for any member of an object keyed by name. A field is a
// value whose schema allows no object with named properties and no array or
// keyed object of them: a number, a boolean, a string, a list of those, or
// an object of those keyed by name, such as a count by operating system. The
// fields of an object with named properties, or of each item or member that
// is one, are listed instead of it.
func Fields(s *Schema) []string {
	var out []string
	seen := map[string]bool{}
	var walk func(v view, tokens []string)
	walk = func(v view, tokens []string) {
		if names := propertyNames(v); len(names) > 0 {
			for _, name := range names {
				walk(s.member(v, name), append(append([]string(nil), tokens...), name))
			}
			return
		}
		if inner, ok := s.nested(v); ok {
			walk(inner, append(append([]string(nil), tokens...), "*"))
			return
		}
		if p := jsonpointer.Format(tokens); !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	walk(s.rootView(), nil)
	return out
}

// Lists lists every array of objects with named properties the schema
// allows, by JSON pointer with * as Fields uses it.
func Lists(s *Schema) []string {
	var out []string
	var walk func(v view, tokens []string)
	walk = func(v view, tokens []string) {
		if names := propertyNames(v); len(names) > 0 {
			for _, name := range names {
				walk(s.member(v, name), append(append([]string(nil), tokens...), name))
			}
			return
		}
		if inner, ok := s.nested(v); ok {
			if item := s.item(v, 0); len(item) > 0 {
				out = append(out, jsonpointer.Format(tokens))
			}
			walk(inner, append(append([]string(nil), tokens...), "*"))
		}
	}
	walk(s.rootView(), nil)
	return out
}

// Written lists the fields doc holds, as Fields defines them, by JSON pointer.
// A field holding null is listed. The fields of an empty array or keyed
// object of objects are not.
func Written(s *Schema, doc any) []string {
	var out []string
	var walk func(node any, v view, tokens []string)
	walk = func(node any, v view, tokens []string) {
		_, nested := s.nested(v)
		switch n := node.(type) {
		case map[string]any:
			if len(propertyNames(v)) > 0 || nested {
				for _, key := range sortedKeys(n) {
					walk(n[key], s.member(v, key), append(append([]string(nil), tokens...), key))
				}
				return
			}
		case []any:
			if nested {
				for i, it := range n {
					walk(it, s.item(v, i), append(append([]string(nil), tokens...), strconv.Itoa(i)))
				}
				return
			}
		}
		out = append(out, jsonpointer.Format(tokens))
	}
	walk(doc, s.rootView(), nil)
	return out
}

// FieldOf gives the field pointer is in, as Fields names it, with * in
// place of each array index and each member of an object keyed by name. It
// gives pointer's own tokens where the schema says nothing of them.
func FieldOf(s *Schema, pointer string) string {
	if pointer == "" {
		return ""
	}
	v := s.rootView()
	var out []string
	for _, token := range jsonpointer.Tokens(pointer) {
		switch {
		case len(propertyNames(v)) > 0:
			out = append(out, token)
			v = s.member(v, token)
		case isArrayIndex(token) && len(s.item(v, 0)) > 0:
			out = append(out, "*")
			v = s.item(v, 0)
		default:
			if inner, ok := s.nested(v); ok {
				out = append(out, "*")
				v = inner
				continue
			}
			out = append(out, token)
			v = s.member(v, token)
		}
	}
	return jsonpointer.Format(out)
}

// nested returns the view of each item of an array, or each member of an
// object keyed by name, when that is an object with named properties.
func (s *Schema) nested(v view) (view, bool) {
	if item := s.item(v, 0); len(item) > 0 && len(propertyNames(item)) > 0 {
		return item, true
	}
	var members view
	for _, obj := range v {
		if ap, ok := obj["additionalProperties"].(map[string]any); ok {
			members = s.expand(members, ap)
		}
	}
	if len(members) > 0 && len(propertyNames(members)) > 0 {
		return members, true
	}
	return nil, false
}

func isArrayIndex(token string) bool {
	_, err := strconv.Atoi(token)
	return err == nil && !strings.HasPrefix(token, "-") && (token == "0" || !strings.HasPrefix(token, "0"))
}

// propertyNames lists the named properties the view's schemas give, in
// order, each once.
func propertyNames(v view) []string {
	var out []string
	seen := map[string]bool{}
	for _, obj := range v {
		props, _ := obj["properties"].(map[string]any)
		for _, name := range sortedKeys(props) {
			if !seen[name] {
				seen[name] = true
				out = append(out, name)
			}
		}
	}
	return out
}
