package shadow

import (
	"encoding/json"
	"regexp"
	"strconv"
	"strings"

	"github.com/locktivity/epack/internal/componenttypes"
	"github.com/locktivity/epack/internal/jsonpointer"
)

// A pattern names a field the way its schema does, so a report can name it
// without naming anything from the account. An array index becomes *. An
// object key the schema declares as a property stays, and any other key,
// such as a region or repository name used as a map key, becomes {key}.
// Without a schema, every key becomes {key}.

// schema is one JSON Schema, decoded.
type schema struct{ root any }

func parseSchema(raw []byte) *schema {
	if len(raw) == 0 {
		return nil
	}
	var root any
	if err := json.Unmarshal(raw, &root); err != nil {
		return nil
	}
	return &schema{root: root}
}

// view is the schema objects that apply at one place in a document.
type view []map[string]any

// expand adds node to v, following $ref within the schema and the
// subschemas of allOf, anyOf, and oneOf.
func (s *schema) expand(v view, node any, seen map[string]bool) view {
	m, ok := node.(map[string]any)
	if !ok {
		return v
	}
	if ref, ok := m["$ref"].(string); ok && strings.HasPrefix(ref, "#") && !seen[ref] {
		seen[ref] = true
		v = s.expand(v, s.at(ref[1:]), seen)
	}
	v = append(v, m)
	for _, key := range []string{"allOf", "anyOf", "oneOf"} {
		if subs, ok := m[key].([]any); ok {
			for _, sub := range subs {
				v = s.expand(v, sub, seen)
			}
		}
	}
	return v
}

// at returns the node at a JSON pointer within the schema, or nil.
func (s *schema) at(pointer string) any {
	node := s.root
	if pointer == "" {
		return node
	}
	for _, token := range jsonpointer.Tokens(pointer) {
		switch n := node.(type) {
		case map[string]any:
			node = n[token]
		case []any:
			i, err := strconv.Atoi(token)
			if err != nil || i < 0 || i >= len(n) {
				return nil
			}
			node = n[i]
		default:
			return nil
		}
	}
	return node
}

func (s *schema) rootView() view {
	if s == nil {
		return nil
	}
	return s.expand(nil, s.root, map[string]bool{})
}

// member returns the view of key within v, and whether a schema in v
// declares key as a property.
func (s *schema) member(v view, key string) (view, bool) {
	var out view
	declared := false
	for _, obj := range v {
		if props, ok := obj["properties"].(map[string]any); ok {
			if child, ok := props[key]; ok {
				declared = true
				out = s.expand(out, child, map[string]bool{})
				continue
			}
		}
		matched := false
		if patterns, ok := obj["patternProperties"].(map[string]any); ok {
			for p, child := range patterns {
				if re, err := regexp.Compile(p); err == nil && re.MatchString(key) {
					matched = true
					out = s.expand(out, child, map[string]bool{})
				}
			}
		}
		if !matched {
			if extra, ok := obj["additionalProperties"].(map[string]any); ok {
				out = s.expand(out, extra, map[string]bool{})
			}
		}
	}
	return out, declared
}

// item returns the view of the array item at index within v.
func (s *schema) item(v view, index int) view {
	var out view
	for _, obj := range v {
		if prefix, ok := obj["prefixItems"].([]any); ok && index < len(prefix) {
			out = s.expand(out, prefix[index], map[string]bool{})
			continue
		}
		if items, ok := obj["items"].(map[string]any); ok {
			out = s.expand(out, items, map[string]bool{})
		}
	}
	return out
}

// above reports whether level a ranks above level b. A string that names no
// level ranks with trust.
func above(a, b string) bool {
	return !componenttypes.Level(b).AtLeast(componenttypes.Level(a))
}

// level is the highest x-epack-level the schemas in v name, or "".
func (v view) level() string {
	best := ""
	for _, obj := range v {
		if l, ok := obj["x-epack-level"].(string); ok {
			if _, known := componenttypes.Level(l).Rank(); known && (best == "" || above(l, best)) {
				best = l
			}
		}
	}
	return best
}

func (v view) isArray() bool {
	for _, obj := range v {
		if _, ok := obj["items"]; ok {
			return true
		}
		if _, ok := obj["prefixItems"]; ok {
			return true
		}
		switch t := obj["type"].(type) {
		case string:
			if t == "array" {
				return true
			}
		case []any:
			for _, x := range t {
				if x == "array" {
					return true
				}
			}
		}
	}
	return false
}

// walker carries the views of the locked version's schema and the
// candidate's down a document, so a key either declares stays named. level
// is the candidate's level there, inherited from enclosing fields.
type walker struct {
	locked, candidate         *schema
	lockedView, candidateView view
	level                     string
}

func newWalker(locked, candidate *schema) walker {
	w := walker{locked: locked, candidate: candidate, lockedView: locked.rootView(), candidateView: candidate.rootView()}
	w.level = higher("", w.candidateView.level())
	return w
}

// key returns the walker for an object member and the pattern token for it.
func (w walker) key(key string) (walker, string) {
	next := w
	var declaredLocked, declaredCandidate bool
	if w.locked != nil {
		next.lockedView, declaredLocked = w.locked.member(w.lockedView, key)
	}
	if w.candidate != nil {
		next.candidateView, declaredCandidate = w.candidate.member(w.candidateView, key)
	}
	next.level = higher(w.level, next.candidateView.level())
	if declaredLocked || declaredCandidate {
		return next, jsonpointer.Escape(key)
	}
	return next, "{key}"
}

// index returns the walker for an array item.
func (w walker) index(i int) walker {
	next := w
	if w.locked != nil {
		next.lockedView = w.locked.item(w.lockedView, i)
	}
	if w.candidate != nil {
		next.candidateView = w.candidate.item(w.candidateView, i)
	}
	next.level = higher(w.level, next.candidateView.level())
	return next
}

// pointerPattern returns the pattern of a JSON pointer read without its
// document, such as a gap's location. A numeric token is an array index
// where the schemas say an array is, and where there is no schema.
func (w walker) pointerPattern(pointer string) string {
	if pointer == "" {
		return ""
	}
	var b strings.Builder
	for _, token := range jsonpointer.Tokens(pointer) {
		i, err := strconv.Atoi(token)
		arrayHere := w.lockedView.isArray() || w.candidateView.isArray() || (w.locked == nil && w.candidate == nil)
		if err == nil && i >= 0 && arrayHere {
			w = w.index(i)
			b.WriteString("/*")
			continue
		}
		var name string
		w, name = w.key(token)
		b.WriteString("/" + name)
	}
	return b.String()
}

// levelAt returns the candidate schema's level for a pattern, read from
// the schema alone, for a field the candidate no longer writes.
func (w walker) levelAt(pattern string) string {
	if pattern == "" {
		return w.level
	}
	for _, token := range jsonpointer.Tokens(pattern) {
		switch token {
		case "*":
			w = w.index(0)
		case "{key}":
			w, _ = w.key("\x00")
		default:
			w, _ = w.key(token)
		}
	}
	return w.level
}

func higher(a, b string) string {
	if b == "" || (a != "" && !above(b, a)) {
		return a
	}
	return b
}

// idSegment matches a path segment that holds an identifier, such as a
// document ID, which a report leaves out of file names.
var idSegment = regexp.MustCompile(`[0-9a-fA-F-]{8,}`)

// filePattern returns an artifact path with each segment that holds an
// identifier replaced by {id}.
func filePattern(path string) string {
	parts := strings.Split(path, "/")
	for i, p := range parts {
		if idSegment.MatchString(p) {
			parts[i] = "{id}"
		}
	}
	return strings.Join(parts, "/")
}
