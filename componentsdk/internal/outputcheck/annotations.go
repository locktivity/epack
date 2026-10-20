package outputcheck

import (
	"net/url"
	"sort"
	"strconv"
	"strings"
)

// view lists the schema objects that apply at one place in an instance, each
// followed by the schemas its local $ref and its allOf, anyOf, and oneOf
// branches reach. A keyword's value is the first one found in that order.
type view []map[string]any

func (s *Schema) rootView() view {
	return s.expand(nil, s.root)
}

func (s *Schema) expand(out view, node any) view {
	return s.expandSeen(out, node, map[string]bool{})
}

// expandSeen follows each ref once, so a recursive schema cannot loop.
func (s *Schema) expandSeen(out view, node any, seen map[string]bool) view {
	obj, ok := node.(map[string]any)
	if !ok {
		return out
	}
	out = append(out, obj)
	if ref, ok := obj["$ref"].(string); ok && !seen[ref] {
		seen[ref] = true
		if target, ok := s.localRef(ref); ok {
			out = s.expandSeen(out, target, seen)
		}
	}
	for _, keyword := range []string{"allOf", "anyOf", "oneOf"} {
		branches, _ := obj[keyword].([]any)
		for _, branch := range branches {
			out = s.expandSeen(out, branch, seen)
		}
	}
	return out
}

// localRef resolves a ref to a JSON pointer within the schema, written as
// "#/..." or as the schema's own $id followed by "#/...". Anchors and
// remote refs resolve to nothing.
func (s *Schema) localRef(ref string) (any, bool) {
	frag, ok := strings.CutPrefix(ref, "#")
	if !ok {
		root, _ := s.root.(map[string]any)
		id, _ := root["$id"].(string)
		id = strings.TrimSuffix(id, "#")
		if id == "" {
			return nil, false
		}
		switch {
		case ref == id:
			frag = ""
		case strings.HasPrefix(ref, id+"#"):
			frag = ref[len(id)+1:]
		default:
			return nil, false
		}
	}
	if decoded, err := url.PathUnescape(frag); err == nil {
		frag = decoded
	}
	return Resolve(s.root, frag)
}

// member returns the view of an object member: the properties entries that
// name it, then the patternProperties entries that match it, then the
// additionalProperties of schemas that did neither. A branch that names the
// member so wins over a catch-all elsewhere in the view.
func (s *Schema) member(v view, name string) view {
	var props, patterns, extra view
	for _, obj := range v {
		matched := false
		if p, ok := obj["properties"].(map[string]any); ok {
			if child, ok := p[name]; ok {
				props = s.expand(props, child)
				matched = true
			}
		}
		if pp, ok := obj["patternProperties"].(map[string]any); ok {
			for _, key := range sortedKeys(pp) {
				if re := s.pattern(key); re != nil && re.MatchString(name) {
					patterns = s.expand(patterns, pp[key])
					matched = true
				}
			}
		}
		if ap, ok := obj["additionalProperties"].(map[string]any); ok && !matched {
			extra = s.expand(extra, ap)
		}
	}
	return append(append(props, patterns...), extra...)
}

// item returns the view of an array item: the schemas for its position, from
// prefixItems (2020-12) or items as an array (draft-07), then the schemas for
// every other item, from items (both drafts) or additionalItems (draft-07).
func (s *Schema) item(v view, index int) view {
	var positional, rest view
	for _, obj := range v {
		if prefix, ok := obj["prefixItems"].([]any); ok {
			if index < len(prefix) {
				positional = s.expand(positional, prefix[index])
			} else if r, ok := obj["items"].(map[string]any); ok {
				rest = s.expand(rest, r)
			}
			continue
		}
		switch items := obj["items"].(type) {
		case []any:
			if index < len(items) {
				positional = s.expand(positional, items[index])
			} else if r, ok := obj["additionalItems"].(map[string]any); ok {
				rest = s.expand(rest, r)
			}
		case map[string]any:
			rest = s.expand(rest, items)
		}
	}
	return append(positional, rest...)
}

// viewAt returns the view of the value at an RFC 6901 pointer in doc,
// walking the schema alongside the instance, or nil when the pointer does
// not resolve.
func (s *Schema) viewAt(doc any, ptr string) view {
	v, _, _ := s.levelAt(doc, ptr)
	return v
}

// levelAt returns the view of the value at an RFC 6901 pointer in doc, as
// viewAt does, with the rank of the highest level x-epack-level names on
// the value or on any value that holds it. It reports false when the
// pointer does not resolve.
func (s *Schema) levelAt(doc any, ptr string) (view, int, bool) {
	v := s.rootView()
	rank := levelOf(v)
	if ptr == "" {
		return v, rank, true
	}
	if !strings.HasPrefix(ptr, "/") {
		return nil, 0, false
	}
	cur := doc
	for _, token := range strings.Split(ptr[1:], "/") {
		token = unescape(token)
		switch node := cur.(type) {
		case map[string]any:
			cur = node[token]
			v = s.member(v, token)
		case []any:
			idx, err := strconv.Atoi(token)
			if err != nil || idx < 0 || idx >= len(node) {
				return nil, 0, false
			}
			cur = node[idx]
			v = s.item(v, idx)
		default:
			return nil, 0, false
		}
		rank = max(rank, levelOf(v))
	}
	return v, rank, true
}

func (v view) keyword(name string) (any, bool) {
	for _, obj := range v {
		if value, ok := obj[name]; ok {
			return value, true
		}
	}
	return nil, false
}

func (v view) text(name string) string {
	value, _ := v.keyword(name)
	s, _ := value.(string)
	return s
}

// types returns every type the view's schemas name, other than null.
func (v view) types() []string {
	var out []string
	add := func(t any) {
		name, ok := t.(string)
		if !ok || name == "null" {
			return
		}
		for _, have := range out {
			if have == name {
				return
			}
		}
		out = append(out, name)
	}
	for _, obj := range v {
		switch t := obj["type"].(type) {
		case []any:
			for _, each := range t {
				add(each)
			}
		default:
			add(t)
		}
	}
	return out
}

// target returns the pointer a reference names from the value at tokens. A
// reference is a sibling's name, an absolute pointer starting with "/", or a
// relative pointer "N/path": up N levels from the object holding the value,
// then path.
func target(ref string, tokens []string) (string, bool) {
	if ref == "" {
		return "", false
	}
	if strings.HasPrefix(ref, "/") {
		return ref, true
	}
	if len(tokens) == 0 {
		return "", false
	}
	base := tokens[:len(tokens)-1]
	if up, rest, ok := relative(ref); ok {
		if up > len(base) {
			return "", false
		}
		return pointer(base[:len(base)-up]) + rest, true
	}
	return pointer(append(append([]string(nil), base...), ref)), true
}

func relative(ref string) (int, string, bool) {
	digits := 0
	for digits < len(ref) && ref[digits] >= '0' && ref[digits] <= '9' {
		digits++
	}
	if digits == 0 || (digits > 1 && ref[0] == '0') {
		return 0, "", false
	}
	rest := ref[digits:]
	if rest != "" && rest[0] != '/' {
		return 0, "", false
	}
	up, err := strconv.Atoi(ref[:digits])
	if err != nil {
		return 0, "", false
	}
	return up, rest, true
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
