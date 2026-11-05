package outputcheck

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"

	"github.com/locktivity/epack/internal/jsonpointer"
)

// AddMethods returns the schema raw with each sentence in methods written as
// the x-epack-method of the field its pointer names. A pointer is an RFC
// 6901 pointer with * for any array index or map key, such as
// /endpoints/*/port or /devices_by_os/*. The
// sentence goes on the schema that declares the field, reached through local
// $refs and allOf, anyOf, and oneOf branches. AddMethods also returns a
// problem for each pointer that names no field, and for each pointer that
// reaches the same schema as another with a different sentence, as two
// fields declared by one shared definition do. It skips those pointers.
func AddMethods(raw []byte, methods map[string]string) ([]byte, []string, error) {
	doc, err := Decode(raw)
	if err != nil {
		return nil, nil, err
	}
	s := &Schema{root: doc}
	type placed struct{ pointer, sentence string }
	seen := map[uintptr]placed{}
	var problems []string
	for _, ptr := range sortedKeys(methods) {
		node, ok := s.fieldNode(ptr)
		if !ok {
			problems = append(problems, ptr+" names no field of the schema")
			continue
		}
		id := reflect.ValueOf(node).Pointer()
		if prev, ok := seen[id]; ok {
			if prev.sentence != methods[ptr] {
				problems = append(problems, fmt.Sprintf("%s and %s are declared by one schema, so one sentence has to cover both", prev.pointer, ptr))
			}
			continue
		}
		seen[id] = placed{pointer: ptr, sentence: methods[ptr]}
		node["x-epack-method"] = methods[ptr]
	}
	out, err := json.Marshal(doc)
	if err != nil {
		return nil, nil, err
	}
	return out, problems, nil
}

// fieldNode returns the schema that declares the field at ptr: the
// properties entry for each name and the items schema for each *. A map's
// values are declared by its additionalProperties.
func (s *Schema) fieldNode(ptr string) (map[string]any, bool) {
	if !strings.HasPrefix(ptr, "/") {
		return nil, false
	}
	cur := s.root
	for _, token := range jsonpointer.Tokens(ptr) {
		next, ok := childNode(s.expand(nil, cur), token)
		if !ok {
			return nil, false
		}
		cur = next
	}
	node, ok := cur.(map[string]any)
	return node, ok
}

// childNode returns the first schema in v that declares token: a properties
// entry, or for *, the items schema. A name no properties entry declares,
// and a * on a map, falls back to the additionalProperties schema, which
// declares every other value of the map.
func childNode(v view, token string) (map[string]any, bool) {
	for _, obj := range v {
		if token == "*" {
			if items, ok := obj["items"].(map[string]any); ok {
				return items, true
			}
			continue
		}
		if props, ok := obj["properties"].(map[string]any); ok {
			if child, ok := props[token].(map[string]any); ok {
				return child, true
			}
		}
	}
	for _, obj := range v {
		if extra, ok := obj["additionalProperties"].(map[string]any); ok {
			return extra, true
		}
	}
	return nil, false
}
