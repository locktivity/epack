package collectortest

import (
	"bytes"
	"encoding/json"
	"sort"
	"strconv"
	"strings"

	"github.com/locktivity/epack/internal/jsonpointer"
)

// The checks read and change canned answers as JSON or XML. parseAnswer
// tells the two apart and returns an answerDoc, which does what the checks
// need in either format. walkJSON walks a decoded JSON document. jsonDoc's
// edit changes one, keeps track of whether anything changed, and encodes
// the result. editJSON decodes a document for it.

// answerDoc is a canned answer's body, read as JSON or XML. reversed and
// withField may change a JSON document as they go, so a document serves one
// of them once.
type answerDoc interface {
	// reversed returns the body with each list reversed, as reverseJSON and
	// reverseXML describe. It returns false when no list has two or more
	// items.
	reversed() (string, bool)
	// each calls fn on each value in the body and where it sits.
	each(fn func(at place, v any))
	// withField returns the body with each value at pattern changed, as
	// changeJSONField and changeXMLField describe. It returns false when no
	// value changed.
	withField(pattern string) (string, bool)
}

// parseAnswer reads text as XML when it starts with "<", and as JSON
// otherwise.
func parseAnswer(text string) answerDoc {
	return readAnswer(text, strings.HasPrefix(strings.TrimSpace(text), "<"))
}

// readAnswer reads text as XML when xml is true, and as JSON otherwise.
// Text that is not JSON reads as an answer with nothing in it.
func readAnswer(text string, xml bool) answerDoc {
	if xml {
		return xmlDoc(text)
	}
	if doc, ok := decodeJSON(text); ok {
		return jsonDoc{doc}
	}
	return noAnswer{}
}

// jsonDoc is a decoded JSON answer.
type jsonDoc struct{ v any }

func (d jsonDoc) reversed() (string, bool) { return d.edit(marshalNoEscape, reverseArrays) }

func (d jsonDoc) each(fn func(at place, v any)) { eachJSON(d.v, fn) }

func (d jsonDoc) withField(pattern string) (string, bool) {
	var strs []string
	d.each(func(at place, v any) {
		if s, ok := v.(string); ok && at.pattern == pattern && !containsString(strs, s) {
			strs = append(strs, s)
		}
	})
	sort.Strings(strs)
	return d.edit(json.Marshal, atPattern(pattern, func(v any) (any, bool) { return changedJSONValue(v, strs) }))
}

// edit walks the document with edit and encodes the result with encode. It
// returns false when edit changed nothing or encode fails.
func (d jsonDoc) edit(encode func(any) ([]byte, error), edit jsonEdit) (string, bool) {
	changed := false
	doc := walkJSON(place{}, d.v, true, func(at place, v any) (any, bool) {
		out, ok, descend := edit(at, v)
		changed = changed || ok
		return out, descend
	})
	if !changed {
		return "", false
	}
	raw, err := encode(doc)
	if err != nil {
		return "", false
	}
	return string(raw), true
}

// xmlDoc is an XML answer's text. Each method reads it the way its check
// always has, so they do not all see the same elements. reversed reads it
// with encoding/xml and sees every element. each and withField match
// xmlLeaf, which finds only an element that holds text alone and has no
// namespace prefix or attribute.
type xmlDoc string

func (d xmlDoc) reversed() (string, bool) { return reverseXML(string(d)) }

// each calls fn on the text of each element xmlLeaf matches. The element's
// name is both its key and its pattern.
func (d xmlDoc) each(fn func(at place, v any)) {
	for _, m := range xmlLeaf.FindAllStringSubmatch(string(d), -1) {
		if m[1] == m[3] {
			fn(place{key: m[1], pattern: m[1]}, m[2])
		}
	}
}

func (d xmlDoc) withField(name string) (string, bool) { return changeXMLField(string(d), name) }

// noAnswer is an answer that is neither XML nor JSON. It has nothing to
// read or change.
type noAnswer struct{}

func (noAnswer) reversed() (string, bool)        { return "", false }
func (noAnswer) each(func(place, any))           {}
func (noAnswer) withField(string) (string, bool) { return "", false }

// decodeJSON decodes the first JSON value in body, with numbers as
// json.Number.
func decodeJSON(body string) (any, bool) {
	dec := json.NewDecoder(strings.NewReader(body))
	dec.UseNumber()
	var doc any
	if err := dec.Decode(&doc); err != nil {
		return nil, false
	}
	return doc, true
}

// place is where a value sits in a document.
type place struct {
	// key is the name of the field that holds the value. An array item has
	// the key of the field that holds its array. The document itself has
	// no key.
	key string
	// pattern is the value's JSON pointer with "*" for each array index. In
	// XML, the key and the pattern are the element's name.
	pattern string
	// pointer is the value's JSON pointer.
	pointer string
	// item is true for an array item.
	item bool
}

// walkJSON calls fn on v, which sits at at, and on each value inside it,
// parents before children. fn returns the value for the place and whether
// to walk into that value. When put is true, walkJSON puts each value fn
// returns in its place in the parent. It returns fn's value for v.
func walkJSON(at place, v any, put bool, fn func(place, any) (any, bool)) any {
	v, descend := fn(at, v)
	if !descend {
		return v
	}
	switch n := v.(type) {
	case map[string]any:
		for key, child := range n {
			p := "/" + jsonpointer.Escape(key)
			got := walkJSON(place{key: key, pattern: at.pattern + p, pointer: at.pointer + p}, child, put, fn)
			if put {
				n[key] = got
			}
		}
	case []any:
		for i, child := range n {
			got := walkJSON(place{key: at.key, pattern: at.pattern + "/*", pointer: at.pointer + "/" + strconv.Itoa(i), item: true}, child, put, fn)
			if put {
				n[i] = got
			}
		}
	}
	return v
}

// eachJSON calls fn on v and on each value inside it, parents before
// children. It changes nothing.
func eachJSON(v any, fn func(at place, v any)) {
	walkJSON(place{}, v, false, func(at place, v any) (any, bool) {
		fn(at, v)
		return v, true
	})
}

// jsonEdit returns the value to put in place of v, whether that changes the
// document, and whether to walk into the value it returns.
type jsonEdit func(at place, v any) (out any, changed, descend bool)

// editJSON decodes body, walks it with edit, and encodes the result with
// encode. It returns false when body is not JSON, when edit changed
// nothing, or when encode fails.
func editJSON(body string, encode func(any) ([]byte, error), edit jsonEdit) (string, bool) {
	doc, ok := decodeJSON(body)
	if !ok {
		return "", false
	}
	return jsonDoc{doc}.edit(encode, edit)
}

// atPattern returns a jsonEdit that changes each value at pattern with
// change and leaves the rest of the document alone. pattern is a JSON
// pointer with "*" for each array index.
func atPattern(pattern string, change func(v any) (any, bool)) jsonEdit {
	return func(at place, v any) (any, bool, bool) {
		if at.pattern == pattern {
			out, changed := change(v)
			return out, changed, false
		}
		return v, false, strings.HasPrefix(pattern, at.pattern+"/")
	}
}

// marshalNoEscape is json.Marshal without HTML escaping, so <, >, and &
// stay as they are.
func marshalNoEscape(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}
