package collectortest

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// The fields check, which Suite.FieldSensitivity turns on, changes one state
// field at a time in an operation's answers. A state field is a status,
// state, enabled flag, operator, condition, or effect. The check reports
// each field whose change moves no value in an object the collector does
// read. The object counts as read when emptying it, or dropping the list
// items it sits in, moves a value. Such a field usually affects whether a
// thing works, as a flow log's delivery status or a policy rule's conditions
// do. A collector that ignores it can count a thing that exists as one that
// works. A state in an object the collector does not read at all, such as an
// app's logout settings, is not reported. The sensitivity check cannot catch
// these fields, since it changes an operation's whole answer at once. A
// field the collector may ignore goes in Suite.IgnoredFields, with the
// reason. The check cannot tell objects apart in an XML answer, so it
// reports every XML state element that moves no value.

// stateField reports whether a field holds a state, going by its name.
func stateField(name string) bool {
	n := strings.ToLower(name)
	switch {
	case strings.HasSuffix(n, "enabled"), strings.HasSuffix(n, "status"), strings.HasSuffix(n, "state"):
	case strings.Contains(n, "operator"), n == "condition", n == "conditions", n == "effect":
	default:
		return false
	}
	return true
}

// opposites maps common two-valued states to their opposites, ignoring
// case. The check uses it for a field that has only one value in the
// answers.
var opposites = map[string]string{
	"active": "inactive", "inactive": "active", "enabled": "disabled", "disabled": "enabled",
	"on": "off", "off": "on", "allow": "deny", "deny": "allow", "and": "or", "or": "and",
	"true": "false", "false": "true", "yes": "no", "no": "yes",
}

// changedValue is a placeholder for a state string with no known opposite.
const changedValue = "collectortest-changed"

// fieldKey identifies a state field the check changes by its operation and
// pattern. The pattern is a JSON pointer with "*" for each array index, or
// an XML element's name.
type fieldKey struct {
	op, pattern string
	xml         bool
}

func (f fieldKey) label() string { return f.op + " " + f.pattern }

// checkFields runs the fields check on the clean scenario.
func (k *kit) checkFields() {
	ops := k.consumedBy()
	clean := k.suite.Scenarios[0]
	keys := map[fieldKey]bool{}
	for i, r := range clean.Responses {
		for _, op := range ops[i] {
			if k.insensitive(op) {
				continue
			}
			for _, f := range stateFields(k.textOf(op, r)) {
				f.op = op
				keys[f] = true
			}
		}
	}
	var ordered []fieldKey
	for f := range keys {
		ordered = append(ordered, f)
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].label() < ordered[j].label() })
	p := perturber{k: k, check: "fields"}
	// moves reports whether changing op's answers with change moves a
	// value. A run that fails, or makes a request the scenario has no
	// response for, also counts, since it reacted to the change.
	moves := func(label, op string, change func(string) (string, bool)) (moved, touched bool) {
		run, ok := p.run(perturbation{label: label, op: op, text: change})
		return ok && (run.unanswered || run.failed() || len(k.moved(run)) > 0), ok
	}
	read := map[string]bool{}
	for _, f := range ordered {
		moved, touched := moves(f.label(), f.op, f.change)
		if moved || !touched {
			continue
		}
		if parent, ok := parentPattern(f); ok {
			key := f.op + " " + parent
			used, seen := read[key]
			if !seen {
				used, _ = moves(key+" (emptied)", f.op, func(text string) (string, bool) { return emptyJSONObject(text, parent) })
				read[key] = used
			}
			if !used {
				continue
			}
		}
		k.report.IgnoredFields = append(k.report.IgnoredFields, f.label())
		if k.ignoredField(f) {
			continue
		}
		k.violate("fields", f.label(), "changing %s in %s's answers changed no value. A state field like this usually affects whether a thing works. "+
			"Read it, or list it in Suite.IgnoredFields with the reason it does not matter", f.pattern, f.op)
	}
}

func (k *kit) ignoredField(f fieldKey) bool {
	for _, pattern := range k.suite.IgnoredFields[f.op] {
		if pattern == f.pattern {
			return true
		}
	}
	return false
}

// change changes every value of f in an answer's text and reports whether
// it changed any.
func (f fieldKey) change(text string) (string, bool) {
	return readAnswer(text, f.xml).withField(f.pattern)
}

// parentPattern returns the pattern of the object that holds a JSON state
// field. It returns false for a field at the top level of an answer or in
// XML, since the check cannot empty the parent of such a field on its own.
func parentPattern(f fieldKey) (string, bool) {
	if f.xml {
		return "", false
	}
	i := strings.LastIndex(f.pattern, "/")
	if i <= 0 {
		return "", false
	}
	return f.pattern[:i], true
}

// emptyJSONObject empties the object at pattern in a JSON document. For
// list items, it empties the list they sit in.
func emptyJSONObject(text, pattern string) (string, bool) {
	target, empty := pattern, any(map[string]any{})
	if strings.HasSuffix(pattern, "/*") {
		target, empty = strings.TrimSuffix(pattern, "/*"), []any{}
	}
	return editJSON(text, json.Marshal, atPattern(target, func(v any) (any, bool) {
		switch n := v.(type) {
		case map[string]any:
			return empty, len(n) > 0
		case []any:
			return empty, len(n) > 0
		}
		return v, false
	}))
}

// xmlLeaf matches an XML element that holds only text.
var xmlLeaf = regexp.MustCompile(`<([A-Za-z_][A-Za-z0-9_.-]*)>([^<]*)</([A-Za-z_][A-Za-z0-9_.-]*)>`)

// stateFields lists the state fields in a body. Each is a JSON pointer with
// "*" for array indices, or an XML element name.
func stateFields(body string) []fieldKey {
	doc := parseAnswer(body)
	_, isXML := doc.(xmlDoc)
	seen := map[string]bool{}
	var out []fieldKey
	doc.each(func(at place, v any) {
		if at.item || v == nil || !stateField(at.key) || seen[at.pattern] {
			return
		}
		seen[at.pattern] = true
		out = append(out, fieldKey{pattern: at.pattern, xml: isXML})
	})
	return out
}

// changeJSONField changes each value at pattern. A boolean flips, and a
// number grows by one. An object or array is emptied. A string becomes
// another value the field holds in the body, its opposite, or a placeholder.
func changeJSONField(body, pattern string) (string, bool) {
	return readAnswer(body, false).withField(pattern)
}

// changedJSONValue returns v changed as changeJSONField describes, and
// false for a value it cannot change, such as null. strs holds the strings
// the field holds in the body.
func changedJSONValue(v any, strs []string) (any, bool) {
	switch n := v.(type) {
	case bool:
		return !n, true
	case json.Number:
		if i, err := n.Int64(); err == nil {
			return json.Number(strconv.FormatInt(i+1, 10)), true
		}
		f, _ := n.Float64()
		return json.Number(strconv.FormatFloat(f+1, 'f', -1, 64)), true
	case string:
		return otherValue(n, strs), true
	case map[string]any:
		return map[string]any{}, true
	case []any:
		return []any{}, true
	}
	return v, false
}

// otherValue returns a different value for a state string. That is the next
// of the values the field holds, its opposite in the same case, or a
// placeholder.
func otherValue(s string, values []string) string {
	if len(values) > 1 {
		for i, v := range values {
			if v == s {
				return values[(i+1)%len(values)]
			}
		}
	}
	if o, ok := opposites[strings.ToLower(s)]; ok {
		switch s {
		case strings.ToUpper(s):
			return strings.ToUpper(o)
		case strings.ToLower(s):
			return o
		}
		return strings.ToUpper(o[:1]) + o[1:]
	}
	return changedValue
}

// changeXMLField changes the text of each element named name that holds
// only text. It changes the text as changeJSONField changes a string.
func changeXMLField(body, name string) (string, bool) {
	var values []string
	for _, m := range xmlLeaf.FindAllStringSubmatch(body, -1) {
		if m[1] == name && m[3] == name && !containsString(values, m[2]) {
			values = append(values, m[2])
		}
	}
	if len(values) == 0 {
		return "", false
	}
	sort.Strings(values)
	out := xmlLeaf.ReplaceAllStringFunc(body, func(el string) string {
		m := xmlLeaf.FindStringSubmatch(el)
		if m[1] != name || m[3] != name {
			return el
		}
		return fmt.Sprintf("<%s>%s</%s>", name, otherValue(m[2], values), name)
	})
	return out, out != body
}
