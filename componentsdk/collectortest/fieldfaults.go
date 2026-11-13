package collectortest

import (
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"reflect"
	"slices"
	"sort"
	"strings"

	"github.com/locktivity/epack/componentsdk"
	"github.com/locktivity/epack/internal/jsonpointer"
)

// The field-faults check holds the rule that a missing or unreadable field
// never lowers a count. It runs in every suite. For each
// operation the clean run called, it runs the clean scenario again with one
// field of the operation's answers changed: set to null, dropped, and, for a
// list, emptied. Each change applies to the field wherever its pattern
// matches, in every answer of the operation.
// After each run, every number and boolean in the output keeps its clean
// value, or is left out under a gap. None may change to another value, or
// appear. With Suite.GapOperations, the gap must name the operation, as a
// gap a fault leaves must. A vendor that leaves a field out, as Azure's
// vault list leaves out each vault's security settings, then shows as a gap
// rather than as a share that reads 0. Strings are not judged, since a name
// or a copy of the answer follows the field it comes from.
//
// The check changes the fields the collector reads. A top-level field
// counts as read. Any other counts when its object does, as in the fields
// check: when changing the field that holds the object, or emptying the list
// the object sits in, moves a value. Fields that only say where the next page
// is, or whether there is one, are left alone: without them an answer is the
// last page, which the pages check covers.
//
// An XML answer has no null, so its elements are only dropped and, for a
// list, emptied. An element counts as a list when its children share the
// name member or item, or are two or more of one name. CBOR answers the
// suite's codec does not decode are left alone.
//
// An empty list can be a real answer: an empty users list means there are no
// users, and the values over them may drop to 0 or be left out. A suite
// declares such a list in Suite.Populations, with the reason. The check then
// lets emptying that list change values without a gap. Setting it to null
// or dropping it still must leave a gap. Some vendors leave a field out, or
// send null, to mean a value, as Key Vault leaves enablePurgeProtection out
// until purge protection is on. A suite declares such a field in
// Suite.Omissions, with the reason. Each entry covers one field of one
// operation, and an entry the check finds no use for is reported.

// Population declares a list in an operation's answers that is the
// population values are taken over, such as the users a user count counts.
// The field-faults check then lets emptying the list change values without
// a gap, since an empty list means there are none.
type Population struct {
	// Operation is the operation whose answers hold the list.
	Operation string
	// List is the list's pattern as the field-faults check reports it: a
	// JSON pointer with "*" for each array index, such as "/value" or
	// "/value/*/members", or an XML element's path. An answer that is
	// itself a list is "/".
	List string
	// Reason says why an empty list means there are none.
	Reason string
}

// Omission declares a field the vendor leaves out, or sends as null, to
// mean a value. The field-faults check then lets setting the field to null,
// or dropping it, change values without a gap.
type Omission struct {
	// Operation is the operation whose answers hold the field.
	Operation string
	// Field is the field's pattern as the field-faults check reports it,
	// such as "/value/*/properties/enablePurgeProtection". A "*" also
	// matches any one key, so "/value/*/tags/*" covers each of a resource's
	// tags.
	Field string
	// Reason says what the vendor means by leaving the field out, and
	// where it says so.
	Reason string
}

// fieldDeclaration is a Suite.Populations or Suite.Omissions entry.
type fieldDeclaration struct {
	// list is the Suite field that holds the entry.
	list, op, pattern, reason string
}

func (d fieldDeclaration) key() string { return d.list + " " + d.op + " " + d.pattern }

// covers reports whether the entry exempts fault on op's field, whose
// pattern the check reports as label. A "*" in the entry's pattern matches
// any one key or index, so one entry can cover every key of a map such as a
// resource's tags.
func (d fieldDeclaration) covers(op, label, fault string) bool {
	if d.op != op || (fault == fieldEmptied) != (d.list == "Populations") {
		return false
	}
	want, got := strings.Split(d.pattern, "/"), strings.Split(label, "/")
	if len(want) != len(got) {
		return false
	}
	for i := range want {
		if want[i] != got[i] && want[i] != "*" {
			return false
		}
	}
	return true
}

func fieldDeclarations(s Suite) []fieldDeclaration {
	var out []fieldDeclaration
	for _, p := range s.Populations {
		out = append(out, fieldDeclaration{list: "Populations", op: p.Operation, pattern: p.List, reason: p.Reason})
	}
	for _, o := range s.Omissions {
		out = append(out, fieldDeclaration{list: "Omissions", op: o.Operation, pattern: o.Field, reason: o.Reason})
	}
	return out
}

// checkFieldDeclarations returns an error for a Suite.Populations or
// Suite.Omissions entry with a field missing, or one listed twice.
func checkFieldDeclarations(s Suite) error {
	seen := map[string]bool{}
	for _, d := range fieldDeclarations(s) {
		switch {
		case d.op == "" || d.pattern == "":
			return fmt.Errorf("a Suite.%s entry needs an operation and a pattern: %+v", d.list, d)
		case !strings.HasPrefix(d.pattern, "/"):
			return fmt.Errorf("a Suite.%s entry lists %s for %s; write it as the field_faults check reports it, such as /value", d.list, d.pattern, d.op)
		case strings.TrimSpace(d.reason) == "":
			return fmt.Errorf("a Suite.%s entry lists %s for %s without a Reason", d.list, d.pattern, d.op)
		case seen[d.key()]:
			return fmt.Errorf("two Suite.%s entries list %s for %s", d.list, d.pattern, d.op)
		}
		seen[d.key()] = true
	}
	return nil
}

// Fault kinds the field-faults check makes.
const (
	fieldNull    = "null"
	fieldDropped = "dropped"
	fieldEmptied = "emptied"
)

// fieldShape is what the check knows of one field across an operation's
// answers.
type fieldShape struct {
	// pattern is the field's JSON pointer with "*" for each array index, or
	// its XML element path. The answer itself is "".
	pattern string
	// parent is the pattern of the field whose object holds this one, or of
	// the list whose items do. It is "" for a top-level field.
	parent string
	// depth counts the fields above this one.
	depth int
	// value is true when an answer holds a value other than null there.
	value bool
	// list is true when an answer holds a list with items there.
	list bool
	xml  bool
}

// checkFieldFaults runs the field-faults check on the clean scenario.
func (k *kit) checkFieldFaults() {
	ff := &fieldFaults{k: k, p: perturber{k: k, check: "field_faults"}, declared: fieldDeclarations(k.suite), made: map[string]bool{}, needed: map[string]bool{}}
	for _, op := range k.pickOps(opPick{skipInsensitive: true}) {
		ff.operation(op.Name)
	}
	for _, d := range ff.declared {
		change := "emptied"
		if d.list == "Omissions" {
			change = "set to null or dropped"
		}
		switch {
		case !ff.made[d.key()]:
			k.violate("field_faults", d.key(), "Suite.%s lists %s's %s, which the check never %s: the clean run's answers do not hold it, or the collector does not read the object it sits in", d.list, d.op, d.pattern, change)
		case !ff.needed[d.key()]:
			k.violate("field_faults", d.key(), "Suite.%s lists %s's %s, but no value moved without a gap when it was %s; remove the entry", d.list, d.op, d.pattern, change)
		}
	}
}

type fieldFaults struct {
	k        *kit
	p        perturber
	declared []fieldDeclaration
	// made and needed hold, by fieldDeclaration.key, the declared fields
	// the check changed and those whose runs needed their entry.
	made, needed map[string]bool
}

// operation runs the check on one operation's fields, parents before
// children, and skips the fields of an object the collector does not read.
// It reports a problem a change to an object or list makes only when no
// change to a field inside it makes the same problem, so a value the
// collector reads deep in an answer is reported at its own field.
func (ff *fieldFaults) operation(op string) {
	shapes := ff.shapes(op)
	read := map[string]bool{}
	var runs []fieldRun
	for _, s := range shapes {
		if s.pattern != "" && !read[s.parent] {
			continue
		}
		moved, ran := false, false
		for _, fault := range s.faults() {
			r, ok := ff.run(op, s, fault)
			if ok {
				runs = append(runs, r)
			}
			moved, ran = moved || r.moved, ran || ok
		}
		read[s.pattern] = moved || (s.pattern == "" && !ran)
	}
	hint := "a field the vendor leaves out, or sends as null, must leave out the values it feeds, with a gap"
	if ff.k.suite.GapOperations {
		hint += " that names " + op
	}
	for _, r := range runs {
		if r.failure != "" {
			ff.k.violate("field_faults", r.label, "%s", r.failure)
			continue
		}
		within := map[string]bool{}
		if r.fault != fieldEmptied {
			for _, inner := range runs {
				if strings.HasPrefix(inner.pattern, r.pattern+"/") {
					for _, p := range inner.found {
						within[p] = true
					}
				}
			}
		}
		if len(r.problems) > 0 && !slices.ContainsFunc(r.found, func(p string) bool { return !within[p] }) {
			continue
		}
		more := hint + ", unless the vendor leaves the field out to mean a value, which Suite.Omissions declares"
		if r.fault == fieldEmptied {
			more = hint + ", unless an empty list means there are none, which Suite.Populations declares"
		}
		for _, p := range r.problems {
			ff.k.violate("field_faults", r.label, "%s; %s", p, more)
		}
	}
}

// fieldRun is the outcome of one run of the check.
type fieldRun struct {
	pattern, fault, label string
	// moved is true when the change moved a value, failed the run, or made
	// it ask for something the scenario has no answer for.
	moved bool
	// failure explains a run that failed although op is not one of
	// Suite.Required.
	failure string
	// found lists the values the run moved against the rule, and problems
	// those no Suite.Populations or Suite.Omissions entry excuses. A field
	// inside an object explains the object's problems by what it found, so
	// a declared field still keeps its object from being reported.
	found, problems []string
}

// faults lists the changes the check makes to a field.
func (s fieldShape) faults() []string {
	var out []string
	if s.pattern != "" && s.value && !s.xml {
		out = append(out, fieldNull)
	}
	if s.pattern != "" {
		out = append(out, fieldDropped)
	}
	if s.list {
		out = append(out, fieldEmptied)
	}
	return out
}

// run makes one change to op's answers, runs the clean scenario with it,
// and judges the run. It returns false when the change changed no answer.
func (ff *fieldFaults) run(op string, s fieldShape, fault string) (fieldRun, bool) {
	k := ff.k
	list := pointerLabel(s.pattern)
	out := fieldRun{pattern: s.pattern, fault: fault, label: op + " " + list + " " + fault}
	run, ok := ff.p.run(perturbation{label: out.label, op: op, text: func(text string) (string, bool) {
		return changeField(text, s, fault)
	}})
	if !ok {
		return out, false
	}
	var declared *fieldDeclaration
	for i, d := range ff.declared {
		if d.covers(op, list, fault) {
			declared = &ff.declared[i]
			ff.made[d.key()] = true
			break
		}
	}
	switch {
	case run.unanswered:
		out.moved = true
		return out, true
	case run.failed():
		out.moved = true
		if !k.required(op) {
			out.failure = fmt.Sprintf("the run failed with exit %d and %s; only Suite.Required operations may fail it, others leave out what they could not read, with a gap", run.res.ExitCode, failureLabel(run.res))
		}
		return out, true
	}
	out.moved = len(k.moved(run)) > 0
	out.found = fieldFaultProblems(k.baseline.Artifacts, run.res.Artifacts, gapsOf(run.res.Result), op, k.suite.GapOperations, k.ignore)
	out.problems = out.found
	if declared != nil && len(out.found) > 0 {
		ff.needed[declared.key()] = true
		out.problems = nil
	}
	return out, true
}

// shapes lists the fields of op's answers in the clean run, parents before
// children. The answer itself comes first, with pattern "".
func (ff *fieldFaults) shapes(op string) []fieldShape {
	consumed := ff.k.consumedBy()
	byPattern := map[string]*fieldShape{}
	add := func(s fieldShape) {
		have, ok := byPattern[s.pattern]
		if !ok {
			byPattern[s.pattern] = &s
			return
		}
		have.value = have.value || s.value
		have.list = have.list || s.list
	}
	for i, r := range ff.k.suite.Scenarios[0].Responses {
		if !containsString(consumed[i], op) {
			continue
		}
		text := ff.k.textOf(op, r)
		if strings.HasPrefix(strings.TrimSpace(text), "<") {
			xmlShapes(text, add)
		} else if doc, ok := decodeJSON(text); ok {
			jsonShapes(doc, add)
		}
	}
	out := make([]fieldShape, 0, len(byPattern))
	for _, s := range byPattern {
		if !pagingField(*s) {
			out = append(out, *s)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].depth != out[j].depth {
			return out[i].depth < out[j].depth
		}
		return out[i].pattern < out[j].pattern
	})
	return out
}

// jsonShapes calls add on each field of a JSON answer, and on the answer
// itself. List items are not fields: their fields' parent is the list.
func jsonShapes(doc any, add func(fieldShape)) {
	eachJSON(doc, func(at place, v any) {
		if at.item {
			return
		}
		items, isList := v.([]any)
		parent, depth := jsonParent(at.pattern)
		add(fieldShape{pattern: at.pattern, parent: parent, depth: depth, value: v != nil, list: isList && len(items) > 0})
	})
}

// jsonParent returns the pattern of the field that holds the field at
// pattern, and how many fields are above it.
func jsonParent(pattern string) (string, int) {
	if pattern == "" {
		return "", 0
	}
	depth := 0
	for _, token := range jsonpointer.Tokens(pattern) {
		if token != "*" {
			depth++
		}
	}
	p := pattern[:strings.LastIndex(pattern, "/")]
	for strings.HasSuffix(p, "/*") {
		p = strings.TrimSuffix(p, "/*")
	}
	return p, depth
}

// moreFields are body fields, by lowercase name, that say whether another
// page follows.
var moreFields = []string{"istruncated", "is_truncated", "hasmore", "has_more", "hasnextpage", "has_next_page", "marker"}

// pagingField reports whether a field only says where the next page is, or
// whether there is one. In JSON that is such a field at the top level, in a
// paging object, or in a GraphQL connection's pageInfo. In XML it is such an
// element anywhere.
func pagingField(s fieldShape) bool {
	if s.pattern == "" {
		return false
	}
	tokens := strings.Split(strings.TrimPrefix(s.pattern, "/"), "/")
	name := strings.ToLower(jsonpointer.Unescape(tokens[len(tokens)-1]))
	paging := slices.Contains(linkFields, name) || slices.Contains(tokenFields, name) || slices.Contains(moreFields, name) || name == "endcursor"
	if !paging || s.xml || len(tokens) == 1 {
		return paging
	}
	holder := strings.ToLower(jsonpointer.Unescape(tokens[len(tokens)-2]))
	return holder == "pageinfo" || (len(tokens) == 2 && slices.Contains(pagingObjects, holder))
}

// changeField makes one change to the field s in an answer's text and
// reports whether it changed anything.
func changeField(text string, s fieldShape, fault string) (string, bool) {
	if s.xml {
		return changeXMLElement(text, s.pattern, fault)
	}
	switch fault {
	case fieldNull:
		return editJSON(text, marshalNoEscape, atPattern(s.pattern, func(v any) (any, bool) { return nil, v != nil }))
	case fieldEmptied:
		return editJSON(text, marshalNoEscape, atPattern(s.pattern, func(v any) (any, bool) {
			items, ok := v.([]any)
			if !ok || len(items) == 0 {
				return v, false
			}
			return []any{}, true
		}))
	}
	i := strings.LastIndex(s.pattern, "/")
	key := jsonpointer.Unescape(s.pattern[i+1:])
	return editJSON(text, marshalNoEscape, atPattern(s.pattern[:i], func(v any) (any, bool) {
		obj, ok := v.(map[string]any)
		if !ok {
			return v, false
		}
		if _, has := obj[key]; !has {
			return v, false
		}
		delete(obj, key)
		return obj, true
	}))
}

// fieldFaultProblems applies the field-fault rule to a run's artifacts:
// every number and boolean keeps its clean value, or is left out under a
// gap, which must name op when nameOp is true. An artifact whose values only
// moved within its lists has no problem, since a field the collector sorts
// by can reorder them. See reordered.
func fieldFaultProblems(clean, faulted []componentsdk.EmittedArtifact, gaps []componentsdk.Gap, op string, nameOp bool, ignore ignoreSet) []string {
	var named, other []componentsdk.Gap
	for _, g := range gaps {
		if !nameOp || g.Operation == op {
			named = append(named, g)
		} else {
			other = append(other, g)
		}
	}
	var problems []string
	cleanByPath, faultedByPath := artifactsByPath(clean), artifactsByPath(faulted)
	for _, path := range sortedKeys(cleanByPath) {
		fa, ok := faultedByPath[path]
		if ok && reordered(cleanByPath[path].Data, fa.Data) {
			continue
		}
		want, err := flatten(cleanByPath[path].Data)
		if err != nil {
			continue
		}
		got := map[string]any{}
		if ok {
			got, _ = flatten(fa.Data)
		}
		pointers := map[string]bool{}
		for p, v := range want {
			pointers[p] = judged(v)
		}
		for p, v := range got {
			pointers[p] = pointers[p] || judged(v)
		}
		for _, p := range sortedKeys(pointers) {
			w, inWant := want[p]
			g, inGot := got[p]
			switch {
			case !pointers[p], ignore.has(path, p), covered(named, path, p):
			case inWant && inGot && reflect.DeepEqual(w, g):
			case w == nil && g == nil:
			default:
				problems = append(problems, describeMove(path, p, w, g, inWant && w != nil, inGot && g != nil, other))
			}
		}
	}
	for _, path := range sortedKeys(faultedByPath) {
		if _, ok := cleanByPath[path]; !ok && !ignore.has(path, "") && !covered(named, path, "") {
			problems = append(problems, fmt.Sprintf("%s appeared", path))
		}
	}
	return problems
}

// reordered reports whether two runs' copies of an artifact differ only in
// the order of their lists and in the strings one run holds and the other
// does not. Those strings, such as names the field the collector sorts by
// fed, are blanked in both before the lists are sorted. A string both runs
// hold keeps its row apart, so a value that moved from one row to another
// still differs.
func reordered(clean, faulted []byte) bool {
	a, okA := decodeJSON(string(clean))
	b, okB := decodeJSON(string(faulted))
	if !okA || !okB {
		return false
	}
	inA, inB := stringsIn(a), stringsIn(b)
	changed := map[string]bool{}
	for s := range inA {
		changed[s] = !inB[s]
	}
	for s := range inB {
		changed[s] = changed[s] || !inA[s]
	}
	rawA, errA := json.Marshal(sortLists(blankStrings(a, changed)))
	rawB, errB := json.Marshal(sortLists(blankStrings(b, changed)))
	return errA == nil && errB == nil && string(rawA) == string(rawB)
}

// stringsIn returns the set of string values in v. Object keys are left
// out.
func stringsIn(v any) map[string]bool {
	out := map[string]bool{}
	eachJSON(v, func(_ place, v any) {
		if s, ok := v.(string); ok {
			out[s] = true
		}
	})
	return out
}

// blankStrings replaces each string value in v that blank holds with "".
// Object keys stay.
func blankStrings(v any, blank map[string]bool) any {
	switch n := v.(type) {
	case string:
		if blank[n] {
			return ""
		}
	case map[string]any:
		for key, child := range n {
			n[key] = blankStrings(child, blank)
		}
	case []any:
		for i, child := range n {
			n[i] = blankStrings(child, blank)
		}
	}
	return v
}

// judged reports whether the rule judges a value: a number or a boolean.
func judged(v any) bool {
	switch v.(type) {
	case json.Number, bool:
		return true
	}
	return false
}

// describeMove says how the value at p moved: left out, changed, or
// appeared. had and has say whether the clean and faulted runs hold a value
// other than null there. It names the operation of a gap that covers the
// value but names another operation, or none.
func describeMove(path, p string, w, g any, had, has bool, other []componentsdk.Gap) string {
	gap := "without a gap"
	for _, og := range other {
		if covered([]componentsdk.Gap{og}, path, p) {
			gap = "under a gap that names no operation"
			if og.Operation != "" {
				gap = "under a gap that names " + og.Operation
			}
			break
		}
	}
	at := path + " " + pointerLabel(p)
	switch {
	case !has:
		return fmt.Sprintf("%s: %s left out %s", at, show(w), gap)
	case !had:
		return fmt.Sprintf("%s: %s appeared %s", at, show(g), gap)
	}
	return fmt.Sprintf("%s: changed from %s to %s %s", at, show(w), show(g), gap)
}

// xmlSpan is one element of an XML answer and where it sits in the text.
type xmlSpan struct {
	path string
	// start and end bound the element, and contentStart and contentEnd its
	// content, as byte offsets.
	start, contentStart, contentEnd, end int64
	children                             []string
}

// xmlSpans lists the elements of an XML answer in document order. It
// returns false for text that is not XML.
func xmlSpans(text string) ([]*xmlSpan, bool) {
	d := xml.NewDecoder(strings.NewReader(text))
	var out, stack []*xmlSpan
	for {
		before := d.InputOffset()
		tok, err := d.RawToken()
		if errors.Is(err, io.EOF) {
			return out, len(stack) == 0 && len(out) > 0
		}
		if err != nil {
			return nil, false
		}
		switch t := tok.(type) {
		case xml.StartElement:
			name := t.Name.Local
			if t.Name.Space != "" {
				name = t.Name.Space + ":" + name
			}
			path := "/" + name
			if len(stack) > 0 {
				top := stack[len(stack)-1]
				top.children = append(top.children, name)
				path = top.path + path
			}
			s := &xmlSpan{path: path, start: before, contentStart: d.InputOffset()}
			out = append(out, s)
			stack = append(stack, s)
		case xml.EndElement:
			if len(stack) == 0 {
				return nil, false
			}
			s := stack[len(stack)-1]
			s.contentEnd, s.end = before, d.InputOffset()
			stack = stack[:len(stack)-1]
		}
	}
}

// isList reports whether an element holds a list: children that share the
// name member or item, or two or more children of one name.
func (s *xmlSpan) isList() bool {
	if len(s.children) == 0 {
		return false
	}
	for _, c := range s.children[1:] {
		if c != s.children[0] {
			return false
		}
	}
	return len(s.children) > 1 || s.children[0] == "member" || s.children[0] == "item"
}

// xmlShapes calls add on each element of an XML answer below its root, and
// on the answer itself. An item of a list is not a field: its elements'
// parent is the list.
func xmlShapes(text string, add func(fieldShape)) {
	spans, ok := xmlSpans(text)
	if !ok {
		return
	}
	add(fieldShape{xml: true})
	lists := map[string]bool{}
	for _, s := range spans {
		if s.isList() {
			lists[s.path] = true
		}
	}
	for _, s := range spans {
		above := s.path[:strings.LastIndex(s.path, "/")]
		if above == "" || lists[above] || mapEntryPart(s.path) {
			continue
		}
		add(fieldShape{pattern: s.path, parent: xmlParent(s.path, lists), depth: strings.Count(s.path, "/") - 1, value: true, list: s.isList(), xml: true})
	}
}

// mapEntryPart reports whether the element at path is the key or value of
// an AWS Query map entry. An entry always has both, so neither is a field
// on its own. Emptying the map is the change that applies.
func mapEntryPart(path string) bool {
	return strings.HasSuffix(path, "/entry/key") || strings.HasSuffix(path, "/entry/value")
}

// xmlParent returns the path of the field that holds the element at path:
// the element above it, or the list above that when the element above it is
// one of the list's items. The root element's children have parent "".
func xmlParent(path string, lists map[string]bool) string {
	p := path[:strings.LastIndex(path, "/")]
	if strings.Count(p, "/") <= 1 {
		return ""
	}
	if above := p[:strings.LastIndex(p, "/")]; lists[above] {
		if strings.Count(above, "/") <= 1 {
			return ""
		}
		return above
	}
	return p
}

// changeXMLElement drops every element at path, or empties every list
// there, and reports whether it changed anything.
func changeXMLElement(text, path, fault string) (string, bool) {
	spans, ok := xmlSpans(text)
	if !ok {
		return "", false
	}
	out, changed := text, false
	for i := len(spans) - 1; i >= 0; i-- {
		s := spans[i]
		if s.path != path {
			continue
		}
		switch {
		case fault == fieldDropped:
			out = out[:s.start] + out[s.end:]
			changed = true
		case fault == fieldEmptied && s.isList():
			out = out[:s.contentStart] + out[s.contentEnd:]
			changed = true
		}
	}
	return out, changed
}
