package collectortest

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"slices"
	"sort"
	"strings"

	"github.com/locktivity/epack/componentsdk"
)

// The order check reports a collector value that depends on the order a
// vendor lists things in. Vendors rarely promise an order. AWS, for example,
// documents that DescribeRegions may list regions in any order. For each
// operation, the check runs the clean scenario with every list in that
// operation's answers reversed. A list is a JSON array or a run of sibling
// XML elements with the same name. The check then compares each artifact
// with its lists sorted. Rows may come out in another order, but no value
// may change. An operation waived as ordered is exempt. Its answers come in
// an order the vendor documents, such as a list sorted by a parameter the
// collector sends.

// maxOrderChanges is the largest number of changed values one operation's
// violation lists.
const maxOrderChanges = 3

func (k *kit) checkOrder() {
	p := perturber{k: k, check: "order"}
	for _, op := range k.pickOps(opPick{skipInsensitive: true, exempt: sorted(k.waived.ordered)}) {
		run, ok := p.run(perturbation{label: op.Name, op: op.Name, text: reverseText})
		switch {
		case !ok, run.unanswered:
			continue
		case run.failed():
			k.violate("order", op.Name, "reversing the lists in %s's answers failed the run with %s", op.Name, failureLabel(run.res))
			continue
		}
		moved := k.moved(run)
		if len(moved) == 0 {
			continue
		}
		shown := moved[:min(len(moved), maxOrderChanges)]
		more := ""
		if len(moved) > len(shown) {
			more = fmt.Sprintf(", and %d more", len(moved)-len(shown))
		}
		k.violate("order", op.Name, "reversing the lists in %s's answers changed %s%s. A value must not depend on the order a vendor lists things in. "+
			"Read the field that sets the order, such as a priority or a date, or waive %s as ordered if the vendor documents its order",
			op.Name, strings.Join(shown, "; "), more, op.Name)
	}
}

// reverseText reverses the lists in an XML or JSON body. It reports false
// for a body with no list of two or more items, or for a body it cannot
// read.
func reverseText(text string) (string, bool) {
	return parseAnswer(text).reversed()
}

// reverseJSON reverses every array in a JSON document.
func reverseJSON(body string) (string, bool) {
	return editJSON(body, marshalNoEscape, reverseArrays)
}

// reverseArrays is a jsonEdit that reverses each array of two or more
// items.
func reverseArrays(_ place, v any) (any, bool, bool) {
	if n, ok := v.([]any); ok && len(n) > 1 {
		slices.Reverse(n)
		return n, true, true
	}
	return v, false, true
}

// xmlNode is an element's place in a document. It holds the element's name
// and the byte span from its start tag through its end tag.
type xmlNode struct {
	name       string
	start, end int64
	children   []*xmlNode
}

// reverseXML reverses each run of sibling elements that share a name, such
// as AWS's <item> and <member> lists. It moves each element's bytes whole.
// Everything else, including the prolog, namespaces, and whitespace, stays
// as it was.
func reverseXML(body string) (string, bool) {
	dec := xml.NewDecoder(strings.NewReader(body))
	var roots []*xmlNode
	var stack []*xmlNode
	for {
		at := dec.InputOffset()
		tok, err := dec.RawToken()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", false
		}
		switch t := tok.(type) {
		case xml.StartElement:
			stack = append(stack, &xmlNode{name: t.Name.Space + ":" + t.Name.Local, start: at})
		case xml.EndElement:
			if len(stack) == 0 {
				return "", false
			}
			n := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			n.end = dec.InputOffset()
			if len(stack) == 0 {
				roots = append(roots, n)
			} else {
				parent := stack[len(stack)-1]
				parent.children = append(parent.children, n)
			}
		}
	}
	if len(stack) != 0 || len(roots) == 0 {
		return "", false
	}
	changed := false
	var b strings.Builder
	var render func(n *xmlNode)
	render = func(n *xmlNode) {
		if len(n.children) == 0 {
			b.WriteString(body[n.start:n.end])
			return
		}
		order := slices.Clone(n.children)
		for i := 0; i < len(order); {
			j := i
			for j+1 < len(order) && order[j+1].name == order[i].name {
				j++
			}
			if j > i {
				slices.Reverse(order[i : j+1])
				changed = true
			}
			i = j + 1
		}
		b.WriteString(body[n.start:n.children[0].start])
		for i, child := range order {
			render(child)
			if i+1 < len(n.children) {
				b.WriteString(body[n.children[i].end:n.children[i+1].start])
			}
		}
		b.WriteString(body[n.children[len(n.children)-1].end:n.end])
	}
	b.WriteString(body[:roots[0].start])
	for i, root := range roots {
		render(root)
		if i+1 < len(roots) {
			b.WriteString(body[root.end:roots[i+1].start])
		}
	}
	b.WriteString(body[roots[len(roots)-1].end:])
	if !changed {
		return "", false
	}
	return b.String(), true
}

// sortedArtifacts flattens each data artifact with every list sorted. Two
// runs that list the same rows in a different order then compare equal.
func sortedArtifacts(artifacts []componentsdk.EmittedArtifact) map[string]map[string]any {
	out := map[string]map[string]any{}
	for path, a := range artifactsByPath(artifacts) {
		doc, ok := decodeJSON(string(a.Data))
		if !ok {
			continue
		}
		raw, err := json.Marshal(sortLists(doc))
		if err != nil {
			continue
		}
		if flat, err := flatten(raw); err == nil {
			out[path] = flat
		}
	}
	return out
}

// sortLists sorts the lists inside each item of every array in v, then sorts
// the array by its items' JSON. A string that holds a JSON object or array is
// sorted the same way. One example is a policy document the collector copies
// as the vendor sent it. A copy of a reordered document then compares equal.
func sortLists(v any) any {
	switch n := v.(type) {
	case string:
		trimmed := strings.TrimSpace(n)
		if !strings.HasPrefix(trimmed, "{") && !strings.HasPrefix(trimmed, "[") {
			return n
		}
		doc, ok := decodeJSON(trimmed)
		if !ok {
			return n
		}
		raw, err := json.Marshal(sortLists(doc))
		if err != nil {
			return n
		}
		return string(raw)
	case map[string]any:
		for key, child := range n {
			n[key] = sortLists(child)
		}
	case []any:
		keys := make([]string, len(n))
		for i := range n {
			n[i] = sortLists(n[i])
			raw, _ := json.Marshal(n[i])
			keys[i] = string(raw)
		}
		idx := make([]int, len(n))
		for i := range idx {
			idx[i] = i
		}
		sort.SliceStable(idx, func(a, b int) bool { return keys[idx[a]] < keys[idx[b]] })
		sorted := make([]any, len(n))
		for i, j := range idx {
			sorted[i] = n[j]
		}
		return sorted
	}
	return v
}

// diffSorted lists each value that differs between two sorted runs, by
// artifact path and pointer. It skips what the suite waives with WaiveIgnore.
func diffSorted(clean, got map[string]map[string]any, ignore ignoreSet) []string {
	var out []string
	for _, path := range sortedKeys(clean) {
		want, have := clean[path], got[path]
		if have == nil {
			out = append(out, fmt.Sprintf("%s: artifact left out", path))
			continue
		}
		pointers := map[string]bool{}
		for p := range want {
			pointers[p] = true
		}
		for p := range have {
			pointers[p] = true
		}
		for _, p := range sortedKeys(pointers) {
			if ignore.has(path, p) {
				continue
			}
			w, inWant := want[p]
			h, inHave := have[p]
			switch {
			case inWant && inHave && fmt.Sprint(w) == fmt.Sprint(h):
			case !inHave:
				out = append(out, fmt.Sprintf("%s %s from %s to absent", path, pointerLabel(p), showLeaf(w)))
			case !inWant:
				out = append(out, fmt.Sprintf("%s %s from absent to %s", path, pointerLabel(p), showLeaf(h)))
			default:
				out = append(out, fmt.Sprintf("%s %s from %s to %s", path, pointerLabel(p), showLeaf(w), showLeaf(h)))
			}
		}
	}
	return out
}

func showLeaf(v any) string {
	switch v {
	case emptyObject:
		return "{}"
	case emptyArray:
		return "[]"
	case nil:
		return "null"
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprint(v)
	}
	return string(raw)
}
