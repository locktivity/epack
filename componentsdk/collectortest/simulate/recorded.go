package simulate

import (
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"

	"github.com/locktivity/epack/componentsdk/collectortest"
)

// Recorded is a sandbox's recording, by operation: the items a simulator
// builds its answers from, and the shapes every answer it builds must keep.
// Once a sandbox has a recording, a simulator copies a recorded item for
// each one it answers with and sets only the fields the roster decides, so
// its answers carry the vendor's nulls, optional fields, and list and read
// shapes.
type Recorded struct {
	path string
	ok   map[string][]collectortest.Response
	// failed holds the answers whose status is not 2xx, by status.
	failed map[int][]collectortest.Response

	mu    sync.Mutex
	items map[string][]map[string]any
}

// LoadRecorded reads a recording that collectortest's TestRecord wrote.
func LoadRecorded(path string) (*Recorded, error) {
	sc, err := collectortest.LoadScenario(path)
	if err != nil {
		return nil, err
	}
	r := &Recorded{path: path, ok: map[string][]collectortest.Response{}, failed: map[int][]collectortest.Response{}}
	for _, resp := range sc.Responses {
		if resp.Operation == "" {
			return nil, fmt.Errorf("%s: an answer to %s names no operation", path, resp.URL)
		}
		if succeeded(resp.Status) {
			r.ok[resp.Operation] = append(r.ok[resp.Operation], resp)
		} else {
			r.failed[resp.Status] = append(r.failed[resp.Status], resp)
		}
	}
	return r, nil
}

func succeeded(status int) bool { return status == 0 || (status >= 200 && status < 300) }

// Operations lists the operations the recording answers.
func (r *Recorded) Operations() []string { return slices.Sorted(maps.Keys(r.ok)) }

// Items returns copies of every item the recorded answers to op hold: the
// elements of a body that is a list, or of the list in field, or the body
// itself when it is an object and field is empty.
func (r *Recorded) Items(op, field string) []map[string]any {
	var out []map[string]any
	for _, item := range r.parsed(op, field) {
		out = append(out, deepCopy(item))
	}
	return out
}

// parsed returns the items Items copies, read once.
func (r *Recorded) parsed(op, field string) []map[string]any {
	r.mu.Lock()
	defer r.mu.Unlock()
	key := op + "\x00" + field
	if items, ok := r.items[key]; ok {
		return items
	}
	var out []map[string]any
	for _, resp := range r.ok[op] {
		var body any
		if err := json.Unmarshal([]byte(resp.Body), &body); err != nil {
			continue
		}
		if field != "" {
			m, _ := body.(map[string]any)
			body = m[field]
		}
		switch b := body.(type) {
		case []any:
			for _, item := range b {
				if m, ok := item.(map[string]any); ok {
					out = append(out, m)
				}
			}
		case map[string]any:
			out = append(out, b)
		}
	}
	if r.items == nil {
		r.items = map[string][]map[string]any{}
	}
	r.items[key] = out
	return out
}

// Like returns a copy of a recorded item of op: the first the first pick
// accepts, else the first the next pick accepts, and so on, or the first
// item when no pick accepts one. Picks go from the closest kind of item to
// the loosest, such as the same app, then the same sign-on mode. It panics
// when the recording holds no item for op, since a simulator can build no
// answer for a call the sandbox never answered.
func (r *Recorded) Like(op, field string, picks ...func(map[string]any) bool) map[string]any {
	items := r.parsed(op, field)
	if len(items) == 0 {
		panic(fmt.Sprintf("simulate: %s holds no item for %s", r.path, op))
	}
	for _, pick := range picks {
		if i := slices.IndexFunc(items, pick); i >= 0 {
			return deepCopy(items[i])
		}
	}
	return deepCopy(items[0])
}

// Body returns a copy of the first recorded answer to op, for a read or a
// list's envelope. It panics when the recording holds no answer to op.
func (r *Recorded) Body(op string) map[string]any {
	for _, resp := range r.ok[op] {
		var body map[string]any
		if err := json.Unmarshal([]byte(resp.Body), &body); err == nil {
			return body
		}
	}
	panic(fmt.Sprintf("simulate: %s holds no object answer to %s", r.path, op))
}

func deepCopy(m map[string]any) map[string]any {
	var out map[string]any
	if err := json.Unmarshal([]byte(JSON(m)), &out); err != nil {
		panic(err)
	}
	return out
}

// Set sets the field at path, field names joined by /, in an item, copying
// each map on the way.
func Set(item map[string]any, path string, value any) { setPath(item, path, value) }

// Drop removes the field at path, field names joined by /, from an item.
func Drop(item map[string]any, path string) {
	parts := strings.Split(path, "/")
	for _, part := range parts[:len(parts)-1] {
		next, ok := item[part].(map[string]any)
		if !ok {
			return
		}
		item = next
	}
	delete(item, parts[len(parts)-1])
}

// ShapeDifference is one way a simulated answer's shape differs from the
// recorded answers to its operation.
type ShapeDifference struct {
	Operation string
	// Field is a path such as [].profile.login, where [] stands for every
	// element of a list, or empty for the call itself.
	Field string
	// Kind is unrecorded operation, unrecorded status, unrecorded field,
	// type, or missing field.
	Kind string
	// Recorded and Simulated give the JSON types each side holds.
	Recorded, Simulated string
}

// Key is the difference without the types, as Harness.Unrecorded lists it.
func (d ShapeDifference) Key() string {
	field := ""
	if d.Field != "" {
		field = " " + d.Field
	}
	return d.Operation + field + ": " + d.Kind
}

func (d ShapeDifference) String() string {
	if d.Recorded == "" && d.Simulated == "" {
		return d.Key()
	}
	return fmt.Sprintf("%s (recorded %s, simulated %s)", d.Key(), orNothing(d.Recorded), orNothing(d.Simulated))
}

func orNothing(s string) string {
	if s == "" {
		return "nothing"
	}
	return s
}

// Check compares each simulated answer with the recorded answers to the
// operation it names, ignoring values and counts: each field it holds must
// be one the recording holds there, with a JSON type the recording gives it,
// null among them, and each field the recording holds in every object at
// that place must be in each such object. A failed answer is compared with
// the recorded answers of the same status to any operation. An answer that
// names no operation, or an operation or status the recording never
// answers, is a difference too.
func (r *Recorded) Check(simulated []collectortest.Response) []ShapeDifference {
	seen := map[string]bool{}
	var out []ShapeDifference
	add := func(d ShapeDifference) {
		if !seen[d.String()] {
			seen[d.String()] = true
			out = append(out, d)
		}
	}
	shapes := map[string]*shape{}
	recordedShape := func(key string, answers []collectortest.Response) *shape {
		if s, ok := shapes[key]; ok {
			return s
		}
		s := newShape()
		for _, a := range answers {
			s.read(a.Body)
		}
		shapes[key] = s
		return s
	}
	for _, resp := range simulated {
		op := resp.Operation
		if op == "" {
			add(ShapeDifference{Operation: resp.URL, Kind: "names no operation"})
			continue
		}
		var rec *shape
		switch {
		case succeeded(resp.Status) && len(r.ok[op]) == 0:
			add(ShapeDifference{Operation: op, Kind: "unrecorded operation"})
			continue
		case succeeded(resp.Status):
			rec = recordedShape(op, r.ok[op])
		case len(r.failed[resp.Status]) == 0:
			add(ShapeDifference{Operation: op, Kind: fmt.Sprintf("unrecorded status %d", resp.Status)})
			continue
		default:
			rec = recordedShape(fmt.Sprint(resp.Status), r.failed[resp.Status])
		}
		if strings.TrimSpace(resp.Body) == "" {
			continue
		}
		sim := newShape()
		sim.read(resp.Body)
		for _, d := range rec.differences(sim) {
			d.Operation = op
			add(d)
		}
	}
	slices.SortFunc(out, func(a, b ShapeDifference) int { return strings.Compare(a.String(), b.String()) })
	return out
}

// shape is what a set of answers holds at each field: its JSON types, and
// in how many of the objects at its parent's place it appears.
type shape struct {
	kinds   map[string]map[string]bool
	objects map[string]int
	present map[string]int
	parent  map[string]string
}

func newShape() *shape {
	return &shape{kinds: map[string]map[string]bool{}, objects: map[string]int{}, present: map[string]int{}, parent: map[string]string{}}
}

func (s *shape) read(body string) {
	var v any
	if err := json.Unmarshal([]byte(body), &v); err != nil {
		s.add("", "not json")
		return
	}
	s.walk("", v)
}

func (s *shape) walk(path string, v any) {
	s.add(path, kindOf(v))
	switch v := v.(type) {
	case map[string]any:
		s.objects[path]++
		for k, child := range v {
			p := join(path, k)
			s.present[p]++
			s.parent[p] = path
			s.walk(p, child)
		}
	case []any:
		for _, child := range v {
			s.walk(path+"[]", child)
		}
	}
}

func (s *shape) add(path, kind string) {
	if s.kinds[path] == nil {
		s.kinds[path] = map[string]bool{}
	}
	s.kinds[path][kind] = true
}

func kindOf(v any) string {
	switch v.(type) {
	case map[string]any:
		return "object"
	case []any:
		return "list"
	case string:
		return "string"
	case float64:
		return "number"
	case bool:
		return "boolean"
	}
	return "null"
}

// differences lists how sim departs from the recorded shape s.
func (s *shape) differences(sim *shape) []ShapeDifference {
	var out []ShapeDifference
	var unrecorded []string
	for _, path := range slices.Sorted(maps.Keys(sim.kinds)) {
		if slices.ContainsFunc(unrecorded, func(parent string) bool { return under(path, parent) }) {
			continue
		}
		rec, ok := s.kinds[path]
		if !ok {
			unrecorded = append(unrecorded, path)
			out = append(out, ShapeDifference{Field: path, Kind: "unrecorded field", Simulated: setString(sim.kinds[path])})
			continue
		}
		var extra []string
		for k := range sim.kinds[path] {
			if !rec[k] {
				extra = append(extra, k)
			}
		}
		if len(extra) > 0 {
			out = append(out, ShapeDifference{Field: path, Kind: "type", Recorded: setString(rec), Simulated: setString(sim.kinds[path])})
		}
	}
	for _, path := range slices.Sorted(maps.Keys(s.present)) {
		parent := s.parent[path]
		always := s.present[path] == s.objects[parent]
		if always && sim.objects[parent] > 0 && sim.present[path] < sim.objects[parent] {
			out = append(out, ShapeDifference{Field: path, Kind: "missing field", Recorded: setString(s.kinds[path])})
		}
	}
	return out
}

// checkShapes fails t on each shape difference in responses that
// unrecorded doesn't list, once per test, and notes each listed one it
// meets.
func checkShapes(t interface{ Errorf(string, ...any) }, rec *Recorded, responses []collectortest.Response, unrecorded map[string]string, met, reported map[string]bool) {
	if rec == nil {
		return
	}
	for _, d := range rec.Check(responses) {
		if _, listed := unrecorded[d.Key()]; listed {
			met[d.Key()] = true
			continue
		}
		if !reported[d.String()] {
			reported[d.String()] = true
			t.Errorf("simulated answer's shape: %s", d)
		}
	}
}

func join(path, key string) string {
	if path == "" {
		return key
	}
	return path + "." + key
}

// under reports whether field is parent or a field within it.
func under(field, parent string) bool {
	return field == parent || strings.HasPrefix(field, parent+".") || strings.HasPrefix(field, parent+"[]")
}

func setString(set map[string]bool) string {
	return strings.Join(slices.Sorted(maps.Keys(set)), " or ")
}
