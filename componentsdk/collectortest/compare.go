package collectortest

import (
	"cmp"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
)

// CompareOptions says how CompareResponses lines two sets of responses up.
type CompareOptions struct {
	// PageParams are the query parameters that page a list, which a call's
	// match leaves out so its pages join. The default is $skiptoken, $skip,
	// cursor, after, page_token, and pageToken.
	PageParams []string

	// Items is the field of a page that holds its items, such as value in
	// Microsoft Graph. A body that is a list holds its items itself.
	Items string

	// Ignore lists fields to leave out of every call, as Fields paths.
	Ignore []string

	// Vocabulary lists the fields whose values are compared, as Fields
	// paths, such as the methods a user has registered. Use it for fields
	// that take one of a set of values, whose spelling a simulator must get
	// right. Other fields are compared by type alone.
	Vocabulary []string
}

// DifferenceKind is what a ResponseDifference found.
type DifferenceKind string

const (
	// OnlyRecorded is a call the recording answers and the simulator does
	// not.
	OnlyRecorded DifferenceKind = "only recorded"
	// OnlySimulated is a call the simulator answers and the recording does
	// not.
	OnlySimulated DifferenceKind = "only simulated"
	// StatusDiffers is a call the two answer with different statuses.
	StatusDiffers DifferenceKind = "status"
	// FieldMissing is a field the recording has and the simulator lacks.
	FieldMissing DifferenceKind = "missing"
	// FieldExtra is a field the simulator has and the recording lacks.
	FieldExtra DifferenceKind = "extra"
	// TypeDiffers is a field whose JSON types differ, null among them.
	TypeDiffers DifferenceKind = "type"
	// ValuesDiffer is a vocabulary field one side gives a value the other
	// never does.
	ValuesDiffer DifferenceKind = "values"
	// CountDiffers is a list call whose pages hold different numbers of
	// items.
	CountDiffers DifferenceKind = "count"
)

// ResponseDifference is one way a simulator's responses differ from a
// recording's.
type ResponseDifference struct {
	// Call is the method, host, path, and query the two matched on.
	Call  string
	Field string
	Kind  DifferenceKind
	// Recorded and Simulated describe each side: a status, a count, the
	// field's types, or the values only that side gives.
	Recorded, Simulated string
}

func (d ResponseDifference) String() string {
	field := ""
	if d.Field != "" {
		field = " " + d.Field
	}
	return fmt.Sprintf("%s%s: %s (recorded %s, simulated %s)", d.Call, field, d.Kind, cmp.Or(d.Recorded, "nothing"), cmp.Or(d.Simulated, "nothing"))
}

// CompareResponses compares a simulator's responses with a recording of
// the tenant it simulates, so a simulator that drifts from the vendor
// shows. Responses match by method, host, path, and query, less
// PageParams, and the pages of a list join into one. A field is a path such
// as value[].signInActivity.lastSignInDateTime, where [] stands for every
// element of a list, and a field the other side lacks is reported once, not
// again for the fields under it. The differences come sorted by call and
// field.
func CompareResponses(recorded, simulated []Response, opts CompareOptions) []ResponseDifference {
	if opts.PageParams == nil {
		opts.PageParams = []string{"$skiptoken", "$skip", "cursor", "after", "page_token", "pageToken"}
	}
	rec, sim := opts.calls(recorded), opts.calls(simulated)
	var out []ResponseDifference
	for _, key := range unionKeys(rec, sim) {
		r, rok := rec[key]
		s, sok := sim[key]
		switch {
		case !sok:
			out = append(out, ResponseDifference{Call: key, Kind: OnlyRecorded, Recorded: fmt.Sprint(r.status)})
			continue
		case !rok:
			out = append(out, ResponseDifference{Call: key, Kind: OnlySimulated, Simulated: fmt.Sprint(s.status)})
			continue
		}
		if r.status != s.status {
			out = append(out, ResponseDifference{Call: key, Kind: StatusDiffers, Recorded: fmt.Sprint(r.status), Simulated: fmt.Sprint(s.status)})
		}
		if r.items >= 0 && s.items >= 0 && r.items != s.items {
			out = append(out, ResponseDifference{Call: key, Kind: CountDiffers, Recorded: fmt.Sprint(r.items), Simulated: fmt.Sprint(s.items)})
		}
		var gone []string
		for _, field := range unionKeys(r.kinds, s.kinds) {
			if slices.ContainsFunc(gone, func(parent string) bool { return under(field, parent) }) {
				continue
			}
			rk, rok := r.kinds[field]
			sk, sok := s.kinds[field]
			switch {
			case !sok:
				gone = append(gone, field)
				out = append(out, ResponseDifference{Call: key, Field: field, Kind: FieldMissing, Recorded: setString(rk)})
			case !rok:
				gone = append(gone, field)
				out = append(out, ResponseDifference{Call: key, Field: field, Kind: FieldExtra, Simulated: setString(sk)})
			case setString(rk) != setString(sk):
				out = append(out, ResponseDifference{Call: key, Field: field, Kind: TypeDiffers, Recorded: setString(rk), Simulated: setString(sk)})
			}
		}
		for _, field := range opts.Vocabulary {
			onlyRec, onlySim := difference(r.values[field], s.values[field]), difference(s.values[field], r.values[field])
			if len(onlyRec)+len(onlySim) > 0 && r.kinds[field] != nil && s.kinds[field] != nil {
				out = append(out, ResponseDifference{Call: key, Field: field, Kind: ValuesDiffer, Recorded: strings.Join(onlyRec, ", "), Simulated: strings.Join(onlySim, ", ")})
			}
		}
	}
	return out
}

// call is what one side's responses to a call hold.
type call struct {
	status int
	// items counts a list's items over its pages, or is -1 for a call
	// that is no list.
	items  int
	kinds  map[string]map[string]bool
	values map[string]map[string]bool
}

func (o CompareOptions) calls(responses []Response) map[string]*call {
	out := map[string]*call{}
	for _, resp := range responses {
		key := o.callKey(resp)
		c := out[key]
		if c == nil {
			c = &call{status: cmp.Or(resp.Status, http.StatusOK), items: -1, kinds: map[string]map[string]bool{}, values: map[string]map[string]bool{}}
			out[key] = c
		}
		if strings.TrimSpace(resp.Body) == "" {
			continue
		}
		var body any
		if err := json.Unmarshal([]byte(resp.Body), &body); err != nil {
			c.add("(body)", "not json", "")
			continue
		}
		if items, ok := o.pageItems(body); ok {
			c.items = max(c.items, 0) + len(items)
		}
		o.walk(c, "", body)
	}
	return out
}

func (o CompareOptions) pageItems(body any) ([]any, bool) {
	if list, ok := body.([]any); ok {
		return list, true
	}
	if m, ok := body.(map[string]any); ok && o.Items != "" {
		list, ok := m[o.Items].([]any)
		return list, ok
	}
	return nil, false
}

func (o CompareOptions) walk(c *call, path string, v any) {
	if path != "" && slices.Contains(o.Ignore, path) {
		return
	}
	switch v := v.(type) {
	case map[string]any:
		c.add(path, "object", "")
		for k, child := range v {
			o.walk(c, join(path, k), child)
		}
	case []any:
		c.add(path, "list", "")
		for _, child := range v {
			o.walk(c, path+"[]", child)
		}
	case string:
		c.add(path, "string", v)
	case float64:
		c.add(path, "number", fmt.Sprint(v))
	case bool:
		c.add(path, "boolean", fmt.Sprint(v))
	default:
		c.add(path, "null", "")
	}
}

func (c *call) add(path, kind, value string) {
	if path == "" {
		return
	}
	if c.kinds[path] == nil {
		c.kinds[path] = map[string]bool{}
	}
	c.kinds[path][kind] = true
	if kind != "object" && kind != "list" && kind != "null" {
		if c.values[path] == nil {
			c.values[path] = map[string]bool{}
		}
		c.values[path][value] = true
	}
}

// callKey is a response's method, host, path, and sorted query, less the
// parameters that page.
func (o CompareOptions) callKey(resp Response) string {
	method := cmp.Or(resp.Method, http.MethodGet)
	u, err := url.Parse(resp.URL)
	if err != nil {
		return method + " " + resp.URL
	}
	query := u.Query()
	for _, p := range o.PageParams {
		query.Del(p)
	}
	key := method + " " + u.Host + u.Path
	if q := query.Encode(); q != "" {
		// Encode escapes the $ and commas of a query such as Graph's
		// $select, and the key is for people to read.
		if unescaped, err := url.QueryUnescape(q); err == nil {
			q = unescaped
		}
		key += "?" + q
	}
	return key
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

func unionKeys[V any](a, b map[string]V) []string {
	var keys []string
	for k := range a {
		keys = append(keys, k)
	}
	for k := range b {
		if _, ok := a[k]; !ok {
			keys = append(keys, k)
		}
	}
	slices.Sort(keys)
	return keys
}

func setString(set map[string]bool) string {
	var items []string
	for k := range set {
		items = append(items, k)
	}
	slices.Sort(items)
	return strings.Join(items, " or ")
}

func difference(a, b map[string]bool) []string {
	var out []string
	for k := range a {
		if !b[k] {
			out = append(out, k)
		}
	}
	slices.Sort(out)
	return out
}
