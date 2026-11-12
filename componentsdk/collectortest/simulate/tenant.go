// Package simulate builds a vendor simulator from a roster and checks a
// collector against the values roster.Derive gives for it.
//
// A simulator answers every call a collector makes for the tenant a roster
// describes, as the vendor answers them. Most of one is a Tenant: for each
// endpoint, the recorded operation it mirrors, the URL, what the call
// needs, how the vendor pages it, and the roster's entries rendered as the
// vendor's JSON. Once the sandbox has a recording, each item is a copy of a
// recorded one with the fields the roster decides set (see Recorded), and
// the harness checks every answer's shape against the recording. The kit
// supplies the paging styles, the refusals for a missing permission or
// plan, and stable IDs. Only the shapes and the error body are the
// vendor's.
//
// A Harness then runs the collector against the simulator and lines its
// normalized artifacts up with the derived values. Each value the collector
// reports otherwise must be listed with a Verdict, so a new difference
// fails, and so does a listed one that goes away.
package simulate

import (
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/locktivity/epack/componentsdk/collectortest"
)

// Tenant collects a simulator's responses and answers each call the way
// the vendor would for the credential the collector holds.
type Tenant struct {
	// Granted lists the permissions or scopes the collector's credential
	// holds.
	Granted []string
	// Plan is the tenant's plan, one of Plans, which lists the vendor's
	// plans from the lowest. An empty Plan is the lowest.
	Plan  string
	Plans []string
	// Refuse renders the vendor's answer to a call the credential or the
	// plan does not allow. The kit sets the URL and method.
	Refuse func(Refusal) collectortest.Response
	// PageSize, when set, replaces each pager's size, as a server may.
	PageSize int

	responses []collectortest.Response
}

// Need is what a call needs: one permission from each group of AnyOf, and
// at least Plan.
type Need struct {
	AnyOf [][]string
	Plan  string
}

// Needs is a Need of one permission from each group given, on any plan.
func Needs(anyOf ...[]string) Need { return Need{AnyOf: anyOf} }

// Refusal is why a call is refused: a group of permissions the credential
// holds none of, or the plan the call needs.
type Refusal struct {
	Permissions []string
	Plan        string
}

// Refused reports why the tenant refuses a call that needs n. A missing
// permission comes before a missing plan, as most vendors check the
// credential first.
func (t *Tenant) Refused(n Need) (Refusal, bool) {
	for _, group := range n.AnyOf {
		if !slices.ContainsFunc(group, func(p string) bool { return slices.Contains(t.Granted, p) }) {
			return Refusal{Permissions: group}, true
		}
	}
	if t.rank(n.Plan) > t.rank(t.Plan) {
		return Refusal{Plan: n.Plan}, true
	}
	return Refusal{}, false
}

func (t *Tenant) rank(plan string) int {
	if plan == "" {
		return 0
	}
	i := slices.Index(t.Plans, plan)
	if i < 0 {
		panic(fmt.Sprintf("simulate: plan %q is not one of %v", plan, t.Plans))
	}
	return i
}

// Get answers a GET of url, the operation op names, with body, or with the
// refusal.
func (t *Tenant) Get(op, url string, n Need, body any) { t.Do(op, http.MethodGet, url, n, body) }

// Do answers a call to op with body, a string or a value to encode as
// JSON, or with the refusal. op is the operation's name in the recording,
// which is the collector's, and the request must carry it too.
func (t *Tenant) Do(op, method, url string, n Need, body any) {
	if t.refuse(op, method, url, n) {
		return
	}
	text, ok := body.(string)
	if !ok {
		text = JSON(body)
	}
	t.Add(collectortest.Response{Operation: op, Method: method, URL: url, Body: text})
}

// List answers a list at url, the operation op names, in the pages p
// makes of items, or with the refusal.
func (t *Tenant) List(op, url string, n Need, p Pager, items []any) {
	if t.refuse(op, http.MethodGet, url, n) {
		return
	}
	if items == nil {
		items = []any{}
	}
	for _, page := range p.Pages(url, items, t.PageSize) {
		page.Operation = op
		t.Add(page)
	}
}

func (t *Tenant) refuse(op, method, url string, n Need) bool {
	refusal, refused := t.Refused(n)
	if !refused {
		return false
	}
	if t.Refuse == nil {
		panic("simulate: the tenant refuses " + url + " and has no Refuse")
	}
	r := t.Refuse(refusal)
	r.Operation, r.Method, r.URL = op, method, url
	t.Add(r)
	return true
}

// Add appends responses as they are.
func (t *Tenant) Add(rs ...collectortest.Response) { t.responses = append(t.responses, rs...) }

// Responses returns every response, in the order added.
func (t *Tenant) Responses() []collectortest.Response { return slices.Clone(t.responses) }

// Each renders each entry with render.
func Each[T any](entries []T, render func(T) any) []any {
	out := make([]any, 0, len(entries))
	for _, e := range entries {
		out = append(out, render(e))
	}
	return out
}

// JSON encodes v, which must encode.
func JSON(v any) string {
	raw, err := json.Marshal(v)
	if err != nil {
		panic(fmt.Sprintf("simulate: %v", err))
	}
	return string(raw)
}

// withParam adds a query parameter to u.
func withParam(u, name, value string) string {
	sep := "&"
	if !strings.Contains(u, "?") {
		sep = "?"
	} else if strings.HasSuffix(u, "?") {
		sep = ""
	}
	return u + sep + name + "=" + value
}

// exactly makes a URL with no query match only a request with none, since
// the next pages add one.
func exactly(u string) string {
	if strings.Contains(u, "?") {
		return u
	}
	return u + "?"
}
