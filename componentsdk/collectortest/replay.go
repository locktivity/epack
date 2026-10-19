package collectortest

import (
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/locktivity/epack/componentsdk"
	"github.com/locktivity/epack/componentsdk/internal/outputcheck"
)

// Scenario is one state of a tenant, as canned responses, DNS records, and
// endpoints.
type Scenario struct {
	// Name labels the scenario in reports.
	Name string

	// Responses answer the collector's requests.
	Responses []Response

	// DNS answers the lookups of the collector's componentsdk.Resolver. A
	// name with no record answers NXDOMAIN.
	DNS []DNSRecord

	// Endpoints answer the dials of the collector's componentsdk.Dialer. A
	// dial to an address with no endpoint is refused and reported.
	Endpoints []Endpoint

	// Config, Secrets, and Env override Suite.Config, Suite.Secrets, and
	// Suite.Env for this scenario's runs, key by key. The secrets of every
	// scenario are canaries in every run. A recording's Config, when it has
	// one, is the whole configuration of its runs instead.
	Config  map[string]any
	Secrets map[string]string
	Env     map[string]string

	// ExpectFailure makes the scenario expect the run to fail with this
	// code, such as a scenario where the sign-in is rejected. Empty means
	// the run must succeed.
	ExpectFailure componentsdk.Code

	// Expect pins values the scenario must produce, by artifact path and
	// JSON pointer, such as what a fixed collector reports for the incident
	// the scenario replays. Values compare as JSON, and a pinned null also
	// matches an absent value.
	Expect map[string]map[string]any

	// source is the file LoadScenario read the scenario from, and
	// recordedAt the moment the recording was made, which its runs see as
	// the time.
	source     string
	recordedAt time.Time
}

// Response is one canned response.
type Response struct {
	// Operation matches requests the collector named this way. Leave it
	// empty to match by Method and URL.
	Operation string

	// Method defaults to GET.
	Method string

	// URL matches the request's scheme, host, and path, and its query when
	// URL has one. Query parameters match in any order. A URL that ends in ?
	// matches only a request without a query.
	URL string

	// Status defaults to 200.
	Status int

	Header http.Header
	Body   string

	// Times limits how many requests this response answers. Responses with
	// the same match answer in the order listed, which suits pagination.
	// Zero means every request.
	Times int

	// RequestBody, when set, is a JSON document the request's body must
	// contain: each key of an object it lists must match recursively, and
	// any other value must be equal. A form-encoded body, as AWS's Query and
	// EC2 calls send, matches as an object of its fields, each a string, or
	// a list of strings when repeated. Calls to one URL that differ only in
	// their bodies, such as per-item JSON-RPC or Query calls, then get their
	// own answers, so a fault on one cannot shift the answers of the rest.
	RequestBody string
}

type replayEntry struct {
	resp     Response
	method   string
	target   *url.URL
	hasQuery bool
	body     any
	hasBody  bool
	used     int
	ops      map[string]bool
	hosts    map[string]bool
}

// Replay answers requests from a scenario's canned responses, as it does in
// each of the kit's runs. Pass it as componentsdk.InProcessOptions.Transport
// for a focused test of one run. A request no response matches gets a 404
// and is listed by Unmatched.
type Replay struct {
	mu        sync.Mutex
	entries   []*replayEntry
	unmatched []string
	answers   *answerLog
}

// NewReplay returns a Replay of s's responses. It fails when a response has
// a URL without a scheme and host, neither an operation nor a URL, or a
// RequestBody that is not JSON.
func NewReplay(s Scenario) (*Replay, error) {
	r := &Replay{}
	for i, resp := range s.Responses {
		e := &replayEntry{resp: resp, method: strings.ToUpper(resp.Method), ops: map[string]bool{}, hosts: map[string]bool{}}
		if e.method == "" {
			e.method = http.MethodGet
		}
		if resp.Operation == "" || resp.URL != "" {
			u, err := url.Parse(resp.URL)
			if err != nil || u.Host == "" {
				return nil, fmt.Errorf("scenario %q response %d: URL %q needs a scheme and host", s.Name, i, resp.URL)
			}
			e.target = u
			e.hasQuery = u.RawQuery != "" || u.ForceQuery
		}
		if resp.RequestBody != "" {
			body, err := outputcheck.Decode([]byte(resp.RequestBody))
			if err != nil {
				return nil, fmt.Errorf("scenario %q response %d: RequestBody is not JSON: %v", s.Name, i, err)
			}
			e.body, e.hasBody = body, true
		}
		r.entries = append(r.entries, e)
	}
	return r, nil
}

// RoundTrip answers req with the first response that matches it and has
// answers left.
func (r *Replay) RoundTrip(req *http.Request) (*http.Response, error) {
	op, _ := componentsdk.OperationOf(req.Context())
	r.mu.Lock()
	defer r.mu.Unlock()
	var body any
	bodyRead, bodyOK := false, false
	for _, e := range r.entries {
		if e.resp.Times > 0 && e.used >= e.resp.Times {
			continue
		}
		if !e.matches(req, op.Name) {
			continue
		}
		if e.hasBody {
			if !bodyRead {
				bodyRead = true
				body, bodyOK = requestBody(req)
			}
			if !bodyOK || !containsJSON(body, e.body) {
				continue
			}
		}
		e.used++
		e.ops[op.Name] = true
		e.hosts[strings.ToLower(req.URL.Hostname())] = true
		resp := e.response(req)
		r.answers.note(req.Context(), componentsdk.ClassifyResponse(resp))
		return resp, nil
	}
	r.unmatched = append(r.unmatched, fmt.Sprintf("%s %s (operation %s)", req.Method, describeURL(req.URL), opName(op)))
	r.answers.note(req.Context(), componentsdk.CodeInvalidResponse)
	return &http.Response{
		StatusCode: http.StatusNotFound,
		Status:     "404 Not Found",
		Header:     http.Header{"Content-Type": []string{"text/plain"}},
		Body:       io.NopCloser(strings.NewReader("collectortest: no canned response")),
		Request:    req,
	}, nil
}

func (e *replayEntry) matches(req *http.Request, op string) bool {
	if e.resp.Operation != "" && e.resp.Operation != op {
		return false
	}
	if e.resp.Method != "" && e.method != req.Method {
		return false
	}
	if e.target == nil {
		return true
	}
	if e.resp.Method == "" && req.Method != http.MethodGet && e.resp.Operation == "" {
		return false
	}
	u := req.URL
	if !strings.EqualFold(e.target.Scheme, u.Scheme) || !strings.EqualFold(e.target.Host, u.Host) || e.target.Path != u.Path {
		return false
	}
	return !e.hasQuery || sameQuery(e.target.Query(), u.Query())
}

// requestBody reads req's body as JSON, or, for a form-encoded request, as
// an object of its fields. The replay is the last transport the request
// reaches, so it may consume the body.
func requestBody(req *http.Request) (any, bool) {
	if req.Body == nil || req.Body == http.NoBody {
		return nil, false
	}
	raw, err := io.ReadAll(req.Body)
	_ = req.Body.Close()
	if err != nil {
		return nil, false
	}
	if doc, err := outputcheck.Decode(raw); err == nil {
		return doc, true
	}
	if !strings.HasPrefix(req.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
		return nil, false
	}
	form, err := url.ParseQuery(string(raw))
	if err != nil {
		return nil, false
	}
	return formObject(form), true
}

// containsJSON reports whether got holds want: an object holds each key want
// lists, with a value that holds want's, and any other value equals want's.
func containsJSON(got, want any) bool {
	w, ok := want.(map[string]any)
	if !ok {
		return equalJSON(got, want)
	}
	g, ok := got.(map[string]any)
	if !ok {
		return false
	}
	for key, wv := range w {
		gv, ok := g[key]
		if !ok || !containsJSON(gv, wv) {
			return false
		}
	}
	return true
}

// equalJSON compares decoded JSON values, numbers by value, so 1 equals 1.0.
func equalJSON(a, b any) bool {
	switch x := a.(type) {
	case json.Number:
		y, ok := b.(json.Number)
		if !ok {
			return false
		}
		xr, xok := new(big.Rat).SetString(string(x))
		yr, yok := new(big.Rat).SetString(string(y))
		return xok && yok && xr.Cmp(yr) == 0
	case []any:
		y, ok := b.([]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for i := range x {
			if !equalJSON(x[i], y[i]) {
				return false
			}
		}
		return true
	case map[string]any:
		y, ok := b.(map[string]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for key, xv := range x {
			yv, ok := y[key]
			if !ok || !equalJSON(xv, yv) {
				return false
			}
		}
		return true
	default:
		return a == b
	}
}

func (e *replayEntry) response(req *http.Request) *http.Response {
	status := e.resp.Status
	if status == 0 {
		status = http.StatusOK
	}
	header := http.Header{}
	for k, v := range e.resp.Header {
		header[k] = append([]string(nil), v...)
	}
	if header.Get("Content-Type") == "" {
		header.Set("Content-Type", "application/json")
	}
	return &http.Response{
		StatusCode:    status,
		Status:        fmt.Sprintf("%d %s", status, http.StatusText(status)),
		Header:        header,
		Body:          io.NopCloser(strings.NewReader(e.resp.Body)),
		ContentLength: int64(len(e.resp.Body)),
		Request:       req,
	}
}

// operationsFor returns the operations that consumed each response, by index.
func (r *Replay) operationsFor() map[int][]string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := map[int][]string{}
	for i, e := range r.entries {
		for op := range e.ops {
			out[i] = append(out[i], op)
		}
		sort.Strings(out[i])
	}
	return out
}

// hostsFor returns the hosts of the requests each response answered, by
// index.
func (r *Replay) hostsFor() map[int][]string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := map[int][]string{}
	for i, e := range r.entries {
		for host := range e.hosts {
			out[i] = append(out[i], host)
		}
		sort.Strings(out[i])
	}
	return out
}

// Unmatched lists the requests no response matched, each as its method, its
// URL with query values left out, and its operation.
func (r *Replay) Unmatched() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.unmatched...)
}

func sameQuery(a, b url.Values) bool {
	if len(a) != len(b) {
		return false
	}
	for k, av := range a {
		bv, ok := b[k]
		if !ok {
			return false
		}
		as := append([]string(nil), av...)
		bs := append([]string(nil), bv...)
		sort.Strings(as)
		sort.Strings(bs)
		if !reflect.DeepEqual(as, bs) {
			return false
		}
	}
	return true
}

// describeURL prints a URL with query values replaced, since they can carry
// tokens.
func describeURL(u *url.URL) string {
	if u == nil {
		return ""
	}
	out := u.Scheme + "://" + u.Host + u.Path
	if u.RawQuery == "" {
		return out
	}
	keys := make([]string, 0)
	for k := range u.Query() {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return out + "?" + strings.Join(keys, "&")
}

func opName(op componentsdk.Operation) string {
	if op.Name == "" {
		return componentsdk.UnnamedOperation
	}
	return op.Name
}
