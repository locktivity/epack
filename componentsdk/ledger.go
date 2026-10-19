package componentsdk

import (
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// maxCallRows bounds the per-request rows a result artifact carries.
const maxCallRows = 1000

// OperationCalls counts one operation's calls in a run.
type OperationCalls struct {
	Name        string         `json:"name"`
	Calls       int            `json:"calls"`
	Attempts    int            `json:"attempts"`
	Retries     int            `json:"retries"`
	Statuses    map[string]int `json:"statuses,omitempty"`
	Errors      map[Code]int   `json:"errors,omitempty"`
	Deprecation string         `json:"deprecation,omitempty"`
	Sunset      string         `json:"sunset,omitempty"`
}

// CallRow is one attempt of one call. Routes are templated and query values
// are dropped, since paths and queries can carry names, emails, and tokens.
// A DNS lookup's row has the method "DNS" and the record type, the queried
// name as its host, its response code, and no route. A dial's row has the
// method "DIAL" and the dialed host, and its error is the code of a failed
// dial or of a timeout or reset on the connection afterwards.
type CallRow struct {
	Operation  string   `json:"operation"`
	Method     string   `json:"method"`
	Host       string   `json:"host"`
	Route      string   `json:"route,omitempty"`
	QueryKeys  []string `json:"query_keys,omitempty"`
	Attempt    int      `json:"attempt"`
	Status     int      `json:"status,omitempty"`
	Rcode      string   `json:"rcode,omitempty"`
	Error      Code     `json:"error,omitempty"`
	DurationMS int64    `json:"duration_ms"`
	RequestID  string   `json:"request_id,omitempty"`
}

type ledger struct {
	mu      sync.Mutex
	ops     map[string]*OperationCalls
	rows    []CallRow
	dropped int
}

func newLedger() *ledger {
	return &ledger{ops: map[string]*OperationCalls{}}
}

func (l *ledger) stats(name string) *OperationCalls {
	s, ok := l.ops[name]
	if !ok {
		s = &OperationCalls{Name: name}
		l.ops[name] = s
	}
	return s
}

func (l *ledger) add(op Operation, req *http.Request, attempt int, resp *http.Response, err error, took time.Duration, requestIDHeaders []string) {
	l.addRouted(op, req, attempt, resp, err, "", took, requestIDHeaders, nil)
}

// addRouted is add with the code the transport's ClassifyResponse hook gave
// the response, if any, and the route template of the transport that sent
// the request.
func (l *ledger) addRouted(op Operation, req *http.Request, attempt int, resp *http.Response, err error, code Code, took time.Duration, requestIDHeaders []string, route func(string) string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	s := l.stats(op.Name)
	s.Attempts++
	if attempt == 1 {
		s.Calls++
	} else {
		s.Retries++
	}
	row := l.row(op, req, attempt, took, route)
	switch {
	case err != nil && lostConnection(err):
		code = CodeVendorError
	case err != nil:
		code = Classify(err)
	case resp != nil:
		row.Status = resp.StatusCode
		if s.Statuses == nil {
			s.Statuses = map[string]int{}
		}
		s.Statuses[strconv.Itoa(resp.StatusCode)]++
		row.RequestID = firstHeader(resp.Header, requestIDHeaders)
		if v := resp.Header.Get("Deprecation"); v != "" {
			s.Deprecation = v
		} else if v := resp.Header.Get("X-Sentry-Deprecation-Date"); v != "" {
			s.Deprecation = v
		}
		if v := resp.Header.Get("Sunset"); v != "" {
			s.Sunset = v
		}
	}
	if code != "" {
		row.Error = code
		if s.Errors == nil {
			s.Errors = map[Code]int{}
		}
		s.Errors[code]++
	}
	l.appendRow(row)
}

// addCall records a DNS lookup or a dial, which the SDK makes once, with no
// retry. rcode is a lookup's response code, which also keys the operation's
// statuses, and code is the failure's code, if any. It returns the call's
// row, or -1 when the rows are full.
func (l *ledger) addCall(op Operation, method, host, rcode string, code Code, took time.Duration) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	s := l.stats(op.Name)
	s.Calls++
	s.Attempts++
	if rcode != "" {
		if s.Statuses == nil {
			s.Statuses = map[string]int{}
		}
		s.Statuses[rcode]++
	}
	if code != "" {
		if s.Errors == nil {
			s.Errors = map[Code]int{}
		}
		s.Errors[code]++
	}
	return l.appendRow(CallRow{Operation: op.Name, Method: method, Host: host, Attempt: 1, Rcode: rcode, Error: code, DurationMS: took.Milliseconds()})
}

// failCall gives a call addCall recorded without an error the code of a
// failure that came later, such as a dial whose connection then reset.
func (l *ledger) failCall(op Operation, row int, code Code) {
	l.mu.Lock()
	defer l.mu.Unlock()
	s := l.stats(op.Name)
	if s.Errors == nil {
		s.Errors = map[Code]int{}
	}
	s.Errors[code]++
	if row >= 0 && row < len(l.rows) {
		l.rows[row].Error = code
	}
}

func (l *ledger) addRefused(op Operation, req *http.Request, route func(string) string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	s := l.stats(op.Name)
	s.Calls++
	if s.Errors == nil {
		s.Errors = map[Code]int{}
	}
	s.Errors[CodeInvalidResponse]++
	row := l.row(op, req, 1, 0, route)
	row.Error = CodeInvalidResponse
	l.appendRow(row)
}

func (l *ledger) row(op Operation, req *http.Request, attempt int, took time.Duration, route func(string) string) CallRow {
	row := CallRow{Operation: op.Name, Method: req.Method, Attempt: attempt, DurationMS: took.Milliseconds()}
	if req.URL != nil {
		if route == nil {
			route = TemplateRoute
		}
		row.Host = strings.ToLower(req.URL.Hostname())
		row.Route = route(req.URL.Path)
		row.QueryKeys = queryKeys(req.URL.Query())
	}
	return row
}

// appendRow adds row and returns its index, or -1 when the rows are full.
func (l *ledger) appendRow(row CallRow) int {
	if len(l.rows) >= maxCallRows {
		l.dropped++
		return -1
	}
	l.rows = append(l.rows, row)
	return len(l.rows) - 1
}

// operations returns a copy of every operation's counts, sorted by name.
func (l *ledger) operations() []OperationCalls {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]OperationCalls, 0, len(l.ops))
	for _, s := range l.ops {
		c := *s
		c.Statuses = copyMap(s.Statuses)
		c.Errors = copyMap(s.Errors)
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func (l *ledger) requests() ([]CallRow, int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]CallRow(nil), l.rows...), l.dropped
}

func copyMap[K comparable](m map[K]int) map[K]int {
	if m == nil {
		return nil
	}
	out := make(map[K]int, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func firstHeader(h http.Header, names []string) string {
	for _, name := range names {
		if v := h.Get(name); v != "" {
			return v
		}
	}
	return ""
}

func queryKeys(q map[string][]string) []string {
	if len(q) == 0 {
		return nil
	}
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

var (
	guidSegment  = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	digitSegment = regexp.MustCompile(`^[0-9]+$`)
	hexSegment   = regexp.MustCompile(`^[0-9a-fA-F]{12,}$`)
)

// TemplateRoute replaces the path segments that look like identifiers with
// "{id}": GUIDs, numbers, long hex strings, anything with an @ in it, and
// long segments that mix in digits. It cannot recognize every name, which is
// why calls are named by Operation and routes appear only in per-request
// rows.
func TemplateRoute(path string) string {
	if path == "" {
		return "/"
	}
	segments := strings.Split(path, "/")
	for i, seg := range segments {
		if identifierSegment(seg) {
			segments[i] = "{id}"
		}
	}
	return strings.Join(segments, "/")
}

func identifierSegment(seg string) bool {
	if seg == "" {
		return false
	}
	switch {
	case guidSegment.MatchString(seg), digitSegment.MatchString(seg), hexSegment.MatchString(seg):
		return true
	case strings.Contains(seg, "@"), strings.Contains(seg, "%40"):
		return true
	case len(seg) >= 20 && strings.ContainsAny(seg, "0123456789"):
		return true
	default:
		return false
	}
}
