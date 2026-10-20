package componentsdk

import (
	"context"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// maxCallRows bounds the per-request rows a result artifact carries, in the
// order the requests finish. maxProblemRows bounds the rows it keeps past
// that, which are only those whose attempt failed or was a retry, so a
// refusal late in a large run still has a row.
const (
	maxCallRows    = 1000
	maxProblemRows = 1000
)

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
//
// Call numbers the calls of a run from 1 in the order they start, and every
// attempt of one call has the same number. StartMS and WaitedMS count from
// the run's start by its clock, which a test kit run fixes. VendorCode is the
// vendor's code for a failed response, as HTTPOptions.VendorCode reads it;
// a row never holds the vendor's message, which can name a resource.
type CallRow struct {
	Call       int      `json:"call,omitempty"`
	Operation  string   `json:"operation"`
	Step       string   `json:"step,omitempty"`
	Method     string   `json:"method"`
	Host       string   `json:"host"`
	Route      string   `json:"route,omitempty"`
	QueryKeys  []string `json:"query_keys,omitempty"`
	Attempt    int      `json:"attempt"`
	StartMS    int64    `json:"start_ms"`
	WaitedMS   int64    `json:"waited_ms,omitempty"`
	Status     int      `json:"status,omitempty"`
	Rcode      string   `json:"rcode,omitempty"`
	Error      Code     `json:"error,omitempty"`
	VendorCode string   `json:"vendor_code,omitempty"`
	DurationMS int64    `json:"duration_ms"`
	RequestID  string   `json:"request_id,omitempty"`
}

// failed reports whether a row's attempt failed: it has an error code or a
// status of 400 or more.
func (row CallRow) failed() bool {
	return row.Error != "" || row.Status >= 400
}

// problem reports whether a row's attempt failed or was a retry.
func (row CallRow) problem() bool {
	return row.failed() || row.Attempt > 1
}

type ledger struct {
	mu              sync.Mutex
	ops             map[string]*OperationCalls
	rows            []CallRow
	problemRows     int
	dropped         int
	problemsDropped int
	calls           int
	steps           []*stepState
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

// startCall numbers a call the run starts.
func (l *ledger) startCall() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.calls++
	return l.calls
}

// callStart is a call as it starts: its operation, the step it belongs to,
// its number in the run, and when it started.
type callStart struct {
	op      Operation
	step    *stepState
	number  int
	started time.Time
	startMS int64
}

// beginCall numbers a call of op that starts now with ctx, in the step ctx
// carries.
func (r *run) beginCall(ctx context.Context, op Operation) callStart {
	started := r.now()
	return callStart{op: op, step: stepIn(ctx, r), number: r.calls.startCall(), started: started, startMS: r.sinceStart(started)}
}

// attemptRecord is one attempt of an HTTP call, as the transport records it.
// startMS is when the attempt started, which for a retry is after the call
// did.
type attemptRecord struct {
	call    callStart
	attempt int
	req     *http.Request
	resp    *http.Response
	err     error
	// code is the code the transport's ClassifyResponse hook gave the
	// response, and vendorCode the code its VendorCode hook read.
	code       Code
	vendorCode string
	startMS    int64
	waited     time.Duration
	took       time.Duration
}

// add records an attempt. requestIDHeaders name the headers that carry the
// vendor's request ID, and route templates the request's path, TemplateRoute
// when nil.
func (l *ledger) add(a attemptRecord, requestIDHeaders []string, route func(string) string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	s := l.stats(a.call.op.Name)
	s.Attempts++
	if a.attempt == 1 {
		s.Calls++
	} else {
		s.Retries++
	}
	row := l.row(a.call, a.req, a.attempt, a.took, route)
	row.StartMS, row.WaitedMS = a.startMS, a.waited.Milliseconds()
	row.VendorCode = a.vendorCode
	code := a.code
	switch {
	case a.err != nil && lostConnection(a.err):
		code = CodeVendorError
	case a.err != nil:
		code = Classify(a.err)
	case a.resp != nil:
		row.Status = a.resp.StatusCode
		if s.Statuses == nil {
			s.Statuses = map[string]int{}
		}
		s.Statuses[strconv.Itoa(a.resp.StatusCode)]++
		row.RequestID = firstHeader(a.resp.Header, requestIDHeaders)
		if v := a.resp.Header.Get("Deprecation"); v != "" {
			s.Deprecation = v
		} else if v := a.resp.Header.Get("X-Sentry-Deprecation-Date"); v != "" {
			s.Deprecation = v
		}
		if v := a.resp.Header.Get("Sunset"); v != "" {
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
	l.count(a.call.step, row)
	l.appendRow(row)
}

// callRef is a row addCall recorded, kept so a later failure can mark it.
type callRef struct {
	index int
	row   CallRow
	step  *stepState
}

// addCall records a DNS lookup or a dial, which the SDK makes once, with no
// retry. rcode is a lookup's response code, which also keys the operation's
// statuses, and code is the failure's code, if any.
func (l *ledger) addCall(c callStart, method, host, rcode string, code Code, took time.Duration) *callRef {
	l.mu.Lock()
	defer l.mu.Unlock()
	s := l.stats(c.op.Name)
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
	row := CallRow{Call: c.number, Operation: c.op.Name, Step: stepName(c.step), Method: method, Host: host, Attempt: 1, StartMS: c.startMS, Rcode: rcode, Error: code, DurationMS: took.Milliseconds()}
	l.count(c.step, row)
	return &callRef{index: l.appendRow(row), row: row, step: c.step}
}

// failCall gives a call addCall recorded without an error the code of a
// failure that came later, such as a dial whose connection then reset. A row
// left out past the first rows is kept now, as a failed one, when there is
// room for it.
func (l *ledger) failCall(op Operation, ref *callRef, code Code) {
	l.mu.Lock()
	defer l.mu.Unlock()
	s := l.stats(op.Name)
	if s.Errors == nil {
		s.Errors = map[Code]int{}
	}
	s.Errors[code]++
	if ref == nil {
		return
	}
	if ref.step != nil {
		ref.step.failed++
	}
	ref.row.Error = code
	switch {
	case ref.index >= 0 && ref.index < len(l.rows):
		l.rows[ref.index].Error = code
	case l.problemRows < maxProblemRows:
		l.problemRows++
		l.dropped--
		l.rows = append(l.rows, ref.row)
		ref.index = len(l.rows) - 1
	default:
		l.problemsDropped++
	}
}

// addRefused records a call the transport refused to send, which counts as
// one failed attempt in its step.
func (l *ledger) addRefused(c callStart, req *http.Request, route func(string) string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	s := l.stats(c.op.Name)
	s.Calls++
	if s.Errors == nil {
		s.Errors = map[Code]int{}
	}
	s.Errors[CodeInvalidResponse]++
	row := l.row(c, req, 1, 0, route)
	row.StartMS = c.startMS
	row.Error = CodeInvalidResponse
	l.count(c.step, row)
	l.appendRow(row)
}

func (l *ledger) row(c callStart, req *http.Request, attempt int, took time.Duration, route func(string) string) CallRow {
	row := CallRow{Call: c.number, Operation: c.op.Name, Step: stepName(c.step), Method: req.Method, Attempt: attempt, DurationMS: took.Milliseconds()}
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

// appendRow keeps row and returns its index, or -1 when it is left out: the
// first maxCallRows rows are kept whatever they hold, and after them up to
// maxProblemRows rows whose attempt failed or was a retry. The caller holds
// l.mu.
func (l *ledger) appendRow(row CallRow) int {
	switch {
	case len(l.rows) < maxCallRows:
	case row.problem() && l.problemRows < maxProblemRows:
		l.problemRows++
	default:
		l.dropped++
		if row.problem() {
			l.problemsDropped++
		}
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

// requests returns a copy of the rows kept, with the count of rows left out
// and of the failed and retried rows among those.
func (l *ledger) requests() ([]CallRow, int, int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]CallRow(nil), l.rows...), l.dropped, l.problemsDropped
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
