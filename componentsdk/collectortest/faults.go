package collectortest

import (
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/locktivity/epack/componentsdk"
	"golang.org/x/net/publicsuffix"
)

// Fault is one failure the kit injects into an operation's calls.
type Fault struct {
	// Name labels the fault in reports and in Semantic.
	Name string

	// Transient faults fail only the first attempt of a call, so the SDK's
	// retry gets the real response. The output must not change at all.
	Transient bool

	// Expect is the code a gap the fault causes must carry.
	Expect componentsdk.Code

	// Operations limits the fault to these operations. Empty means every
	// operation the clean scenario calls.
	Operations []string

	// apply answers a request the fault hits. It calls changed once the
	// caller could tell its answer from the real one: at once for most
	// faults, when the caller reads to the cut for "truncated", and never
	// for a response that fault passes through.
	apply  func(real func() (*http.Response, error), req *http.Request, changed func()) (*http.Response, error)
	lookup func(name string) error
	dial   func(network, address string) (net.Conn, error)
}

// kind says which operations the fault hits: those the collector calls
// through its HTTP client, its Resolver, or its Dialer.
func (f Fault) kind() string {
	switch {
	case f.lookup != nil:
		return kindDNS
	case f.dial != nil:
		return kindDial
	default:
		return kindHTTP
	}
}

// Faults returns the built-in faults the matrix injects, in the order it
// runs them. Suite.Faults run after them. Each fault hits operations of one
// kind: HTTP calls, componentsdk.Resolver lookups (servfail, timeout, and
// refused), or componentsdk.Dialer dials (refused, reset, and timeout). A
// fault that times out returns at once.
func Faults() []Fault {
	return []Fault{
		statusFault("401", http.StatusUnauthorized, nil, componentsdk.CodeAuthFailed, false),
		statusFault("403", http.StatusForbidden, nil, componentsdk.CodePermissionDenied, false),
		statusFault("404", http.StatusNotFound, nil, componentsdk.CodeInvalidResponse, false),
		statusFault("429-once", http.StatusTooManyRequests, http.Header{"Retry-After": []string{"1"}}, "", true),
		statusFault("429", http.StatusTooManyRequests, http.Header{"Retry-After": []string{"1"}}, componentsdk.CodeRateLimited, false),
		statusFault("500-once", http.StatusInternalServerError, nil, "", true),
		statusFault("500", http.StatusInternalServerError, nil, componentsdk.CodeVendorError, false),
		ErrorFault("timeout", timeoutError{}, componentsdk.CodeTimeout),
		ErrorFault("reset", &net.OpError{Op: "read", Net: "tcp", Err: syscall.ECONNRESET}, componentsdk.CodeVendorError),
		{Name: "truncated", Expect: componentsdk.CodeInvalidResponse, apply: truncate},
		BodyFault("malformed", "{not json", componentsdk.CodeInvalidResponse),
		BodyFault("empty-object", "{}", componentsdk.CodeInvalidResponse),
		{Name: "servfail", Expect: componentsdk.CodeVendorError, lookup: servfail},
		{Name: "timeout", Expect: componentsdk.CodeTimeout, lookup: lookupTimeout},
		{Name: "refused", Expect: componentsdk.CodeVendorError, lookup: lookupRefused},
		{Name: "refused", Expect: componentsdk.CodeVendorError, dial: dialRefused},
		{Name: "reset", Expect: componentsdk.CodeVendorError, dial: dialReset},
		{Name: "timeout", Expect: componentsdk.CodeTimeout, dial: dialTimeout},
	}
}

func statusFault(name string, status int, header http.Header, expect componentsdk.Code, transient bool) Fault {
	return StatusFault(name, status, header, `{"error":{"code":"collectortest","message":"injected `+name+`"}}`, expect, transient)
}

// StatusFault answers with status, header, and body, such as a vendor's
// throttle sent as a 400 whose body names the error. The Content-Type is
// application/json unless header sets another. A transient fault must clear
// on retry, so it needs no expect.
func StatusFault(name string, status int, header http.Header, body string, expect componentsdk.Code, transient bool) Fault {
	return Fault{Name: name, Transient: transient, Expect: expect, apply: func(_ func() (*http.Response, error), req *http.Request, changed func()) (*http.Response, error) {
		changed()
		h := http.Header{"Content-Type": []string{"application/json"}}
		for k, v := range header {
			h[k] = v
		}
		return &http.Response{StatusCode: status, Status: http.StatusText(status), Header: h, Body: io.NopCloser(strings.NewReader(body)), Request: req}, nil
	}}
}

// ErrorFault fails the request with err in place of a response, as a
// dropped connection does.
func ErrorFault(name string, err error, expect componentsdk.Code) Fault {
	return Fault{Name: name, Expect: expect, apply: func(_ func() (*http.Response, error), _ *http.Request, changed func()) (*http.Response, error) {
		changed()
		return nil, err
	}}
}

// BodyFault answers 200 OK with body, such as one the collector cannot
// parse.
func BodyFault(name, body string, expect componentsdk.Code) Fault {
	return Fault{Name: name, Expect: expect, apply: func(_ func() (*http.Response, error), req *http.Request, changed func()) (*http.Response, error) {
		changed()
		return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(body)), Request: req}, nil
	}}
}

// truncate cuts a 2xx response's body in half, as a connection lost mid-body
// would. Other statuses pass through unchanged. A caller that never reads to
// the cut, such as one that takes a count from a header, sees no change.
func truncate(real func() (*http.Response, error), _ *http.Request, changed func()) (*http.Response, error) {
	resp, err := real()
	if err != nil || resp.Body == nil || resp.StatusCode < 200 || resp.StatusCode > 299 {
		return resp, err
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	half := body[:len(body)/2]
	resp.ContentLength = int64(len(half))
	if len(body) == 0 {
		resp.Body = io.NopCloser(strings.NewReader(""))
		return resp, nil
	}
	resp.Body = &cutBody{Reader: strings.NewReader(string(half)), cut: changed}
	return resp, nil
}

// cutBody is a body cut short. It calls cut when its reader reaches the end
// of what is left, where the rest went missing.
type cutBody struct {
	io.Reader
	cut  func()
	once sync.Once
}

func (b *cutBody) Read(p []byte) (int, error) {
	n, err := b.Reader.Read(p)
	if err == io.EOF {
		b.once.Do(b.cut)
	}
	return n, err
}

func (b *cutBody) Close() error { return nil }

type timeoutError struct{}

func (timeoutError) Error() string   { return "collectortest: injected timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

func lookupTimeout(name string) error {
	return &net.DNSError{Err: "i/o timeout", Name: name, Server: kitDNSServer, IsTimeout: true, IsTemporary: true}
}

// lookupRefused is what net.Resolver returns for a REFUSED response: the
// error it returns for SERVFAIL, but not temporary.
func lookupRefused(name string) error {
	return &net.DNSError{Err: "server misbehaving", Name: name, Server: kitDNSServer}
}

func dialRefused(network, address string) (net.Conn, error) {
	return nil, connRefused(network, address)
}

func dialTimeout(network, address string) (net.Conn, error) {
	return nil, &net.OpError{Op: "dial", Net: network, Addr: dialAddr(address), Err: os.ErrDeadlineExceeded}
}

func dialReset(_, address string) (net.Conn, error) {
	return resetConn{address: address}, nil
}

// resetConn is a connection the far end resets: writes go nowhere, and every
// read fails with ECONNRESET.
type resetConn struct{ address string }

func (c resetConn) Read([]byte) (int, error) {
	return 0, &net.OpError{Op: "read", Net: "tcp", Addr: dialAddr(c.address), Err: &os.SyscallError{Syscall: "read", Err: syscall.ECONNRESET}}
}

func (resetConn) Write(b []byte) (int, error)      { return len(b), nil }
func (resetConn) Close() error                     { return nil }
func (resetConn) LocalAddr() net.Addr              { return dialAddr("127.0.0.1:0") }
func (c resetConn) RemoteAddr() net.Addr           { return dialAddr(c.address) }
func (resetConn) SetDeadline(time.Time) error      { return nil }
func (resetConn) SetReadDeadline(time.Time) error  { return nil }
func (resetConn) SetWriteDeadline(time.Time) error { return nil }

// Positions say which calls of an operation a fault hits. A loop that skips
// a failed item and keeps going shows up only when one call fails, so the
// matrix hits every call, then the first, a middle, and the last.
const (
	PositionAll    = "all"
	PositionFirst  = "first"
	PositionMiddle = "middle"
	PositionLast   = "last"
)

func positionsFor(calls int, transient bool) []string {
	if transient || calls < 2 {
		return []string{PositionAll}
	}
	positions := []string{PositionAll, PositionFirst}
	if calls >= 3 {
		positions = append(positions, PositionMiddle)
	}
	return append(positions, PositionLast)
}

func positionHits(position string, call, total int) bool {
	switch position {
	case PositionFirst:
		return call == 1
	case PositionMiddle:
		return call == (total+1)/2
	case PositionLast:
		return call == total
	default:
		return true
	}
}

// injector applies one fault to one operation's calls. For an HTTP fault it
// is the transport over the replay and passes everything else through; the
// DNS server and the endpoints ask it about each lookup and dial.
type injector struct {
	base     http.RoundTripper
	op       string
	fault    Fault
	position string
	total    int

	mu    sync.Mutex
	calls int
	// callOf numbers the SDK's calls by their IDs, so each retry counts as
	// its own call even when another call started since.
	callOf  map[uint64]int
	hits    int
	changed []int
}

// install puts the injector in front of the part of n its fault hits.
func (in *injector) install(n *network) {
	switch in.fault.kind() {
	case kindDNS:
		n.dns.injector = in
	case kindDial:
		n.endpoints.injector = in
	default:
		in.base = n.transport
		n.transport = in
	}
}

func (in *injector) RoundTrip(req *http.Request) (*http.Response, error) {
	hit, call := in.strike(req.Context())
	if !hit {
		return in.base.RoundTrip(req)
	}
	return in.fault.apply(func() (*http.Response, error) { return in.base.RoundTrip(req) }, req, func() { in.change(call) })
}

// strike counts a call of the injector's operation and reports whether the
// fault hits it, and which call it is, from 1. A retry is the call it
// retries, found by the ID the SDK's transport gives the call, and anything
// else, such as a lookup or a dial, is a call of its own. A transient fault
// hits only a call's first attempt.
func (in *injector) strike(ctx context.Context) (bool, int) {
	op, _ := componentsdk.OperationOf(ctx)
	if opName(op) != in.op {
		return false, 0
	}
	attempt, id := componentsdk.AttemptOf(ctx), componentsdk.CallOf(ctx)
	in.mu.Lock()
	defer in.mu.Unlock()
	call, known := in.callOf[id]
	if attempt <= 1 || !known {
		in.calls++
		call = in.calls
		if id != 0 {
			if in.callOf == nil {
				in.callOf = map[uint64]int{}
			}
			in.callOf[id] = call
		}
	}
	hit := positionHits(in.position, call, in.total) && (!in.fault.Transient || attempt <= 1)
	if hit {
		in.hits++
	}
	return hit, call
}

// change notes a call whose answer the fault changed.
func (in *injector) change(call int) {
	in.mu.Lock()
	defer in.mu.Unlock()
	if !slices.Contains(in.changed, call) {
		in.changed = append(in.changed, call)
	}
}

func (in *injector) hitCount() int {
	in.mu.Lock()
	defer in.mu.Unlock()
	return in.hits
}

// changedCalls lists the calls whose answers the fault changed.
func (in *injector) changedCalls() []int {
	in.mu.Lock()
	defer in.mu.Unlock()
	return append([]int(nil), in.changed...)
}

// foreignHost is a host no collector may send credentials to.
const foreignHost = "collectortest.invalid"

var credentialHeaders = []string{
	"Authorization", "Proxy-Authorization", "Cookie",
	"PRIVATE-TOKEN", "X-API-Key", "X-Auth-Token", "Api-Key", "Ocp-Apim-Subscription-Key",
}

// foreignWatch answers every request to foreignHost with a 404 and records
// what reached it: any credential header, and any header, URL, or body
// carrying a secret's value, each header once by its canonical name. Other
// requests pass through to base.
type foreignWatch struct {
	base     http.RoundTripper
	canaries []canary

	mu     sync.Mutex
	leaked []string
}

func (w *foreignWatch) RoundTrip(req *http.Request) (*http.Response, error) {
	if !strings.EqualFold(req.URL.Hostname(), foreignHost) {
		return w.base.RoundTrip(req)
	}
	w.mu.Lock()
	leak := func(what string) {
		if !containsString(w.leaked, what) {
			w.leaked = append(w.leaked, what)
		}
	}
	for _, h := range credentialHeaders {
		if req.Header.Get(h) != "" {
			leak(http.CanonicalHeaderKey(h))
		}
	}
	for name, values := range req.Header {
		for _, v := range values {
			if containsSecret(v, w.canaries) {
				leak(http.CanonicalHeaderKey(name))
			}
		}
	}
	if containsSecret(req.URL.String(), w.canaries) {
		leak("the URL")
	}
	if req.Body != nil {
		body, _ := io.ReadAll(req.Body)
		_ = req.Body.Close()
		if containsSecret(string(body), w.canaries) {
			leak("the body")
		}
	}
	w.mu.Unlock()
	return &http.Response{StatusCode: http.StatusNotFound, Status: "404 Not Found", Header: http.Header{}, Body: io.NopCloser(strings.NewReader("")), Request: req}, nil
}

// leaks lists what reached foreignHost, sorted.
func (w *foreignWatch) leaks() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := append([]string(nil), w.leaked...)
	sort.Strings(out)
	return out
}

// publicSuffixWildcard reports whether a CredentialHosts entry is a wildcard
// over an ICANN public suffix, such as "*.com" or "*.co.uk", and returns the
// suffix.
func publicSuffixWildcard(entry string) (string, bool) {
	base, ok := strings.CutPrefix(strings.ToLower(strings.TrimSpace(entry)), "*.")
	base = strings.TrimSuffix(base, ".")
	if !ok || base == "" {
		return "", false
	}
	suffix, icann := publicsuffix.PublicSuffix(base)
	return base, icann && suffix == base
}

// redirector answers an operation's first call with a redirect to
// foreignHost, and watches what reaches it.
type redirector struct {
	foreignWatch
	op   string
	done bool
}

func (r *redirector) RoundTrip(req *http.Request) (*http.Response, error) {
	op, _ := componentsdk.OperationOf(req.Context())
	r.mu.Lock()
	redirect := !r.done && opName(op) == r.op && !strings.EqualFold(req.URL.Hostname(), foreignHost)
	if redirect {
		r.done = true
	}
	r.mu.Unlock()
	if !redirect {
		return r.foreignWatch.RoundTrip(req)
	}
	target := *req.URL
	target.Host = foreignHost
	target.Scheme = "https"
	return &http.Response{
		StatusCode: http.StatusTemporaryRedirect,
		Status:     "307 Temporary Redirect",
		Header:     http.Header{"Location": []string{target.String()}},
		Body:       io.NopCloser(strings.NewReader("")),
		Request:    req,
	}, nil
}

func containsSecret(s string, canaries []canary) bool {
	for _, c := range canaries {
		if strings.Contains(s, c.value) {
			return true
		}
	}
	return false
}

// foreignLinks returns s with the absolute URLs on a request's own host,
// such as a next-page link, pointed at foreignHost in the body and Link
// header of the first response op consumed that has any. ops and hosts give,
// by response index, the operations each response answered and the hosts it
// answered them on. It reports false when no response op consumed has one.
func foreignLinks(s Scenario, op string, ops, hosts map[int][]string) (Scenario, bool) {
	for i, r := range s.Responses {
		if !containsString(ops[i], op) {
			continue
		}
		changed := false
		for _, host := range hosts[i] {
			link := selfLink(host)
			rewrite := func(text string) string {
				out := link.ReplaceAllString(text, "${1}"+foreignHost+"${2}")
				changed = changed || out != text
				return out
			}
			r.Body = rewrite(r.Body)
			if values := r.Header.Values("Link"); len(values) > 0 {
				r.Header = r.Header.Clone()
				r.Header.Del("Link")
				for _, v := range values {
					r.Header.Add("Link", rewrite(v))
				}
			}
		}
		if !changed {
			continue
		}
		out := s
		out.Responses = append([]Response(nil), s.Responses...)
		out.Responses[i] = r
		return out, true
	}
	return s, false
}

// selfLink matches an absolute URL on host, with its slashes escaped as JSON
// allows or not, capturing the scheme and the character after the host.
func selfLink(host string) *regexp.Regexp {
	return regexp.MustCompile(`(?i)(https?:(?:\\?/){2})` + regexp.QuoteMeta(host) + `([/:?#"'<>\\\s]|$)`)
}
