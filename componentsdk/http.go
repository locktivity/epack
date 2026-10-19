package componentsdk

import (
	"bytes"
	"context"
	"errors"
	"io"
	"math"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
	"unicode/utf16"
	"unicode/utf8"
)

// HTTPOptions configures the client NewHTTPClient returns.
type HTTPOptions struct {
	// CredentialHosts lists the hosts that may receive credentials. A request
	// that carries an Authorization header, a cookie, or another credential
	// header to any other host fails with a RefusedHostError, including on
	// redirects and next-page links. "*.example.com" matches subdomains. An
	// empty list turns the check off. Whatever the list holds, credentials
	// never go over plain http, except to a loopback host such as 127.0.0.1
	// or localhost.
	CredentialHosts []string

	// CredentialHeaders names headers beyond the built-in list that carry
	// credentials for this vendor.
	CredentialHeaders []string

	// RequestIDHeaders names headers beyond the built-in list that carry the
	// vendor's request ID.
	RequestIDHeaders []string

	// NameOperation names a request before its context's Operation is
	// consulted. Clients built by vendor SDKs use it, such as AWS, whose
	// middleware knows each operation's name, and it also names requests an
	// SDK sends with the caller's context, such as a token refresh. Return
	// false to leave a request to its context's Operation.
	NameOperation func(*http.Request) (Operation, bool)

	// MaxAttempts caps attempts for a retry-safe request. The default is 5.
	MaxAttempts int

	// AttemptTimeout bounds the wait for response headers on each attempt.
	// The default is 60 seconds.
	AttemptTimeout time.Duration

	// RetryAfterCap bounds how long a Retry-After header, or a throttled
	// response's rate limit reset header, can make a retry wait. The default
	// is 60 seconds.
	RetryAfterCap time.Duration

	// TemplateRoute replaces TemplateRoute for the routes in this client's
	// per-request rows. Set it when the vendor's paths carry names the
	// default cannot recognize, such as Azure resource group and resource
	// names.
	TemplateRoute func(path string) string

	// ClassifyResponse gives a failed response its code when the status
	// alone misleads, such as AWS's 400 whose body names the error code
	// Throttling. The transport calls it for each response with status 400
	// or higher, and each 2xx response too with ClassifySuccess, passing up
	// to the first 64 KiB of the body; the caller still reads the whole
	// body. When it answers with a valid code, that code decides whether a
	// safe request is retried (rate_limited, vendor_error, and timeout are),
	// the call ledger records it, and the ClassifyResponse function returns
	// it for the response, so an error built with CodeError carries it to a
	// gap. Otherwise the status decides, as it does without the hook.
	ClassifyResponse func(resp *http.Response, body []byte) (Code, bool)

	// ClassifySuccess passes 2xx responses to ClassifyResponse as well, for
	// APIs that report errors inside a 200, such as JSON-RPC and GraphQL, so
	// a throttle there is retried when the request is safe. The transport
	// then reads the first 64 KiB of every successful response before the
	// caller does.
	ClassifySuccess bool

	// Base is the transport requests go out through, such as one whose
	// dialer refuses private addresses. It defaults to a clone of
	// http.DefaultTransport, which honors proxy settings; a Base should
	// too. RunInProcess's Transport replaces Base, so collectortest runs
	// never reach the network and never exercise Base: a guard in Base
	// needs a test of its own.
	Base http.RoundTripper
}

// Operation names a call. Names key the call ledger, retries, and the test
// kit's fault matrix, so they are part of a collector's contract: rename one
// only on purpose.
type Operation struct {
	// Name identifies the call, such as "graph.users.list".
	Name string

	// Safe marks a call that can be repeated without side effects. GET and
	// HEAD requests are always safe; set Safe on reads sent with POST, such as
	// GraphQL queries.
	Safe bool
}

type operationKey struct{}

// WithOperation returns a copy of ctx that names the requests, DNS lookups,
// and dials made with it.
func WithOperation(ctx context.Context, op Operation) context.Context {
	return context.WithValue(ctx, operationKey{}, op)
}

// OperationOf returns the operation ctx names, if any.
func OperationOf(ctx context.Context) (Operation, bool) {
	op, ok := ctx.Value(operationKey{}).(Operation)
	return op, ok && op.Name != ""
}

type attemptKey struct{}

// attemptMark is what the SDK's transport marks each attempt's context with:
// the call the attempt belongs to and which attempt of it the attempt is.
type attemptMark struct {
	call    uint64
	attempt int
}

// callIDs numbers the calls the SDK's transport sends, across every run in
// the process.
var callIDs atomic.Uint64

// AttemptOf returns which attempt of a call a request is, starting at 1, as
// the SDK's transport marks it for the transport beneath. It returns 0 for a
// request that did not pass through the SDK's transport. Test transports use
// it to tell a retry from a new call.
func AttemptOf(ctx context.Context) int {
	m, _ := ctx.Value(attemptKey{}).(attemptMark)
	return m.attempt
}

// CallOf returns the ID the SDK's transport gives a call, the same for each
// of the call's attempts and unique within the process, or 0 for a request
// that did not pass through the SDK's transport. Test transports use it to
// tell which call a retry belongs to while other calls are in flight.
func CallOf(ctx context.Context) uint64 {
	m, _ := ctx.Value(attemptKey{}).(attemptMark)
	return m.call
}

// UnnamedOperation is the ledger name of a request that carried no name.
const UnnamedOperation = "unnamed"

// RefusedHostError reports a request that would have sent credentials to a
// host outside HTTPOptions.CredentialHosts, or over plain http.
type RefusedHostError struct {
	Host string
	// Plaintext marks a refusal of a plain http request to a listed host
	// that is not a loopback host.
	Plaintext bool
}

func (e *RefusedHostError) Error() string {
	if e.Plaintext {
		return "refused to send credentials to " + e.Host + " over plain http"
	}
	return "refused to send credentials to " + e.Host
}

// NewHTTPClient returns a client for the collector's vendor calls. Its
// transport retries safe requests on 429, 5xx, and transport errors, keeps
// credentials on CredentialHosts, names and times each call in the run's
// ledger, and passes every response's status, headers, and body through
// unchanged.
func NewHTTPClient(ctx CollectorContext, opts HTTPOptions) *http.Client {
	return &http.Client{Transport: NewTransport(ctx, opts)}
}

// NewTransport returns the transport NewHTTPClient uses, for vendor SDKs that
// take a RoundTripper rather than a client.
func NewTransport(ctx CollectorContext, opts HTTPOptions) http.RoundTripper {
	r := runOf(ctx)
	r.noteCredentialHosts(opts.CredentialHosts)
	t := &transport{
		run:              r,
		base:             r.baseTransport(opts.Base),
		maxAttempts:      opts.MaxAttempts,
		attemptTimeout:   opts.AttemptTimeout,
		retryAfterCap:    opts.RetryAfterCap,
		nameOperation:    opts.NameOperation,
		templateRoute:    opts.TemplateRoute,
		classifyResponse: opts.ClassifyResponse,
		classifySuccess:  opts.ClassifySuccess,
		credentialHost:   newHostSet(opts.CredentialHosts),
		credentialHdrs:   append(append([]string{}, defaultCredentialHeaders...), opts.CredentialHeaders...),
		requestIDHdrs:    append(append([]string{}, defaultRequestIDHeaders...), opts.RequestIDHeaders...),
	}
	if t.maxAttempts <= 0 {
		t.maxAttempts = 5
	}
	if t.attemptTimeout <= 0 {
		t.attemptTimeout = 60 * time.Second
	}
	if t.retryAfterCap <= 0 {
		t.retryAfterCap = 60 * time.Second
	}
	return t
}

var defaultCredentialHeaders = []string{
	"Authorization", "Proxy-Authorization", "Cookie",
	"PRIVATE-TOKEN", "X-API-Key", "X-Auth-Token", "Api-Key", "Ocp-Apim-Subscription-Key",
}

var defaultRequestIDHeaders = []string{
	"X-Ms-Request-Id", "Request-Id", "X-Request-Id", "X-GitHub-Request-Id",
	"X-Amzn-RequestId", "X-Amz-Request-Id", "X-Okta-Request-Id",
}

const (
	backoffBase   = 250 * time.Millisecond
	backoffCap    = 8 * time.Second
	drainLimit    = 64 << 10
	classifyLimit = 64 << 10
	deadlineRoom  = time.Second
)

type transport struct {
	run              *run
	base             http.RoundTripper
	maxAttempts      int
	attemptTimeout   time.Duration
	retryAfterCap    time.Duration
	nameOperation    func(*http.Request) (Operation, bool)
	templateRoute    func(string) string
	classifyResponse func(*http.Response, []byte) (Code, bool)
	classifySuccess  bool
	credentialHost   hostSet
	credentialHdrs   []string
	requestIDHdrs    []string
}

func (t *transport) RoundTrip(req *http.Request) (*http.Response, error) {
	op := t.operation(req)
	checked, err := t.checkCredentials(req, op)
	if err != nil {
		t.run.calls.addRefused(op, req, t.templateRoute)
		return nil, err
	}
	req = checked
	if op.Safe && req.GetBody == nil && req.Body != nil && req.Body != http.NoBody {
		var err error
		if req, err = replayable(req); err != nil {
			return nil, err
		}
	}
	attempts := 1
	if (op.Safe || safeMethod(req.Method)) && (req.Body == nil || req.Body == http.NoBody || req.GetBody != nil) {
		attempts = t.maxAttempts
	}
	call := callIDs.Add(1)
	for attempt := 1; ; attempt++ {
		areq, err := t.attemptRequest(req, op, attempt)
		if err != nil {
			return nil, err
		}
		started := t.run.now()
		resp, err := t.attempt(areq, attemptMark{call: call, attempt: attempt})
		took := t.run.now().Sub(started)
		code := t.classify(areq, resp)
		t.run.calls.addRouted(op, req, attempt, resp, err, code, took, t.requestIDHdrs, t.templateRoute)
		if attempt >= attempts || !retryable(req.Context(), resp, err, code) {
			return resp, err
		}
		delay := t.delay(resp, code, attempt)
		if !fitsDeadline(req.Context(), delay) {
			return resp, err
		}
		drain(resp)
		if err := t.run.wait(req.Context(), delay); err != nil {
			return nil, err
		}
	}
}

func (t *transport) operation(req *http.Request) Operation {
	if t.nameOperation != nil {
		if op, ok := t.nameOperation(req); ok && op.Name != "" {
			return op
		}
	}
	if op, ok := OperationOf(req.Context()); ok {
		return op
	}
	return Operation{Name: UnnamedOperation}
}

// checkCredentials refuses a request that would carry a credential to a host
// outside CredentialHosts, or over plain http to a host that is not a loopback
// one. A credential is a credential header, or a value the collector read
// through Secret in the URL or the body, such as a client secret in a token
// request's form, which net/http sends on when a 307 points elsewhere. It
// returns the request to send, whose body it may have read to look inside.
func (t *transport) checkCredentials(req *http.Request, op Operation) (*http.Request, error) {
	if req.URL == nil {
		return req, nil
	}
	if t.credentialHost.empty() && t.credentialHeader(req) {
		t.run.noteUnlistedCredentials(op.Name)
	}
	host := strings.ToLower(req.URL.Hostname())
	unlisted := !t.credentialHost.empty() && !t.credentialHost.allows(host)
	plaintext := strings.EqualFold(req.URL.Scheme, "http") && !loopbackHost(host)
	if !unlisted && !plaintext {
		return req, nil
	}
	refuse := func() (*http.Request, error) {
		if req.Body != nil {
			_ = req.Body.Close()
		}
		return nil, &RefusedHostError{Host: host, Plaintext: !unlisted}
	}
	if t.credentialHeader(req) {
		return refuse()
	}
	secrets := t.run.secrets.list()
	if len(secrets) == 0 {
		return req, nil
	}
	if carriesSecret(req.URL.String(), secrets) {
		return refuse()
	}
	if req.Body == nil || req.Body == http.NoBody {
		return req, nil
	}
	held, err := io.ReadAll(io.LimitReader(req.Body, maxReplayBody+1))
	if err != nil {
		_ = req.Body.Close()
		return nil, err
	}
	if carriesSecret(string(held), secrets) {
		return refuse()
	}
	out := req.Clone(req.Context())
	if len(held) > maxReplayBody {
		out.Body = struct {
			io.Reader
			io.Closer
		}{io.MultiReader(bytes.NewReader(held), req.Body), req.Body}
		return out, nil
	}
	_ = req.Body.Close()
	out.Body = io.NopCloser(bytes.NewReader(held))
	out.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(held)), nil }
	return out, nil
}

func (t *transport) credentialHeader(req *http.Request) bool {
	for _, name := range t.credentialHdrs {
		if req.Header.Get(name) != "" {
			return true
		}
	}
	return false
}

// carriesSecret reports whether s contains a secret value, as written or as
// a form, a URL, or a JSON string escapes it: percent-encoding escapes the
// +, /, and = of a base64 secret, and JSON escapes quotes and backslashes
// and, from Go's encoder, <, >, and &. Values shorter than six characters
// are skipped, as redaction skips them, since they match too much ordinary
// text.
func carriesSecret(s string, secrets []string) bool {
	forms := unescapedForms(s)
	for _, v := range secrets {
		if len(v) < 6 {
			continue
		}
		for _, f := range forms {
			if strings.Contains(f, v) {
				return true
			}
		}
	}
	return false
}

// unescapedForms returns s, s percent-decoded as a form and as a path, and
// each of those with its JSON string escapes decoded too, as for JSON sent
// in a form field, each distinct form once.
func unescapedForms(s string) []string {
	forms := make([]string, 0, 6)
	for _, p := range []string{s, unescapeLoosely(s, true), unescapeLoosely(s, false)} {
		for _, f := range []string{p, unescapeJSONLoosely(p)} {
			if !slices.Contains(forms, f) {
				forms = append(forms, f)
			}
		}
	}
	return forms
}

// unescapeLoosely percent-decodes s, in either case of hex, leaving a
// malformed escape as written rather than failing as url.QueryUnescape
// does, so one stray % cannot hide the rest of a body. With plus set, it
// decodes + as a space, as forms and queries do; paths keep it.
func unescapeLoosely(s string, plus bool) string {
	if !strings.ContainsAny(s, "%+") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '%' && i+2 < len(s):
			if v, err := strconv.ParseUint(s[i+1:i+3], 16, 8); err == nil {
				b.WriteByte(byte(v))
				i += 2
				continue
			}
			b.WriteByte(c)
		case c == '+' && plus:
			b.WriteByte(' ')
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// unescapeJSONLoosely decodes the escapes a JSON string can hold wherever
// they appear in s: \" \\ \/ \b \f \n \r \t, and \uXXXX in either case of
// hex, a surrogate pair as one character. It leaves a malformed escape as
// written, so any encoder's choice of what to escape decodes the same.
func unescapeJSONLoosely(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+1 == len(s) {
			b.WriteByte(s[i])
			continue
		}
		switch c := s[i+1]; c {
		case '"', '\\', '/':
			b.WriteByte(c)
		case 'b':
			b.WriteByte('\b')
		case 'f':
			b.WriteByte('\f')
		case 'n':
			b.WriteByte('\n')
		case 'r':
			b.WriteByte('\r')
		case 't':
			b.WriteByte('\t')
		case 'u':
			r, n := jsonEscapedRune(s[i:])
			if n == 0 {
				b.WriteByte('\\')
				continue
			}
			b.WriteRune(r)
			i += n - 1
			continue
		default:
			b.WriteByte('\\')
			continue
		}
		i++
	}
	return b.String()
}

// jsonEscapedRune decodes the \uXXXX escape s starts with, joined with the
// one after it when the two make a surrogate pair. It returns the rune and
// the bytes the escapes span, or 0 bytes when s starts with none.
func jsonEscapedRune(s string) (rune, int) {
	r, ok := jsonEscapedUnit(s)
	if !ok {
		return 0, 0
	}
	if utf16.IsSurrogate(r) {
		if low, ok := jsonEscapedUnit(s[6:]); ok {
			if pair := utf16.DecodeRune(r, low); pair != utf8.RuneError {
				return pair, 12
			}
		}
	}
	return r, 6
}

func jsonEscapedUnit(s string) (rune, bool) {
	if len(s) < 6 || s[0] != '\\' || s[1] != 'u' {
		return 0, false
	}
	v, err := strconv.ParseUint(s[2:6], 16, 16)
	return rune(v), err == nil
}

// loopbackHost reports whether host is localhost or a loopback address,
// where plain http never leaves the machine.
func loopbackHost(host string) bool {
	host = strings.TrimSuffix(host, ".")
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// attemptRequest copies req for one attempt with a fresh body and the
// collector's User-Agent, leaving the caller's request untouched. The copy's
// context carries the operation the transport resolved, so transports below
// it, such as the test kit's fault injector, see names that came from
// NameOperation too.
func (t *transport) attemptRequest(req *http.Request, op Operation, attempt int) (*http.Request, error) {
	ctx := req.Context()
	if op.Name != UnnamedOperation {
		ctx = WithOperation(ctx, op)
	}
	areq := req.Clone(ctx)
	if attempt > 1 && req.GetBody != nil {
		body, err := req.GetBody()
		if err != nil {
			return nil, err
		}
		areq.Body = body
	}
	if ua := t.run.userAgent(); ua != "" {
		if existing := areq.Header.Get("User-Agent"); existing != "" {
			areq.Header.Set("User-Agent", existing+" "+ua)
		} else {
			areq.Header.Set("User-Agent", ua)
		}
	}
	return areq, nil
}

// attempt sends one request, cancelling it if response headers take longer
// than attemptTimeout. The cancel runs when the caller closes the body.
func (t *transport) attempt(req *http.Request, mark attemptMark) (*http.Response, error) {
	ctx, cancel := context.WithCancel(context.WithValue(req.Context(), attemptKey{}, mark))
	timer := time.AfterFunc(t.attemptTimeout, cancel)
	resp, err := t.base.RoundTrip(req.WithContext(ctx))
	fired := !timer.Stop()
	if err != nil {
		cancel()
		if fired && req.Context().Err() == nil {
			return nil, &attemptTimeoutError{after: t.attemptTimeout, err: err}
		}
		return nil, err
	}
	resp.Body = &cancelOnClose{ReadCloser: resp.Body, cancel: cancel}
	return resp, nil
}

type responseCodeKey struct{}

// classify asks the ClassifyResponse hook about a failed response, or with
// ClassifySuccess a successful one, and returns the code it answers with,
// or "". The hook reads the first classifyLimit bytes of the body, and the
// caller reads them again before the rest.
func (t *transport) classify(sent *http.Request, resp *http.Response) Code {
	if t.classifyResponse == nil || resp == nil {
		return ""
	}
	success := resp.StatusCode >= 200 && resp.StatusCode <= 299
	if asked := resp.StatusCode >= 400 || (t.classifySuccess && success); !asked {
		return ""
	}
	head, err := io.ReadAll(io.LimitReader(resp.Body, classifyLimit))
	var rest io.Reader = resp.Body
	if err != nil {
		rest = failedRead{err}
	}
	resp.Body = &peekedBody{Reader: io.MultiReader(bytes.NewReader(head), rest), body: resp.Body}
	code, ok := t.classifyResponse(resp, head)
	if !ok || !code.Valid() {
		return ""
	}
	// The code rides on the response's request, not its body: clients and
	// vendor SDKs wrap or replace a response's body but keep its request.
	if resp.Request != nil {
		sent = resp.Request
	}
	resp.Request = sent.WithContext(context.WithValue(sent.Context(), responseCodeKey{}, code))
	return code
}

// peekedBody reads the bytes classify read, then the rest of the body.
type peekedBody struct {
	io.Reader
	body io.Closer
}

func (b *peekedBody) Close() error { return b.body.Close() }

// failedRead returns the error that cut short classify's read, where the
// caller would have met it.
type failedRead struct{ err error }

func (f failedRead) Read([]byte) (int, error) { return 0, f.err }

// delay is how long to wait before the next attempt: as long as Retry-After
// asks, or for a throttle without one, until the rate limit resets, and
// otherwise exponential backoff. code is the ClassifyResponse hook's answer
// for the response.
func (t *transport) delay(resp *http.Response, code Code, attempt int) time.Duration {
	if resp != nil {
		wait, ok := retryAfter(resp.Header.Get("Retry-After"))
		if !ok && rateLimited(resp, code) {
			wait, ok = rateLimitReset(resp.Header, t.run.now())
		}
		if ok {
			if wait > t.retryAfterCap {
				wait = t.retryAfterCap
			}
			return wait + t.run.jitter(minDuration(time.Second, wait/10+1))
		}
	}
	backoff := backoffBase << (attempt - 1)
	if backoff > backoffCap || backoff <= 0 {
		backoff = backoffCap
	}
	return t.run.jitter(backoff)
}

// retryable reports whether an attempt's outcome is worth another try. code
// is the ClassifyResponse hook's answer for the response, which outranks its
// status. A transport error is retried only when its own code says another
// try could go differently, so a guard in Base that refuses a request is
// not asked again.
func retryable(ctx context.Context, resp *http.Response, err error, code Code) bool {
	if ctx.Err() != nil {
		return false
	}
	if err != nil {
		var slow *attemptTimeoutError
		if errors.As(err, &slow) {
			return true
		}
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return false
		}
		if lostConnection(err) {
			return true
		}
		return transientCode(Classify(err))
	}
	if code != "" {
		return transientCode(code)
	}
	switch resp.StatusCode {
	case http.StatusTooManyRequests, http.StatusInternalServerError, http.StatusBadGateway,
		http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	case http.StatusForbidden:
		return throttled(resp.Header)
	default:
		return false
	}
}

// maxReplayBody bounds the request body the transport holds so a retry-safe
// request can be sent again.
const maxReplayBody = 1 << 20

// replayable returns a copy of req whose body can be sent again, when the
// body fits in maxReplayBody. Vendor SDKs such as AWS's build requests without
// GetBody, which would otherwise rule out every retry of a safe POST. A larger
// body is passed on whole, without GetBody.
func replayable(req *http.Request) (*http.Request, error) {
	held, err := io.ReadAll(io.LimitReader(req.Body, maxReplayBody+1))
	if err != nil {
		_ = req.Body.Close()
		return nil, err
	}
	out := req.Clone(req.Context())
	if len(held) > maxReplayBody {
		out.Body = struct {
			io.Reader
			io.Closer
		}{io.MultiReader(bytes.NewReader(held), req.Body), req.Body}
		return out, nil
	}
	_ = req.Body.Close()
	out.Body = io.NopCloser(bytes.NewReader(held))
	out.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(held)), nil }
	return out, nil
}

// lostConnection reports whether a transport error says the connection closed
// before the response arrived in full, as when a server drops an idle
// keep-alive connection. A fresh connection clears it. net/http retries some
// of these itself, but only for idempotent methods, not a POST marked Safe.
func lostConnection(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)
}

// transientCode reports whether a failure with code can clear on its own.
func transientCode(code Code) bool {
	return code == CodeRateLimited || code == CodeVendorError || code == CodeTimeout
}

// retryAfter parses a Retry-After value in seconds or as an HTTP date.
func retryAfter(raw string) (time.Duration, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, false
	}
	if seconds, err := strconv.Atoi(raw); err == nil {
		if seconds < 0 {
			return 0, false
		}
		return time.Duration(seconds) * time.Second, true
	}
	when, err := http.ParseTime(raw)
	if err != nil {
		return 0, false
	}
	wait := time.Until(when)
	if wait < 0 {
		wait = 0
	}
	return wait, true
}

// rateLimited reports whether a response is a throttle, by the code the
// ClassifyResponse hook gave it, or else by its status and headers.
func rateLimited(resp *http.Response, code Code) bool {
	if code != "" {
		return code == CodeRateLimited
	}
	return classifyStatus(resp.StatusCode, resp.Header) == CodeRateLimited
}

// rateLimitResetHeaders say when a vendor's rate limit resets: Okta's,
// GitHub's, GitLab's and the IETF draft's, and Sentry's.
var rateLimitResetHeaders = []string{"X-Rate-Limit-Reset", "X-RateLimit-Reset", "RateLimit-Reset", "X-Sentry-Rate-Limit-Reset"}

const (
	// epochReset tells the two forms of reset apart: a value above it is a
	// time in epoch seconds, since no rate limit window lasts 30 years, and
	// a smaller one counts seconds from now.
	epochReset = 1e9
	// maxReset bounds the values parsed, so none overflows a Duration.
	maxReset = 1e12
)

// rateLimitReset returns how long until the rate limit resets, by the run's
// clock, from the first reset header that parses.
func rateLimitReset(header http.Header, now time.Time) (time.Duration, bool) {
	for _, name := range rateLimitResetHeaders {
		seconds, err := strconv.ParseFloat(strings.TrimSpace(header.Get(name)), 64)
		// Negated, the range check also turns away NaN, which ParseFloat
		// accepts and every comparison fails.
		if err != nil || !(seconds >= 0 && seconds < maxReset) {
			continue
		}
		if seconds <= epochReset {
			return time.Duration(seconds * float64(time.Second)), true
		}
		whole, frac := math.Modf(seconds)
		return max(time.Unix(int64(whole), int64(frac*1e9)).Sub(now), 0), true
	}
	return 0, false
}

func fitsDeadline(ctx context.Context, delay time.Duration) bool {
	deadline, ok := ctx.Deadline()
	if !ok {
		return true
	}
	return time.Until(deadline) > delay+deadlineRoom
}

func sleepContext(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func drain(resp *http.Response) {
	if resp == nil || resp.Body == nil {
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, drainLimit))
	_ = resp.Body.Close()
}

func safeMethod(method string) bool {
	switch method {
	case "", http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	default:
		return false
	}
}

func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

type cancelOnClose struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (c *cancelOnClose) Close() error {
	err := c.ReadCloser.Close()
	c.cancel()
	return err
}

type attemptTimeoutError struct {
	after time.Duration
	err   error
}

func (e *attemptTimeoutError) Error() string {
	return "no response headers within " + e.after.String() + ": " + e.err.Error()
}
func (e *attemptTimeoutError) Unwrap() error   { return e.err }
func (e *attemptTimeoutError) Timeout() bool   { return true }
func (e *attemptTimeoutError) Temporary() bool { return true }

type hostSet struct {
	exact    map[string]bool
	suffixes []string
}

func newHostSet(hosts []string) hostSet {
	set := hostSet{exact: map[string]bool{}}
	for _, h := range hosts {
		h = strings.ToLower(strings.TrimSpace(h))
		switch {
		case h == "":
		case strings.HasPrefix(h, "*."):
			set.suffixes = append(set.suffixes, h[1:])
		default:
			set.exact[h] = true
		}
	}
	return set
}

func (s hostSet) empty() bool { return len(s.exact) == 0 && len(s.suffixes) == 0 }

func (s hostSet) allows(host string) bool {
	if s.exact[host] {
		return true
	}
	for _, suffix := range s.suffixes {
		if strings.HasSuffix(host, suffix) {
			return true
		}
	}
	return false
}
