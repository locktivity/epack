package componentsdk

import (
	"context"
	"io"
	"net/http"
	"sync/atomic"
	"time"
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

	// VendorCode reads the vendor's own error code from a failed response,
	// such as Okta's errorCode E0000047 or an OAuth error such as
	// invalid_client. The code goes on the response's row in the collector
	// result, and on a gap recorded from an error built with ResponseError.
	// The transport calls it for each response with status 400 or higher,
	// and for a 2xx response that ClassifyResponse gave a code, passing up to
	// the first 64 KiB of the body; the caller still reads the whole body.
	// Return the code alone, never the vendor's message, which can name a
	// resource. A value that is not a code of up to 64 letters, digits, and
	// . _ : / - is dropped.
	VendorCode func(resp *http.Response, body []byte) string

	// NamesPermission reports whether a permission_denied response shows
	// that the credential lacks the call's Operation.Permission. If it does,
	// a gap may list that permission as missing. Return false for a refusal
	// that granting the permission would not lift, such as AWS's explicit
	// deny from a service control policy. Also return false for a denial
	// whose message does not say what was refused. The function gets up to
	// the first 64 KiB of the body, and the caller still reads the whole
	// body. When NamesPermission is nil, a gap from any permission_denied
	// response lists the call's permission as missing.
	NamesPermission func(resp *http.Response, body []byte) bool

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

	// Permission is the permission the call needs, in the vendor's own
	// terms, such as iam:ListRoles or administration:read. The collector
	// result lists it with the operation. A permission_denied gap recorded
	// from the call's error lists it as the missing permission. This covers
	// errors the client returns and errors ResponseError builds. When
	// HTTPOptions.NamesPermission returns false, the gap leaves it out. A
	// MissingPermission option on the gap overrides it.
	Permission string
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
		vendorCode:       opts.VendorCode,
		namesPermission:  opts.NamesPermission,
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

var defaultRequestIDHeaders = []string{
	"X-Ms-Request-Id", "Request-Id", "X-Request-Id", "X-GitHub-Request-Id",
	"X-Amzn-RequestId", "X-Amz-Request-Id", "X-Okta-Request-Id",
}

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
	vendorCode       func(*http.Response, []byte) string
	namesPermission  func(*http.Response, []byte) bool
	credentialHost   hostSet
	credentialHdrs   []string
	requestIDHdrs    []string
}

func (t *transport) RoundTrip(req *http.Request) (*http.Response, error) {
	op := t.operation(req)
	call := t.run.beginCall(req.Context(), op)
	failed := func(err error) error {
		if err == nil {
			return nil
		}
		return &callError{err: err, responseCall: responseCall{operation: op.Name, call: call.number}}
	}
	checked, err := t.checkCredentials(req, op)
	if err != nil {
		t.run.calls.addRefused(call, req, t.templateRoute)
		return nil, failed(err)
	}
	req, attempts, err := t.retries(checked, op)
	if err != nil {
		return nil, failed(err)
	}
	processCall := callIDs.Add(1)
	var waited time.Duration
	for attempt := 1; ; attempt++ {
		areq, err := t.attemptRequest(req, op, attempt)
		if err != nil {
			return nil, failed(err)
		}
		started := t.run.now()
		resp, err := t.attempt(areq, attemptMark{call: processCall, attempt: attempt})
		took := t.run.now().Sub(started)
		code, vendorCode := t.inspect(resp)
		if resp != nil {
			markResponse(resp, areq, code, responseCall{operation: op.Name, call: call.number, vendorCode: vendorCode, permission: t.deniedPermission(op, resp, code)})
		}
		t.run.calls.add(attemptRecord{
			call: call, attempt: attempt, req: req, resp: resp, err: err,
			code: code, vendorCode: vendorCode, startMS: t.run.sinceStart(started), waited: waited, took: took,
		}, t.requestIDHdrs, t.templateRoute)
		if attempt >= attempts || !retryable(req.Context(), resp, err, code) {
			return resp, failed(err)
		}
		delay := t.delay(resp, code, attempt)
		if !fitsDeadline(req.Context(), delay) {
			return resp, failed(err)
		}
		drain(resp)
		if err := t.run.wait(req.Context(), delay); err != nil {
			return nil, failed(err)
		}
		waited = delay
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

func (e *attemptTimeoutError) Unwrap() error { return e.err }

func (e *attemptTimeoutError) Timeout() bool { return true }

func (e *attemptTimeoutError) Temporary() bool { return true }
