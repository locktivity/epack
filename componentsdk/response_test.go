package componentsdk

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"testing/synctest"
)

// awsStyleCode returns a code for the error types in an AWS-style JSON body.
func awsStyleCode(_ *http.Response, body []byte) (Code, bool) {
	var e struct {
		Type string `json:"__type"`
	}
	if json.Unmarshal(body, &e) != nil {
		return "", false
	}
	switch e.Type {
	case "ThrottlingException":
		return CodeRateLimited, true
	case "RequestTimeout":
		return CodeTimeout, true
	case "InternalFailure":
		return CodeVendorError, true
	case "OptInRequired":
		return CodeNotLicensed, true
	case "Unlisted":
		return Code("throttled"), true
	}
	return "", false
}

func TestTransportAsksClassifyResponse(t *testing.T) {
	throttle := `{"__type":"ThrottlingException","message":"Rate exceeded"}`
	cases := []struct {
		name     string
		status   int
		body     string
		post     bool
		noHook   bool
		attempts int
		errors   map[Code]int
		code     Code
	}{
		{name: "throttle sent as a 400", status: 400, body: throttle, attempts: 3, errors: map[Code]int{CodeRateLimited: 3}, code: CodeRateLimited},
		{name: "timeout sent as a 400", status: 400, body: `{"__type":"RequestTimeout"}`, attempts: 3, errors: map[Code]int{CodeTimeout: 3}, code: CodeTimeout},
		{name: "vendor failure sent as a 400", status: 400, body: `{"__type":"InternalFailure"}`, attempts: 3, errors: map[Code]int{CodeVendorError: 3}, code: CodeVendorError},
		{name: "the hook's code takes precedence over the status", status: 503, body: `{"__type":"OptInRequired"}`, attempts: 1, errors: map[Code]int{CodeNotLicensed: 1}, code: CodeNotLicensed},
		{name: "with no code from the hook, the status rules apply", status: 503, body: `{}`, attempts: 3, code: CodeVendorError},
		{name: "an invalid code from the hook is ignored", status: 400, body: `{"__type":"Unlisted"}`, attempts: 1, code: CodeInvalidResponse},
		{name: "an unsafe request is not retried", status: 400, body: throttle, post: true, attempts: 1, errors: map[Code]int{CodeRateLimited: 1}, code: CodeRateLimited},
		{name: "a success is not asked", status: 200, body: throttle, attempts: 1},
		{name: "no hook", status: 400, body: throttle, noHook: true, attempts: 1, code: CodeInvalidResponse},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				script := newScript().on("api.example.com/things", respond(tc.status, tc.body, nil))
				c := testContext(script)
				asked := 0
				opts := HTTPOptions{MaxAttempts: 3, ClassifyResponse: func(resp *http.Response, body []byte) (Code, bool) {
					asked++
					return awsStyleCode(resp, body)
				}}
				if tc.noHook {
					opts.ClassifyResponse = nil
				}
				method, reqBody := http.MethodGet, io.Reader(nil)
				if tc.post {
					method, reqBody = http.MethodPost, strings.NewReader(`{}`)
				}
				req, _ := http.NewRequest(method, "https://api.example.com/things", reqBody)
				resp, err := NewHTTPClient(c, opts).Do(req)
				if err != nil {
					t.Fatal(err)
				}
				got, _ := io.ReadAll(resp.Body)
				_ = resp.Body.Close()
				if string(got) != tc.body {
					t.Errorf("body = %q, want the vendor's body", got)
				}
				if n := len(script.requests()); n != tc.attempts {
					t.Errorf("attempts = %d, want %d", n, tc.attempts)
				}
				wantAsked := tc.attempts
				if tc.status < 400 || tc.noHook {
					wantAsked = 0
				}
				if asked != wantAsked {
					t.Errorf("the hook ran %d times, want %d", asked, wantAsked)
				}
				if ops := c.run.calls.operations(); !reflect.DeepEqual(ops[0].Errors, tc.errors) {
					t.Errorf("ledger errors = %v, want %v", ops[0].Errors, tc.errors)
				}
				resp.Body = io.NopCloser(strings.NewReader(""))
				if got := ClassifyResponse(resp); got != tc.code {
					t.Errorf("ClassifyResponse = %q after the body was replaced, want %q", got, tc.code)
				}
				if tc.code != "" {
					err := CodeError(ClassifyResponse(resp), &apiErr{status: resp.StatusCode})
					if got := Classify(err); got != tc.code {
						t.Errorf("Classify of an error built from the response = %q, want %q", got, tc.code)
					}
				}
			})
		})
	}
}

// rpcThrottle returns rate_limited for a JSON-RPC rate limit error. The
// vendor sends that error inside a 200.
func rpcThrottle(_ *http.Response, body []byte) (Code, bool) {
	if bytes.Contains(body, []byte(`"code":-32003`)) {
		return CodeRateLimited, true
	}
	return "", false
}

func TestClassifySuccessRetriesAThrottleInsideA200(t *testing.T) {
	throttle := `{"jsonrpc":"2.0","id":1,"error":{"code":-32003,"message":"Too many requests"}}`
	result := `{"jsonrpc":"2.0","id":1,"result":{"name":"alpha"}}`
	cases := []struct {
		name     string
		success  bool
		answers  []func(*http.Request) (*http.Response, error)
		attempts int
		body     string
		code     Code
		errors   map[Code]int
	}{
		{name: "a throttle that clears", success: true, answers: []func(*http.Request) (*http.Response, error){respond(200, throttle, nil), respond(200, result, nil)},
			attempts: 2, body: result, errors: map[Code]int{CodeRateLimited: 1}},
		{name: "a throttle that lasts", success: true, answers: []func(*http.Request) (*http.Response, error){respond(200, throttle, nil)},
			attempts: 3, body: throttle, code: CodeRateLimited, errors: map[Code]int{CodeRateLimited: 3}},
		{name: "without ClassifySuccess", answers: []func(*http.Request) (*http.Response, error){respond(200, throttle, nil), respond(200, result, nil)},
			attempts: 1, body: throttle},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				script := newScript().on("rpc.example.com/rpc", tc.answers...)
				c := testContext(script)
				client := NewHTTPClient(c, HTTPOptions{MaxAttempts: 3, ClassifyResponse: rpcThrottle, ClassifySuccess: tc.success})
				ctx := WithOperation(context.Background(), Operation{Name: "items.get", Safe: true})
				req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://rpc.example.com/rpc", strings.NewReader(`{"method":"items.get"}`))
				if err != nil {
					t.Fatal(err)
				}
				resp, err := client.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				got, _ := io.ReadAll(resp.Body)
				_ = resp.Body.Close()
				if string(got) != tc.body {
					t.Errorf("body = %q, want %q", got, tc.body)
				}
				if n := len(script.requests()); n != tc.attempts {
					t.Errorf("attempts = %d, want %d", n, tc.attempts)
				}
				if code := ClassifyResponse(resp); code != tc.code {
					t.Errorf("ClassifyResponse = %q, want %q", code, tc.code)
				}
				if ops := c.run.calls.operations(); !reflect.DeepEqual(ops[0].Errors, tc.errors) || ops[0].Statuses["200"] != tc.attempts {
					t.Errorf("ledger = %+v, want errors %v", ops[0], tc.errors)
				}
			})
		})
	}
}

// closeRecorder is a response body that records whether it was closed.
type closeRecorder struct {
	io.Reader
	closed bool
}

func (b *closeRecorder) Close() error {
	b.closed = true
	return nil
}

// failOnce returns its data with err and then io.EOF. A network body would
// keep returning err.
type failOnce struct {
	data string
	err  error
	done bool
}

func (f *failOnce) Read(p []byte) (int, error) {
	if f.done {
		return 0, io.EOF
	}
	f.done = true
	return copy(p, f.data), f.err
}

func TestClassifiedResponseBodyReadsInFull(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		big := `{"__type":"ValidationException","message":"` + strings.Repeat("x", 200<<10) + `"}`
		bigBody := &closeRecorder{Reader: strings.NewReader(big)}
		cut := `{"__type":"Valid`
		answer := func(body io.ReadCloser) func(*http.Request) (*http.Response, error) {
			return func(req *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: 400, Header: http.Header{}, Body: body, Request: req}, nil
			}
		}
		script := newScript().
			on("api.example.com/big", answer(bigBody)).
			on("api.example.com/cut", answer(io.NopCloser(&failOnce{data: cut, err: io.ErrUnexpectedEOF})))
		var seen []byte
		client := NewHTTPClient(testContext(script), HTTPOptions{ClassifyResponse: func(_ *http.Response, body []byte) (Code, bool) {
			seen = body
			return CodeInvalidResponse, true
		}})

		resp, err := get(t, client, context.Background(), "https://api.example.com/big")
		if err != nil {
			t.Fatal(err)
		}
		got, err := io.ReadAll(resp.Body)
		if err != nil || string(got) != big {
			t.Fatalf("read %d bytes (%v), want all %d", len(got), err, len(big))
		}
		if string(seen) != big[:64<<10] {
			t.Errorf("the hook got %d bytes, want the first 64 KiB", len(seen))
		}
		_ = resp.Body.Close()
		if !bigBody.closed {
			t.Error("closing the body should close the vendor's body")
		}

		resp, err = get(t, client, context.Background(), "https://api.example.com/cut")
		if err != nil {
			t.Fatal(err)
		}
		got, err = io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if string(got) != cut || !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Errorf("read %q, %v, want the bytes before the failure and then the error", got, err)
		}
	})
}

func TestVendorCodeHookReadsFailedResponses(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		okta := `{"errorCode":"E0000006","errorSummary":"You do not have permission to perform the requested action for user 00u1abc"}`
		script := newScript().
			on("api.example.com/logs", respond(403, okta, nil)).
			on("api.example.com/users", respond(200, `{"errorCode":"E0000001"}`, nil)).
			on("api.example.com/chatty", respond(400, `{"errorCode":"bad request for jane@example.com"}`, nil)).
			on("api.example.com/leaky", respond(400, `{"errorCode":"tok-abcdef123"}`, nil))
		c := testContext(script)
		c.run.secrets.add("tok-abcdef123")
		var asked []int
		client := NewHTTPClient(c, HTTPOptions{VendorCode: func(resp *http.Response, body []byte) string {
			asked = append(asked, resp.StatusCode)
			var e struct {
				ErrorCode string `json:"errorCode"`
			}
			_ = json.Unmarshal(body, &e)
			return e.ErrorCode
		}})
		for _, path := range []string{"/logs", "/users", "/chatty", "/leaky"} {
			resp, err := get(t, client, context.Background(), "https://api.example.com"+path)
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if path == "/logs" && string(body) != okta {
				t.Errorf("the caller read %q, want the whole body after the hook read it", body)
			}
		}
		if !reflect.DeepEqual(asked, []int{403, 400, 400}) {
			t.Errorf("the hook ran for statuses %v, want only the failed responses", asked)
		}
		rows, _, _ := c.run.calls.requests()
		var codes []string
		for _, r := range rows {
			codes = append(codes, r.VendorCode)
		}
		if want := []string{"E0000006", "", "", ""}; !reflect.DeepEqual(codes, want) {
			t.Errorf("vendor codes = %q, want %q with no message or secret", codes, want)
		}
		raw, _ := json.Marshal(rows)
		if strings.Contains(string(raw), "permission") || strings.Contains(string(raw), "jane") {
			t.Errorf("rows hold the vendor's message: %s", raw)
		}
	})
}

func TestVendorCodeHookReadsAFailureInsideA200(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		script := newScript().on("api.example.com/rpc",
			respond(200, `{"error":{"code":"RATE_LIMIT"}}`, nil),
			respond(200, `{"result":{}}`, nil))
		c := testContext(script)
		client := NewHTTPClient(c, HTTPOptions{
			ClassifySuccess: true,
			ClassifyResponse: func(_ *http.Response, body []byte) (Code, bool) {
				return CodeRateLimited, strings.Contains(string(body), "RATE_LIMIT")
			},
			VendorCode: func(*http.Response, []byte) string { return "RATE_LIMIT" },
		})
		resp, err := get(t, client, context.Background(), "https://api.example.com/rpc")
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		rows, _, _ := c.run.calls.requests()
		if len(rows) != 2 || rows[0].VendorCode != "RATE_LIMIT" || rows[1].VendorCode != "" {
			t.Errorf("rows = %+v, want the code on the throttled 200 and none on its retry", rows)
		}
	})
}

func TestADeniedCallNamesThePermissionItDeclares(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		script := newScript().
			on("api.example.com/logs", respond(403, `{"message":"missing scope"}`, nil)).
			on("api.example.com/roles", respond(403, `{"message":"explicit deny in a service control policy"}`, nil)).
			on("api.example.com/groups", respond(403, `{}`, nil)).
			on("api.example.com/apps", respond(500, `{}`, nil)).
			on("api.example.com/users", respond(403, `{}`, nil))
		c := testContext(script)
		client := NewHTTPClient(c, HTTPOptions{NamesPermission: func(_ *http.Response, body []byte) bool {
			return !strings.Contains(string(body), "explicit deny")
		}})
		denied := func(op Operation, path string) error {
			resp, err := get(t, client, WithOperation(context.Background(), op), "https://api.example.com"+path)
			if err != nil {
				t.Fatal(err)
			}
			_ = resp.Body.Close()
			return ResponseError(resp, CodeError(ClassifyResponse(resp), &apiErr{status: resp.StatusCode}))
		}
		rec := c.run.records
		at := func(p string) Location { return Location{Path: "a.json", Pointer: p} }
		rec.NotCollected(at("/logs"), denied(Operation{Name: "logs.list", Permission: "okta.logs.read"}, "/logs"))
		rec.NotCollected(at("/roles"), denied(Operation{Name: "roles.list", Permission: "iam:ListRoles"}, "/roles"))
		rec.NotCollected(at("/groups"), denied(Operation{Name: "groups.list"}, "/groups"))
		rec.NotCollected(at("/apps"), denied(Operation{Name: "apps.list", Permission: "okta.apps.read"}, "/apps"))
		rec.NotCollected(at("/users"), denied(Operation{Name: "users.list", Permission: "okta.users.read"}, "/users"), MissingPermission("okta.users.manage"))

		want := map[string]string{"/logs": "okta.logs.read", "/roles": "", "/groups": "", "/apps": "", "/users": "okta.users.manage"}
		for _, g := range rec.Gaps() {
			if g.MissingPermission != want[g.Pointer] {
				t.Errorf("gap at %s has missing permission %q, want %q", g.Pointer, g.MissingPermission, want[g.Pointer])
			}
		}
		declared := map[string]string{}
		for _, op := range c.run.calls.operations() {
			declared[op.Name] = op.Permission
		}
		if declared["logs.list"] != "okta.logs.read" || declared["roles.list"] != "iam:ListRoles" || declared["groups.list"] != "" {
			t.Errorf("declared permissions = %v, want each operation's Permission", declared)
		}
	})
}
