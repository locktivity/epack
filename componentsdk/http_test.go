package componentsdk

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"testing/synctest"
	"time"
	"unicode/utf16"
)

// scriptedTransport answers requests from a list of responses per host and
// path, the last one repeating, and records every request it receives.
type scriptedTransport struct {
	mu       sync.Mutex
	script   map[string][]func(*http.Request) (*http.Response, error)
	seen     []*http.Request
	position map[string]int
}

func newScript() *scriptedTransport {
	return &scriptedTransport{script: map[string][]func(*http.Request) (*http.Response, error){}, position: map[string]int{}}
}

func (s *scriptedTransport) on(hostPath string, steps ...func(*http.Request) (*http.Response, error)) *scriptedTransport {
	s.script[hostPath] = steps
	return s
}

func (s *scriptedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	s.mu.Lock()
	s.seen = append(s.seen, req)
	key := req.URL.Host + req.URL.Path
	steps, ok := s.script[key]
	if !ok {
		s.mu.Unlock()
		return respond(404, "not scripted", nil)(req)
	}
	i := s.position[key]
	if i < len(steps)-1 {
		s.position[key] = i + 1
	}
	step := steps[i]
	s.mu.Unlock()
	return step(req)
}

func (s *scriptedTransport) requests() []*http.Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]*http.Request(nil), s.seen...)
}

func respond(status int, body string, header http.Header) func(*http.Request) (*http.Response, error) {
	return func(req *http.Request) (*http.Response, error) {
		h := http.Header{}
		for k, v := range header {
			h[k] = v
		}
		return &http.Response{StatusCode: status, Header: h, Body: io.NopCloser(strings.NewReader(body)), Request: req}, nil
	}
}

func failWith(err error) func(*http.Request) (*http.Response, error) {
	return func(*http.Request) (*http.Response, error) { return nil, err }
}

func testContext(base http.RoundTripper) *collectorContext {
	return &collectorContext{
		ctx:  context.Background(),
		name: "demo",
		spec: CollectorSpec{Name: "demo", Version: "1.2.3"},
		run:  newRun(CollectorSpec{Name: "demo", Version: "1.2.3"}, "demo", "run-1", base, 1),
	}
}

func get(t *testing.T, client *http.Client, ctx context.Context, url string) (*http.Response, error) {
	t.Helper()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	return client.Do(req)
}

func TestTransportRetriesSafeRequests(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		script := newScript().on("api.example.com/users",
			respond(503, "busy", nil),
			respond(200, `{"value":[1]}`, http.Header{"X-Ms-Request-Id": []string{"req-2"}}))
		c := testContext(script)
		client := NewHTTPClient(c, HTTPOptions{})
		ctx := WithOperation(context.Background(), Operation{Name: "users.list"})
		resp, err := get(t, client, ctx, "https://api.example.com/users")
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != 200 || string(body) != `{"value":[1]}` {
			t.Fatalf("got %d %q", resp.StatusCode, body)
		}
		ops := c.run.calls.operations()
		if len(ops) != 1 || ops[0].Name != "users.list" || ops[0].Calls != 1 || ops[0].Attempts != 2 || ops[0].Retries != 1 {
			t.Fatalf("ledger = %+v", ops)
		}
		if ops[0].Statuses["503"] != 1 || ops[0].Statuses["200"] != 1 {
			t.Errorf("statuses = %v", ops[0].Statuses)
		}
		rows, _, _ := c.run.calls.requests()
		if rows[1].RequestID != "req-2" || rows[1].Attempt != 2 {
			t.Errorf("second row = %+v", rows[1])
		}
	})
}

func TestTransportReturnsLastResponseWhenRetriesRunOut(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		script := newScript().on("api.example.com/users", respond(500, "still broken", nil))
		c := testContext(script)
		client := NewHTTPClient(c, HTTPOptions{MaxAttempts: 3})
		resp, err := get(t, client, context.Background(), "https://api.example.com/users")
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != 500 || string(body) != "still broken" {
			t.Fatalf("got %d %q, want the last response untouched", resp.StatusCode, body)
		}
		if got := len(script.requests()); got != 3 {
			t.Errorf("attempts = %d, want 3", got)
		}
	})
}

func TestTransportDoesNotRetryUnsafeRequests(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		script := newScript().on("api.example.com/things", respond(503, "busy", nil))
		c := testContext(script)
		client := NewHTTPClient(c, HTTPOptions{})
		post := func(ctx context.Context) {
			req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.example.com/things", bytes.NewReader([]byte(`{}`)))
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			_ = resp.Body.Close()
		}
		post(context.Background())
		if got := len(script.requests()); got != 1 {
			t.Fatalf("unsafe POST attempts = %d, want 1", got)
		}
		post(WithOperation(context.Background(), Operation{Name: "things.query", Safe: true}))
		if got := len(script.requests()) - 1; got != 5 {
			t.Fatalf("safe POST attempts = %d, want 5", got)
		}
		for _, req := range script.requests()[1:] {
			body, _ := io.ReadAll(req.Body)
			if string(body) != `{}` {
				t.Fatalf("retried body = %q, want the original", body)
			}
		}
	})
}

func TestTransportHonorsRetryAfter(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		script := newScript().on("api.example.com/users",
			respond(429, "slow down", http.Header{"Retry-After": []string{"7"}}),
			respond(200, "{}", nil))
		c := testContext(script)
		client := NewHTTPClient(c, HTTPOptions{})
		start := time.Now()
		resp, err := get(t, client, context.Background(), "https://api.example.com/users")
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		waited := time.Since(start)
		if waited < 7*time.Second || waited > 8*time.Second {
			t.Errorf("waited %s, want 7s plus at most 1s of jitter", waited)
		}
	})
}

func TestTransportCapsRetryAfterAndRespectsDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		script := newScript().on("api.example.com/users",
			respond(429, "slow down", http.Header{"Retry-After": []string{"3600"}}),
			respond(200, "{}", nil))
		c := testContext(script)
		client := NewHTTPClient(c, HTTPOptions{RetryAfterCap: 5 * time.Second})
		start := time.Now()
		resp, err := get(t, client, context.Background(), "https://api.example.com/users")
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if waited := time.Since(start); waited > 6*time.Second {
			t.Errorf("waited %s, want the 5s cap", waited)
		}

		script2 := newScript().on("api.example.com/users", respond(503, "busy", http.Header{"Retry-After": []string{"30"}}))
		c2 := testContext(script2)
		client2 := NewHTTPClient(c2, HTTPOptions{})
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		resp, err = get(t, client2, ctx, "https://api.example.com/users")
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != 503 || len(script2.requests()) != 1 {
			t.Errorf("a wait past the deadline should return the response at once, got %d after %d attempts", resp.StatusCode, len(script2.requests()))
		}
	})
}

func TestTransportWaitsForARateLimitReset(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	epoch := func(d time.Duration) string { return strconv.FormatInt(now.Add(d).Unix(), 10) }
	header := func(pairs ...string) http.Header {
		h := http.Header{}
		for i := 0; i < len(pairs); i += 2 {
			h.Set(pairs[i], pairs[i+1])
		}
		return h
	}
	cases := []struct {
		name   string
		status int
		body   string
		header http.Header
		wait   time.Duration
	}{
		{name: "Okta", status: 429, header: header("X-Rate-Limit-Remaining", "0", "X-Rate-Limit-Reset", epoch(30*time.Second)), wait: 30 * time.Second},
		{name: "GitHub", status: 429, header: header("X-RateLimit-Remaining", "0", "X-RateLimit-Reset", epoch(30*time.Second)), wait: 30 * time.Second},
		{name: "GitHub, throttled with a 403", status: 403, header: header("X-RateLimit-Remaining", "0", "X-RateLimit-Reset", epoch(30*time.Second)), wait: 30 * time.Second},
		{name: "Okta, throttled with a 403", status: 403, header: header("X-Rate-Limit-Remaining", "0", "X-Rate-Limit-Reset", epoch(30*time.Second)), wait: 30 * time.Second},
		{name: "GitLab, in epoch seconds", status: 429, header: header("RateLimit-Reset", epoch(30*time.Second)), wait: 30 * time.Second},
		{name: "IETF draft, in seconds from now", status: 429, header: header("RateLimit-Reset", "12"), wait: 12 * time.Second},
		{name: "Sentry", status: 429, header: header("X-Sentry-Rate-Limit-Reset", epoch(30*time.Second)), wait: 30 * time.Second},
		{name: "a throttle the hook names", status: 400, body: `{"__type":"ThrottlingException"}`, header: header("X-Rate-Limit-Reset", epoch(30*time.Second)), wait: 30 * time.Second},
		{name: "a reset already past", status: 429, header: header("X-Rate-Limit-Reset", epoch(-time.Minute)), wait: 0},
		{name: "a reset past the cap", status: 429, header: header("X-Rate-Limit-Reset", epoch(time.Hour)), wait: time.Minute},
		{name: "Retry-After first", status: 429, header: header("Retry-After", "7", "X-Rate-Limit-Reset", epoch(30*time.Second)), wait: 7 * time.Second},
		{name: "not a throttle", status: 503, header: header("X-Rate-Limit-Reset", epoch(30*time.Second)), wait: -1},
		{name: "unparsable", status: 429, header: header("X-Rate-Limit-Reset", "soon"), wait: -1},
		{name: "not a number", status: 429, header: header("X-Rate-Limit-Reset", "NaN"), wait: -1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			script := newScript().on("api.example.com/users", respond(tc.status, tc.body, tc.header))
			c := testContext(script)
			c.run.clock = func() time.Time { return now }
			var waits []time.Duration
			c.run.sleep = func(_ context.Context, d time.Duration) error {
				waits = append(waits, d)
				return nil
			}
			client := NewHTTPClient(c, HTTPOptions{MaxAttempts: 2, ClassifyResponse: awsStyleCode})
			resp, err := get(t, client, context.Background(), "https://api.example.com/users")
			if err != nil {
				t.Fatal(err)
			}
			_ = resp.Body.Close()
			if len(waits) != 1 {
				t.Fatalf("waits = %v, want one before the retry", waits)
			}
			if tc.wait < 0 {
				if waits[0] >= backoffBase {
					t.Errorf("waited %s, want the first backoff, under %s", waits[0], backoffBase)
				}
				return
			}
			if limit := tc.wait + minDuration(time.Second, tc.wait/10+1); waits[0] < tc.wait || waits[0] >= limit {
				t.Errorf("waited %s, want %s plus jitter under %s", waits[0], tc.wait, limit-tc.wait)
			}
		})
	}
}

func TestTransportDoesNotRetryADenied403(t *testing.T) {
	script := newScript().on("api.example.com/users", respond(403, "denied", http.Header{"X-RateLimit-Remaining": []string{"4999"}}))
	c := testContext(script)
	client := NewHTTPClient(c, HTTPOptions{})
	resp, err := get(t, client, context.Background(), "https://api.example.com/users")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if got := len(script.requests()); got != 1 {
		t.Errorf("attempts = %d, want 1 for a 403 with rate limit to spare", got)
	}
}

func TestTransportTimesOutSlowHeaders(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		hang := func(req *http.Request) (*http.Response, error) {
			<-req.Context().Done()
			return nil, req.Context().Err()
		}
		script := newScript().on("api.example.com/users", hang)
		c := testContext(script)
		client := NewHTTPClient(c, HTTPOptions{AttemptTimeout: time.Second, MaxAttempts: 2})
		_, err := get(t, client, context.Background(), "https://api.example.com/users")
		if err == nil || Classify(err) != CodeTimeout {
			t.Fatalf("err = %v (%s), want a timeout", err, Classify(err))
		}
		if got := len(script.requests()); got != 2 {
			t.Errorf("attempts = %d, want 2", got)
		}
	})
}

func TestTransportRetriesTransportErrors(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		script := newScript().on("api.example.com/users",
			failWith(&net.OpError{Op: "read", Net: "tcp", Err: syscall.ECONNRESET}),
			respond(200, "{}", nil))
		c := testContext(script)
		client := NewHTTPClient(c, HTTPOptions{})
		resp, err := get(t, client, context.Background(), "https://api.example.com/users")
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Errorf("status = %d", resp.StatusCode)
		}
	})
}

func TestTransportRetriesOnlyErrorsThatCanClear(t *testing.T) {
	cases := []struct {
		name     string
		err      error
		attempts int
	}{
		{"a reset connection", &net.OpError{Op: "read", Net: "tcp", Err: syscall.ECONNRESET}, 3},
		{"a server closing an idle connection", fmt.Errorf("failed to read from server: %w", io.EOF), 3},
		{"a connection closed mid-response", fmt.Errorf("transport connection broken: %w", io.ErrUnexpectedEOF), 3},
		{"a timeout", timeoutErr{}, 3},
		{"a throttle the error names", CodeError(CodeRateLimited, errors.New("slow down")), 3},
		{"a guard refusing a private address", CodeError(CodeConfigInvalid, errors.New("refusing 10.0.0.7")), 1},
		{"a guard refusing a host", CodeError(CodePermissionDenied, errors.New("host is not allowed")), 1},
		{"a guard refusing a URL", CodeError(CodeInvalidResponse, errors.New("refusing a non-https URL")), 1},
		{"an error with no code", errors.New("something broke"), 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				script := newScript().on("files.example.com/doc", failWith(tc.err))
				client := NewHTTPClient(testContext(nil), HTTPOptions{Base: script, MaxAttempts: 3})
				if _, err := get(t, client, context.Background(), "https://files.example.com/doc"); !errors.Is(err, tc.err) {
					t.Fatalf("err = %v, want %v", err, tc.err)
				}
				if n := len(script.requests()); n != tc.attempts {
					t.Errorf("attempts = %d, want %d", n, tc.attempts)
				}
			})
		})
	}
}

func TestTransportKeepsCredentialsOffPlainHTTP(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		script := newScript().
			on("api.example.com/start", respond(302, "", http.Header{"Location": []string{"http://api.example.com/next"}})).
			on("api.example.com/next", respond(200, "{}", nil)).
			on("api.example.com/plain", respond(200, "{}", nil)).
			on("127.0.0.1:8080/local", respond(200, "{}", nil)).
			on("[::1]:8080/local", respond(200, "{}", nil)).
			on("localhost:8080/local", respond(200, "{}", nil))
		c := testContext(script)
		listed := NewHTTPClient(c, HTTPOptions{CredentialHosts: []string{"api.example.com"}})
		unlisted := NewHTTPClient(c, HTTPOptions{})
		send := func(client *http.Client, url string, credential bool) error {
			req, err := http.NewRequest(http.MethodGet, url, nil)
			if err != nil {
				t.Fatal(err)
			}
			if credential {
				req.Header.Set("PRIVATE-TOKEN", "glpat-secret-value")
			}
			resp, err := client.Do(req)
			if err == nil {
				_ = resp.Body.Close()
			}
			return err
		}

		var refused *RefusedHostError
		err := send(listed, "https://api.example.com/start", true)
		if !errors.As(err, &refused) || !refused.Plaintext || refused.Host != "api.example.com" {
			t.Fatalf("redirect to plain http: err = %v, want a plaintext refusal", err)
		}
		if !strings.Contains(err.Error(), "over plain http") || Classify(err) != CodeInvalidResponse {
			t.Errorf("err = %v classifies as %s", err, Classify(err))
		}
		for _, r := range script.requests() {
			if r.URL.Path == "/next" {
				t.Fatal("the token went to http://api.example.com/next")
			}
		}
		if err := send(unlisted, "http://api.example.com/plain", true); !errors.As(err, &refused) || !refused.Plaintext {
			t.Errorf("plain http with no host list: err = %v, want a plaintext refusal", err)
		}
		for _, url := range []string{"http://127.0.0.1:8080/local", "http://[::1]:8080/local", "http://localhost:8080/local"} {
			if err := send(unlisted, url, true); err != nil {
				t.Errorf("%s: %v, want loopback allowed", url, err)
			}
		}
		if err := send(unlisted, "http://api.example.com/plain", false); err != nil {
			t.Errorf("a request without credentials may use plain http: %v", err)
		}
	})
}

func TestTransportKeepsCredentialsOnTheirHosts(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		script := newScript().
			on("api.example.com/start", respond(302, "", http.Header{"Location": []string{"https://evil.example/steal"}})).
			on("evil.example/steal", respond(200, "{}", nil)).
			on("cdn.example.net/file", respond(200, "{}", nil))
		c := testContext(script)
		client := NewHTTPClient(c, HTTPOptions{CredentialHosts: []string{"api.example.com", "*.example.org"}})

		req, _ := http.NewRequest(http.MethodGet, "https://api.example.com/start", nil)
		req.Header.Set("PRIVATE-TOKEN", "glpat-secret-value")
		_, err := client.Do(req)
		var refused *RefusedHostError
		if !errors.As(err, &refused) || refused.Host != "evil.example" {
			t.Fatalf("redirect err = %v, want a refusal for evil.example", err)
		}
		for _, r := range script.requests() {
			if r.URL.Host == "evil.example" {
				t.Fatal("the token reached evil.example")
			}
		}

		req, _ = http.NewRequest(http.MethodGet, "https://cdn.example.net/file", nil)
		req.Header.Set("Authorization", "Bearer token")
		if _, err := client.Do(req); !errors.As(err, &refused) {
			t.Fatalf("next-page err = %v, want a refusal", err)
		}

		req, _ = http.NewRequest(http.MethodGet, "https://cdn.example.net/file", nil)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("a request without credentials may go anywhere: %v", err)
		}
		_ = resp.Body.Close()

		if !newHostSet([]string{"*.example.org"}).allows("api.example.org") {
			t.Error("*.example.org should match api.example.org")
		}
	})
}

func TestTransportRecordsCalls(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		script := newScript().
			on("management.example.com/subscriptions/0f3e5c2a-1b2c-4d5e-8f90-123456789abc/assessments",
				respond(200, "{}", http.Header{"Deprecation": []string{"@1688169599"}, "Sunset": []string{"Wed, 01 Jul 2026 00:00:00 GMT"}})).
			on("management.example.com/plain", respond(200, "{}", nil))
		c := testContext(script)
		client := NewHTTPClient(c, HTTPOptions{})
		ctx := WithOperation(context.Background(), Operation{Name: "defender.assessments.list"})
		resp, err := get(t, client, ctx, "https://management.example.com/subscriptions/0f3e5c2a-1b2c-4d5e-8f90-123456789abc/assessments?api-version=2020-01-01&$filter=secret")
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.Request.Header.Get("User-Agent") != "epack-collector-demo/1.2.3 (run run-1)" {
			t.Errorf("User-Agent = %q", resp.Request.Header.Get("User-Agent"))
		}
		resp, err = get(t, client, context.Background(), "https://management.example.com/plain")
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()

		ops := c.run.calls.operations()
		if len(ops) != 2 || ops[0].Name != "defender.assessments.list" || ops[1].Name != UnnamedOperation {
			t.Fatalf("operations = %+v", ops)
		}
		if ops[0].Deprecation != "@1688169599" || ops[0].Sunset == "" {
			t.Errorf("deprecation headers = %q / %q", ops[0].Deprecation, ops[0].Sunset)
		}
		rows, _, _ := c.run.calls.requests()
		if rows[0].Route != "/subscriptions/{id}/assessments" {
			t.Errorf("route = %q, want the subscription templated", rows[0].Route)
		}
		if strings.Join(rows[0].QueryKeys, ",") != "$filter,api-version" {
			t.Errorf("query keys = %v, want keys without values", rows[0].QueryKeys)
		}
	})
}

func TestTransportUsesTheCollectorsRouteTemplate(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		path := "/subscriptions/0f3e5c2a-1b2c-4d5e-8f90-123456789abc/resourceGroups/payments/providers/Microsoft.Sql/servers/ledger"
		script := newScript().on("management.example.com"+path, respond(200, "{}", nil))
		c := testContext(script)
		client := NewHTTPClient(c, HTTPOptions{
			CredentialHosts: []string{"management.example.com"},
			TemplateRoute: func(p string) string {
				return strings.NewReplacer("/payments/", "/{name}/", "/ledger", "/{name}").Replace(TemplateRoute(p))
			},
		})
		ctx := WithOperation(context.Background(), Operation{Name: "sql.servers.get"})
		resp, err := get(t, client, ctx, "https://management.example.com"+path)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()

		refused, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://other.example.net"+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		refused.Header.Set("Authorization", "Bearer token")
		if _, err := client.Do(refused); err == nil {
			t.Fatal("a credential to another host should be refused")
		}

		rows, _, _ := c.run.calls.requests()
		want := "/subscriptions/{id}/resourceGroups/{name}/providers/Microsoft.Sql/servers/{name}"
		if len(rows) != 2 || rows[0].Route != want || rows[1].Route != want {
			t.Fatalf("rows = %+v, want both routes templated as %s", rows, want)
		}
	})
}

// awsStyleCode answers for the error types in an AWS-style JSON body.
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
		{name: "the answer outranks the status", status: 503, body: `{"__type":"OptInRequired"}`, attempts: 1, errors: map[Code]int{CodeNotLicensed: 1}, code: CodeNotLicensed},
		{name: "no answer leaves the status rules", status: 503, body: `{}`, attempts: 3, code: CodeVendorError},
		{name: "an invalid code is no answer", status: 400, body: `{"__type":"Unlisted"}`, attempts: 1, code: CodeInvalidResponse},
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
					t.Errorf("body = %q, want the vendor's", got)
				}
				if n := len(script.requests()); n != tc.attempts {
					t.Errorf("attempts = %d, want %d", n, tc.attempts)
				}
				wantAsked := tc.attempts
				if tc.status < 400 || tc.noHook {
					wantAsked = 0
				}
				if asked != wantAsked {
					t.Errorf("the hook was asked %d times, want %d", asked, wantAsked)
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

// rpcThrottle reads a JSON-RPC rate limit error, which comes inside a 200.
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

func TestRunInProcessListsEachClientsCredentialHosts(t *testing.T) {
	handler := func(ctx CollectorContext) error {
		NewHTTPClient(ctx, HTTPOptions{CredentialHosts: []string{"api.example.com"}})
		NewTransport(ctx, HTTPOptions{CredentialHosts: []string{"*.example.org", "login.example.org"}})
		NewHTTPClient(ctx, HTTPOptions{CredentialHosts: []string{"api.example.com"}})
		NewHTTPClient(ctx, HTTPOptions{})
		return ctx.Emit([]CollectedArtifact{{Data: map[string]any{}, Path: "artifacts/demo.json"}})
	}
	res := RunInProcess(CollectorSpec{Name: "demo"}, handler, InProcessOptions{})
	want := [][]string{{"api.example.com"}, {"*.example.org", "login.example.org"}, {}}
	if !reflect.DeepEqual(res.CredentialHosts, want) {
		t.Errorf("CredentialHosts = %q, want each distinct list once, in order", res.CredentialHosts)
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

// failOnce returns its data with err, then io.EOF, where a network body
// would keep returning err.
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
			t.Errorf("the hook saw %d bytes, want the first 64 KiB", len(seen))
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
			t.Errorf("read %q, %v; want the bytes before the failure, then the failure", got, err)
		}
	})
}

func TestTransportSendsThroughBase(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		base := newScript().on("api.example.com/users", respond(200, "{}", nil))
		// No transport of the run's own, as RunCollector makes it.
		c := testContext(nil)
		resp, err := get(t, NewHTTPClient(c, HTTPOptions{Base: base}), context.Background(), "https://api.example.com/users")
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if n := len(base.requests()); n != 1 {
			t.Errorf("Base got %d requests, want 1", n)
		}
	})
}

func TestRunInProcessTransportReplacesBase(t *testing.T) {
	guard := newScript().on("api.example.com/users", respond(200, "{}", nil))
	handler := func(ctx CollectorContext) error {
		req, err := http.NewRequestWithContext(ctx.Context(), http.MethodGet, "https://api.example.com/users", nil)
		if err != nil {
			return err
		}
		resp, err := NewHTTPClient(ctx, HTTPOptions{Base: guard}).Do(req)
		if err != nil {
			return err
		}
		_ = resp.Body.Close()
		return ctx.Emit([]CollectedArtifact{{Data: map[string]any{}, Path: "artifacts/demo.json"}})
	}
	spec := CollectorSpec{Name: "demo"}
	replay := newScript().on("api.example.com/users", respond(200, "{}", nil))
	if res := RunInProcess(spec, handler, InProcessOptions{Transport: replay}); res.ExitCode != 0 {
		t.Fatalf("exit = %d: %s", res.ExitCode, res.Stderr)
	}
	if len(guard.requests()) != 0 || len(replay.requests()) != 1 {
		t.Errorf("Base got %d requests and Transport %d, want Transport to take the one", len(guard.requests()), len(replay.requests()))
	}

	if res := RunInProcess(spec, handler, InProcessOptions{}); res.ExitCode != 0 {
		t.Fatalf("exit without a Transport = %d: %s", res.ExitCode, res.Stderr)
	}
	if n := len(guard.requests()); n != 1 {
		t.Errorf("without a Transport, Base got %d requests, want 1", n)
	}
}

func TestTemplateRoute(t *testing.T) {
	cases := map[string]string{
		"/v1.0/users":                            "/v1.0/users",
		"/v1.0/users/alice@example.com":          "/v1.0/users/{id}",
		"/repos/12345/hooks":                     "/repos/{id}/hooks",
		"/objects/a1b2c3d4e5f6a7b8":              "/objects/{id}",
		"/tokens/AbCdEfGhIjKlMnOp1234567890":     "/tokens/{id}",
		"/providers/Microsoft.Security/pricings": "/providers/Microsoft.Security/pricings",
		"":                                       "/",
	}
	for in, want := range cases {
		if got := TemplateRoute(in); got != want {
			t.Errorf("TemplateRoute(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNameOperationNamesFirstAndReachesTheBase(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		seen := map[string]string{}
		var mu sync.Mutex
		base := roundTripFunc(func(req *http.Request) (*http.Response, error) {
			op, ok := OperationOf(req.Context())
			mu.Lock()
			if ok {
				seen[req.URL.Path] = op.Name
			} else {
				seen[req.URL.Path] = "(none)"
			}
			mu.Unlock()
			return respond(200, "{}", nil)(req)
		})
		c := testContext(base)
		client := NewHTTPClient(c, HTTPOptions{NameOperation: func(req *http.Request) (Operation, bool) {
			if req.URL.Path == "/token" {
				return Operation{Name: "demo.token.create", Safe: true}, true
			}
			return Operation{}, false
		}})
		caller := WithOperation(context.Background(), Operation{Name: "demo.items.list"})
		for _, target := range []struct {
			ctx context.Context
			url string
		}{
			{caller, "https://api.example.com/items"},
			{caller, "https://api.example.com/token"},
			{context.Background(), "https://api.example.com/other"},
		} {
			resp, err := get(t, client, target.ctx, target.url)
			if err != nil {
				t.Fatal(err)
			}
			_ = resp.Body.Close()
		}
		want := map[string]string{"/items": "demo.items.list", "/token": "demo.token.create", "/other": "(none)"}
		if !reflect.DeepEqual(seen, want) {
			t.Errorf("operations seen below the transport = %v, want %v", seen, want)
		}
		var names []string
		for _, op := range c.run.calls.operations() {
			names = append(names, op.Name)
		}
		if strings.Join(names, ",") != "demo.items.list,demo.token.create,"+UnnamedOperation {
			t.Errorf("ledger operations = %v", names)
		}
	})
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func TestTransportReplaysASafeBodyBuiltWithoutGetBody(t *testing.T) {
	post := func(t *testing.T, body string) (*http.Response, []string) {
		t.Helper()
		var mu sync.Mutex
		var bodies []string
		base := roundTripFunc(func(req *http.Request) (*http.Response, error) {
			b, err := io.ReadAll(req.Body)
			if err != nil {
				return nil, err
			}
			mu.Lock()
			bodies = append(bodies, string(b))
			n := len(bodies)
			mu.Unlock()
			if n == 1 {
				return respond(503, "", nil)(req)
			}
			return respond(200, "{}", nil)(req)
		})
		client := NewHTTPClient(testContext(base), HTTPOptions{})
		ctx := WithOperation(context.Background(), Operation{Name: "rpc.items.get", Safe: true})
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.example.com/rpc", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Body = io.NopCloser(strings.NewReader(body))
		req.ContentLength = int64(len(body))
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp, bodies
	}
	t.Run("a small body is sent again", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			resp, bodies := post(t, `{"id":7}`)
			if resp.StatusCode != 200 || len(bodies) != 2 || bodies[0] != `{"id":7}` || bodies[1] != `{"id":7}` {
				t.Errorf("status %d, bodies %q; want a retry with the same body", resp.StatusCode, bodies)
			}
		})
	})
	t.Run("a body too large to hold is sent once", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			large := strings.Repeat("x", maxReplayBody+1)
			resp, bodies := post(t, large)
			if resp.StatusCode != 503 || len(bodies) != 1 || len(bodies[0]) != len(large) {
				t.Errorf("status %d, %d attempts; want one attempt carrying the whole body", resp.StatusCode, len(bodies))
			}
		})
	})
}

// The +, /, and = of a base64 secret are what form and query encoding
// escape, and the quote, backslash, <, >, & and non-ASCII characters of a
// password are what JSON encoders escape.
const (
	base64Secret   = "s3cr3t+value/123456=="
	passwordSecret = "p<a&s>\"w\\ord-é🔑"
)

// jsonBody returns a JSON object holding value under key, as Go's encoder
// writes it with or without HTML escapes.
func jsonBody(key, value string, escapeHTML bool) string {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(escapeHTML)
	_ = enc.Encode(map[string]string{key: value})
	return strings.TrimSpace(b.String())
}

// asciiJSON escapes each character of s other than an ASCII letter or digit
// as \uXXXX in lowercase hex, as an encoder that keeps its output ASCII can.
func asciiJSON(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' {
			b.WriteRune(r)
			continue
		}
		for _, unit := range utf16.Encode([]rune{r}) {
			fmt.Fprintf(&b, `\u%04x`, unit)
		}
	}
	return b.String()
}

func TestTransportKeepsSecretsOffUnlistedHosts(t *testing.T) {
	const secret = base64Secret
	lowercase := strings.NewReplacer("+", "%2b", "/", "%2f", "=", "%3d")
	cases := []struct {
		name    string
		url     string
		body    string
		refused bool
	}{
		{"a secret in the body to an unlisted host", "https://evil.example/token", "client_secret=" + secret, true},
		{"a secret in the URL to an unlisted host", "https://evil.example/token?key=" + secret, "", true},
		{"a form-encoded secret in the body", "https://evil.example/token", url.Values{"client_secret": {secret}}.Encode(), true},
		{"a query-escaped secret in the URL", "https://evil.example/token?key=" + url.QueryEscape(secret), "", true},
		{"a path-escaped secret in the URL", "https://evil.example/keys/" + url.PathEscape(secret), "", true},
		{"a secret escaped in lowercase hex", "https://evil.example/token", "client_secret=" + lowercase.Replace(secret), true},
		{"an encoded secret after a stray percent", "https://evil.example/token", "note=100%&client_secret=" + url.QueryEscape(secret), true},
		{"a JSON-escaped secret in the body", "https://evil.example/token", jsonBody("password", passwordSecret, true), true},
		{"a secret in JSON without HTML escapes", "https://evil.example/token", jsonBody("password", passwordSecret, false), true},
		{"a secret in ASCII-only JSON", "https://evil.example/token", `{"password":"` + asciiJSON(passwordSecret) + `"}`, true},
		{"JSON in a form field", "https://evil.example/token", url.Values{"assertion": {jsonBody("password", passwordSecret, true)}}.Encode(), true},
		{"JSON in the URL", "https://evil.example/token?filter=" + url.QueryEscape(jsonBody("password", passwordSecret, true)), "", true},
		{"no secret to an unlisted host", "https://evil.example/token", "grant_type=client_credentials", false},
		{"a secret in the body to a listed host", "https://login.example.com/token", "client_secret=" + secret, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var mu sync.Mutex
				var seen []string
				base := roundTripFunc(func(req *http.Request) (*http.Response, error) {
					b := ""
					if req.Body != nil {
						raw, _ := io.ReadAll(req.Body)
						b = string(raw)
					}
					mu.Lock()
					seen = append(seen, b)
					mu.Unlock()
					return respond(200, "{}", nil)(req)
				})
				c := testContext(base)
				c.run.secrets.add(base64Secret)
				c.run.secrets.add(passwordSecret)
				client := NewHTTPClient(c, HTTPOptions{CredentialHosts: []string{"login.example.com"}})
				req, err := http.NewRequest(http.MethodPost, tc.url, strings.NewReader(tc.body))
				if err != nil {
					t.Fatal(err)
				}
				resp, err := client.Do(req)
				var refused *RefusedHostError
				if got := errors.As(err, &refused); got != tc.refused {
					t.Fatalf("refused = %v (err %v), want %v", got, err, tc.refused)
				}
				if err == nil {
					_ = resp.Body.Close()
					if len(seen) != 1 || seen[0] != tc.body {
						t.Errorf("the vendor saw %q, want the body intact", seen)
					}
				} else if len(seen) != 0 {
					t.Errorf("a refused request reached the vendor: %q", seen)
				}
			})
		})
	}
}

func TestTransportRefusesARedirectThatCarriesAnEncodedSecret(t *testing.T) {
	cases := []struct {
		name, contentType, body string
	}{
		{"a form", "application/x-www-form-urlencoded", url.Values{"grant_type": {"client_credentials"}, "client_secret": {base64Secret}}.Encode()},
		{"JSON", "application/json", jsonBody("password", passwordSecret, true)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			script := newScript().
				on("login.example.com/token", respond(http.StatusTemporaryRedirect, "", http.Header{"Location": []string{"https://evil.example/token"}})).
				on("evil.example/token", respond(200, "{}", nil))
			c := testContext(script)
			c.run.secrets.add(base64Secret)
			c.run.secrets.add(passwordSecret)
			client := NewHTTPClient(c, HTTPOptions{CredentialHosts: []string{"login.example.com"}})
			req, err := http.NewRequest(http.MethodPost, "https://login.example.com/token", strings.NewReader(tc.body))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Content-Type", tc.contentType)
			resp, err := client.Do(req)
			if err == nil {
				_ = resp.Body.Close()
			}
			var refused *RefusedHostError
			if !errors.As(err, &refused) || refused.Host != "evil.example" {
				t.Fatalf("err = %v, want a refusal of evil.example", err)
			}
			for _, r := range script.requests() {
				if r.URL.Host == "evil.example" {
					t.Errorf("the redirect reached %s", r.URL)
				}
			}
		})
	}
}

func TestUnescapeJSONLoosely(t *testing.T) {
	cases := map[string]string{
		`a\"b\\c\/d`:         `a"b\c/d`,
		`\u003C\u003e\u0026`: "<>&",
		`\ud83d\udd11`:       "🔑",
		`\\u003c`:            `\u003c`,
		`\u12 \x \`:          `\u12 \x \`,
		`\n\t\r\b\f`:         "\n\t\r\b\f",
		`lone \ud83d high`:   "lone \uFFFD high",
		`no escapes at all`:  "no escapes at all",
	}
	for in, want := range cases {
		if got := unescapeJSONLoosely(in); got != want {
			t.Errorf("unescapeJSONLoosely(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestTransportNumbersCallsAndTimesEachAttempt(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		script := newScript().
			on("api.example.com/users",
				respond(429, `{"errorCode":"E0000047"}`, http.Header{"Retry-After": []string{"2"}}),
				respond(200, "[]", nil)).
			on("api.example.com/apps", respond(200, "[]", nil))
		c := testContext(script)
		client := NewHTTPClient(c, HTTPOptions{})
		time.Sleep(3 * time.Second)
		for _, path := range []string{"/users", "/apps"} {
			resp, err := get(t, client, WithOperation(context.Background(), Operation{Name: "list" + path}), "https://api.example.com"+path)
			if err != nil {
				t.Fatal(err)
			}
			_ = resp.Body.Close()
		}
		rows, _, _ := c.run.calls.requests()
		if len(rows) != 3 {
			t.Fatalf("rows = %+v", rows)
		}
		first, retry, apps := rows[0], rows[1], rows[2]
		if first.Call != 1 || retry.Call != 1 || apps.Call != 2 {
			t.Errorf("calls = %d, %d, %d; want both attempts of the first call numbered 1 and the next call 2", first.Call, retry.Call, apps.Call)
		}
		if first.StartMS != 3000 || first.WaitedMS != 0 {
			t.Errorf("first attempt started at %dms and waited %dms, want 3000ms after the run started and no wait", first.StartMS, first.WaitedMS)
		}
		if retry.WaitedMS < 2000 || retry.WaitedMS > 2201 || retry.StartMS != first.StartMS+retry.WaitedMS {
			t.Errorf("retry waited %dms and started at %dms, want the Retry-After with its jitter, sent after the wait", retry.WaitedMS, retry.StartMS)
		}
		if apps.StartMS != retry.StartMS || apps.WaitedMS != 0 {
			t.Errorf("next call started at %dms and waited %dms", apps.StartMS, apps.WaitedMS)
		}
		if first.VendorCode != "" {
			t.Errorf("vendor code %q without a VendorCode hook", first.VendorCode)
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
			t.Errorf("the hook was asked about statuses %v, want only the failed responses", asked)
		}
		rows, _, _ := c.run.calls.requests()
		var codes []string
		for _, r := range rows {
			codes = append(codes, r.VendorCode)
		}
		if want := []string{"E0000006", "", "", ""}; !reflect.DeepEqual(codes, want) {
			t.Errorf("vendor codes = %q, want %q: a message or a secret is never a code", codes, want)
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

func TestLedgerKeepsProblemRowsPastTheLimit(t *testing.T) {
	l := newLedger()
	req := mustRequest("https://api.example.com/users")
	add := func(n, status, attempt int) {
		for range n {
			l.add(attemptRecord{call: callStart{op: Operation{Name: "users.list"}, number: l.startCall()}, attempt: attempt, req: req, resp: &http.Response{StatusCode: status, Header: http.Header{}}}, nil, nil)
		}
	}
	add(maxCallRows, 200, 1)
	add(5, 200, 1)
	add(maxProblemRows-1, 403, 1)
	add(1, 200, 2)
	add(7, 429, 1)
	rows, dropped, problemsDropped := l.requests()
	if len(rows) != maxCallRows+maxProblemRows {
		t.Errorf("kept %d rows, want the first %d and %d problem rows after them", len(rows), maxCallRows, maxProblemRows)
	}
	if rows[maxCallRows].Status != 403 || rows[len(rows)-1].Attempt != 2 {
		t.Errorf("rows past the limit = %+v ... %+v, want the failures and the retry", rows[maxCallRows], rows[len(rows)-1])
	}
	if dropped != 12 || problemsDropped != 7 {
		t.Errorf("dropped = %d, problems dropped = %d; want 12 and 7", dropped, problemsDropped)
	}
	if ops := l.operations(); ops[0].Attempts != maxCallRows+5+maxProblemRows+7 || ops[0].Statuses["429"] != 7 {
		t.Errorf("operation counts leave out dropped rows: %+v", ops[0])
	}
}

func TestLedgerKeepsALateDialFailurePastTheLimit(t *testing.T) {
	l := newLedger()
	op := Operation{Name: "dial"}
	for range maxCallRows {
		l.addCall(callStart{op: op, number: l.startCall()}, "DIAL", "a.example.com", "", "", 0)
	}
	late := l.addCall(callStart{op: op, number: l.startCall()}, "DIAL", "b.example.com", "", "", 0)
	if rows, dropped, _ := l.requests(); len(rows) != maxCallRows || dropped != 1 {
		t.Fatalf("rows = %d, dropped = %d; want the successful dial left out", len(rows), dropped)
	}
	l.failCall(op, late, CodeVendorError)
	rows, dropped, problemsDropped := l.requests()
	if len(rows) != maxCallRows+1 || rows[maxCallRows].Host != "b.example.com" || rows[maxCallRows].Error != CodeVendorError {
		t.Errorf("rows end with %+v, want the dial kept once its connection reset", rows[len(rows)-1])
	}
	if dropped != 0 || problemsDropped != 0 {
		t.Errorf("dropped = %d, problems dropped = %d; want neither", dropped, problemsDropped)
	}
}

func TestTransportErrorsCarryTheirCall(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		hang := func(req *http.Request) (*http.Response, error) {
			<-req.Context().Done()
			return nil, req.Context().Err()
		}
		script := newScript().on("api.example.com/me", respond(200, "{}", nil)).on("api.example.com/logs", hang)
		c := testContext(script)
		client := NewHTTPClient(c, HTTPOptions{AttemptTimeout: time.Second, MaxAttempts: 2, CredentialHosts: []string{"api.example.com"}})
		resp, err := get(t, client, WithOperation(context.Background(), Operation{Name: "me.get"}), "https://api.example.com/me")
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		_, err = get(t, client, WithOperation(context.Background(), Operation{Name: "logs.list"}), "https://api.example.com/logs")
		var urlErr *url.Error
		if !errors.As(err, &urlErr) || !urlErr.Timeout() || Classify(err) != CodeTimeout {
			t.Fatalf("err = %v, want a *url.Error that still reports its timeout", err)
		}
		req, _ := http.NewRequestWithContext(WithOperation(context.Background(), Operation{Name: "leak"}), http.MethodGet, "https://elsewhere.example.org/x", nil)
		req.Header.Set("Authorization", "Bearer x")
		_, refused := client.Do(req)

		rec := c.run.records
		rec.NotCollected(Location{Path: "a.json", Pointer: "/logs"}, err)
		rec.NotCollected(Location{Path: "a.json", Pointer: "/leak"}, refused)
		gaps := rec.Gaps()
		if gaps[0].Operation != "logs.list" || gaps[0].Call != 2 || gaps[0].Code != CodeTimeout {
			t.Errorf("gap = %+v, want the timed-out call, the second of the run", gaps[0])
		}
		if gaps[1].Operation != "leak" || gaps[1].Call != 3 {
			t.Errorf("gap = %+v, want the refused call", gaps[1])
		}
		rows, _, _ := c.run.calls.requests()
		if rows[len(rows)-1].Call != 3 || rows[len(rows)-1].Error != CodeInvalidResponse {
			t.Errorf("the refused call's row = %+v", rows[len(rows)-1])
		}
	})
}

func TestResponseErrorGivesAGapTheResponsesCall(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		script := newScript().
			on("api.example.com/me", respond(200, "{}", nil)).
			on("api.example.com/users", respond(200, `{"users": [`, nil)).
			on("api.example.com/logs", respond(403, `{"errorCode":"E0000006"}`, nil))
		c := testContext(script)
		client := NewHTTPClient(c, HTTPOptions{VendorCode: func(*http.Response, []byte) string { return "E0000006" }})
		call := func(op, path string) *http.Response {
			resp, err := get(t, client, WithOperation(context.Background(), Operation{Name: op}), "https://api.example.com"+path)
			if err != nil {
				t.Fatal(err)
			}
			return resp
		}
		_ = call("me.get", "/me").Body.Close()
		users := call("users.list", "/users")
		var decoded struct{ Users []string }
		decodeErr := ResponseError(users, json.NewDecoder(users.Body).Decode(&decoded))
		_ = users.Body.Close()
		logs := call("logs.list", "/logs")
		_ = logs.Body.Close()
		denied := ResponseError(logs, &apiErr{status: logs.StatusCode})

		rec := c.run.records
		rec.NotCollected(Location{Path: "a.json", Pointer: "/users"}, decodeErr)
		rec.NotCollected(Location{Path: "a.json", Pointer: "/logs"}, denied, MissingPermission("logs.read"))
		gaps := rec.Gaps()
		if gaps[0].Operation != "users.list" || gaps[0].Call != 2 || gaps[0].Code != CodeInvalidResponse {
			t.Errorf("decode gap = %+v, want the users call and invalid_response", gaps[0])
		}
		if gaps[1].Operation != "logs.list" || gaps[1].Call != 3 || gaps[1].VendorCode != "E0000006" || gaps[1].MissingPermission != "logs.read" || gaps[1].Code != CodePermissionDenied {
			t.Errorf("denied gap = %+v, want the logs call with its vendor code and the permission to grant", gaps[1])
		}

		foreign := &http.Response{StatusCode: 500, Request: mustRequest("https://api.example.com/x")}
		plain := errors.New("bad")
		if ResponseError(foreign, plain) != plain || ResponseError(nil, plain) != plain || ResponseError(users, nil) != nil {
			t.Error("ResponseError should leave an error about a response the SDK did not send alone, and nil as nil")
		}
	})
}
