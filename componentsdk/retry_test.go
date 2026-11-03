package componentsdk

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"testing/synctest"
	"time"
)

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
		{name: "a throttle code from the hook", status: 400, body: `{"__type":"ThrottlingException"}`, header: header("X-Rate-Limit-Reset", epoch(30*time.Second)), wait: 30 * time.Second},
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
			if limit := tc.wait + min(time.Second, tc.wait/10+1); waits[0] < tc.wait || waits[0] >= limit {
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
		{"an error with the rate_limited code", CodeError(CodeRateLimited, errors.New("slow down")), 3},
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
				t.Errorf("status %d, bodies %q, want a retry with the same body", resp.StatusCode, bodies)
			}
		})
	})
	t.Run("a body too large to hold is sent once", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			large := strings.Repeat("x", maxReplayBody+1)
			resp, bodies := post(t, large)
			if resp.StatusCode != 503 || len(bodies) != 1 || len(bodies[0]) != len(large) {
				t.Errorf("status %d, %d attempts, want one attempt with the whole body", resp.StatusCode, len(bodies))
			}
		})
	})
}
