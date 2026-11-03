package componentsdk

import (
	"context"
	"io"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"
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
