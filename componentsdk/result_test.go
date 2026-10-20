package componentsdk

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/locktivity/epack/componentsdk/internal/outputcheck"
)

func TestResolveGaps(t *testing.T) {
	artifacts := []CollectedArtifact{
		{Data: map[string]any{"mfa": map[string]any{"coverage_pct": nil}, "users": 4}, Path: "artifacts/demo.entra.json"},
		{Data: map[string]any{"mfa_coverage_pct": nil}, Schema: "evidencepack/idp-posture@v1"},
	}
	gaps, err := resolveGaps([]Gap{
		{Path: "artifacts/demo.entra.json", Pointer: "/mfa/coverage_pct"},
		{Schema: "evidencepack/idp-posture@v1", Pointer: "/mfa_coverage_pct"},
		{Path: "artifacts/never-emitted.json", Pointer: "/x"},
	}, artifacts, "demo")
	if err != nil {
		t.Fatal(err)
	}
	if gaps[1].Path != "artifacts/demo_1.json" {
		t.Errorf("schema gap path = %q, want the runner's default path", gaps[1].Path)
	}
	if gaps[0].Schema != "" || gaps[2].Path != "artifacts/never-emitted.json" {
		t.Errorf("gaps = %+v", gaps)
	}

	_, err = resolveGaps([]Gap{{Path: "artifacts/demo.entra.json", Pointer: "/users"}}, artifacts, "demo")
	if err == nil || !strings.Contains(err.Error(), "has a value at /users") {
		t.Errorf("err = %v, want a value-and-gap conflict", err)
	}

	twins := append(artifacts, CollectedArtifact{Data: map[string]any{}, Schema: "evidencepack/idp-posture@v1", Path: "b.json"})
	_, err = resolveGaps([]Gap{{Schema: "evidencepack/idp-posture@v1", Pointer: "/x"}}, twins, "demo")
	if err == nil || !strings.Contains(err.Error(), "several artifacts share") {
		t.Errorf("err = %v, want an ambiguity error", err)
	}

	_, err = resolveGaps([]Gap{{Path: "artifacts/demo.entra.json", Pointer: "mfa"}}, artifacts, "demo")
	if err == nil {
		t.Error("a pointer without a leading slash should fail")
	}
}

func TestAPartialGapMayNameAListReadInPart(t *testing.T) {
	artifacts := []CollectedArtifact{{Data: map[string]any{
		"users":   []any{map[string]any{"id": "1"}},
		"groups":  map[string]any{"admins": 2},
		"mfa_pct": 50,
	}, Path: "artifacts/demo.json"}}
	at := func(pointer, status string) Gap {
		return Gap{Path: "artifacts/demo.json", Pointer: pointer, Status: status}
	}
	if _, err := resolveGaps([]Gap{at("/users", GapPartial), at("/groups", GapPartial)}, artifacts, "demo"); err != nil {
		t.Errorf("a partial gap at a list or object read in part: %v", err)
	}
	for _, g := range []Gap{at("/users", GapNotCollected), at("/mfa_pct", GapPartial), at("/users/0/id", GapPartial)} {
		if _, err := resolveGaps([]Gap{g}, artifacts, "demo"); err == nil || !strings.Contains(err.Error(), "has a value at "+g.Pointer) {
			t.Errorf("%s gap at %s: err = %v, want a value-and-gap conflict", g.Status, g.Pointer, err)
		}
	}
}

func TestResolvePointer(t *testing.T) {
	doc, _ := decodeData(map[string]any{
		"a/b":  1,
		"m~n":  2,
		"list": []any{map[string]any{"x": 3}},
		"none": nil,
	})
	cases := []struct {
		pointer string
		found   bool
	}{
		{"/a~1b", true}, {"/m~0n", true}, {"/list/0/x", true},
		{"/list/1/x", false}, {"/missing", false}, {"/none/deeper", false},
	}
	for _, tc := range cases {
		_, found, err := resolvePointer(doc, tc.pointer)
		if err != nil || found != tc.found {
			t.Errorf("resolvePointer(%q) = %v, %v; want found=%v", tc.pointer, found, err, tc.found)
		}
	}
	if _, _, err := resolvePointer(doc, "/list/01"); err == nil {
		t.Error("an index with a leading zero should fail")
	}
}

func TestBuildResultGatesByLevel(t *testing.T) {
	r := newRun(CollectorSpec{Name: "demo", Version: "1.0.0", Commit: "abc"}, "demo", "run-9", nil, 1)
	r.secrets.add("s3cr3t-token-value")
	r.records.NotCollected(Location{Path: "artifacts/demo.json", Pointer: "/defender/score"},
		CodeError(CodeVendorError, errors.New("request failed with s3cr3t-token-value in it")))
	r.records.Partial(Location{Path: "artifacts/demo.json", Pointer: "/mfa/coverage_pct"}, 12,
		&apiErr{status: 403, vendor: "E0000006"})
	r.records.SignedInAs(Principal{Provider: "okta", Kind: "service_app", TenantID: "acme", ID: "0oa123", Scopes: []string{"okta.users.read", "okta.apps.read"}})
	r.calls.add(attemptRecord{call: callStart{op: Operation{Name: "users.list"}, number: 1}, attempt: 1, req: mustRequest("https://acme.okta.com/api/v1/users"),
		resp: &http.Response{StatusCode: 200, Header: http.Header{}}, took: 20 * time.Millisecond}, defaultRequestIDHeaders, nil)
	artifacts := []CollectedArtifact{{Data: map[string]any{"defender": map[string]any{}}, Path: "artifacts/demo.json"}}

	trust, err := buildResult(resultInput{run: r, level: LevelTrust, artifacts: artifacts, getenv: func(string) string { return "" }, finished: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	if trust.Outcome.Status != OutcomePartial || trust.Outcome.Code != CodeVendorError || trust.Outcome.Owner != OwnerVendor {
		t.Errorf("outcome = %+v", trust.Outcome)
	}
	if len(trust.Gaps) != 2 || trust.Gaps[0].Pointer != "/defender/score" || trust.Gaps[1].Unmeasured != 12 || trust.Gaps[1].VendorCode != "E0000006" {
		t.Fatalf("gaps = %+v", trust.Gaps)
	}
	for _, g := range trust.Gaps {
		if g.Detail != "" {
			t.Errorf("trust gap carries detail %q", g.Detail)
		}
	}
	if trust.SignedInAs == nil || trust.SignedInAs.ID != "" || strings.Join(trust.SignedInAs.Scopes, ",") != "okta.apps.read,okta.users.read" {
		t.Errorf("trust principal = %+v", trust.SignedInAs)
	}
	if len(trust.Calls.Requests) != 0 || len(trust.Calls.Operations) != 1 {
		t.Errorf("trust calls = %+v", trust.Calls)
	}
	if trust.Run.RunID != "run-9" || trust.Collector.Commit != "abc" {
		t.Errorf("run = %+v, collector = %+v", trust.Run, trust.Collector)
	}

	audit, err := buildResult(resultInput{run: r, level: LevelAudit, artifacts: artifacts, getenv: func(k string) string {
		if k == "HTTPS_PROXY" {
			return "http://proxy:3128"
		}
		return ""
	}, finished: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(audit.Gaps[0].Detail, "s3cr3t-token-value") || !strings.Contains(audit.Gaps[0].Detail, "request failed") {
		t.Errorf("audit detail = %q, want it redacted by value", audit.Gaps[0].Detail)
	}
	if audit.SignedInAs.ID != "0oa123" || len(audit.Calls.Requests) != 1 || !audit.Run.Proxy {
		t.Errorf("audit result = %+v", audit)
	}
}

func mustRequest(url string) *http.Request {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		panic(err)
	}
	return req
}

func TestRunInProcess(t *testing.T) {
	base := newScript().
		on("api.example.com/users", respond(200, `{"value":[{"id":"1","mfa":true},{"id":"2","mfa":false}]}`, nil)).
		on("api.example.com/score", respond(503, "down", nil))
	handler := func(ctx CollectorContext) error {
		client := NewHTTPClient(ctx, HTTPOptions{CredentialHosts: []string{"api.example.com"}, MaxAttempts: 2})
		token := ctx.Secret("DEMO_TOKEN")
		call := func(name, url string) (*http.Response, error) {
			req, _ := http.NewRequestWithContext(WithOperation(ctx.Context(), Operation{Name: name}), http.MethodGet, url, nil)
			req.Header.Set("Authorization", "Bearer "+token)
			return client.Do(req)
		}
		resp, err := call("users.list", "https://api.example.com/users")
		if err != nil {
			return err
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		out := map[string]any{"users": 2, "score": nil}
		resp, err = call("score.get", "https://api.example.com/score")
		if err == nil {
			_ = resp.Body.Close()
			if code := ClassifyResponse(resp); code != "" {
				Records(ctx).NotCollectedCode(Location{Path: "artifacts/demo.json", Pointer: "/score"}, code, "score unavailable")
			}
		}
		Records(ctx).SignedInAs(Principal{Provider: "demo", Kind: "token", TenantID: "acme"})
		return ctx.Emit([]CollectedArtifact{{Data: out, Path: "artifacts/demo.json"}})
	}
	spec := CollectorSpec{Name: "demo", Version: "0.1.0"}
	res := RunInProcess(spec, handler, InProcessOptions{
		Name: "demo-prod", Secrets: map[string]string{"DEMO_TOKEN": "tok-abcdef123"}, Transport: base, RunID: "r1", Seed: 7,
	})
	if res.ExitCode != 0 || res.Failure != nil || res.Panic != "" {
		t.Fatalf("exit = %d failure = %+v panic = %s stderr = %s", res.ExitCode, res.Failure, res.Panic, res.Stderr)
	}
	if len(res.Artifacts) != 3 || res.Artifacts[2].Path != "artifacts/demo-prod.collector-result.json" || res.Artifacts[2].Schema != ResultSchema {
		t.Fatalf("artifacts = %+v", res.Artifacts)
	}
	if res.Artifacts[1].Path != "artifacts/demo-prod.collector-build.json" || res.Build == nil || res.Build.Collector.Name != "demo" {
		t.Fatalf("build file = %+v, want it before the result, named for the spec", res.Build)
	}
	if res.Result == nil || res.Result.Outcome.Status != OutcomePartial || len(res.Result.Gaps) != 1 || res.Result.Gaps[0].Code != CodeVendorError {
		t.Fatalf("result = %+v", res.Result)
	}
	if res.Result.Collector.Name != "demo-prod" || res.Result.Run.RunID != "r1" {
		t.Errorf("collector = %+v run = %+v", res.Result.Collector, res.Result.Run)
	}
	again := RunInProcess(spec, handler, InProcessOptions{
		Name: "demo-prod", Secrets: map[string]string{"DEMO_TOKEN": "tok-abcdef123"}, Transport: newScript().
			on("api.example.com/users", respond(200, `{"value":[]}`, nil)).
			on("api.example.com/score", respond(200, `{}`, nil)), RunID: "r1", Seed: 7,
	})
	if again.Result.Outcome.Status != OutcomeCollected || len(again.Result.Gaps) != 0 {
		t.Errorf("clean run outcome = %+v", again.Result.Outcome)
	}
}

func TestRunInProcessGivesUnnamedArtifactsTheRunnersPaths(t *testing.T) {
	res := RunInProcess(CollectorSpec{Name: "demo"}, func(ctx CollectorContext) error {
		return ctx.Emit([]CollectedArtifact{{Data: map[string]any{"a": 1}}, {Data: map[string]any{"b": 2}}})
	}, InProcessOptions{Name: "demo-prod"})
	if res.ExitCode != 0 {
		t.Fatalf("exit = %d failure = %+v stderr = %s", res.ExitCode, res.Failure, res.Stderr)
	}
	var paths []string
	for _, a := range res.Artifacts {
		paths = append(paths, a.Path)
	}
	want := []string{"artifacts/demo-prod.json", "artifacts/demo-prod_1.json", "artifacts/demo-prod.collector-build.json", "artifacts/demo-prod.collector-result.json"}
	if strings.Join(paths, " ") != strings.Join(want, " ") {
		t.Errorf("paths = %q, want %q", paths, want)
	}
}

func TestRunInProcessFailure(t *testing.T) {
	spec := CollectorSpec{Name: "demo"}
	res := RunInProcess(spec, func(ctx CollectorContext) error {
		secret := ctx.Secret("DEMO_TOKEN")
		return NewAuthError("token %s rejected: %w", secret, &apiErr{status: 401, vendor: "invalid_client"})
	}, InProcessOptions{Secrets: map[string]string{"DEMO_TOKEN": "tok-abcdef123"}})
	if res.ExitCode != 3 {
		t.Errorf("exit = %d, want 3", res.ExitCode)
	}
	if res.Failure == nil || res.Failure.Code != CodeAuthFailed || res.Failure.Owner != OwnerCustomer || res.Failure.VendorCode != "invalid_client" {
		t.Fatalf("failure = %+v", res.Failure)
	}
	if strings.Contains(res.Failure.Message, "tok-abcdef123") || strings.Contains(res.Stdout, "tok-abcdef123") {
		t.Errorf("failure record leaks the secret: %q", res.Failure.Message)
	}
	if len(res.Artifacts) != 0 {
		t.Errorf("a failed run emits nothing, got %d artifacts", len(res.Artifacts))
	}

	panicked := RunInProcess(spec, func(CollectorContext) error { panic("nil map") }, InProcessOptions{})
	if panicked.ExitCode != 2 || panicked.Failure == nil || panicked.Failure.Code != CodeInternal || !strings.Contains(panicked.Panic, "nil map") {
		t.Errorf("panic run = %+v", panicked)
	}

	silent := RunInProcess(spec, func(CollectorContext) error { return nil }, InProcessOptions{})
	if silent.ExitCode != 1 || silent.Failure == nil || silent.Failure.Code != CodeInternal {
		t.Errorf("a run that emits nothing = %+v", silent)
	}
}

func TestEmitRejectsValueAndGapForOneField(t *testing.T) {
	res := RunInProcess(CollectorSpec{Name: "demo"}, func(ctx CollectorContext) error {
		Records(ctx).NotCollected(Location{Path: "artifacts/demo.json", Pointer: "/score"}, &apiErr{status: 500})
		return ctx.Emit([]CollectedArtifact{{Data: map[string]any{"score": 0}, Path: "artifacts/demo.json"}})
	}, InProcessOptions{})
	if res.ExitCode == 0 || res.Failure == nil || !strings.Contains(res.Failure.Message, "has a value at /score") {
		t.Errorf("run = exit %d failure %+v, want Emit to refuse a value with a gap", res.ExitCode, res.Failure)
	}
}

func TestCollectorDeadline(t *testing.T) {
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	spec := CollectorSpec{Timeout: 30 * time.Minute}
	env := func(v string) func(string) string {
		return func(k string) string {
			if k == "EPACK_DEADLINE" {
				return v
			}
			return ""
		}
	}
	if got := collectorDeadline(spec, env(""), now); !got.Equal(now.Add(30 * time.Minute)) {
		t.Errorf("no runner deadline: %s", got)
	}
	runner := now.Add(10 * time.Minute).Format(time.RFC3339Nano)
	if got := collectorDeadline(spec, env(runner), now); !got.Equal(now.Add(10*time.Minute - 10*time.Second)) {
		t.Errorf("runner deadline: %s, want 10s before the runner's", got)
	}
	short := now.Add(30 * time.Second).Format(time.RFC3339Nano)
	if got := collectorDeadline(spec, env(short), now); !got.Equal(now.Add(27 * time.Second)) {
		t.Errorf("short runner deadline: %s, want a tenth of the time held back", got)
	}
	if got := collectorDeadline(CollectorSpec{Timeout: time.Minute}, env(runner), now); !got.Equal(now.Add(time.Minute)) {
		t.Errorf("a shorter spec timeout should win: %s", got)
	}
	if got := collectorDeadline(spec, env("garbage"), now); !got.Equal(now.Add(30 * time.Minute)) {
		t.Errorf("an unparsable deadline is ignored: %s", got)
	}
}

func TestResultJSONShape(t *testing.T) {
	r := newRun(CollectorSpec{Name: "demo"}, "demo", "", nil, 1)
	res, err := buildResult(resultInput{run: r, level: LevelTrust, getenv: func(string) string { return "" }, finished: time.Unix(0, 0)})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(res)
	var generic map[string]any
	_ = json.Unmarshal(raw, &generic)
	for _, key := range []string{"collector", "outcome", "gaps", "calls", "run"} {
		if _, ok := generic[key]; !ok {
			t.Errorf("result JSON lacks %q: %s", key, raw)
		}
	}
	if gaps, _ := generic["gaps"].([]any); gaps == nil {
		t.Errorf("gaps should encode as [] when empty: %s", raw)
	}
}

func validateResult(t *testing.T, raw []byte) []outputcheck.Finding {
	t.Helper()
	sch, err := outputcheck.Compile(ResultSchemaJSON())
	if err != nil {
		t.Fatal(err)
	}
	doc, err := outputcheck.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	return outputcheck.Validate(sch, "result", doc)
}

func TestResultSchemaTakesEveryNewField(t *testing.T) {
	base := newScript().
		on("api.example.com/users", respond(429, `{"errorCode":"E0000047"}`, http.Header{"Retry-After": []string{"1"}}), respond(200, "[]", nil)).
		on("api.example.com/logs", respond(403, `{"errorCode":"E0000006"}`, nil))
	handler := func(ctx CollectorContext) error {
		client := NewHTTPClient(ctx, HTTPOptions{VendorCode: func(_ *http.Response, body []byte) string {
			var e struct {
				ErrorCode string `json:"errorCode"`
			}
			_ = json.Unmarshal(body, &e)
			return e.ErrorCode
		}})
		people, step := StartStep(ctx.Context(), "people", "People and sign-in methods")
		req, _ := http.NewRequestWithContext(WithOperation(people, Operation{Name: "users.list"}), http.MethodGet, "https://api.example.com/users", nil)
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		_ = resp.Body.Close()
		step.End()
		logs, _ := StartStep(ctx.Context(), "system_log", "Activity log")
		req, _ = http.NewRequestWithContext(WithOperation(logs, Operation{Name: "logs.list"}), http.MethodGet, "https://api.example.com/logs?since=x", nil)
		resp, err = client.Do(req)
		if err != nil {
			return err
		}
		_ = resp.Body.Close()
		Records(ctx).NotCollected(Location{Path: "artifacts/demo.json", Pointer: "/system_log"}, ResponseError(resp, &apiErr{status: resp.StatusCode}),
			MissingPermission("okta.logs.read"), Warning("system log: access denied"))
		Records(ctx).SignedInAs(Principal{Provider: "okta", Kind: "service_app", TenantID: "acme.okta.com", AuthMethod: AuthPrivateKeyJWT,
			RequestedScopes: []string{"okta.logs.read", "okta.users.read"}, Scopes: []string{"okta.users.read"}, ReadOnly: true, ID: "0oa1"})
		return ctx.Emit([]CollectedArtifact{{Data: map[string]any{"system_log": nil}, Path: "artifacts/demo.json"}})
	}
	res := RunInProcess(CollectorSpec{Name: "demo"}, handler, InProcessOptions{
		Transport: base, Config: map[string]any{"level": "internal"},
		Sleep: func(ctx context.Context, _ time.Duration) error { return ctx.Err() },
	})
	if res.ExitCode != 0 || res.Result == nil {
		t.Fatalf("exit = %d failure = %+v stderr = %s", res.ExitCode, res.Failure, res.Stderr)
	}
	r := res.Result
	if len(r.Steps) != 2 || r.Calls.Requests[1].WaitedMS == 0 || r.Calls.Requests[2].VendorCode != "E0000006" || r.Calls.ProblemRequestsDropped == nil {
		t.Fatalf("result = %+v, want steps, a retry with its wait, and a refused row with its vendor code", r)
	}
	g := r.Gaps[0]
	if g.Operation != "logs.list" || g.Call != 2 || g.Source == "" || g.MissingPermission != "okta.logs.read" || g.Warning == "" || g.VendorCode != "E0000006" {
		t.Fatalf("gap = %+v", g)
	}
	for _, a := range res.Artifacts {
		if a.Schema == ResultSchema {
			if found := validateResult(t, a.Data); len(found) > 0 {
				t.Errorf("the result does not match its schema: %+v", found)
			}
		}
	}
}

func TestResultSchemaStillTakesAnOktaV030Result(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "okta-v0.3.0.collector-result.json"))
	if err != nil {
		t.Fatal(err)
	}
	if found := validateResult(t, raw); len(found) > 0 {
		t.Errorf("the v0.3.0 Okta result no longer validates: %+v", found)
	}
	var old map[string]any
	if err := json.Unmarshal(raw, &old); err != nil {
		t.Fatal(err)
	}
	// Fault runs, which the kit does not export, hold v0.3.0's gaps.
	old["outcome"] = map[string]any{"status": "partial", "code": "permission_denied", "owner": "customer"}
	old["gaps"] = []any{map[string]any{
		"path": "artifacts/okta.json", "pointer": "/system_log", "status": "not_collected", "code": "permission_denied",
		"owner": "customer", "vendor_code": "E0000006", "detail": "API returned status 403",
	}}
	withGap, _ := json.Marshal(old)
	if found := validateResult(t, withGap); len(found) > 0 {
		t.Errorf("a v0.3.0 gap no longer validates: %+v", found)
	}
}
