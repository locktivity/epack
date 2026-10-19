package collectortest

import (
	"cmp"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/locktivity/epack/componentsdk"
)

// demoSchema is the demo's schema, which it embeds as a collector embeds its
// docs/schema files.
//
//go:embed testdata/demo.schema.json
var demoSchema []byte

// demo is a small collector with the bugs the kit exists to catch, each
// behind a switch. With every switch off it handles faults correctly.
type demo struct {
	zeroOnError  bool // writes 0 when the score call fails
	failRun      bool // returns an error when the score call fails
	skipBadPage  bool // keeps counting when a users page fails
	wrongCode    bool // records every gap as vendor_error
	unnamed      bool // sends the score call without an operation name
	leakToken    bool // writes the token into the artifact
	noHostList   bool // leaves CredentialHosts empty
	ignoreScore  bool // never reads the score body
	signInFails  bool // fails the run when the sign-in call fails
	treat404Zero bool // reads a 404 on the score call as "no score configured"
	pctOverNone  bool // writes 100 for the MFA percentage when there are no users
	nullFlag     bool // reads mfa_enforced from a field the vendor renamed, so it is always null
	laggedCount  bool // takes the user count from the vendor's lagged total instead of the rows
	rowsAtTrust  bool // emits the audit-only user rows at every level
	scoreAtTrust bool // emits the score at trust only
	noClassify   bool // leaves out its ClassifyResponse hook, so a throttle sent as a 400 reads as a bad request
	hookNames    bool // names its calls only through HTTPOptions.NameOperation, as vendor SDK clients do
	orgMissing   bool // fails the run with config_invalid when the sign-in answers 404, as for an organization that does not exist
	partialRows  bool // emits the user rows it read before a users page failed, with a partial gap
	bearer       bool // sends its token in Authorization rather than X-Demo-Token
	gitlabHeader bool // sends its token in PRIVATE-TOKEN rather than X-Demo-Token
	linkPages    bool // follows the next page in the Link header rather than the body
	broadHosts   bool // lists "*.com" among its CredentialHosts

	// base is the transport the demo's real runs would send through.
	base http.RoundTripper

	// api is where the demo's API lives. It defaults to demoHost.
	api string
}

const demoHost = "https://api.demo.test"

type demoAPIError struct{ status int }

func (e *demoAPIError) Error() string   { return fmt.Sprintf("demo API returned %d", e.status) }
func (e *demoAPIError) HTTPStatus() int { return e.status }

// demoThrottleBody is the body of the demo vendor's throttle, which it sends
// with a 400, the way AWS does.
const demoThrottleBody = `{"__type":"ThrottlingException","message":"Rate exceeded"}`

// demoThrottle reads the demo vendor's throttle as rate_limited.
func demoThrottle(resp *http.Response, body []byte) (componentsdk.Code, bool) {
	var e struct {
		Type string `json:"__type"`
	}
	if resp.StatusCode == http.StatusBadRequest && json.Unmarshal(body, &e) == nil && e.Type == "ThrottlingException" {
		return componentsdk.CodeRateLimited, true
	}
	return "", false
}

func (d demo) run(ctx componentsdk.CollectorContext) error {
	api := cmp.Or(d.api, demoHost)
	apiURL, err := url.Parse(api)
	if err != nil {
		return componentsdk.CodeError(componentsdk.CodeConfigInvalid, err)
	}
	opts := componentsdk.HTTPOptions{
		CredentialHosts:   []string{apiURL.Hostname()},
		CredentialHeaders: []string{"X-Demo-Token"},
		ClassifyResponse:  demoThrottle,
		Base:              d.base,
	}
	if d.noHostList {
		opts.CredentialHosts = nil
	}
	if d.broadHosts {
		opts.CredentialHosts = append(opts.CredentialHosts, "*.com")
	}
	if d.noClassify {
		opts.ClassifyResponse = nil
	}
	if d.hookNames {
		opts.NameOperation = func(req *http.Request) (componentsdk.Operation, bool) {
			switch req.URL.Path {
			case "/me":
				return componentsdk.Operation{Name: "demo.me.get"}, true
			case "/users":
				return componentsdk.Operation{Name: "demo.users.list"}, true
			case "/score":
				return componentsdk.Operation{Name: "demo.score.get"}, true
			}
			return componentsdk.Operation{}, false
		}
	}
	client := componentsdk.NewHTTPClient(ctx, opts)
	token := ctx.Secret("DEMO_TOKEN")
	rec := componentsdk.Records(ctx)

	var link string
	get := func(op, url string, out any) error {
		reqCtx := ctx.Context()
		if !d.hookNames && (!d.unnamed || op != "demo.score.get") {
			reqCtx = componentsdk.WithOperation(reqCtx, componentsdk.Operation{Name: op})
		}
		req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, url, nil)
		if err != nil {
			return err
		}
		switch {
		case d.bearer:
			req.Header.Set("Authorization", "Bearer "+token)
		case d.gitlabHeader:
			req.Header.Set("PRIVATE-TOKEN", token)
		default:
			req.Header.Set("X-Demo-Token", token)
		}
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer func() { _ = resp.Body.Close() }()
		link = resp.Header.Get("Link")
		if resp.StatusCode != http.StatusOK {
			return componentsdk.CodeError(componentsdk.ClassifyResponse(resp), &demoAPIError{status: resp.StatusCode})
		}
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		if out == nil {
			return nil
		}
		return json.Unmarshal(body, out)
	}

	var me struct {
		Org         *string `json:"org"`
		MFAEnforced *bool   `json:"mfa_enforced"`
		Renamed     *bool   `json:"mfaEnforced"`
	}
	if err := get("demo.me.get", api+"/me", &me); err != nil {
		var apiErr *demoAPIError
		switch {
		case d.signInFails:
			return componentsdk.NewAuthError("signing in: %w", err)
		case d.orgMissing && errors.As(err, &apiErr) && apiErr.status == http.StatusNotFound:
			return componentsdk.CodeError(componentsdk.CodeConfigInvalid, fmt.Errorf("the organization does not exist: %w", err))
		}
		return fmt.Errorf("signing in: %w", err)
	}
	if me.Org == nil {
		return componentsdk.CodeError(componentsdk.CodeInvalidResponse, errors.New("sign-in response has no org"))
	}
	rec.SignedInAs(componentsdk.Principal{Provider: "demo", Kind: "token", TenantID: *me.Org})

	out := map[string]any{"org": *me.Org}
	at := func(pointer string) componentsdk.Location {
		return componentsdk.Location{Path: "artifacts/demo.json", Pointer: pointer}
	}
	record := func(pointer string, err error) {
		if d.wrongCode {
			rec.NotCollectedCode(at(pointer), componentsdk.CodeVendorError, err.Error())
			return
		}
		rec.NotCollected(at(pointer), err)
	}

	enforced := me.MFAEnforced
	if d.nullFlag {
		enforced = me.Renamed
	} else if enforced == nil {
		rec.NotCollectedCode(at("/mfa_enforced"), componentsdk.CodeInvalidResponse, "sign-in response has no mfa_enforced")
	}
	out["mfa_enforced"] = enforced

	audit := ctx.Level().AtLeast(componentsdk.LevelAudit)
	users, mfa, failed, total := 0, 0, 0, -1
	rows := []any{}
	var firstErr error
	next := api + "/users?page=1"
	for next != "" {
		var page struct {
			Users *[]struct {
				MFA *bool `json:"mfa"`
			} `json:"users"`
			Next  string `json:"next"`
			Total *int   `json:"total"`
		}
		err := get("demo.users.list", next, &page)
		if err == nil && page.Users == nil {
			err = componentsdk.CodeError(componentsdk.CodeInvalidResponse, errors.New("users page has no users"))
		}
		if err != nil {
			failed++
			firstErr = err
			if d.skipBadPage {
				break
			}
			break
		}
		if page.Total != nil && total < 0 {
			total = *page.Total
		}
		for _, u := range *page.Users {
			users++
			on := u.MFA != nil && *u.MFA
			if on {
				mfa++
			}
			rows = append(rows, map[string]any{"mfa": on})
		}
		next = page.Next
		if d.linkPages {
			next = nextPage(link)
		}
	}
	switch {
	case failed > 0 && !d.skipBadPage:
		record("/users", firstErr)
		record("/mfa_pct", firstErr)
		switch {
		case audit && d.partialRows:
			out["user_mfa"] = rows
			rec.Partial(at("/user_mfa"), max(total-users, 0), firstErr)
		case audit:
			record("/user_mfa", firstErr)
		}
	default:
		count := users
		if d.laggedCount && total >= 0 {
			count = total
		}
		out["users"] = count
		switch {
		case count > 0:
			out["mfa_pct"] = mfa * 100 / count
		case d.pctOverNone:
			out["mfa_pct"] = 100
		default:
			out["mfa_pct"] = nil
		}
		if audit || d.rowsAtTrust {
			out["user_mfa"] = rows
		}
	}

	var score struct {
		Value *int `json:"value"`
	}
	scoreTarget := &score
	if d.ignoreScore {
		scoreTarget = nil
	}
	switch err := get("demo.score.get", api+"/score", scoreTarget); {
	case err != nil && d.treat404Zero && componentsdk.Classify(err) == componentsdk.CodeInvalidResponse && strings.Contains(err.Error(), "404"):
		out["score"] = 0
	case err != nil && d.failRun:
		return err
	case err != nil && d.zeroOnError:
		out["score"] = 0
	case err != nil:
		record("/score", err)
	case d.ignoreScore:
		out["score"] = 50
	case score.Value == nil:
		record("/score", componentsdk.CodeError(componentsdk.CodeInvalidResponse, errors.New("score response has no value")))
	default:
		out["score"] = *score.Value
	}
	if d.scoreAtTrust && audit {
		delete(out, "score")
	}
	if d.leakToken {
		out["debug"] = token
	}
	return ctx.Emit([]componentsdk.CollectedArtifact{{Data: out, Path: "artifacts/demo.json"}})
}

// nextPage returns the next page's URL from a Link header, or "".
func nextPage(link string) string {
	for _, part := range strings.Split(link, ",") {
		target, params, _ := strings.Cut(part, ";")
		if strings.Contains(params, `rel="next"`) {
			return strings.Trim(strings.TrimSpace(target), "<>")
		}
	}
	return ""
}

// demoResponses answers the sign-in, the given users pages, and the score.
// Each users page but the last links to the next in its Link header too.
func demoResponses(pages ...string) []Response {
	responses := []Response{{URL: demoHost + "/me", Body: `{"org":"acme","mfa_enforced":true}`}}
	for i, body := range pages {
		r := Response{URL: fmt.Sprintf("%s/users?page=%d", demoHost, i+1), Body: body}
		if i < len(pages)-1 {
			r.Header = http.Header{"Link": {fmt.Sprintf(`<%s/users?page=%d>; rel="next"`, demoHost, i+2)}}
		}
		responses = append(responses, r)
	}
	return append(responses, Response{URL: demoHost + "/score", Body: `{"value":72}`})
}

func demoScenario() Scenario {
	return Scenario{Name: "clean", Responses: demoResponses(
		`{"users":[{"mfa":true},{"mfa":false}],"next":"`+demoHost+`/users?page=2","total":4}`,
		`{"users":[{"mfa":true},{"mfa":true}],"next":"","total":4}`,
	)}
}

// laggedScenario has a users total from a report the vendor has not updated
// since a fifth user left.
func laggedScenario() Scenario {
	return Scenario{Name: "lagged total", Responses: demoResponses(
		`{"users":[{"mfa":true},{"mfa":false}],"next":"`+demoHost+`/users?page=2","total":5}`,
		`{"users":[{"mfa":true},{"mfa":true}],"next":"","total":5}`,
	)}
}

func demoSuite(d demo) Suite {
	return Suite{
		Spec:    componentsdk.CollectorSpec{Name: "demo", Version: "0.0.1", Schemas: map[string][]byte{"artifacts/demo.json": demoSchema}},
		Run:     d.run,
		Config:  map[string]any{"level": "audit"},
		Secrets: map[string]string{"DEMO_TOKEN": "demo-token-0123456789"},
		Scenarios: []Scenario{
			demoScenario(),
			{Name: "no users", Responses: demoResponses(`{"users":[],"next":"","total":0}`)},
			laggedScenario(),
		},
		Required:   []string{"demo.me.get"},
		Operations: []string{"demo.me.get", "demo.users.list", "demo.score.get"},
		Insensitive: []string{
			"demo.me.get",
		},
	}
}

// kitOnly gives the demo's schema to the kit alone, so the kit runs the
// output checks itself instead of reading them from the result.
func kitOnly(s Suite) Suite {
	s.Spec.Schemas = nil
	s.Schemas = map[string]string{"artifacts/demo.json": "testdata/demo.schema.json"}
	return s
}

func checkSuite(t *testing.T, s Suite) *Report {
	t.Helper()
	report, err := Check(s)
	if err != nil {
		t.Fatal(err)
	}
	return report
}

func checkDemo(t *testing.T, d demo) *Report {
	t.Helper()
	return checkSuite(t, demoSuite(d))
}

func violationsOf(r *Report, check string) []Violation {
	var out []Violation
	for _, v := range r.Violations {
		if v.Check == check {
			out = append(out, v)
		}
	}
	return out
}

func TestAWellBehavedCollectorPasses(t *testing.T) {
	for mode, s := range map[string]Suite{"sdk": demoSuite(demo{}), "kit": kitOnly(demoSuite(demo{}))} {
		t.Run(mode, func(t *testing.T) {
			report := checkSuite(t, s)
			for _, v := range report.Violations {
				t.Errorf("%s/%s: %s", v.Check, v.Case, v.Message)
			}
			if report.Runs < 50 {
				t.Errorf("runs = %d, want the full matrix", report.Runs)
			}
			if strings.Join(report.Operations, ",") != "demo.me.get,demo.score.get,demo.users.list" {
				t.Errorf("operations = %v", report.Operations)
			}
		})
	}
}

func expectViolation(t *testing.T, report *Report, check, want string) {
	t.Helper()
	for _, v := range violationsOf(report, check) {
		if strings.Contains(v.Message, want) || strings.Contains(v.Case, want) {
			return
		}
	}
	t.Errorf("no %s violation mentioning %q; got %+v", check, want, report.Violations)
}

// outputBugs are the bugs the output checks catch.
var outputBugs = []struct {
	name  string
	demo  demo
	check string
	want  string
}{
	{"percentage over no users", demo{pctOverNone: true}, "population", "/mfa_pct: value 100, but its denominator /users is 0"},
	{"unexplained null flag", demo{nullFlag: true}, "nulls", "/mfa_enforced: null with no gap"},
	{"count from a lagged total", demo{laggedCount: true}, "rollups", "/users: value 5, but there are 4 rows at /user_mfa"},
	{"audit rows at trust", demo{rowsAtTrust: true}, "levels", "/user_mfa: present at trust, but its schema marks it audit"},
	{"score dropped above trust", demo{scoreAtTrust: true}, "levels", "/score: present at trust but missing at audit"},
}

func TestTheKitCatchesEachBug(t *testing.T) {
	cases := []struct {
		name  string
		demo  demo
		check string
		want  string
	}{
		{"timeout becomes zero", demo{zeroOnError: true}, "faults", "value changed from 72 to 0"},
		{"optional call fails the run", demo{failRun: true}, "faults", "failed the whole run"},
		{"partial pages counted as complete", demo{skipBadPage: true}, "faults", "value changed from"},
		{"wrong code", demo{wrongCode: true}, "faults", "has code vendor_error, want"},
		{"unnamed call", demo{unnamed: true}, "coverage", "carry no operation name"},
		{"secret in an artifact", demo{leakToken: true}, "secrets", "DEMO_TOKEN"},
		{"no credential host list", demo{noHostList: true}, "credentials", "X-Demo-Token"},
		{"response never read", demo{ignoreScore: true}, "sensitivity", "demo.score.get"},
		{"404 read as an answer", demo{treat404Zero: true}, "faults", "demo.score.get/404"},
	}
	cases = append(cases, outputBugs...)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			expectViolation(t, checkDemo(t, tc.demo), tc.check, tc.want)
		})
	}
}

func TestTheKitRunsOutputChecksForSchemasOnlyItHas(t *testing.T) {
	for _, tc := range outputBugs {
		t.Run(tc.name, func(t *testing.T) {
			expectViolation(t, checkSuite(t, kitOnly(demoSuite(tc.demo))), tc.check, tc.want)
		})
	}
}

func TestOutputChecksReportWhereTheyFound(t *testing.T) {
	report := checkDemo(t, demo{pctOverNone: true})
	for _, v := range violationsOf(report, "population") {
		if v.Case != "scenario/no users" {
			t.Errorf("only the no-users scenario has no users, got %s: %s", v.Case, v.Message)
		}
	}
	report = checkDemo(t, demo{laggedCount: true})
	var found []string
	for _, v := range violationsOf(report, "rollups") {
		found = append(found, v.Case+": "+v.Message)
	}
	want := []string{
		"scenario/lagged total: artifacts/demo.json /mfa_pct: value 60, but 3 of the 4 rows at /user_mfa have /mfa equal to true, which is 75",
		"scenario/lagged total: artifacts/demo.json /users: value 5, but there are 4 rows at /user_mfa",
	}
	if strings.Join(found, "|") != strings.Join(want, "|") {
		t.Errorf("rollups violations = %q, want %q", found, want)
	}
}

func TestSkipChecksTurnsOffTheOutputChecks(t *testing.T) {
	for _, tc := range outputBugs {
		t.Run(tc.check+"/"+tc.name, func(t *testing.T) {
			s := demoSuite(tc.demo)
			s.SkipChecks = []string{tc.check}
			if got := violationsOf(checkSuite(t, s), tc.check); len(got) > 0 {
				t.Errorf("skipped check %s still reported %+v", tc.check, got)
			}
		})
	}
}

func TestSensitivityRunsSkipTheValueChecks(t *testing.T) {
	s := demoSuite(demo{laggedCount: true})
	mutated := demoScenario()
	for i := range mutated.Responses {
		if strings.Contains(mutated.Responses[i].URL, "/users") {
			mutated.Responses[i].Body, _ = mutateJSON(mutated.Responses[i].Body)
		}
	}
	rp, err := NewReplay(mutated)
	if err != nil {
		t.Fatal(err)
	}
	res := componentsdk.RunInProcess(s.Spec, s.Run, componentsdk.InProcessOptions{Config: s.Config, Secrets: s.Secrets, Transport: rp})
	if res.Result == nil || len(res.Result.Checks) == 0 || res.Result.Checks[0].Check != componentsdk.CheckRollups {
		t.Fatalf("a mutated response should leave a rollup finding in the result, got %+v", res.Result)
	}
	for _, v := range checkSuite(t, s).Violations {
		if strings.HasPrefix(v.Case, "sensitivity/") || strings.HasPrefix(v.Case, "determinism/") {
			t.Errorf("value checks should skip %s runs: %s", v.Case, v.Message)
		}
	}
}

func TestAnUnusableSchemaIsReportedOnce(t *testing.T) {
	s := demoSuite(demo{})
	s.Spec.Schemas = map[string][]byte{"artifacts/demo.json": []byte(`{"type": 5}`)}
	report := checkSuite(t, s)
	got := violationsOf(report, "schema_unusable")
	if len(got) != 1 || got[0].Case != "" || !strings.Contains(got[0].Message, "artifacts/demo.json") {
		t.Errorf("schema_unusable violations = %+v", got)
	}
	if len(report.Violations) != 1 {
		t.Errorf("an unusable schema should be the only violation, got %+v", report.Violations)
	}
}

func TestTheKitReportsFindingsTheResultDropped(t *testing.T) {
	spec := componentsdk.CollectorSpec{Name: "flags", Schemas: map[string][]byte{
		"artifacts/flags.json": []byte(`{"type": "object", "additionalProperties": {"type": ["boolean", "null"]}}`),
	}}
	data := map[string]any{}
	for i := 0; i < 150; i++ {
		data[fmt.Sprintf("flag_%03d", i)] = nil
	}
	res := componentsdk.RunInProcess(spec, func(ctx componentsdk.CollectorContext) error {
		return ctx.Emit([]componentsdk.CollectedArtifact{{Data: data, Path: "artifacts/flags.json"}})
	}, componentsdk.InProcessOptions{})
	if res.Result == nil || res.Result.ChecksDropped != 50 {
		t.Fatalf("result = %+v", res.Result)
	}
	k := &kit{suite: Suite{Spec: spec}, report: &Report{}, reported: map[Violation]bool{}}
	k.checkOutput("scenario", "clean", res)
	if got := len(violationsOf(k.report, "nulls")); got != 150 {
		t.Errorf("nulls violations = %d, want all 150", got)
	}
}

func TestLevelLossesCountGapsAsEmitted(t *testing.T) {
	low := componentsdk.InProcessResult{Artifacts: []componentsdk.EmittedArtifact{
		{Path: "a.json", Data: json.RawMessage(`{"kept": 1, "changed": 2, "gapped": 3, "lost": [], "ignored": {"x": 1}}`)},
		{Path: "b.json", Data: json.RawMessage(`{}`)},
	}}
	high := componentsdk.InProcessResult{
		Artifacts: []componentsdk.EmittedArtifact{{Path: "a.json", Data: json.RawMessage(`{"kept": 1, "changed": null}`)}},
		Result:    &componentsdk.CollectorResult{Gaps: []componentsdk.Gap{{Path: "a.json", Pointer: "/gapped"}}},
	}
	got := levelLosses(componentsdk.LevelTrust, componentsdk.LevelAudit, low, high, newIgnoreSet(map[string][]string{"a.json": {"/ignored"}}))
	want := []string{
		"b.json: emitted at trust but missing at audit",
		"a.json /lost: present at trust but missing at audit",
	}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("losses = %q, want %q", got, want)
	}
}

func TestRequiredOperationsMayFailTheRun(t *testing.T) {
	report := checkDemo(t, demo{signInFails: true})
	for _, v := range violationsOf(report, "faults") {
		if strings.HasPrefix(v.Case, "demo.me.get/401") || strings.HasPrefix(v.Case, "demo.me.get/403") {
			t.Errorf("a required operation's failure should pass: %s", v.Message)
		}
	}
}

func TestSemanticsExemptDeclaredMeanings(t *testing.T) {
	s := demoSuite(demo{treat404Zero: true})
	s.Semantics = []Semantic{{
		Operation: "demo.score.get", Fault: "404", Meaning: "no score configured",
		Expect: map[string]map[string]any{"artifacts/demo.json": {"/score": 0}},
	}}
	report, err := Check(s)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range report.Violations {
		if strings.HasPrefix(v.Case, "demo.score.get/404") {
			t.Errorf("a declared 404 should pass: %s", v.Message)
		}
	}
}

func TestSemanticsPinTheirMeaning(t *testing.T) {
	s := demoSuite(demo{treat404Zero: true})
	s.Semantics = []Semantic{{
		Operation: "demo.score.get", Fault: "404", Meaning: "no score configured",
		Expect: map[string]map[string]any{"artifacts/demo.json": {"/score": 1}},
	}}
	expectViolation(t, checkSuite(t, s), "faults", "404 (no score configured): artifacts/demo.json /score is 0, want 1")
}

func TestSuiteFaultsJoinTheMatrix(t *testing.T) {
	added := []Fault{
		BodyFault("html", "<html>down for maintenance</html>", componentsdk.CodeInvalidResponse),
		ErrorFault("dns", &net.DNSError{Err: "no such host", Name: "api.demo.test", IsNotFound: true}, componentsdk.CodeVendorError),
	}
	s := demoSuite(demo{})
	s.Faults = added
	report := checkSuite(t, s)
	for _, v := range report.Violations {
		t.Errorf("%s/%s: %s", v.Check, v.Case, v.Message)
	}
	if base := checkDemo(t, demo{}); report.Runs != base.Runs+10 {
		t.Errorf("runs = %d, want %d plus 5 for each added fault", report.Runs, base.Runs)
	}

	s = demoSuite(demo{wrongCode: true})
	s.Faults = added
	expectViolation(t, checkSuite(t, s), "faults", "demo.score.get/html/all")
}

// throttleFaults send the demo vendor's throttle once, which a retry clears,
// and on every attempt.
func throttleFaults() []Fault {
	return []Fault{
		StatusFault("400-throttled-once", http.StatusBadRequest, nil, demoThrottleBody, "", true),
		StatusFault("400-throttled", http.StatusBadRequest, nil, demoThrottleBody, componentsdk.CodeRateLimited, false),
	}
}

func TestClassifyResponseHandlesAVendorThrottle(t *testing.T) {
	s := demoSuite(demo{})
	s.Faults = throttleFaults()
	report := checkSuite(t, s)
	for _, v := range report.Violations {
		t.Errorf("%s/%s: %s", v.Check, v.Case, v.Message)
	}
	if base := checkDemo(t, demo{}); report.Runs != base.Runs+8 {
		t.Errorf("runs = %d, want %d plus the throttles on each operation's calls", report.Runs, base.Runs+8)
	}

	s = demoSuite(demo{noClassify: true})
	s.Faults = throttleFaults()
	report = checkSuite(t, s)
	expectViolation(t, report, "faults", "a fault that clears on retry left a gap at artifacts/demo.json /score (invalid_response)")
	expectViolation(t, report, "faults", "the gap at artifacts/demo.json /score has code invalid_response, want rate_limited")
}

func TestAVendorThrottleReachesTheLedgerAndTheGap(t *testing.T) {
	s := demoSuite(demo{})
	run := func(f Fault) componentsdk.InProcessResult {
		t.Helper()
		rp, err := NewReplay(demoScenario())
		if err != nil {
			t.Fatal(err)
		}
		in := &injector{base: rp, op: "demo.score.get", fault: f, position: PositionAll, total: 1}
		res := componentsdk.RunInProcess(s.Spec, s.Run, componentsdk.InProcessOptions{
			Config: s.Config, Secrets: s.Secrets, Transport: in,
			Sleep: func(ctx context.Context, _ time.Duration) error { return ctx.Err() },
		})
		if res.ExitCode != 0 || res.Result == nil {
			t.Fatalf("%s: exit %d, %s", f.Name, res.ExitCode, failureLabel(res))
		}
		return res
	}
	scoreCalls := func(res componentsdk.InProcessResult) componentsdk.OperationCalls {
		for _, op := range res.Result.Calls.Operations {
			if op.Name == "demo.score.get" {
				return op
			}
		}
		return componentsdk.OperationCalls{}
	}
	faults := throttleFaults()

	once := run(faults[0])
	leaves, err := flatten(once.Artifacts[0].Data)
	if err != nil || show(leaves["/score"]) != "72" || len(once.Result.Gaps) != 0 {
		t.Errorf("a throttle that clears on retry left score %s and gaps %+v, want 72 and none", show(leaves["/score"]), once.Result.Gaps)
	}
	if c := scoreCalls(once); c.Attempts != 2 || c.Statuses["400"] != 1 || c.Statuses["200"] != 1 || c.Errors[componentsdk.CodeRateLimited] != 1 {
		t.Errorf("ledger = %+v, want the throttle and the retry that cleared it", c)
	}

	always := run(faults[1])
	if gaps := always.Result.Gaps; len(gaps) != 1 || gaps[0].Pointer != "/score" || gaps[0].Code != componentsdk.CodeRateLimited {
		t.Errorf("gaps = %+v, want a rate_limited gap at /score", gaps)
	}
	if c := scoreCalls(always); c.Attempts != 5 || c.Statuses["400"] != 5 || c.Errors[componentsdk.CodeRateLimited] != 5 {
		t.Errorf("ledger = %+v, want five throttled attempts", c)
	}
}

func TestAFaultWithOperationsHitsOnlyThose(t *testing.T) {
	throttle := throttleFaults()[1]
	throttle.Operations = []string{"demo.score.get"}
	s := demoSuite(demo{noClassify: true})
	s.Faults = []Fault{throttle}
	report := checkSuite(t, s)
	hit := false
	for _, v := range violationsOf(report, "faults") {
		if !strings.Contains(v.Case, "/400-throttled/") {
			continue
		}
		hit = true
		if !strings.HasPrefix(v.Case, "demo.score.get/") {
			t.Errorf("the fault hit %s, which its Operations leave out", v.Case)
		}
	}
	if !hit {
		t.Error("the fault never hit demo.score.get")
	}
	if base := checkDemo(t, demo{noClassify: true}); report.Runs != base.Runs+1 {
		t.Errorf("runs = %d, want %d plus one for demo.score.get's single call", report.Runs, base.Runs)
	}
}

// tripwire fails and counts every request that reaches it.
type tripwire struct{ hits atomic.Int32 }

func (w *tripwire) RoundTrip(*http.Request) (*http.Response, error) {
	w.hits.Add(1)
	return nil, errors.New("tripwire: a request reached the collector's base transport")
}

func TestKitRunsNeverReachTheBaseTransport(t *testing.T) {
	wire := &tripwire{}
	report := checkDemo(t, demo{base: wire})
	for _, v := range report.Violations {
		t.Errorf("%s/%s: %s", v.Check, v.Case, v.Message)
	}
	if n := wire.hits.Load(); n != 0 {
		t.Errorf("%d requests reached the demo's base transport, want the kit's replay to answer them all", n)
	}
}

func TestScenarioFailuresAreReported(t *testing.T) {
	s := demoSuite(demo{})
	s.Scenarios = append(s.Scenarios, Scenario{
		Name: "token rejected", ExpectFailure: componentsdk.CodeAuthFailed,
		Responses: []Response{{URL: demoHost + "/me", Status: 401, Body: `{}`}},
	})
	report, err := Check(s)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range violationsOf(report, "scenario") {
		t.Errorf("unexpected scenario violation: %s", v.Message)
	}

	s.Scenarios[len(s.Scenarios)-1].Responses = nil
	report, _ = Check(s)
	if len(violationsOf(report, "scenario")) == 0 {
		t.Error("a request with no canned response should be reported")
	}
}

func TestScenarioExpectPinsValues(t *testing.T) {
	s := demoSuite(demo{})
	s.Scenarios[0].Expect = map[string]map[string]any{"artifacts/demo.json": {
		"/score": 72, "/users": 4, "/mfa_pct": 75, "/debug": nil,
		"/user_mfa": []any{map[string]any{"mfa": true}, map[string]any{"mfa": false}, map[string]any{"mfa": true}, map[string]any{"mfa": true}},
	}}
	s.Scenarios[1].Expect = map[string]map[string]any{"artifacts/demo.json": {"/users": 0, "/mfa_pct": nil}}
	for _, v := range violationsOf(checkSuite(t, s), "scenario") {
		t.Errorf("a value the demo produces was reported: %s: %s", v.Case, v.Message)
	}

	s.Scenarios[0].Expect = map[string]map[string]any{
		"artifacts/demo.json":  {"/score": 50, "/org": nil, "/missing": 1},
		"artifacts/other.json": {"/x": 1},
	}
	var got []string
	for _, v := range violationsOf(checkSuite(t, s), "scenario") {
		got = append(got, v.Case+": "+v.Message)
	}
	want := []string{
		"clean: artifacts/demo.json /missing is absent, want 1",
		`clean: artifacts/demo.json /org is "acme", want null`,
		"clean: artifacts/demo.json /score is 72, want 50",
		"clean: artifact artifacts/other.json was not emitted",
	}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("scenario violations = %q, want %q", got, want)
	}
}

func TestScenarioExpectPinsAbsence(t *testing.T) {
	s := demoSuite(demo{})
	s.Scenarios[1].Expect = map[string]map[string]any{"artifacts/demo.json": {"/debug": Absent, "/mfa_pct": nil}}
	for _, v := range violationsOf(checkSuite(t, s), "scenario") {
		t.Errorf("an absent value and a null one should match their pins: %s: %s", v.Case, v.Message)
	}

	s.Scenarios[1].Expect = map[string]map[string]any{"artifacts/demo.json": {"/mfa_pct": Absent, "/users": Absent}}
	var got []string
	for _, v := range violationsOf(checkSuite(t, s), "scenario") {
		got = append(got, v.Case+": "+v.Message)
	}
	want := []string{
		"no users: artifacts/demo.json /mfa_pct is null, want it absent",
		"no users: artifacts/demo.json /users is 0, want it absent",
	}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("scenario violations = %q, want %q", got, want)
	}
}

func TestScenarioExpectCatchesAnIncidentComingBack(t *testing.T) {
	s := demoSuite(demo{laggedCount: true})
	s.Scenarios[2].Expect = map[string]map[string]any{"artifacts/demo.json": {"/users": 4}}
	expectViolation(t, checkSuite(t, s), "scenario", "artifacts/demo.json /users is 5, want 4")
}

func TestCheckRejectsAnUnusableSuite(t *testing.T) {
	if _, err := Check(Suite{}); err == nil {
		t.Error("an empty suite should be rejected")
	}
	s := demoSuite(demo{})
	s.Scenarios[0].ExpectFailure = componentsdk.CodeAuthFailed
	if _, err := Check(s); err == nil {
		t.Error("a failing first scenario should be rejected")
	}
	s = demoSuite(demo{})
	s.Faults = []Fault{{Name: "bare", Expect: componentsdk.CodeVendorError}}
	if _, err := Check(s); err == nil || !strings.Contains(err.Error(), "StatusFault") {
		t.Errorf("a fault built without a constructor should be rejected, got %v", err)
	}
	s = demoSuite(demo{})
	s.Scenarios = append(s.Scenarios, Scenario{
		Name: "token rejected", ExpectFailure: componentsdk.CodeAuthFailed,
		Expect: map[string]map[string]any{"artifacts/demo.json": {"/org": "acme"}},
	})
	if _, err := Check(s); err == nil || !strings.Contains(err.Error(), "token rejected") {
		t.Errorf("a scenario that expects a failure and pins values should be rejected, got %v", err)
	}
}

func TestMutateJSON(t *testing.T) {
	got, ok := mutateJSON(`{"a":true,"b":[1,2],"c":{"d":false},"e":3,"f":1.5,"s":"keep"}`)
	if !ok || got != `{"a":false,"b":[],"c":{"d":true},"e":4,"f":2.5,"s":"keep"}` {
		t.Errorf("mutateJSON = %s, %v", got, ok)
	}
	if _, ok := mutateJSON(`{"s":"only strings"}`); ok {
		t.Error("a body with nothing to change should report no change")
	}
}

func TestFaultsReachOperationsNamedByTheHook(t *testing.T) {
	named := checkDemo(t, demo{})
	hooked := checkDemo(t, demo{hookNames: true})
	for _, v := range hooked.Violations {
		t.Errorf("%s/%s: %s", v.Check, v.Case, v.Message)
	}
	if hooked.Runs != named.Runs {
		t.Errorf("runs = %d with names from the hook, %d with names on the context; the fault matrix skipped hook-named operations", hooked.Runs, named.Runs)
	}
	report := checkDemo(t, demo{hookNames: true, zeroOnError: true})
	found := false
	for _, v := range violationsOf(report, "faults") {
		if strings.Contains(v.Message, "value changed from 72 to 0") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("a zero written on a failed score read went unreported when the hook names the call; got %+v", report.Violations)
	}
}

func TestScenariosOverrideConfigSecretsAndEnv(t *testing.T) {
	const rotated = "rotated-token-9876543210"
	pin := func(path string, values map[string]any) map[string]map[string]any {
		return map[string]map[string]any{path: values}
	}
	s := demoSuite(demo{leakToken: true})
	base := checkSuite(t, s)
	s.Scenarios = append(s.Scenarios,
		Scenario{
			Name: "trust level", Responses: demoScenario().Responses, Config: map[string]any{"level": "trust"},
			Expect: pin("artifacts/demo.json", map[string]any{"/user_mfa": nil, "/users": 4}),
		},
		Scenario{
			Name: "rotated token", Responses: demoScenario().Responses, Secrets: map[string]string{"DEMO_TOKEN": rotated},
			Expect: pin("artifacts/demo.json", map[string]any{"/debug": rotated}),
		},
		Scenario{
			Name: "behind a proxy", Responses: demoScenario().Responses, Env: map[string]string{"HTTPS_PROXY": "http://proxy.example:3128"},
			Expect: pin("artifacts/demo.collector-result.json", map[string]any{"/run/proxy": true}),
		},
	)
	s.Scenarios[0].Expect = pin("artifacts/demo.collector-result.json", map[string]any{"/run/proxy": false})
	report := checkSuite(t, s)
	for _, v := range violationsOf(report, "scenario") {
		t.Errorf("a scenario's own config, secrets, or env did not reach its run: %s: %s", v.Case, v.Message)
	}
	expectViolation(t, report, "secrets", "scenario/rotated token")
	if report.Runs != base.Runs+3 {
		t.Errorf("runs = %d, want %d plus one for each added scenario; the other checks run on the first scenario", report.Runs, base.Runs)
	}
}

func TestTheFirstScenariosOverridesReachEveryCheck(t *testing.T) {
	want := checkSuite(t, tlsDemoSuite(tlsDemo{}))
	s := tlsDemoSuite(tlsDemo{})
	s.Config = map[string]any{"level": "audit"}
	for i := range s.Scenarios {
		s.Scenarios[i].Config = map[string]any{"address": "www.example.com:443"}
	}
	report := checkSuite(t, s)
	for _, v := range report.Violations {
		t.Errorf("%s/%s: %s", v.Check, v.Case, v.Message)
	}
	if report.Runs != want.Runs {
		t.Errorf("runs = %d, want %d, as when the suite's config has the address", report.Runs, want.Runs)
	}
}

func TestSemanticsDeclareAFailure(t *testing.T) {
	orgGone := Semantic{Operation: "demo.me.get", Fault: "404", Meaning: "the organization does not exist", ExpectFailure: componentsdk.CodeConfigInvalid}
	expectViolation(t, checkDemo(t, demo{orgMissing: true}), "faults", "the run failed with code config_invalid")

	s := demoSuite(demo{orgMissing: true})
	s.Semantics = []Semantic{orgGone}
	for _, v := range checkSuite(t, s).Violations {
		t.Errorf("a declared failure should pass: %s/%s: %s", v.Check, v.Case, v.Message)
	}

	s = demoSuite(demo{})
	s.Semantics = []Semantic{orgGone}
	expectViolation(t, checkSuite(t, s), "faults", "404 (the organization does not exist): the run failed with code invalid_response")

	s = demoSuite(demo{})
	s.Required = append(s.Required, "demo.score.get")
	s.Semantics = []Semantic{{Operation: "demo.score.get", Fault: "404", Meaning: "no score", ExpectFailure: componentsdk.CodeConfigInvalid}}
	expectViolation(t, checkSuite(t, s), "faults", "404 (no score): the run succeeded, want a failure with code config_invalid")
}

func TestCheckRejectsAFailureSemanticItCannotHonor(t *testing.T) {
	s := demoSuite(demo{})
	s.Semantics = []Semantic{{Operation: "demo.score.get", Fault: "404", ExpectFailure: componentsdk.CodeConfigInvalid}}
	if _, err := Check(s); err == nil || !strings.Contains(err.Error(), "Suite.Required") {
		t.Errorf("a failure semantic on an operation outside Suite.Required should be rejected, got %v", err)
	}
	s.Semantics = []Semantic{{
		Operation: "demo.me.get", Fault: "404", ExpectFailure: componentsdk.CodeConfigInvalid,
		Expect: map[string]map[string]any{"artifacts/demo.json": {"/org": nil}},
	}}
	if _, err := Check(s); err == nil || !strings.Contains(err.Error(), "Expect") {
		t.Errorf("a failure semantic that pins values should be rejected, got %v", err)
	}
}

func TestCompareRunsAcceptsContainersEmptiedByGaps(t *testing.T) {
	art := func(data string) []componentsdk.EmittedArtifact {
		return []componentsdk.EmittedArtifact{{Path: "a.json", Data: json.RawMessage(data)}}
	}
	gap := func(pointers ...string) []componentsdk.Gap {
		var gaps []componentsdk.Gap
		for _, p := range pointers {
			gaps = append(gaps, componentsdk.Gap{Path: "a.json", Pointer: p})
		}
		return gaps
	}
	clean := art(`{"accounts": [{"mfa": true, "sso": false}], "policy": {"lockout": 5}, "kept": 1}`)
	if got := compareRuns(clean, art(`{"accounts": [{}], "policy": {}, "kept": 1}`), gap("/accounts/0/mfa", "/accounts/0/sso", "/policy/lockout"), nil); len(got) != 0 {
		t.Errorf("containers left empty by gaps were reported: %q", got)
	}
	got := compareRuns(clean, art(`{"accounts": [{}], "policy": {}, "kept": 1, "new": {}}`), gap("/accounts/0/mfa", "/policy/lockout"), nil)
	want := []string{
		"a.json /accounts/0/sso: value false left out without a gap",
		"a.json /new: value {} appeared under the fault",
	}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("problems = %q, want %q", got, want)
	}
}

func TestCompareRunsCoversAListReadInPart(t *testing.T) {
	clean := []componentsdk.EmittedArtifact{{Path: "a.json", Data: json.RawMessage(`{"users": [{"mfa": true}, {"mfa": false}, {"mfa": true}], "count": 3}`)}}
	faulted := []componentsdk.EmittedArtifact{{Path: "a.json", Data: json.RawMessage(`{"users": [{"mfa": false}, {"mfa": true}, {"mfa": true, "admin": true}], "count": null}`)}}
	gaps := []componentsdk.Gap{
		{Path: "a.json", Pointer: "/users", Status: componentsdk.GapPartial},
		{Path: "a.json", Pointer: "/count", Status: componentsdk.GapPartial},
	}
	if got := compareRuns(clean, faulted, gaps, nil); len(got) != 0 {
		t.Errorf("items under a partial gap were reported: %q", got)
	}
	if got := compareRuns(clean, faulted, gaps[1:], nil); len(got) != 3 {
		t.Errorf("without the gap, the changed and added items should be reported, got %q", got)
	}
}

func TestAListReadInPartPassesWithAPartialGap(t *testing.T) {
	report := checkDemo(t, demo{partialRows: true})
	for _, v := range report.Violations {
		t.Errorf("%s/%s: %s", v.Check, v.Case, v.Message)
	}
	rp, err := NewReplay(Scenario{Name: "second page fails", Responses: replaceResponse(demoScenario().Responses, demoHost+"/users?page=2", Response{Status: 500, Body: `{}`})})
	if err != nil {
		t.Fatal(err)
	}
	s := demoSuite(demo{partialRows: true})
	res := componentsdk.RunInProcess(s.Spec, s.Run, componentsdk.InProcessOptions{
		Config: s.Config, Secrets: s.Secrets, Transport: rp,
		Sleep: func(ctx context.Context, _ time.Duration) error { return ctx.Err() },
	})
	if res.ExitCode != 0 || res.Result == nil {
		t.Fatalf("exit %d, %s", res.ExitCode, failureLabel(res))
	}
	leaves, _ := flatten(res.Artifacts[0].Data)
	if show(leaves["/user_mfa/1/mfa"]) != "false" || leaves["/user_mfa/2/mfa"] != nil {
		t.Errorf("artifact = %s, want the first page's two rows", res.Artifacts[0].Data)
	}
	var partial *componentsdk.Gap
	for i, g := range res.Result.Gaps {
		if g.Pointer == "/user_mfa" {
			partial = &res.Result.Gaps[i]
		}
	}
	if partial == nil || partial.Status != componentsdk.GapPartial || partial.Unmeasured != 2 {
		t.Errorf("gaps = %+v, want a partial gap at /user_mfa with 2 rows unmeasured", res.Result.Gaps)
	}
}

// replaceResponse swaps the response for url with r, keeping its URL.
func replaceResponse(responses []Response, url string, r Response) []Response {
	out := append([]Response(nil), responses...)
	for i := range out {
		if out[i].URL == url {
			r.URL = url
			out[i] = r
		}
	}
	return out
}

func TestTruncatedCutsOnly2xxBodies(t *testing.T) {
	var truncated Fault
	for _, f := range Faults() {
		if f.Name == "truncated" {
			truncated = f
		}
	}
	const body = `{"error":{"code":"NotFound","message":"no such thing"}}`
	for status, want := range map[int]string{200: body[:len(body)/2], 206: body[:len(body)/2], 304: body, 404: body, 503: body} {
		req, _ := http.NewRequest(http.MethodGet, demoHost+"/score", nil)
		changed := false
		resp, err := truncated.apply(func() (*http.Response, error) {
			return &http.Response{StatusCode: status, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(body)), Request: req}, nil
		}, req, func() { changed = true })
		if err != nil {
			t.Fatal(err)
		}
		if changed {
			t.Errorf("status %d: a body not yet read counts as changed", status)
		}
		got, _ := io.ReadAll(resp.Body)
		if string(got) != want || changed != (want != body) {
			t.Errorf("status %d: body %q, changed %v; want %q", status, got, changed, want)
		}
	}
}

// headerCount reads a user count from a response header and never reads the
// body, as a collector that pages one item at a time to learn the total does.
func headerCount(ctx componentsdk.CollectorContext) error {
	client := componentsdk.NewHTTPClient(ctx, componentsdk.HTTPOptions{CredentialHosts: []string{"api.demo.test"}})
	rec := componentsdk.Records(ctx)
	at := componentsdk.Location{Path: "artifacts/count.json", Pointer: "/users"}
	out := map[string]any{}
	req, err := http.NewRequestWithContext(componentsdk.WithOperation(ctx.Context(), componentsdk.Operation{Name: "count.users.get"}), http.MethodGet, demoHost+"/users?per_page=1", nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		rec.NotCollected(at, err)
		return ctx.Emit([]componentsdk.CollectedArtifact{{Data: out, Path: at.Path}})
	}
	_ = resp.Body.Close()
	n, convErr := strconv.Atoi(resp.Header.Get("X-Total-Count"))
	switch {
	case resp.StatusCode != http.StatusOK:
		rec.NotCollected(at, componentsdk.CodeError(componentsdk.ClassifyResponse(resp), &demoAPIError{status: resp.StatusCode}))
	case convErr != nil:
		rec.NotCollectedCode(at, componentsdk.CodeInvalidResponse, "the response has no X-Total-Count")
	default:
		out["users"] = n
	}
	return ctx.Emit([]componentsdk.CollectedArtifact{{Data: out, Path: at.Path}})
}

// A fault that changes nothing the collector reads need not leave a gap.
func TestAFaultThatChangesNothingNeedNotLeaveAGap(t *testing.T) {
	t.Run("a clean failure", func(t *testing.T) {
		// The clean score read fails with a 404, which "truncated" passes
		// through and "malformed" turns into another invalid_response.
		s := demoSuite(demo{})
		s.Scenarios = s.Scenarios[:1]
		s.Scenarios[0].Responses = replaceResponse(demoScenario().Responses, demoHost+"/score", Response{Status: http.StatusNotFound, Body: `{}`})
		for _, v := range checkSuite(t, s).Violations {
			t.Errorf("%s/%s: %s", v.Check, v.Case, v.Message)
		}
	})
	t.Run("a body never read", func(t *testing.T) {
		report := checkSuite(t, Suite{
			Spec: componentsdk.CollectorSpec{Name: "count"},
			Run:  headerCount,
			Scenarios: []Scenario{{Name: "clean", Responses: []Response{
				{URL: demoHost + "/users?per_page=1", Header: http.Header{"X-Total-Count": {"7"}}, Body: `[{"id":1}]`},
			}}},
			SkipChecks: []string{"sensitivity"},
		})
		for _, v := range report.Violations {
			t.Errorf("%s/%s: %s", v.Check, v.Case, v.Message)
		}
	})
}

func TestNewReplayAnswersAFocusedRun(t *testing.T) {
	s := demoSuite(demo{})
	run := func(sc Scenario) (componentsdk.InProcessResult, *Replay) {
		t.Helper()
		rp, err := NewReplay(sc)
		if err != nil {
			t.Fatal(err)
		}
		return componentsdk.RunInProcess(s.Spec, s.Run, componentsdk.InProcessOptions{Config: s.Config, Secrets: s.Secrets, Transport: rp}), rp
	}
	res, rp := run(demoScenario())
	if res.ExitCode != 0 || len(rp.Unmatched()) != 0 {
		t.Fatalf("exit %d, unmatched %q", res.ExitCode, rp.Unmatched())
	}
	sc := demoScenario()
	sc.Responses = sc.Responses[:len(sc.Responses)-1]
	if _, rp = run(sc); strings.Join(rp.Unmatched(), "|") != "GET https://api.demo.test/score (operation demo.score.get)" {
		t.Errorf("unmatched = %q, want the score request", rp.Unmatched())
	}
	if _, err := NewReplay(Scenario{Name: "relative", Responses: []Response{{URL: "/me"}}}); err == nil {
		t.Error("a response URL without a host should be rejected")
	}
}

// probe signs in with a call whose response reaches only the result's
// signed_in_as, then counts users.
type probe struct {
	ignoreScopes bool // leaves the scopes the sign-in returns out of signed_in_as
}

func (p probe) run(ctx componentsdk.CollectorContext) error {
	client := componentsdk.NewHTTPClient(ctx, componentsdk.HTTPOptions{CredentialHosts: []string{"api.demo.test"}})
	get := func(op, url string, out any) error {
		req, err := http.NewRequestWithContext(componentsdk.WithOperation(ctx.Context(), componentsdk.Operation{Name: op}), http.MethodGet, url, nil)
		if err != nil {
			return err
		}
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer func() { _ = resp.Body.Close() }()
		return json.NewDecoder(resp.Body).Decode(out)
	}
	var me struct {
		Scopes []string `json:"scopes"`
	}
	if err := get("probe.me.get", demoHost+"/me", &me); err != nil {
		return err
	}
	principal := componentsdk.Principal{Provider: "demo", Kind: "token", Scopes: me.Scopes}
	if p.ignoreScopes {
		principal.Scopes = nil
	}
	componentsdk.Records(ctx).SignedInAs(principal)
	var users struct {
		Count int `json:"count"`
	}
	if err := get("probe.users.count", demoHost+"/users/count", &users); err != nil {
		return err
	}
	return ctx.Emit([]componentsdk.CollectedArtifact{{Data: map[string]any{"users": users.Count}, Path: "artifacts/probe.json"}})
}

func TestSensitivityCountsTheSignInIdentity(t *testing.T) {
	suite := func(p probe) Suite {
		return Suite{
			Spec: componentsdk.CollectorSpec{Name: "probe"},
			Run:  p.run,
			Scenarios: []Scenario{{Name: "clean", Responses: []Response{
				{URL: demoHost + "/me", Body: `{"scopes":["users.read","groups.read"],"admin":true}`},
				{URL: demoHost + "/users/count", Body: `{"count":3}`},
			}}},
			SkipChecks: []string{"faults", "levels", "determinism", "credentials"},
		}
	}
	for _, v := range checkSuite(t, suite(probe{})).Violations {
		t.Errorf("a sign-in whose response reaches signed_in_as should prove itself: %s/%s: %s", v.Check, v.Case, v.Message)
	}
	expectViolation(t, checkSuite(t, suite(probe{ignoreScopes: true})), "sensitivity", "probe.me.get")
}

func TestTheCredentialsCheckFollowsLinksToAForeignHost(t *testing.T) {
	report := checkDemo(t, demo{noHostList: true, bearer: true, linkPages: true})
	expectViolation(t, report, "credentials", "following a link in a response to demo.users.list sent Authorization to collectortest.invalid")
	for _, v := range violationsOf(report, "credentials") {
		if strings.Contains(v.Message, "built without HTTPOptions.CredentialHosts") {
			continue
		}
		if v.Case != "demo.users.list/link" {
			t.Errorf("only the users pages carry a link, and the client drops Authorization on a redirect to another domain: %s: %s", v.Case, v.Message)
		}
	}
	for _, d := range []demo{{bearer: true, linkPages: true}, {bearer: true}} {
		for _, v := range checkDemo(t, d).Violations {
			t.Errorf("with CredentialHosts set, %+v: %s/%s: %s", d, v.Check, v.Case, v.Message)
		}
	}
}

func TestTheCredentialsCheckNamesEachHeaderOnce(t *testing.T) {
	report := checkDemo(t, demo{noHostList: true, gitlabHeader: true})
	expectViolation(t, report, "credentials", "a redirect from demo.me.get sent Private-Token to collectortest.invalid;")
	for _, v := range violationsOf(report, "credentials") {
		if strings.Contains(v.Message, "PRIVATE-TOKEN") {
			t.Errorf("the header should appear once, by its canonical name: %s", v.Message)
		}
	}
}

func TestTheCredentialsCheckFlagsAPublicSuffixWildcard(t *testing.T) {
	report := checkDemo(t, demo{broadHosts: true})
	expectViolation(t, report, "credentials", `CredentialHosts entry "*.com" lets credentials go to every host under com, a public suffix`)
	if len(report.Violations) != 1 {
		t.Errorf("the wildcard should be reported once, got %+v", report.Violations)
	}
	cases := map[string]bool{
		"*.com": true, "*.co.uk": true, "*.COM.": true,
		"*.example.com": false, "*.github.io": false, "*.test": false, "api.example.com": false, "*": false, "*.": false,
	}
	for entry, want := range cases {
		if _, got := publicSuffixWildcard(entry); got != want {
			t.Errorf("publicSuffixWildcard(%q) = %v, want %v", entry, got, want)
		}
	}
}

func TestForeignLinksRewriteOneResponsesLinksToItsOwnHost(t *testing.T) {
	s := Scenario{Responses: []Response{
		{URL: "https://api.example.com/me", Body: `{"self":"https://api.example.com/me"}`},
		{URL: "https://api.example.com/users", Header: http.Header{"Link": {`<https://API.example.com/users?page=2>; rel="next"`, `<https://api.example.com:8443/users?page=9>; rel="last"`}},
			Body: `{"next":"https:\/\/api.example.com\/users?page=2","site":"https://api.example.com.evil/x","docs":"https://docs.example.com/users","bare":"https://api.example.com"}`},
		{URL: "https://api.example.com/users", Body: `{"next":"https://api.example.com/users?page=3"}`},
	}}
	ops := map[int][]string{0: {"me.get"}, 1: {"users.list"}, 2: {"users.list"}}
	hosts := map[int][]string{0: {"api.example.com"}, 1: {"api.example.com"}, 2: {"api.example.com"}}
	got, ok := foreignLinks(s, "users.list", ops, hosts)
	if !ok {
		t.Fatal("the users response has links to its own host")
	}
	r := got.Responses[1]
	wantBody := `{"next":"https:\/\/collectortest.invalid\/users?page=2","site":"https://api.example.com.evil/x","docs":"https://docs.example.com/users","bare":"https://collectortest.invalid"}`
	wantLinks := []string{`<https://collectortest.invalid/users?page=2>; rel="next"`, `<https://collectortest.invalid:8443/users?page=9>; rel="last"`}
	if r.Body != wantBody || strings.Join(r.Header.Values("Link"), "|") != strings.Join(wantLinks, "|") {
		t.Errorf("rewritten response = %q %q", r.Body, r.Header.Values("Link"))
	}
	if got.Responses[2].Body != s.Responses[2].Body || got.Responses[0].Body != s.Responses[0].Body {
		t.Error("only the first users response should change")
	}
	if s.Responses[1].Header.Get("Link") != `<https://API.example.com/users?page=2>; rel="next"` || strings.Contains(s.Responses[1].Body, foreignHost) {
		t.Error("the scenario passed in should not change")
	}
	if _, ok := foreignLinks(s, "score.get", ops, hosts); ok {
		t.Error("an operation that consumed no response has no links to rewrite")
	}
}

// stager reads a policy document and stages its text as a file artifact,
// beside an index that records the text's length, with bugs behind
// switches. With every switch off it handles faults correctly.
type stager struct {
	noFileGap   bool // leaves the file out without a gap when the read fails
	placeholder bool // stages a placeholder text when the read fails
	leakToken   bool // writes its token into the staged file
	stageToken  bool // stages a debug file with its token, which it does not emit
	// stamp, when set, numbers each run's staged file, so no two runs stage
	// the same bytes.
	stamp *atomic.Int64
	// moveFile, when set, emits the file at another path every other run.
	moveFile *atomic.Int64
}

const (
	stagerIndex = "artifacts/stager.json"
	stagerFile  = "artifacts/policy.txt"
)

func (s stager) run(ctx componentsdk.CollectorContext) error {
	staging, ok := componentsdk.Staging(ctx)
	if !ok {
		return errors.New("this context cannot stage files")
	}
	client := componentsdk.NewHTTPClient(ctx, componentsdk.HTTPOptions{CredentialHosts: []string{"files.demo.test"}, CredentialHeaders: []string{"X-Files-Token"}})
	token := ctx.Secret("FILES_TOKEN")
	read := func() (string, error) {
		req, err := http.NewRequestWithContext(componentsdk.WithOperation(ctx.Context(), componentsdk.Operation{Name: "files.policy.get"}), http.MethodGet, "https://files.demo.test/policy", nil)
		if err != nil {
			return "", err
		}
		req.Header.Set("X-Files-Token", token)
		resp, err := client.Do(req)
		if err != nil {
			return "", err
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			return "", componentsdk.CodeError(componentsdk.ClassifyResponse(resp), &demoAPIError{status: resp.StatusCode})
		}
		var doc struct {
			Text *string `json:"text"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
			return "", err
		}
		if doc.Text == nil {
			return "", componentsdk.CodeError(componentsdk.CodeInvalidResponse, errors.New("policy response has no text"))
		}
		return *doc.Text, nil
	}
	rec := componentsdk.Records(ctx)
	text, err := read()
	chars := any(len(text))
	if err != nil {
		rec.NotCollected(componentsdk.Location{Path: stagerIndex, Pointer: "/policy_chars"}, err)
		chars = nil
		switch {
		case s.placeholder:
			text = "Policy unavailable."
		case !s.noFileGap:
			rec.NotCollected(componentsdk.Location{Path: stagerFile}, err)
		}
	}
	artifacts := []componentsdk.CollectedArtifact{
		componentsdk.JSONArtifact(stagerIndex, map[string]any{"policy_chars": chars}, componentsdk.ArtifactMeta{}),
	}
	if err == nil || s.placeholder {
		if s.leakToken {
			text += "\nfetched with " + token
		}
		if s.stamp != nil {
			text += fmt.Sprintf("\nrun %d", s.stamp.Add(1))
		}
		path := stagerFile
		if s.moveFile != nil && s.moveFile.Add(1)%2 == 0 {
			path = "artifacts/policy-copy.txt"
		}
		staged, err := staging.WriteStagedFile("policy.txt", []byte(text))
		if err != nil {
			return err
		}
		artifacts = append(artifacts, componentsdk.FileArtifact(path, staged, componentsdk.ArtifactMeta{}))
	}
	if s.stageToken {
		if _, err := staging.WriteStagedFile("debug/request.log", []byte("X-Files-Token: "+token)); err != nil {
			return err
		}
	}
	return ctx.Emit(artifacts)
}

func stagerSuite(s stager) Suite {
	return Suite{
		Spec:    componentsdk.CollectorSpec{Name: "stager"},
		Run:     s.run,
		Secrets: map[string]string{"FILES_TOKEN": "files-token-0123456789"},
		Scenarios: []Scenario{{
			Name:      "clean",
			Responses: []Response{{URL: "https://files.demo.test/policy", Body: `{"text":"Passwords rotate yearly."}`}},
			Expect:    map[string]map[string]any{stagerIndex: {"/policy_chars": 24}},
		}},
	}
}

func TestTheKitStagesFileArtifacts(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	report := checkSuite(t, stagerSuite(stager{}))
	for _, v := range report.Violations {
		t.Errorf("%s/%s: %s", v.Check, v.Case, v.Message)
	}
	if report.Runs < 10 {
		t.Errorf("runs = %d, want the fault matrix too", report.Runs)
	}
	if left, _ := os.ReadDir(tmp); len(left) > 0 {
		t.Errorf("%d staging directories were left behind", len(left))
	}
}

func TestDeterminismComparesFileArtifacts(t *testing.T) {
	report := checkSuite(t, stagerSuite(stager{stamp: new(atomic.Int64)}))
	expectViolation(t, report, "determinism", "two runs of the same scenario produced different "+stagerFile)
	report = checkSuite(t, stagerSuite(stager{moveFile: new(atomic.Int64)}))
	expectViolation(t, report, "determinism", "only the first emitted")
	expectViolation(t, report, "determinism", "only the second emitted")
}

func TestTheKitComparesFileArtifacts(t *testing.T) {
	expectViolation(t, checkSuite(t, stagerSuite(stager{noFileGap: true})), "faults",
		"artifacts/policy.txt: file artifact left out without a gap for the whole artifact")
	report := checkSuite(t, stagerSuite(stager{placeholder: true}))
	expectViolation(t, report, "faults", "artifacts/policy.txt: file changed from 24 bytes with sha256 ")
	expectViolation(t, report, "faults", " to 19 bytes with sha256 ")
}

func TestTheKitFindsSecretsInStagedFiles(t *testing.T) {
	expectViolation(t, checkSuite(t, stagerSuite(stager{leakToken: true})), "secrets",
		"the value of FILES_TOKEN appears in staged file policy.txt")
	expectViolation(t, checkSuite(t, stagerSuite(stager{stageToken: true})), "secrets",
		"the value of FILES_TOKEN appears in staged file debug/request.log")
}

func TestTheKitListsOperationsItCouldNotMutate(t *testing.T) {
	run := func(ctx componentsdk.CollectorContext) error {
		client := componentsdk.NewHTTPClient(ctx, componentsdk.HTTPOptions{})
		req, err := http.NewRequestWithContext(componentsdk.WithOperation(ctx.Context(), componentsdk.Operation{Name: "plain.status.get"}), http.MethodGet, demoHost+"/status", nil)
		if err != nil {
			return err
		}
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer func() { _ = resp.Body.Close() }()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		return ctx.Emit([]componentsdk.CollectedArtifact{{Data: map[string]any{"status": string(body)}, Path: "artifacts/plain.json"}})
	}
	report, err := Check(Suite{
		Spec:       componentsdk.CollectorSpec{Name: "plain", Version: "0.0.1"},
		Run:        run,
		Scenarios:  []Scenario{{Name: "clean", Responses: []Response{{URL: demoHost + "/status", Body: "all systems normal", Header: http.Header{"Content-Type": []string{"text/plain"}}}}}},
		SkipChecks: []string{"faults", "credentials", "determinism", "levels"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(report.Unmutated, ",") != "plain.status.get" {
		t.Errorf("unmutated = %v, want the plain-text operation listed", report.Unmutated)
	}
}

func TestIgnoreSetMatchesPrefixesAndTheirChildren(t *testing.T) {
	set := newIgnoreSet(map[string][]string{
		"artifacts/a.json": {"/diagnostics", "/rows/0/note"},
		"artifacts/b.json": {""},
	})
	cases := []struct {
		path, pointer string
		want          bool
	}{
		{"artifacts/a.json", "/diagnostics", true},
		{"artifacts/a.json", "/diagnostics/0/message", true},
		{"artifacts/a.json", "/diagnosticsx", false},
		{"artifacts/a.json", "/rows/0/note", true},
		{"artifacts/a.json", "/rows/0", false},
		{"artifacts/a.json", "", false},
		{"artifacts/b.json", "/anything/at/all", true},
		{"artifacts/b.json", "", true},
		{"artifacts/c.json", "/diagnostics", false},
	}
	for _, tc := range cases {
		if got := set.has(tc.path, tc.pointer); got != tc.want {
			t.Errorf("has(%s, %q) = %v, want %v", tc.path, tc.pointer, got, tc.want)
		}
	}
}

func TestTheCredentialsCheckFindsASecretInARedirectedBody(t *testing.T) {
	signIn := func(hosts []string) func(componentsdk.CollectorContext) error {
		return func(ctx componentsdk.CollectorContext) error {
			client := componentsdk.NewHTTPClient(ctx, componentsdk.HTTPOptions{CredentialHosts: hosts})
			op := componentsdk.WithOperation(ctx.Context(), componentsdk.Operation{Name: "demo.token.create", Safe: true})
			req, err := http.NewRequestWithContext(op, http.MethodPost, demoHost+"/token", strings.NewReader("client_secret="+ctx.Secret("DEMO_CLIENT_SECRET")))
			if err != nil {
				return err
			}
			resp, err := client.Do(req)
			if err != nil {
				return err
			}
			defer func() { _ = resp.Body.Close() }()
			return ctx.Emit([]componentsdk.CollectedArtifact{{Data: map[string]any{"signed_in": resp.StatusCode == http.StatusOK}, Path: "artifacts/token.json"}})
		}
	}
	suite := func(hosts []string) Suite {
		return Suite{
			Spec:       componentsdk.CollectorSpec{Name: "token", Version: "0.0.1"},
			Run:        signIn(hosts),
			Secrets:    map[string]string{"DEMO_CLIENT_SECRET": "client-secret-0123456789"},
			Scenarios:  []Scenario{{Name: "clean", Responses: []Response{{Method: http.MethodPost, URL: demoHost + "/token", Body: `{"access_token":"x"}`}}}},
			SkipChecks: []string{"faults", "determinism", "levels", "sensitivity"},
		}
	}
	report, err := Check(suite(nil))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, v := range violationsOf(report, "credentials") {
		if strings.Contains(v.Message, "the body") {
			found = true
		}
	}
	if !found {
		t.Errorf("a client secret that followed a redirect in the form body went unreported; got %+v", report.Violations)
	}
	report, err = Check(suite([]string{"api.demo.test"}))
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range violationsOf(report, "credentials") {
		t.Errorf("with the host listed the SDK refuses the redirect, yet: %s", v.Message)
	}
}

func TestTheKitReportsCredentialsSentWithoutAHostList(t *testing.T) {
	report := checkDemo(t, demo{noHostList: true})
	found := false
	for _, v := range violationsOf(report, "credentials") {
		if strings.Contains(v.Message, "built without HTTPOptions.CredentialHosts") {
			found = true
		}
	}
	if !found {
		t.Errorf("credentials sent through a client with no host list went unreported; got %+v", report.Violations)
	}
	for _, v := range violationsOf(checkDemo(t, demo{}), "credentials") {
		t.Errorf("a client with a host list was reported: %s", v.Message)
	}
}

func TestSemanticsApplyByPosition(t *testing.T) {
	first := Semantic{Operation: "demo.users.list", Fault: "404", Meaning: "first page gone", Positions: []string{PositionFirst}}
	rest := Semantic{Operation: "demo.users.list", Fault: "404", Meaning: "later page gone", Positions: []string{PositionLast, PositionAll}}
	k := &kit{suite: Suite{Semantics: []Semantic{first, rest}}}
	for _, tc := range []struct {
		position, meaning string
		pin               bool
	}{
		{PositionFirst, "first page gone", true},
		{PositionLast, "later page gone", true},
		{PositionAll, "later page gone", true},
		{PositionMiddle, "first page gone", false},
	} {
		sem, pin := k.semantic("demo.users.list", "404", tc.position)
		if sem == nil || sem.Meaning != tc.meaning || pin != tc.pin {
			t.Errorf("at %s: semantic %+v, pin %v; want %q, pin %v", tc.position, sem, pin, tc.meaning, tc.pin)
		}
	}
	s := demoSuite(demo{})
	s.Semantics = []Semantic{first, {Operation: "demo.users.list", Fault: "404", Meaning: "overlaps", Positions: []string{PositionFirst}}}
	if _, err := Check(s); err == nil {
		t.Error("two semantics for one fault at the same position should be rejected")
	}
	s.Semantics = []Semantic{first, {Operation: "demo.users.list", Fault: "404", Meaning: "every position"}}
	if _, err := Check(s); err == nil {
		t.Error("a semantic without Positions overlaps every other one for the same fault and should be rejected")
	}
}

func TestRequestBodyMatchesFormFields(t *testing.T) {
	rp, err := NewReplay(Scenario{Name: "query", Responses: []Response{
		{Method: http.MethodPost, URL: "https://iam.amazonaws.com/", RequestBody: `{"Action":"ListMFADevices","UserName":"alice"}`, Body: `<alice/>`},
		{Method: http.MethodPost, URL: "https://iam.amazonaws.com/", RequestBody: `{"Action":"ListMFADevices","UserName":"bob"}`, Body: `<bob/>`},
	}})
	if err != nil {
		t.Fatal(err)
	}
	post := func(form string) string {
		req, err := http.NewRequest(http.MethodPost, "https://iam.amazonaws.com/", strings.NewReader(form))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
		resp, err := rp.RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		return string(body)
	}
	if got := post("Action=ListMFADevices&UserName=bob&Version=2010-05-08"); got != "<bob/>" {
		t.Errorf("bob's call got %q, want bob's answer", got)
	}
	if got := post("Action=ListMFADevices&UserName=alice&Version=2010-05-08"); got != "<alice/>" {
		t.Errorf("alice's call got %q, want alice's answer", got)
	}
	if got := post("Action=ListMFADevices&UserName=carol&Version=2010-05-08"); !strings.Contains(got, "no canned response") || len(rp.Unmatched()) != 1 {
		t.Errorf("carol's call got %q with unmatched %v, want no answer", got, rp.Unmatched())
	}
}
