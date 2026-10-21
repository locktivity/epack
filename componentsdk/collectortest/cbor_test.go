package collectortest

import (
	"bytes"
	"context"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/aws/smithy-go/encoding/cbor"
	"github.com/locktivity/epack/componentsdk"
)

const (
	realAlarmsToken = "real-alarms-token-Wq4nYb7Z"
	alarmsPath      = "artifacts/alarms.json"
	describeAlarms  = "/service/Monitoring/operation/DescribeAlarms"
)

var alarmsSpec = componentsdk.CollectorSpec{Name: "alarms", Version: "1.0.0"}

// alarms reads a tenant's alarms from an API that answers in CBOR, as AWS
// services on the Smithy RPC v2 CBOR protocol do.
type alarms struct {
	api        string
	ignoreBody bool // reads nothing from the answer, so changing it changes no value
}

func (a alarms) run(ctx componentsdk.CollectorContext) error {
	api, err := url.Parse(a.api)
	if err != nil {
		return componentsdk.CodeError(componentsdk.CodeConfigInvalid, err)
	}
	client := componentsdk.NewHTTPClient(ctx, componentsdk.HTTPOptions{CredentialHosts: []string{api.Hostname()}, CredentialHeaders: []string{"X-Alarms-Token"}})
	out, err := a.read(ctx, client)
	if err != nil {
		out = map[string]any{}
		rec := componentsdk.Records(ctx)
		for _, pointer := range []string{"/alarms", "/enabled", "/threshold", "/account", "/owner_account"} {
			rec.NotCollected(componentsdk.Location{Path: alarmsPath, Pointer: pointer}, err)
		}
	}
	return ctx.Emit([]componentsdk.CollectedArtifact{{Data: out, Path: alarmsPath}})
}

// read calls DescribeAlarms and reads how many alarms there are and how many
// have actions enabled, the first one's threshold and account, and the
// owner's account.
func (a alarms) read(ctx componentsdk.CollectorContext, client *http.Client) (map[string]any, error) {
	reqCtx := componentsdk.WithOperation(ctx.Context(), componentsdk.Operation{Name: "alarms.describe", Safe: true})
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, a.api+describeAlarms, bytes.NewReader(cbor.Encode(cbor.Map{"MaxRecords": cbor.Uint(100)})))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/cbor")
	req.Header.Set("X-Alarms-Token", ctx.Secret("ALARMS_TOKEN"))
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, componentsdk.CodeError(componentsdk.ClassifyResponse(resp), &demoAPIError{status: resp.StatusCode})
	}
	if a.ignoreBody {
		return map[string]any{}, nil
	}
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	invalid := componentsdk.CodeError(componentsdk.CodeInvalidResponse, errors.New("the alarms response is not as documented"))
	v, err := cbor.Decode(raw)
	page, _ := v.(cbor.Map)
	list, _ := page["MetricAlarms"].(cbor.List)
	owner, _ := page["Owner"].(cbor.Map)
	if err != nil || len(list) == 0 || owner == nil {
		return nil, invalid
	}
	first, _ := list[0].(cbor.Map)
	threshold, hasThreshold := first["Threshold"].(cbor.Float64)
	arn, _ := first["AlarmArn"].(cbor.String)
	account, hasAccount := owner["Account"].(cbor.Uint)
	arnParts := strings.Split(string(arn), ":")
	if !hasThreshold || !hasAccount || len(arnParts) < 5 {
		return nil, invalid
	}
	enabled := 0
	for _, item := range list {
		alarm, _ := item.(cbor.Map)
		if on, _ := alarm["ActionsEnabled"].(cbor.Bool); on {
			enabled++
		}
	}
	return map[string]any{
		"alarms": len(list), "enabled": enabled, "threshold": float64(threshold), "account": arnParts[4], "owner_account": uint64(account),
	}, nil
}

// tenantAlarms is the alarms API's answer for a tenant full of values a
// recording must not keep: its name, its account as text, as an integer, and
// as a map key, emails, the API token, a session token, and a signature.
func tenantAlarms() cbor.Map {
	signature := sha512.Sum512([]byte("alarm signature"))
	return cbor.Map{
		"MetricAlarms": cbor.List{
			cbor.Map{
				"AlarmName":             cbor.String("acme-sandbox-cpu-high"),
				"AlarmArn":              cbor.String("arn:aws:cloudwatch:us-east-1:210987654321:alarm:acme-sandbox-cpu-high"),
				"AlarmDescription":      cbor.String("Pages Alice.Ng@acme-sandbox.io; debug token " + realAlarmsToken),
				"AlarmActions":          cbor.List{cbor.String("arn:aws:sns:us-east-1:210987654321:acme-sandbox-pager")},
				"ActionsEnabled":        cbor.Bool(true),
				"Dimensions":            cbor.List{cbor.Map{"Name": cbor.String("InstanceId"), "Value": cbor.String("i-0abc123def4567890")}},
				"EvaluationPeriods":     cbor.Uint(3),
				"StateUpdatedTimestamp": &cbor.Tag{ID: 1, Value: cbor.Float64(1760000000.5)},
				"Threshold":             cbor.Float64(80.5),
			},
			cbor.Map{
				"AlarmArn":          cbor.String("arn:aws:cloudwatch:us-east-1:210987654321:alarm:root-sign-in"),
				"ActionsEnabled":    cbor.Bool(false),
				"EvaluationPeriods": cbor.Uint(1),
				"OKActions":         cbor.List{},
				"Threshold":         cbor.Float32(1),
				"Unit":              &cbor.Nil{},
			},
		},
		"Owner": cbor.Map{
			"Account":      cbor.Uint(210987654321),
			"ByAccount":    cbor.Map{"210987654321": cbor.String("acme-sandbox")},
			"Flags":        cbor.Slice{1, 2},
			"Note":         cbor.Slice("escalate to bob@acme-sandbox.io"),
			"SessionToken": cbor.String("opaque-session-0123456789"),
			"Signature":    cbor.Slice(signature[:]),
		},
	}
}

func alarmsTenant(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+describeAlarms, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Alarms-Token") != realAlarmsToken {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/cbor")
		w.Header().Set("Smithy-Protocol", "rpc-v2-cbor")
		_, _ = w.Write(cbor.Encode(tenantAlarms()))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func alarmsRules() ScrubRules {
	return ScrubRules{Identifiers: map[string]string{"acme-sandbox": "example-org", "210987654321": "111122223333"}}
}

func recordAlarms(t *testing.T, api, out string, rules ScrubRules) (RecordReport, error) {
	t.Helper()
	return Record(RecordOptions{
		Spec:    alarmsSpec,
		Run:     alarms{api: api}.run,
		Config:  map[string]any{"level": "audit"},
		Secrets: map[string]string{"ALARMS_TOKEN": realAlarmsToken},
		Out:     out,
		Scrub:   rules,
	})
}

func TestARecordedCBORBodyIsScrubbedAndReplaysByteForByte(t *testing.T) {
	srv := alarmsTenant(t)
	out := filepath.Join(t.TempDir(), "alarms.json")
	rec, err := recordAlarms(t, srv.URL, out, alarmsRules())
	if err != nil {
		t.Fatal(err)
	}
	if rec.ExitCode != 0 || rec.Responses != 1 {
		t.Fatalf("report = %+v, want a clean run with 1 response", rec)
	}
	for kind, want := range map[string]int{"identifier": 2, "secret": 1, "email": 2, "token": 2} {
		if rec.Replaced[kind] != want {
			t.Errorf("replaced %d values by %s, want %d (all: %v)", rec.Replaced[kind], kind, want, rec.Replaced)
		}
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"body_encoding": "base64"`) {
		t.Errorf("the recording does not mark its body as base64:\n%s", raw)
	}

	loaded, err := LoadScenario(out)
	if err != nil {
		t.Fatal(err)
	}
	want := tenantAlarms()
	metric := want["MetricAlarms"].(cbor.List)
	cpu, root, owner := metric[0].(cbor.Map), metric[1].(cbor.Map), want["Owner"].(cbor.Map)
	cpu["AlarmName"] = cbor.String("example-org-cpu-high")
	cpu["AlarmArn"] = cbor.String("arn:aws:cloudwatch:us-east-1:111122223333:alarm:example-org-cpu-high")
	cpu["AlarmDescription"] = cbor.String("Pages user1@example.com; debug token REDACTED")
	cpu["AlarmActions"] = cbor.List{cbor.String("arn:aws:sns:us-east-1:111122223333:example-org-pager")}
	root["AlarmArn"] = cbor.String("arn:aws:cloudwatch:us-east-1:111122223333:alarm:root-sign-in")
	owner["Account"] = cbor.Uint(111122223333)
	owner["ByAccount"] = cbor.Map{"111122223333": cbor.String("example-org")}
	owner["Note"] = cbor.Slice("escalate to user2@example.com")
	owner["SessionToken"] = cbor.String(redacted)
	owner["Signature"] = cbor.Slice("scrubbed-token-1")
	body := []byte(loaded.Responses[0].Body)
	if !bytes.Equal(body, encodeCBOR(want)) {
		got, err := cbor.Decode(body)
		t.Errorf("the recorded body decodes to\n%v (%v)\nwant\n%v", got, err, want)
	}

	replay, err := NewReplay(loaded)
	if err != nil {
		t.Fatal(err)
	}
	reqCtx := componentsdk.WithOperation(context.Background(), componentsdk.Operation{Name: "alarms.describe"})
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, srv.URL+describeAlarms, bytes.NewReader(cbor.Encode(cbor.Map{})))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := replay.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	served, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(served, body) || resp.Header.Get("Content-Type") != "application/cbor" {
		t.Errorf("the replay served %d bytes as %q, want the recorded %d bytes as application/cbor", len(served), resp.Header.Get("Content-Type"), len(body))
	}

	srv.Close()
	loaded.Expect = map[string]map[string]any{alarmsPath: {"/alarms": 2, "/enabled": 1, "/threshold": 80.5, "/account": "111122223333", "/owner_account": 111122223333}}
	report := checkSuite(t, Suite{
		Spec:       alarmsSpec,
		Run:        alarms{api: srv.URL}.run,
		Secrets:    map[string]string{"ALARMS_TOKEN": "fake-alarms-token-0123"},
		Scenarios:  []Scenario{loaded},
		Operations: []string{"alarms.describe"},
	})
	for _, v := range report.Violations {
		t.Errorf("%s/%s: %s", v.Check, v.Case, v.Message)
	}
	if report.Runs < 15 {
		t.Errorf("runs = %d, want the fault matrix on the recording too", report.Runs)
	}
}

func TestRecordWritesNoCBORBodyThatStillNamesTheTenant(t *testing.T) {
	out := filepath.Join(t.TempDir(), "alarms.json")
	rules := alarmsRules()
	// A pattern runs after the identifiers, so this one puts the name back.
	rules.Patterns = []ScrubPattern{{Pattern: regexp.MustCompile(`example-org`), Replace: "ACME-Sandbox"}}
	_, err := recordAlarms(t, alarmsTenant(t).URL, out, rules)
	if err == nil || !strings.Contains(err.Error(), "responses[0].body: the tenant identifier ScrubRules.Identifiers replaces with example-org") {
		t.Errorf("err = %v, want the identifier in the CBOR body flagged by its fake", err)
	}
	if err != nil && strings.Contains(strings.ToLower(err.Error()), "acme-sandbox") {
		t.Error("the error repeats the identifier it flags")
	}
	if _, statErr := os.Stat(out); !errors.Is(statErr, os.ErrNotExist) {
		t.Errorf("the recording was written anyway: %v", statErr)
	}
}

func TestRecordRefusesABodyItCannotScrub(t *testing.T) {
	for name, c := range map[string]struct {
		contentType string
		body        []byte
		want        string
	}{
		"CBOR that does not decode": {"application/cbor", []byte{0xa1, 0x61}, "it does not decode, so it cannot be scrubbed"},
		"binary that is not CBOR":   {"image/png", []byte("\x89PNG\r\n\x1a\n"), "is neither text nor CBOR"},
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", c.contentType)
			_, _ = w.Write(c.body)
		}))
		out := filepath.Join(t.TempDir(), "alarms.json")
		_, err := recordAlarms(t, srv.URL, out, alarmsRules())
		srv.Close()
		if err == nil || !strings.Contains(err.Error(), "response to POST "+srv.URL+describeAlarms+" (operation alarms.describe)") || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want the response named and %q", name, err, c.want)
		}
		if _, statErr := os.Stat(out); !errors.Is(statErr, os.ErrNotExist) {
			t.Errorf("%s: the recording was written anyway: %v", name, statErr)
		}
	}
}

func TestTheScrubCheckReadsCBORBodiesDecoded(t *testing.T) {
	secrets := []canary{{key: "ALARMS_TOKEN", value: realAlarmsToken}}
	ids := map[string]string{"acme-sandbox": "example-org", "210987654321": "111122223333"}
	signature := sha512.Sum512([]byte("x"))
	// A text string sent in chunks, "acme-" and "sandbox", whose raw bytes
	// never hold the name whole.
	chunked := []byte{0x7f, 0x65, 'a', 'c', 'm', 'e', '-', 0x67, 's', 'a', 'n', 'd', 'b', 'o', 'x', 0xff}
	repeatedKey := append(append([]byte{0xa2, 0x61, 'a'}, cbor.Encode(cbor.String("debug "+realAlarmsToken))...), 0x61, 'a', 0x61, 'x')
	identifier := "the tenant identifier ScrubRules.Identifiers replaces with "
	cases := map[string]struct {
		body []byte
		want string
	}{
		"secret in a nested map":      {encodeCBOR(cbor.Map{"Outer": cbor.Map{"Inner": cbor.List{cbor.String("debug " + realAlarmsToken)}}}), "the value of secret ALARMS_TOKEN"},
		"identifier as a map key":     {encodeCBOR(cbor.Map{"ByAccount": cbor.Map{"210987654321": cbor.Bool(true)}}), identifier + "111122223333"},
		"identifier as an integer":    {encodeCBOR(cbor.Map{"Account": cbor.Uint(210987654321)}), identifier + "111122223333"},
		"identifier in chunks":        {chunked, identifier + "example-org"},
		"identifier in bytes":         {encodeCBOR(cbor.Map{"Note": cbor.Slice("ask Alice@ACME-Sandbox.io")}), identifier + "example-org"},
		"token in a list":             {encodeCBOR(cbor.List{cbor.String("ghp_" + strings.Repeat("aB3", 12))}), "a GitHub token"},
		"binary token":                {encodeCBOR(cbor.Map{"Signature": cbor.Slice(signature[:])}), "a long token"},
		"secret under a repeated key": {repeatedKey, "the value of secret ALARMS_TOKEN"},
		"secret after the item":       {append(cbor.Encode(cbor.String("ok")), realAlarmsToken...), "the value of secret ALARMS_TOKEN"},
		"no CBOR":                     {[]byte{0xa1, 0x61}, "a CBOR body that does not decode, so the scrub check cannot read it"},
	}
	for name, c := range cases {
		sc := Scenario{Responses: []Response{{URL: "https://a.example/", Header: http.Header{"Content-Type": {"application/cbor"}}, Body: string(c.body)}}}
		leaks := scanScenario(sc, secrets, ids)
		if len(leaks) != 1 || leaks[0].String() != "responses[0].body: "+c.want {
			t.Errorf("%s: leaks = %v, want %q", name, leaks, c.want)
		}
	}

	cert, _, _ := publicMaterialSamples(t)
	der, err := base64.StdEncoding.DecodeString(cert)
	if err != nil {
		t.Fatal(err)
	}
	clean := encodeCBOR(cbor.Map{
		"Account": cbor.Uint(111122223333), "Cert": cbor.Slice(der), "Flags": cbor.Slice{1, 2}, "Name": cbor.String("example-org"),
		"SessionToken": cbor.String(redacted), "Signature": cbor.Slice("scrubbed-token-1"), "Updated": &cbor.Tag{ID: 1, Value: cbor.Float64(1760000000)},
	})
	sc := Scenario{Responses: []Response{{URL: "https://a.example/", Header: http.Header{"Content-Type": {"application/cbor; charset=binary"}}, Body: string(clean)}}}
	if leaks := scanScenario(sc, secrets, ids); len(leaks) > 0 {
		t.Errorf("a scrubbed CBOR body was flagged: %v", leaks)
	}
}

func TestScrubbingCBORFailsWhereTheBodyWouldLoseItsShape(t *testing.T) {
	s := newScrubber(nil, ScrubRules{Literals: map[string]string{"acme": "example-org", "424242": "unknown"}})
	for name, c := range map[string]struct {
		body []byte
		want string
	}{
		"keys that scrub alike": {encodeCBOR(cbor.Map{"Acme": cbor.Uint(1), "ACME": cbor.Uint(2)}), "scrubbing gave two keys of one map the same name"},
		"a number made text":    {encodeCBOR(cbor.Map{"n": cbor.Uint(424242)}), "scrubbing turned a number into text"},
		"a truncated body":      {[]byte{0xa1, 0x61}, "it does not decode"},
	} {
		if _, err := s.cborBody(c.body); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want %q", name, err, c.want)
		}
	}
	if out, err := s.cborBody(nil); err != nil || len(out) != 0 {
		t.Errorf("an empty body scrubbed to %v (%v), want it left empty", out, err)
	}
}

func TestMutateCBOR(t *testing.T) {
	in := encodeCBOR(cbor.Map{
		"a": cbor.Bool(true), "b": cbor.List{cbor.Uint(1), cbor.Uint(2)}, "c": cbor.Map{"d": cbor.Bool(false)},
		"e": cbor.Uint(3), "f": cbor.Float64(1.5), "g": cbor.Float32(-2), "h": cbor.NegInt(1), "i": cbor.NegInt(5),
		"t": &cbor.Tag{ID: 1, Value: cbor.Float64(1760000000)}, "s": cbor.String("keep"), "x": cbor.Slice{1, 2},
	})
	want := encodeCBOR(cbor.Map{
		"a": cbor.Bool(false), "b": cbor.List{}, "c": cbor.Map{"d": cbor.Bool(true)},
		"e": cbor.Uint(4), "f": cbor.Float64(2.5), "g": cbor.Float32(-1), "h": cbor.Uint(0), "i": cbor.NegInt(4),
		"t": &cbor.Tag{ID: 1, Value: cbor.Float64(1760000001)}, "s": cbor.String("keep"), "x": cbor.Slice{1, 2},
	})
	if got, ok := mutateCBOR(string(in)); !ok || got != string(want) {
		decoded, err := cbor.Decode([]byte(got))
		t.Errorf("mutateCBOR = %v (%v), %v", decoded, err, ok)
	}
	for name, body := range map[string][]byte{
		"only strings": encodeCBOR(cbor.Map{"s": cbor.String("only strings"), "x": cbor.Slice{1}}),
		"not CBOR":     {0xa1, 0x61},
	} {
		if _, ok := mutateCBOR(string(body)); ok {
			t.Errorf("%s: a body with nothing to change should report no change", name)
		}
	}
}

func TestTheSensitivityCheckChangesCBORResponses(t *testing.T) {
	api := "https://alarms.test"
	suite := func(a alarms) Suite {
		return Suite{
			Spec:    alarmsSpec,
			Run:     a.run,
			Secrets: map[string]string{"ALARMS_TOKEN": "fake-alarms-token-0123"},
			Scenarios: []Scenario{{Name: "clean", Responses: []Response{{
				Operation: "alarms.describe", Method: http.MethodPost, URL: api + describeAlarms,
				Header: http.Header{"Content-Type": {"application/cbor"}}, Body: string(encodeCBOR(tenantAlarms())),
			}}}},
			Operations: []string{"alarms.describe"},
		}
	}
	report := checkSuite(t, suite(alarms{api: api}))
	if len(report.Unmutated) > 0 || len(report.Violations) > 0 {
		t.Errorf("unmutated = %v, violations = %+v, want the CBOR answer changed and the change seen", report.Unmutated, report.Violations)
	}
	got := violationsOf(checkSuite(t, suite(alarms{api: api, ignoreBody: true})), "sensitivity")
	if len(got) != 1 || got[0].Case != "alarms.describe" {
		t.Errorf("sensitivity violations = %+v, want the collector that ignores its CBOR answer flagged", got)
	}
}

func TestEncodeCBORSortsKeysSoTheSameValuesEncodeAlike(t *testing.T) {
	if got, want := encodeCBOR(cbor.Map{"b": cbor.Uint(1), "a": cbor.Uint(2)}), []byte{0xa2, 0x61, 'a', 0x02, 0x61, 'b', 0x01}; !bytes.Equal(got, want) {
		t.Errorf("encoded % x, want % x", got, want)
	}
	for _, n := range []uint64{0, 23, 24, math.MaxUint8, math.MaxUint8 + 1, math.MaxUint16, math.MaxUint16 + 1, math.MaxUint32, math.MaxUint32 + 1, math.MaxUint64} {
		if got, want := cborHead(0, n), cbor.Encode(cbor.Uint(n)); !bytes.Equal(got, want) {
			t.Errorf("head of %d is % x, want % x", n, got, want)
		}
	}
	long := make(cbor.List, 300)
	for i := range long {
		long[i] = cbor.Uint(i)
	}
	tree := cbor.Map{
		"list": long, "text": cbor.String(strings.Repeat("x", 70000)), "bytes": cbor.Slice{0, 0xff}, "neg": cbor.NegInt(5),
		"tag":  &cbor.Tag{ID: 1000, Value: cbor.Map{"z": cbor.Float32(1.5), "y": cbor.Float64(-2.25)}},
		"bool": cbor.Bool(false), "nil": &cbor.Nil{}, "undefined": &cbor.Undefined{},
	}
	encoded := encodeCBOR(tree)
	decoded, err := cbor.Decode(encoded)
	if err != nil || !reflect.DeepEqual(decoded, tree) {
		t.Fatalf("the encoding decodes to another tree (%v)", err)
	}
	if !bytes.Equal(encodeCBOR(decoded), encoded) {
		t.Error("the same tree encoded two ways")
	}
}

func TestRecordingsWriteBodiesThatAreNotUTF8AsBase64(t *testing.T) {
	body := string(encodeCBOR(cbor.Map{"a": cbor.Slice{0x00, 0xff}, "b": cbor.String("café")}))
	r := Response{URL: "https://a.example/x", Header: http.Header{"Content-Type": {"application/cbor"}}, Body: body}
	raw, err := marshalJSON(r)
	if err != nil {
		t.Fatal(err)
	}
	if want := `"body_encoding":"base64","body":"` + base64.StdEncoding.EncodeToString([]byte(body)) + `"`; !strings.Contains(string(raw), want) {
		t.Errorf("a CBOR body is written as %s, want it in base64, marked", raw)
	}
	var back Response
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if back.Body != body {
		t.Errorf("the body came back as % x, want % x", back.Body, body)
	}
	if raw, _ := marshalJSON(Response{URL: "https://a.example/x", Body: "ok"}); strings.Contains(string(raw), "body_encoding") {
		t.Errorf("a text body is written as %s, want it without an encoding", raw)
	}
}
