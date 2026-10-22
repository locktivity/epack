package collectortest

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/locktivity/epack/componentsdk"
)

const (
	realRosterToken   = "real-roster-token-Hq3vXc9P"
	rosterPath        = "artifacts/roster.json"
	rosterContentType = "application/x-roster"
	getOrg            = "/roster.Roster/GetOrg"
	listMembers       = "/roster.Roster/ListMembers"
)

var rosterSpec = componentsdk.CollectorSpec{Name: "roster", Version: "1.0.0"}

// rosterField is a field of a roster API message: its number on the wire,
// its name in JSON, and its kind, which is "string", "uint", "bool", or a
// message type, and repeated after "[]".
type rosterField struct {
	num  uint64
	name string
	kind string
}

// rosterTypes are the roster API's message types. On the wire, as in
// protobuf, a field is a varint key, its number over its wire type, then a
// varint, or a varint length and that many bytes. Reading a message needs
// its type, and a string that changes length changes the lengths around
// it.
var rosterTypes = map[string][]rosterField{
	"Empty":   nil,
	"Team":    {{1, "team", "string"}},
	"Org":     {{1, "name", "string"}, {2, "seats", "uint"}, {3, "sso", "bool"}, {4, "contact", "string"}, {5, "account", "uint"}, {6, "apiKey", "string"}, {7, "note", "string"}},
	"Members": {{1, "members", "[]Member"}},
	"Member":  {{1, "email", "string"}, {2, "admin", "bool"}, {3, "lastSeen", "uint"}, {4, "id", "uint"}},
}

// rosterCalls gives each operation's request and response types.
var rosterCalls = map[string][2]string{
	"roster.org.get":      {"Empty", "Org"},
	"roster.members.list": {"Team", "Members"},
}

// encodeWire encodes m, a message of type typ, field by field in number
// order.
func encodeWire(typ string, m map[string]any) ([]byte, error) {
	var out []byte
	for _, f := range rosterTypes[typ] {
		v, ok := m[f.name]
		if !ok {
			continue
		}
		kind, repeated := strings.CutPrefix(f.kind, "[]")
		values := []any{v}
		if repeated {
			if values, ok = v.([]any); !ok {
				return nil, fmt.Errorf("%s.%s: not a list", typ, f.name)
			}
		}
		for _, v := range values {
			var err error
			if out, err = appendWireField(out, f.num, kind, v); err != nil {
				return nil, fmt.Errorf("%s.%s: %w", typ, f.name, err)
			}
		}
	}
	return out, nil
}

func appendWireField(out []byte, num uint64, kind string, v any) ([]byte, error) {
	switch kind {
	case "string":
		s, ok := v.(string)
		if !ok {
			return nil, errors.New("not a string")
		}
		return appendWireBytes(out, num, []byte(s)), nil
	case "uint":
		var n uint64
		var err error
		switch x := v.(type) {
		case uint64:
			n = x
		case json.Number:
			n, err = strconv.ParseUint(string(x), 10, 64)
		default:
			err = errors.New("not an unsigned integer")
		}
		if err != nil {
			return nil, err
		}
		return binary.AppendUvarint(binary.AppendUvarint(out, num<<3), n), nil
	case "bool":
		b, ok := v.(bool)
		if !ok {
			return nil, errors.New("not a bool")
		}
		n := uint64(0)
		if b {
			n = 1
		}
		return binary.AppendUvarint(binary.AppendUvarint(out, num<<3), n), nil
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, errors.New("not an object")
	}
	message, err := encodeWire(kind, m)
	if err != nil {
		return nil, err
	}
	return appendWireBytes(out, num, message), nil
}

func appendWireBytes(out []byte, num uint64, b []byte) []byte {
	out = binary.AppendUvarint(out, num<<3|2)
	out = binary.AppendUvarint(out, uint64(len(b)))
	return append(out, b...)
}

// readWire decodes a message of type typ.
func readWire(typ string, b []byte) (map[string]any, error) {
	out := map[string]any{}
	for len(b) > 0 {
		key, n := binary.Uvarint(b)
		if n <= 0 {
			return nil, fmt.Errorf("%s: a field key is cut short", typ)
		}
		b = b[n:]
		var f *rosterField
		for i := range rosterTypes[typ] {
			if rosterTypes[typ][i].num == key>>3 {
				f = &rosterTypes[typ][i]
			}
		}
		if f == nil {
			return nil, fmt.Errorf("%s has no field %d", typ, key>>3)
		}
		kind, repeated := strings.CutPrefix(f.kind, "[]")
		var v any
		switch key & 7 {
		case 0:
			x, n := binary.Uvarint(b)
			if n <= 0 {
				return nil, fmt.Errorf("%s.%s is cut short", typ, f.name)
			}
			b, v = b[n:], x
			if kind == "bool" {
				v = x != 0
			}
		case 2:
			size, n := binary.Uvarint(b)
			if n <= 0 || size > uint64(len(b)-n) {
				return nil, fmt.Errorf("%s.%s is cut short", typ, f.name)
			}
			raw := b[n : n+int(size)]
			b = b[n+int(size):]
			v = string(raw)
			if kind != "string" {
				var err error
				if v, err = readWire(kind, raw); err != nil {
					return nil, err
				}
			}
		default:
			return nil, fmt.Errorf("%s.%s has wire type %d", typ, f.name, key&7)
		}
		if repeated {
			list, _ := out[f.name].([]any)
			v = append(list, v)
		}
		out[f.name] = v
	}
	return out, nil
}

// rosterFrame frames a message as gRPC does: a flag byte, 0 for
// uncompressed, then the message's length and the message.
func rosterFrame(message []byte) []byte {
	return append(binary.BigEndian.AppendUint32([]byte{0}, uint32(len(message))), message...)
}

func rosterUnframe(body []byte) ([]byte, error) {
	if len(body) < 5 || body[0] != 0 || uint64(binary.BigEndian.Uint32(body[1:5])) != uint64(len(body)-5) {
		return nil, errors.New("the body is not one framed message")
	}
	return body[5:], nil
}

// rosterBody frames m, a message of type typ, as the roster API sends it.
func rosterBody(typ string, m map[string]any) []byte {
	message, err := encodeWire(typ, m)
	if err != nil {
		panic(err)
	}
	return rosterFrame(message)
}

// rosterCodec reads each call's messages as the types its operation names,
// as a gRPC collector's codec reads protobuf with its generated types. It
// leaves a body of any other Content-Type to the kit, and knows every
// operation but unknown.
type rosterCodec struct{ unknown string }

func (c rosterCodec) DecodeRequest(op string, header http.Header, body []byte) ([]byte, error) {
	return c.decode(op, 0, header, body)
}

func (c rosterCodec) DecodeResponse(op string, header http.Header, body []byte) ([]byte, error) {
	return c.decode(op, 1, header, body)
}

func (c rosterCodec) EncodeResponse(op string, _ http.Header, raw []byte) ([]byte, error) {
	call, ok := rosterCalls[op]
	if !ok || op == c.unknown {
		return nil, fmt.Errorf("no call %s", op)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil {
		return nil, err
	}
	message, err := encodeWire(call[1], m)
	if err != nil {
		return nil, err
	}
	return rosterFrame(message), nil
}

func (c rosterCodec) decode(op string, side int, header http.Header, body []byte) ([]byte, error) {
	if header.Get("Content-Type") != rosterContentType {
		return nil, nil
	}
	call, ok := rosterCalls[op]
	if !ok || op == c.unknown {
		return nil, fmt.Errorf("no call %s", op)
	}
	message, err := rosterUnframe(body)
	if err != nil {
		return nil, err
	}
	m, err := readWire(call[side], message)
	if err != nil {
		return nil, err
	}
	return json.Marshal(m)
}

// roster reads a tenant's organization and its teams' members from an API
// whose bodies only a codec can read, as a gRPC API's are.
type roster struct {
	api        string
	ignoreBody bool // reads nothing from the answers, so changing them changes no value
	reversed   bool // reads the teams in the other order
}

func (r roster) run(ctx componentsdk.CollectorContext) error {
	api, err := url.Parse(r.api)
	if err != nil {
		return componentsdk.CodeError(componentsdk.CodeConfigInvalid, err)
	}
	client := componentsdk.NewHTTPClient(ctx, componentsdk.HTTPOptions{CredentialHosts: []string{api.Hostname()}, CredentialHeaders: []string{"X-Roster-Token"}})
	org, err := r.call(ctx, client, "roster.org.get", getOrg, map[string]any{})
	if err != nil {
		return fmt.Errorf("signing in: %w", err)
	}
	out := map[string]any{"org": org["name"], "seats": org["seats"], "sso": org["sso"], "account": org["account"]}
	rec := componentsdk.Records(ctx)
	teams := []string{"dev", "ops"}
	if r.reversed {
		teams = []string{"ops", "dev"}
	}
	members, admins, adminsRead := map[string]any{}, 0, true
	for _, team := range teams {
		answer, err := r.call(ctx, client, "roster.members.list", listMembers, map[string]any{"team": team})
		if err != nil {
			rec.NotCollected(componentsdk.Location{Path: rosterPath, Pointer: "/members/" + team}, err)
			rec.NotCollected(componentsdk.Location{Path: rosterPath, Pointer: "/admins"}, err)
			adminsRead = false
			continue
		}
		list, _ := answer["members"].([]any)
		members[team] = len(list)
		for _, item := range list {
			if member, _ := item.(map[string]any); member["admin"] == true {
				admins++
			}
		}
	}
	out["members"] = members
	if adminsRead {
		out["admins"] = admins
	}
	return ctx.Emit([]componentsdk.CollectedArtifact{{Data: out, Path: rosterPath}})
}

// call posts message to path and reads the answer, each as the type op
// names.
func (r roster) call(ctx componentsdk.CollectorContext, client *http.Client, op, path string, message map[string]any) (map[string]any, error) {
	payload, err := encodeWire(rosterCalls[op][0], message)
	if err != nil {
		return nil, err
	}
	reqCtx := componentsdk.WithOperation(ctx.Context(), componentsdk.Operation{Name: op, Safe: true})
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, r.api+path, bytes.NewReader(rosterFrame(payload)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", rosterContentType)
	req.Header.Set("X-Roster-Token", ctx.Secret("ROSTER_TOKEN"))
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, componentsdk.CodeError(componentsdk.ClassifyResponse(resp), &demoAPIError{status: resp.StatusCode})
	}
	if r.ignoreBody {
		return map[string]any{}, nil
	}
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	answer, err := rosterUnframe(raw)
	var m map[string]any
	if err == nil {
		m, err = readWire(rosterCalls[op][1], answer)
	}
	if err != nil {
		return nil, componentsdk.CodeError(componentsdk.CodeInvalidResponse, fmt.Errorf("the %s answer is not as documented: %w", op, err))
	}
	return m, nil
}

// tenantOrg is the roster API's organization for a tenant full of values a
// recording must not keep: its name, its account, an email, an API key, and
// the token the collector signs in with.
func tenantOrg() map[string]any {
	return map[string]any{
		"name": "acme-sandbox", "seats": uint64(25), "sso": true, "contact": "Alice.Ng@acme-sandbox.io",
		"account": uint64(210987654321), "apiKey": "roster-key-0123456789", "note": "debug token " + realRosterToken,
	}
}

// tenantTeams is each team's members. The ops team's hold nothing to
// scrub.
func tenantTeams() map[string]map[string]any {
	return map[string]map[string]any{
		"dev": {"members": []any{
			map[string]any{"email": "dana@acme-sandbox.io", "admin": true, "lastSeen": uint64(1760000000)},
			map[string]any{"email": "eli@acme-sandbox.io", "admin": false},
		}},
		"ops": {"members": []any{map[string]any{"id": uint64(7), "admin": false, "lastSeen": uint64(1760000500)}}},
	}
}

// scrubbedOrg and scrubbedTeams are what recording tenantOrg and
// tenantTeams leaves.
func scrubbedOrg() map[string]any {
	org := tenantOrg()
	org["name"], org["account"], org["contact"] = "example-org", uint64(111122223333), "user1@example.com"
	org["apiKey"], org["note"] = redacted, "debug token "+redacted
	return org
}

func scrubbedTeams() map[string]map[string]any {
	teams := tenantTeams()
	teams["dev"] = map[string]any{"members": []any{
		map[string]any{"email": "user2@example.com", "admin": true, "lastSeen": uint64(1760000000)},
		map[string]any{"email": "user3@example.com", "admin": false},
	}}
	return teams
}

// rosterTenant serves the roster API, answering the organization read with
// org.
func rosterTenant(t *testing.T, org []byte) *httptest.Server {
	t.Helper()
	signedIn := func(w http.ResponseWriter, r *http.Request) bool {
		if r.Header.Get("X-Roster-Token") == realRosterToken {
			return true
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"unauthorized"}`))
		return false
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+getOrg, func(w http.ResponseWriter, r *http.Request) {
		if signedIn(w, r) {
			w.Header().Set("Content-Type", rosterContentType)
			_, _ = w.Write(org)
		}
	})
	mux.HandleFunc("POST "+listMembers, func(w http.ResponseWriter, r *http.Request) {
		if !signedIn(w, r) {
			return
		}
		raw, _ := io.ReadAll(r.Body)
		payload, err := rosterUnframe(raw)
		var req map[string]any
		if err == nil {
			req, err = readWire("Team", payload)
		}
		team, _ := req["team"].(string)
		members, ok := tenantTeams()[team]
		if err != nil || !ok {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", rosterContentType)
		_, _ = w.Write(rosterBody("Members", members))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func rosterRules() ScrubRules {
	return ScrubRules{Identifiers: map[string]string{"acme-sandbox": "example-org", "210987654321": "111122223333"}}
}

func recordRoster(api, out, token string, rules ScrubRules, codec BodyCodec) (RecordReport, error) {
	return Record(RecordOptions{
		Spec:    rosterSpec,
		Run:     roster{api: api}.run,
		Config:  map[string]any{"level": "audit"},
		Secrets: map[string]string{"ROSTER_TOKEN": token},
		Out:     out,
		Scrub:   rules,
		Codec:   codec,
	})
}

func rosterSuite(r roster, codec BodyCodec, scenarios ...Scenario) Suite {
	return Suite{
		Spec:       rosterSpec,
		Run:        r.run,
		Secrets:    map[string]string{"ROSTER_TOKEN": "fake-roster-token-0123"},
		Scenarios:  scenarios,
		Required:   []string{"roster.org.get"},
		Operations: []string{"roster.org.get", "roster.members.list"},
		Codec:      codec,
	}
}

func TestARecordedCodecBodyIsScrubbedAndReplaysByteForByte(t *testing.T) {
	srv := rosterTenant(t, rosterBody("Org", tenantOrg()))
	out := filepath.Join(t.TempDir(), "roster.json")
	rec, err := recordRoster(srv.URL, out, realRosterToken, rosterRules(), rosterCodec{})
	if err != nil {
		t.Fatal(err)
	}
	if rec.ExitCode != 0 || rec.Responses != 3 {
		t.Fatalf("report = %+v, want a clean run with 3 responses", rec)
	}
	for kind, want := range map[string]int{"identifier": 2, "secret": 1, "email": 3, "token": 1} {
		if rec.Replaced[kind] != want {
			t.Errorf("replaced %d values by %s, want %d (all: %v)", rec.Replaced[kind], kind, want, rec.Replaced)
		}
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"body_encoding": "codec"`, `"name": "example-org"`, `"apiKey": "REDACTED"`} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("the recording does not hold %s:\n%s", want, raw)
		}
	}

	loaded, err := LoadScenario(out)
	if err != nil {
		t.Fatal(err)
	}
	for i, want := range []string{`{}`, `{"team":"dev"}`, `{"team":"ops"}`} {
		if r := loaded.Responses[i]; !r.decoded || r.RequestBody != want {
			t.Errorf("response %d is decoded %v with request body %s, want a codec body that matches %s", i, r.decoded, r.RequestBody, want)
		}
	}
	replay, err := newReplay(loaded, rosterCodec{})
	if err != nil {
		t.Fatal(err)
	}
	serve := func(op, path string, message map[string]any) []byte {
		t.Helper()
		reqCtx := componentsdk.WithOperation(context.Background(), componentsdk.Operation{Name: op})
		req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, srv.URL+path, bytes.NewReader(rosterBody(rosterCalls[op][0], message)))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", rosterContentType)
		resp, err := replay.RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != rosterContentType {
			t.Errorf("%s: the replay answered %d as %q", op, resp.StatusCode, resp.Header.Get("Content-Type"))
		}
		return body
	}
	// The ops team's answer held nothing to scrub, so it replays as the
	// tenant sent it. The others are encoded from their scrubbed JSON, with
	// the lengths their new values need.
	if got, want := serve("roster.members.list", listMembers, map[string]any{"team": "ops"}), rosterBody("Members", tenantTeams()["ops"]); !bytes.Equal(got, want) {
		t.Errorf("the ops team replayed as % x, want the tenant's % x", got, want)
	}
	if got, want := serve("roster.members.list", listMembers, map[string]any{"team": "dev"}), rosterBody("Members", scrubbedTeams()["dev"]); !bytes.Equal(got, want) {
		t.Errorf("the dev team replayed as % x, want % x", got, want)
	}
	if got, want := serve("roster.org.get", getOrg, map[string]any{}), rosterBody("Org", scrubbedOrg()); !bytes.Equal(got, want) {
		t.Errorf("the organization replayed as % x, want % x", got, want)
	}

	srv.Close()
	// Reading the teams in the other order still gets each its own answer,
	// since the replay matches the JSON the codec decodes a request to.
	loaded.Expect = map[string]map[string]any{rosterPath: {
		"/org": "example-org", "/seats": 25, "/sso": true, "/account": 111122223333, "/members": map[string]any{"dev": 2, "ops": 1}, "/admins": 1,
	}}
	report := checkSuite(t, rosterSuite(roster{api: srv.URL, reversed: true}, rosterCodec{}, loaded))
	for _, v := range report.Violations {
		t.Errorf("%s/%s: %s", v.Check, v.Case, v.Message)
	}
	if len(report.Unmutated) > 0 {
		t.Errorf("unmutated = %v, want the sensitivity check to change the recorded codec bodies", report.Unmutated)
	}
	if report.Runs < 20 {
		t.Errorf("runs = %d, want the fault matrix on the recording too", report.Runs)
	}
}

func TestRecordWritesNoCodecBodyThatStillNamesTheTenant(t *testing.T) {
	out := filepath.Join(t.TempDir(), "roster.json")
	rules := rosterRules()
	// A pattern runs after the identifiers, so this one puts the name back.
	rules.Patterns = []ScrubPattern{{Pattern: regexp.MustCompile(`example-org`), Replace: "ACME-Sandbox"}}
	_, err := recordRoster(rosterTenant(t, rosterBody("Org", tenantOrg())).URL, out, realRosterToken, rules, rosterCodec{})
	if err == nil || !strings.Contains(err.Error(), "responses[0].body: the tenant identifier ScrubRules.Identifiers replaces with example-org") {
		t.Errorf("err = %v, want the identifier in the codec's JSON flagged by its fake", err)
	}
	if err != nil && strings.Contains(strings.ToLower(err.Error()), "acme-sandbox") {
		t.Error("the error repeats the identifier it flags")
	}
	if _, statErr := os.Stat(out); !errors.Is(statErr, os.ErrNotExist) {
		t.Errorf("the recording was written anyway: %v", statErr)
	}
}

func TestRecordRefusesABodyTheCodecCannotRead(t *testing.T) {
	org := rosterBody("Org", tenantOrg())
	call := func(path, op string) string { return "POST %s" + path + " (operation " + op + ")" }
	for name, c := range map[string]struct {
		org   []byte
		codec rosterCodec
		rules ScrubRules
		want  string
	}{
		"a frame cut short": {
			org:  org[:len(org)-1],
			want: "the response to " + call(getOrg, "roster.org.get") + ": the codec could not decode it: the body is not one framed message",
		},
		"a field its type lacks": {
			org:  rosterFrame([]byte{9 << 3, 1}),
			want: "the response to " + call(getOrg, "roster.org.get") + ": the codec could not decode it: Org has no field 9",
		},
		"a request it cannot read": {
			org: org, codec: rosterCodec{unknown: "roster.org.get"},
			want: "the request body of " + call(getOrg, "roster.org.get") + ": the codec could not decode it: no call roster.org.get",
		},
		"JSON scrubbing broke": {
			org: org, rules: ScrubRules{Patterns: []ScrubPattern{{Pattern: regexp.MustCompile(`"sso":true`), Replace: `"sso":yes`}}},
			want: "the response to " + call(getOrg, "roster.org.get") + ": scrubbing left the codec's JSON unreadable",
		},
		"JSON the codec cannot encode": {
			org: org, rules: ScrubRules{Patterns: []ScrubPattern{{Pattern: regexp.MustCompile(`"seats":(\d+)`), Replace: `"seats":"$1"`}}},
			want: `the scrubbed recording does not replay: scenario "roster" response 0: the codec could not encode its body: Org.seats: not an unsigned integer`,
		},
	} {
		srv := rosterTenant(t, c.org)
		out := filepath.Join(t.TempDir(), "roster.json")
		_, err := recordRoster(srv.URL, out, realRosterToken, c.rules, c.codec)
		srv.Close()
		if want := strings.ReplaceAll(c.want, "%s", srv.URL); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: err = %v, want %q", name, err, want)
		}
		if _, statErr := os.Stat(out); !errors.Is(statErr, os.ErrNotExist) {
			t.Errorf("%s: the recording was written anyway: %v", name, statErr)
		}
	}
}

func TestRecordLeavesABodyTheCodecDeclinesToTheKit(t *testing.T) {
	out := filepath.Join(t.TempDir(), "rejected.json")
	rec, err := recordRoster(rosterTenant(t, nil).URL, out, "wrong-roster-token-0123", rosterRules(), rosterCodec{})
	if err != nil {
		t.Fatal(err)
	}
	if rec.Failure == nil || rec.Failure.Code != componentsdk.CodeAuthFailed {
		t.Fatalf("failure = %+v, want the rejected sign-in recorded", rec.Failure)
	}
	loaded, err := LoadScenario(out)
	if err != nil {
		t.Fatal(err)
	}
	if r := loaded.Responses[0]; r.decoded || r.Body != `{"error":"unauthorized"}` {
		t.Errorf("the JSON error was recorded decoded %v as %s, want it kept as text", r.decoded, r.Body)
	}
}

// codecRecording writes the scrubbed tenant as Record writes it, with note
// as the organization's note, and returns the file's path.
func codecRecording(t *testing.T, note string) string {
	t.Helper()
	api := "https://roster.test"
	header := http.Header{"Content-Type": {rosterContentType}}
	body := func(m map[string]any) string {
		raw, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}
	org := scrubbedOrg()
	org["note"] = note
	teams := scrubbedTeams()
	responses := []Response{{Operation: "roster.org.get", Method: http.MethodPost, URL: api + getOrg, RequestBody: `{}`, Header: header, Body: body(org), decoded: true}}
	for _, team := range []string{"dev", "ops"} {
		responses = append(responses, Response{
			Operation: "roster.members.list", Method: http.MethodPost, URL: api + listMembers, RequestBody: fmt.Sprintf(`{"team":%q}`, team),
			Header: header, Body: body(teams[team]), decoded: true,
		})
	}
	path := filepath.Join(t.TempDir(), "roster.json")
	if err := writeRecording(path, recording{Name: "roster", RecordedAt: "2026-10-22T12:00:00Z", Responses: responses}); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestCheckFlagsACodecRecordingThatHoldsAToken(t *testing.T) {
	path := codecRecording(t, "ghp_"+strings.Repeat("x9Y", 12))
	loaded, err := LoadScenario(path)
	if err != nil {
		t.Fatal(err)
	}
	got := violationsOf(checkSuite(t, rosterSuite(roster{api: "https://roster.test"}, rosterCodec{}, loaded)), "recording")
	if len(got) != 1 || got[0].Message != path+" responses[0].body holds a GitHub token; scrub it out of the recording" {
		t.Errorf("recording violations = %+v, want the token in the codec's JSON flagged", got)
	}

	// The scrub check reads a codec's JSON as JSON, whatever the body's
	// Content-Type says it was.
	sc := Scenario{Responses: []Response{{URL: "https://a.example/", Header: http.Header{"Content-Type": {"application/cbor"}}, Body: `{"name":"example-org"}`, decoded: true}}}
	if leaks := scanScenario(sc, nil, map[string]string{"acme-sandbox": "example-org"}); len(leaks) > 0 {
		t.Errorf("a codec's JSON was read as CBOR: %v", leaks)
	}
}

func TestACodecRecordingReplaysOnlyWithSuiteCodec(t *testing.T) {
	loaded, err := LoadScenario(codecRecording(t, "nothing to see"))
	if err != nil {
		t.Fatal(err)
	}
	want := "its body is JSON a BodyCodec decoded, which only a run with Suite.Codec set can encode"
	if _, err := NewReplay(loaded); err == nil || !strings.Contains(err.Error(), want) {
		t.Errorf("NewReplay err = %v, want %q", err, want)
	}
	found := false
	for _, v := range violationsOf(checkSuite(t, rosterSuite(roster{api: "https://roster.test"}, nil, loaded)), "scenario") {
		found = found || strings.Contains(v.Message, want)
	}
	if !found {
		t.Errorf("a run without Suite.Codec did not say the recording needs it")
	}
	loaded.Expect = map[string]map[string]any{rosterPath: {"/org": "example-org", "/members": map[string]any{"dev": 2, "ops": 1}}}
	s := rosterSuite(roster{api: "https://roster.test"}, rosterCodec{}, loaded)
	s.SkipChecks = []string{"faults", "credentials", "determinism", "levels", "sensitivity"}
	for _, v := range checkSuite(t, s).Violations {
		t.Errorf("%s/%s: %s", v.Check, v.Case, v.Message)
	}
}

// rosterScenario answers the roster API with bodies in its own format, as a
// gRPC collector's scenarios built in code do, matching each team's read by
// its request's body when byBody is set, and otherwise once, in order.
func rosterScenario(byBody bool) Scenario {
	api := "https://roster.test"
	header := http.Header{"Content-Type": {rosterContentType}}
	responses := []Response{{Operation: "roster.org.get", Method: http.MethodPost, URL: api + getOrg, Header: header, Body: string(rosterBody("Org", tenantOrg()))}}
	for _, team := range []string{"dev", "ops"} {
		r := Response{Operation: "roster.members.list", Method: http.MethodPost, URL: api + listMembers, Header: header, Body: string(rosterBody("Members", tenantTeams()[team]))}
		if byBody {
			r.RequestBody = fmt.Sprintf(`{"team":%q}`, team)
		} else {
			r.Times = 1
		}
		responses = append(responses, r)
	}
	return Scenario{Name: "clean", Responses: responses}
}

func TestTheSensitivityCheckChangesCodecBodies(t *testing.T) {
	api := "https://roster.test"
	report := checkSuite(t, rosterSuite(roster{api: api, reversed: true}, rosterCodec{}, rosterScenario(true)))
	if len(report.Unmutated) > 0 || len(report.Violations) > 0 {
		t.Errorf("unmutated = %v, violations = %+v, want the codec's bodies changed and each change seen", report.Unmutated, report.Violations)
	}
	got := violationsOf(checkSuite(t, rosterSuite(roster{api: api, ignoreBody: true}, rosterCodec{}, rosterScenario(true))), "sensitivity")
	if len(got) != 2 || got[0].Case != "roster.members.list" || got[1].Case != "roster.org.get" {
		t.Errorf("sensitivity violations = %+v, want the collector that ignores its answers flagged for each operation", got)
	}
	if report := checkSuite(t, rosterSuite(roster{api: api}, nil, rosterScenario(false))); strings.Join(report.Unmutated, ",") != "roster.members.list,roster.org.get" {
		t.Errorf("unmutated = %v, want both operations listed without a codec", report.Unmutated)
	}
	got = violationsOf(checkSuite(t, rosterSuite(roster{api: api}, rosterCodec{unknown: "roster.members.list"}, rosterScenario(false))), "sensitivity")
	want := "the check cannot change roster.members.list's responses: response 1: the codec could not decode it: no call roster.members.list"
	if len(got) != 1 || got[0].Message != want {
		t.Errorf("sensitivity violations = %+v, want %q", got, want)
	}
}

func TestRecordingsWriteCodecBodiesAsJSON(t *testing.T) {
	for _, body := range []string{`{"b":[1,2],"a":"<&>"}`, `"ok"`, `[]`, `null`} {
		raw, err := marshalJSON(Response{URL: "https://a.example/x", Body: body, decoded: true})
		if err != nil {
			t.Fatal(err)
		}
		if want := `"body_encoding":"codec","body":` + body + `}`; !strings.HasSuffix(string(raw), want) {
			t.Errorf("a codec body is written as %s, want it in place as JSON, ending %s", raw, want)
		}
		var back Response
		if err := json.Unmarshal(raw, &back); err != nil {
			t.Fatal(err)
		}
		if !back.decoded || back.Body != body {
			t.Errorf("%s came back decoded %v as %s", raw, back.decoded, back.Body)
		}
	}
}
