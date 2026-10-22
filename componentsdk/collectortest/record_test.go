package collectortest

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/locktivity/epack/componentsdk"
)

const (
	realDemoToken = "real-token-Zq81mXbV0Lp3"
	builtinRole   = "62e90394-69f5-4237-9190-012177145e10"
	aliceID       = "1b4e28ba-2fa1-11d2-883f-0016d3cca427"
	bobID         = "9e107d9d-372b-4c4b-a7a5-5f6c1e5b2a10"
)

// tenantJWT is a signed token, as a vendor issues one.
func tenantJWT() string {
	enc := base64.RawURLEncoding
	sig := sha512.Sum512([]byte("signature"))
	return enc.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`)) + "." +
		enc.EncodeToString([]byte(`{"sub":"alice","tid":"6f9619ff-8b86-d011-b42d-00c04fc964ff"}`)) + "." +
		enc.EncodeToString(sig[:])
}

// tenantCursor is an opaque page cursor, as long and random as a token.
func tenantCursor() string {
	sum := sha512.Sum512([]byte("cursor"))
	return base64.RawURLEncoding.EncodeToString(sum[:48])
}

// sshKey is an Ed25519 public key as authorized_keys lists it.
func sshKey() string {
	var blob []byte
	for _, part := range [][]byte{[]byte("ssh-ed25519"), bytes.Repeat([]byte{7}, 32)} {
		blob = binary.BigEndian.AppendUint32(blob, uint32(len(part)))
		blob = append(blob, part...)
	}
	return "ssh-ed25519 " + base64.StdEncoding.EncodeToString(blob)
}

// wrapBase64 encodes text as GitHub's contents API does: base64 wrapped at 60
// characters, each line ending in a line break.
func wrapBase64(text string) string {
	enc := base64.StdEncoding.EncodeToString([]byte(text))
	var b strings.Builder
	for len(enc) > 60 {
		b.WriteString(enc[:60] + "\n")
		enc = enc[60:]
	}
	return b.String() + enc + "\n"
}

const (
	credentialReport = "user,arn,mfa_active\nalice,arn:aws:iam::210987654321:user/alice,true\n<root_account>,arn:aws:iam::210987654321:root,false\n"
	codeowners       = "* @acme-sandbox/security Alice.Ng@acme-sandbox.io\n/infra/ @acme-sandbox/platform\n"
)

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(v)
}

// demoTenant serves the demo's API from a tenant full of values a recording
// must not keep: the real token, emails, GUIDs, an AWS account, public
// addresses, a signed token, and a cursor. Its first score answer is a 503.
func demoTenant(t *testing.T) *httptest.Server {
	t.Helper()
	var scoreCalls atomic.Int32
	authorized := func(w http.ResponseWriter, r *http.Request) bool {
		if r.Header.Get("X-Demo-Token") != realDemoToken {
			w.WriteHeader(http.StatusUnauthorized)
			return false
		}
		return true
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /me", func(w http.ResponseWriter, r *http.Request) {
		if !authorized(w, r) {
			return
		}
		writeJSON(w, map[string]any{
			"org": "acme-sandbox", "mfa_enforced": true, "owner": "Alice.Ng@acme-sandbox.io",
			"tenant_id": "6F9619FF-8B86-D011-B42D-00C04FC964FF", "role_arn": "arn:aws:iam::210987654321:role/epack-reader",
			"egress": []string{"52.94.236.248", "2600:1f18:4a3:6900::12", "10.20.30.40"}, "allowed_from": "0.0.0.0/0",
			"session": tenantJWT(), "debug": realDemoToken, "access_token": "opaque-access-0123456789abc",
			"github": "ghp_" + strings.Repeat("aB3", 12), "deploy_key": sshKey(), "admin_role": builtinRole,
			"credential_report": base64.StdEncoding.EncodeToString([]byte(credentialReport)),
			"codeowners":        wrapBase64(codeowners),
		})
	})
	mux.HandleFunc("GET /users", func(w http.ResponseWriter, r *http.Request) {
		if !authorized(w, r) {
			return
		}
		next := fmt.Sprintf("http://%s/users?page=2&after=%s&cursor=%s&account=210987654321", r.Host, bobID, tenantCursor())
		w.Header().Set("X-RateLimit-Remaining", "4999")
		w.Header().Set("X-Request-Id", "req-9f8e7d")
		w.Header().Set("Set-Cookie", "session=cookie-0123456789")
		w.Header().Set("X-Demo-Region", "us-east-1")
		q := r.URL.Query()
		switch {
		case q.Get("page") == "1":
			w.Header().Set("Link", "<"+next+`>; rel="next"`)
			writeJSON(w, map[string]any{"users": []any{
				map[string]any{"mfa": true, "email": "Alice.Ng@acme-sandbox.io", "id": aliceID},
				map[string]any{"mfa": false, "email": "bob@acme-sandbox.io", "id": bobID},
			}, "next": next, "total": 4})
		case q.Get("page") == "2" && q.Get("after") == bobID && q.Get("cursor") == tenantCursor():
			writeJSON(w, map[string]any{"users": []any{
				map[string]any{"mfa": true, "email": "carol@acme-sandbox.io"},
				map[string]any{"mfa": true, "email": "Alice.Ng@acme-sandbox.io"},
			}, "next": "", "total": 4})
		default:
			http.Error(w, "no such page", http.StatusBadRequest)
		}
	})
	mux.HandleFunc("GET /score", func(w http.ResponseWriter, r *http.Request) {
		if !authorized(w, r) {
			return
		}
		if scoreCalls.Add(1) == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		writeJSON(w, map[string]any{"value": 72})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func recordDemo(t *testing.T, api, out string, rules ScrubRules) (RecordReport, error) {
	t.Helper()
	return Record(RecordOptions{
		Spec:    demoSuite(demo{}).Spec,
		Run:     demo{api: api}.run,
		Name:    "clean",
		Config:  map[string]any{"level": "audit"},
		Secrets: map[string]string{"DEMO_TOKEN": realDemoToken},
		Out:     out,
		Scrub:   rules,
		Headers: []string{"X-Demo-Region"},
	})
}

func demoRules() ScrubRules {
	return ScrubRules{Literals: map[string]string{"acme-sandbox": "example-org"}, Keep: []string{builtinRole}}
}

func TestARecordedDemoReplaysClean(t *testing.T) {
	srv := demoTenant(t)
	out := filepath.Join(t.TempDir(), "testdata", "recordings", "clean.json")
	rec, err := recordDemo(t, srv.URL, out, demoRules())
	if err != nil {
		t.Fatal(err)
	}
	if rec.ExitCode != 0 || rec.Responses != 4 || rec.DNS != 0 {
		t.Errorf("report = %+v, want a clean run with 4 responses: the score's 503 was retried, so it is left out", rec)
	}
	for kind, want := range map[string]int{"email": 3, "guid": 3, "aws_account": 1, "ip": 2, "secret": 1} {
		if rec.Replaced[kind] != want {
			t.Errorf("replaced %d values by %s, want %d (all: %v)", rec.Replaced[kind], kind, want, rec.Replaced)
		}
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, gone := range []string{
		"acme-sandbox", "Alice.Ng", "bob@", "carol@", "6F9619FF", "6f9619ff", aliceID, bobID, "210987654321",
		"52.94.236.248", "2600:1f18", realDemoToken, tenantJWT(), "opaque-access", "ghp_", tenantCursor(),
		"X-Request-Id", "req-9f8e7d", "Set-Cookie", "cookie-0123456789",
	} {
		if strings.Contains(text, gone) {
			t.Errorf("the recording still holds %q", gone)
		}
	}
	for _, kept := range []string{
		`"name": "clean"`, `"collector": "demo"`, `"collector_version": "0.0.1"`, `"recorded_at"`,
		"example-org", "user1@example.com", "123456789012", "192.0.2.1", "2001:db8::2", "10.20.30.40", "0.0.0.0/0",
		builtinRole, sshKey(), "X-Ratelimit-Remaining", "X-Demo-Region", `"access_token": "REDACTED"`,
	} {
		if !strings.Contains(text, kept) {
			t.Errorf("the recording lacks %q", kept)
		}
	}

	var file recording
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	if len(file.Responses) != 4 {
		t.Fatalf("responses = %d, want 4", len(file.Responses))
	}
	me, page1, page2, score := file.Responses[0], file.Responses[1], file.Responses[2], file.Responses[3]
	if !strings.HasSuffix(me.URL, "/me?") || me.Operation != "demo.me.get" || me.Method != http.MethodGet {
		t.Errorf("the sign-in response is %s %s (%s), want a URL that ends in ? so it answers only requests with no query", me.Method, me.URL, me.Operation)
	}
	if score.Status != http.StatusOK || score.Times != 0 {
		t.Errorf("the score response has status %d and times %d, want the 200 the retry got, for every request", score.Status, score.Times)
	}
	var meBody struct {
		Report     string `json:"credential_report"`
		Codeowners string `json:"codeowners"`
	}
	if err := json.Unmarshal([]byte(me.Body), &meBody); err != nil {
		t.Fatal(err)
	}
	if report, err := base64.StdEncoding.DecodeString(meBody.Report); err != nil || !strings.Contains(string(report), "arn:aws:iam::123456789012:user/alice") {
		t.Errorf("the credential report decodes to %q (%v), want its account scrubbed inside the base64", report, err)
	}
	lines := strings.Split(strings.TrimSuffix(meBody.Codeowners, "\n"), "\n")
	decoded, err := base64.StdEncoding.DecodeString(strings.Join(lines, ""))
	if err != nil || len(lines[0]) != 60 || !strings.Contains(string(decoded), "@example-org/security user1@example.com") {
		t.Errorf("the wrapped CODEOWNERS decodes to %q (%v) with lines of %d, want it scrubbed inside and wrapped at 60", decoded, err, len(lines[0]))
	}

	var p1 struct {
		Users []struct {
			ID string `json:"id"`
		} `json:"users"`
		Next string `json:"next"`
	}
	if err := json.Unmarshal([]byte(page1.Body), &p1); err != nil {
		t.Fatal(err)
	}
	next, err := url.Parse(p1.Next)
	if err != nil {
		t.Fatal(err)
	}
	asked, err := url.Parse(page2.URL)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := asked.Query(), next.Query(); got.Encode() != want.Encode() || got.Get("after") != p1.Users[1].ID || got.Get("account") != "123456789012" {
		t.Errorf("page 2 was requested with %v, want the query of page 1's next link, %v, scrubbed the same way", got, want)
	}
	if link := page1.Header.Get("Link"); !strings.Contains(link, next.Query().Get("cursor")) {
		t.Errorf("the Link header %q carries another cursor than the body's next link", link)
	}

	loaded, err := LoadScenario(out)
	if err != nil {
		t.Fatal(err)
	}
	srv.Close()
	loaded.Expect = map[string]map[string]any{
		"artifacts/demo.json":                  {"/org": "example-org", "/users": 4, "/mfa_pct": 75, "/score": 72},
		"artifacts/demo.collector-result.json": {"/run/started_at": file.RecordedAt},
	}
	s := demoSuite(demo{api: srv.URL})
	s.Scenarios = []Scenario{loaded}
	report := checkSuite(t, s)
	for _, v := range report.Violations {
		t.Errorf("%s/%s: %s", v.Check, v.Case, v.Message)
	}
	if report.Runs < 40 {
		t.Errorf("runs = %d, want the fault matrix on the recording too", report.Runs)
	}
}

const (
	realDirectorySecret = "real-directory-secret-8Kq2"
	directoryClientID   = "d9b8a7c6-5e4f-4a3b-9c2d-1e0f9a8b7c6d"
	directoryPath       = "artifacts/directory.json"
)

// directory signs in with a client secret in a form, lists a tenant's users,
// and reads each user's admin flag with a JSON body that names the user, as
// vendors key per-item reads by body.
type directory struct{ api string }

func (d directory) run(ctx componentsdk.CollectorContext) error {
	api, err := url.Parse(d.api)
	if err != nil {
		return componentsdk.CodeError(componentsdk.CodeConfigInvalid, err)
	}
	client := componentsdk.NewHTTPClient(ctx, componentsdk.HTTPOptions{CredentialHosts: []string{api.Hostname()}})
	tenant, _ := ctx.Config()["tenant"].(string)
	clientID, _ := ctx.Config()["client_id"].(string)
	call := func(op, method, path, contentType string, body []byte, token string, out any) error {
		reqCtx := componentsdk.WithOperation(ctx.Context(), componentsdk.Operation{Name: op, Safe: true})
		req, err := http.NewRequestWithContext(reqCtx, method, d.api+path, bytes.NewReader(body))
		if err != nil {
			return err
		}
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			return componentsdk.CodeError(componentsdk.ClassifyResponse(resp), &demoAPIError{status: resp.StatusCode})
		}
		raw, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		return json.Unmarshal(raw, out)
	}
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {clientID}, "client_secret": {ctx.Secret("DIRECTORY_SECRET")}}
	var token struct {
		AccessToken string `json:"access_token"`
	}
	if err := call("directory.token.create", http.MethodPost, "/oauth/token", "application/x-www-form-urlencoded", []byte(form.Encode()), "", &token); err != nil {
		return fmt.Errorf("signing in: %w", err)
	}
	if token.AccessToken == "" {
		return componentsdk.CodeError(componentsdk.CodeInvalidResponse, errors.New("the token response has no access_token"))
	}
	rec := componentsdk.Records(ctx)
	at := func(pointer string) componentsdk.Location {
		return componentsdk.Location{Path: directoryPath, Pointer: pointer}
	}
	out := map[string]any{"tenant": tenant}
	emit := func() error { return ctx.Emit([]componentsdk.CollectedArtifact{{Data: out, Path: directoryPath}}) }
	var list struct {
		Users *[]struct {
			ID    string `json:"id"`
			Email string `json:"email"`
		} `json:"users"`
	}
	err = call("directory.users.list", http.MethodGet, "/tenants/"+tenant+"/users", "", nil, token.AccessToken, &list)
	if err == nil && list.Users == nil {
		err = componentsdk.CodeError(componentsdk.CodeInvalidResponse, errors.New("the users response has no users"))
	}
	if err != nil {
		rec.NotCollected(at("/users"), err)
		rec.NotCollected(at("/admins"), err)
		return emit()
	}
	out["users"] = len(*list.Users)
	admins := 0
	for _, u := range *list.Users {
		body, err := json.Marshal(map[string]any{"user": map[string]string{"id": u.ID, "email": u.Email}})
		if err != nil {
			return err
		}
		var flag struct {
			Admin *bool `json:"admin"`
		}
		err = call("directory.admin.get", http.MethodPost, "/admin", "application/json", body, token.AccessToken, &flag)
		if err == nil && flag.Admin == nil {
			err = componentsdk.CodeError(componentsdk.CodeInvalidResponse, errors.New("the admin response has no admin flag"))
		}
		if err != nil {
			rec.NotCollected(at("/admins"), err)
			return emit()
		}
		if *flag.Admin {
			admins++
		}
	}
	out["admins"] = admins
	return emit()
}

func directoryTenant(t *testing.T) *httptest.Server {
	t.Helper()
	jwt := tenantJWT()
	mux := http.NewServeMux()
	mux.HandleFunc("POST /oauth/token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil || r.PostForm.Get("client_secret") != realDirectorySecret || r.PostForm.Get("client_id") != directoryClientID {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		writeJSON(w, map[string]any{"access_token": jwt, "token_type": "Bearer", "expires_in": 3599})
	})
	mux.HandleFunc("GET /tenants/acme-sandbox/users", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+jwt {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		writeJSON(w, map[string]any{"users": []any{
			map[string]any{"id": "0f8fad5b-d9cb-469f-a165-70867728950e", "email": "dana@acme-sandbox.io"},
			map[string]any{"id": "7c9e6679-7425-40de-944b-e07fc1f90ae7", "email": "eli@acme-sandbox.io"},
			map[string]any{"id": "16fd2706-8baf-433b-82eb-8c7fada847da", "email": "fay@acme-sandbox.io"},
		}})
	})
	mux.HandleFunc("POST /admin", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			User struct {
				Email string `json:"email"`
			} `json:"user"`
		}
		if r.Header.Get("Authorization") != "Bearer "+jwt || json.NewDecoder(r.Body).Decode(&body) != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		writeJSON(w, map[string]any{"admin": body.User.Email == "dana@acme-sandbox.io"})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestARecordingMatchesRequestBodiesAfterScrubbing(t *testing.T) {
	srv := directoryTenant(t)
	spec := componentsdk.CollectorSpec{Name: "directory", Version: "1.2.0"}
	out := filepath.Join(t.TempDir(), "directory.json")
	rec, err := Record(RecordOptions{
		Spec:    spec,
		Run:     directory{api: srv.URL}.run,
		Config:  map[string]any{"tenant": "acme-sandbox", "client_id": directoryClientID, "level": "audit"},
		Secrets: map[string]string{"DIRECTORY_SECRET": realDirectorySecret},
		Out:     out,
		Scrub:   ScrubRules{Literals: map[string]string{"acme-sandbox": "example-org"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if rec.ExitCode != 0 || rec.Responses != 5 {
		t.Fatalf("report = %+v, want a clean run with 5 responses", rec)
	}
	loaded, err := LoadScenario(out)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Name != "directory" {
		t.Errorf("name = %q, want the file's name", loaded.Name)
	}
	if got := fmt.Sprint(loaded.Config); got != "map[client_id:00000000-0000-4000-8000-000000000001 level:audit tenant:example-org]" {
		t.Errorf("config = %s, want the run's config, scrubbed", got)
	}
	signIn := loaded.Responses[0]
	if signIn.RequestBody != `{"client_id":"00000000-0000-4000-8000-000000000001","grant_type":"client_credentials"}` {
		t.Errorf("the sign-in's request body is %s, want it without the client secret and with the config's fake client ID", signIn.RequestBody)
	}
	var users struct {
		Users []struct {
			ID    string `json:"id"`
			Email string `json:"email"`
		} `json:"users"`
	}
	if err := json.Unmarshal([]byte(loaded.Responses[1].Body), &users); err != nil {
		t.Fatal(err)
	}
	for i, u := range users.Users {
		want := fmt.Sprintf(`{"user":{"email":%q,"id":%q}}`, u.Email, u.ID)
		if got := loaded.Responses[2+i].RequestBody; got != want {
			t.Errorf("admin read %d has request body %s, want %s, the user as the list response names it", i, got, want)
		}
	}
	srv.Close()
	loaded.Expect = map[string]map[string]any{directoryPath: {"/tenant": "example-org", "/users": 3, "/admins": 1}}
	report := checkSuite(t, Suite{
		Spec:        spec,
		Run:         directory{api: srv.URL}.run,
		Secrets:     map[string]string{"DIRECTORY_SECRET": "fake-directory-secret-0123"},
		Scenarios:   []Scenario{loaded},
		Required:    []string{"directory.token.create"},
		Operations:  []string{"directory.token.create", "directory.users.list", "directory.admin.get"},
		Insensitive: []string{"directory.token.create"},
	})
	for _, v := range report.Violations {
		t.Errorf("%s/%s: %s", v.Check, v.Case, v.Message)
	}
}

func TestARecordedDNSCollectorReplaysClean(t *testing.T) {
	resolver, err := newDNSServer(Scenario{DNS: []DNSRecord{
		{Name: "acme-sandbox.io", Type: "TXT", Values: []string{"google-site-verification=rXOxyZounnZasA8Z7oaD3c14JdjS9aKSWvsR1EbUSIQ", "v=spf1 ip4:52.94.236.248 include:_spf.google.com -all"}},
		{Name: "_dmarc.acme-sandbox.io", Type: "TXT", Values: []string{"v=DMARC1; p=reject; rua=mailto:dmarc@acme-sandbox.io"}},
		{Name: "acme-sandbox.io", Type: "MX", Values: []string{"20 mx2.acme-sandbox.io.", "10 mx1.acme-sandbox.io."}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	s := dnsDemoSuite(dnsDemo{})
	out := filepath.Join(t.TempDir(), "dns.json")
	rec, err := Record(RecordOptions{
		Spec:     s.Spec,
		Run:      s.Run,
		Config:   map[string]any{"domain": "acme-sandbox.io", "level": "audit"},
		Out:      out,
		Scrub:    ScrubRules{Literals: map[string]string{"acme-sandbox.io": "example.com"}},
		resolver: resolver,
	})
	if err != nil {
		t.Fatal(err)
	}
	if rec.Responses != 0 || rec.DNS != 3 {
		t.Errorf("report = %+v, want 3 DNS records and no responses", rec)
	}
	loaded, err := LoadScenario(out)
	if err != nil {
		t.Fatal(err)
	}
	want := []DNSRecord{
		{Name: "example.com", Type: "TXT", Values: []string{"google-site-verification=scrubbed-token-1", "v=spf1 ip4:192.0.2.1 include:_spf.google.com -all"}},
		{Name: "_dmarc.example.com", Type: "TXT", Values: []string{"v=DMARC1; p=reject; rua=mailto:user1@example.com"}},
		{Name: "example.com", Type: "MX", Values: []string{"10 mx1.example.com.", "20 mx2.example.com."}},
	}
	if fmt.Sprint(loaded.DNS) != fmt.Sprint(want) {
		t.Errorf("dns = %v, want %v", loaded.DNS, want)
	}
	loaded.Expect = map[string]map[string]any{dnsDemoPath: {"/has_spf": true, "/has_dmarc": true, "/mx": []any{"mx1.example.com", "mx2.example.com"}}}
	s.Scenarios = []Scenario{loaded}
	for _, v := range checkSuite(t, s).Violations {
		t.Errorf("%s/%s: %s", v.Check, v.Case, v.Message)
	}
}

func TestRecordWritesNothingTheScrubCheckFlags(t *testing.T) {
	out := filepath.Join(t.TempDir(), "clean.json")
	rules := demoRules()
	rules.Keep = append(rules.Keep, tenantCursor())
	_, err := recordDemo(t, demoTenant(t).URL, out, rules)
	if err == nil || !strings.Contains(err.Error(), "responses[1].body: a long token") || !strings.Contains(err.Error(), "responses[2].url: a long token") {
		t.Errorf("err = %v, want the kept cursor flagged where it remains", err)
	}
	if err != nil && strings.Contains(err.Error(), tenantCursor()) {
		t.Error("the error repeats the value it flags")
	}
	if _, statErr := os.Stat(out); !errors.Is(statErr, os.ErrNotExist) {
		t.Errorf("the recording was written anyway: %v", statErr)
	}
}

func TestRecordFailsForACallWithNoResponse(t *testing.T) {
	down := httptest.NewServer(http.NotFoundHandler())
	api := down.URL
	down.Close()
	run := func(ctx componentsdk.CollectorContext) error {
		client := componentsdk.NewHTTPClient(ctx, componentsdk.HTTPOptions{})
		reqCtx := componentsdk.WithOperation(ctx.Context(), componentsdk.Operation{Name: "down.items.create"})
		req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, api+"/items?token=abc", strings.NewReader(`{}`))
		if err != nil {
			return err
		}
		if resp, err := client.Do(req); err == nil {
			_ = resp.Body.Close()
		}
		return ctx.Emit([]componentsdk.CollectedArtifact{{Data: map[string]any{}, Path: "artifacts/down.json"}})
	}
	out := filepath.Join(t.TempDir(), "down.json")
	_, err := Record(RecordOptions{Spec: componentsdk.CollectorSpec{Name: "down"}, Run: run, Out: out})
	if err == nil || !strings.Contains(err.Error(), "POST "+api+"/items?token (operation down.items.create): vendor_error") {
		t.Errorf("err = %v, want the call that got no response named, without its query values", err)
	}
	if _, statErr := os.Stat(out); !errors.Is(statErr, os.ErrNotExist) {
		t.Errorf("the recording was written anyway: %v", statErr)
	}
	if _, err := Record(RecordOptions{Spec: componentsdk.CollectorSpec{Name: "down"}, Run: func(ctx componentsdk.CollectorContext) error {
		return ctx.Emit(nil)
	}, Out: out}); err == nil || !strings.Contains(err.Error(), "nothing to record") {
		t.Errorf("a run with no calls: err = %v", err)
	}
}

func TestCheckFlagsALoadedRecordingThatHoldsAToken(t *testing.T) {
	sc := demoScenario()
	sc.Name = "hand edited"
	sc.Responses = append([]Response(nil), sc.Responses...)
	sc.Responses[0].Body = `{"org":"acme","mfa_enforced":true,"note":"ghp_` + strings.Repeat("x9Y", 12) + `"}`
	path := filepath.Join(t.TempDir(), "edited.json")
	if err := writeRecording(path, recording{Name: sc.Name, Responses: sc.Responses}); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadScenario(path)
	if err != nil {
		t.Fatal(err)
	}
	s := demoSuite(demo{})
	s.Scenarios = append(s.Scenarios, loaded)
	got := violationsOf(checkSuite(t, s), "recording")
	if len(got) != 1 || got[0].Case != "hand edited" || got[0].Message != path+" responses[0].body holds a GitHub token; scrub it out of the recording" {
		t.Errorf("recording violations = %+v", got)
	}
	s.Scenarios = s.Scenarios[:len(s.Scenarios)-1]
	s.Scenarios = append(s.Scenarios, sc)
	if got := violationsOf(checkSuite(t, s), "recording"); len(got) != 0 {
		t.Errorf("a scenario built in code is not a recording, yet: %+v", got)
	}
}

func TestLoadScenarioRejectsAnUnusableRecording(t *testing.T) {
	dir := t.TempDir()
	for name, content := range map[string]string{
		"unknown field":  `{"name":"x","respones":[]}`,
		"bad time":       `{"name":"x","recorded_at":"yesterday"}`,
		"relative URL":   `{"name":"x","responses":[{"url":"/me"}]}`,
		"bad DNS record": `{"name":"x","dns":[{"name":"example.com","type":"A","values":["2001:db8::1"]}]}`,
		"response field": `{"name":"x","responses":[{"url":"https://a.example/","bodyy":"{}"}]}`,
		"body encoding":  `{"name":"x","responses":[{"url":"https://a.example/","body_encoding":"hex","body":"a0"}]}`,
		"bad base64":     `{"name":"x","responses":[{"url":"https://a.example/","body_encoding":"base64","body":"not base64!"}]}`,
		"base64 object":  `{"name":"x","responses":[{"url":"https://a.example/","body_encoding":"base64","body":{"a":1}}]}`,
		"codec, no body": `{"name":"x","responses":[{"url":"https://a.example/","body_encoding":"codec"}]}`,
		"no port":        `{"name":"x","endpoints":[{"address":"www.example.com"}]}`,
		"bad version":    `{"name":"x","endpoints":[{"address":"www.example.com:443","min_version":"TLS 1.4"}]}`,
		"endpoint field": `{"name":"x","endpoints":[{"address":"www.example.com:443","plain_text":true}]}`,
		"no moment":      `{"name":"x","endpoints":[{"address":"www.example.com:443","cert":{"not_after":"2026-12-01T00:00:00Z"}}]}`,
		"two endpoints":  `{"name":"x","endpoints":[{"address":"www.example.com:443"},{"address":"WWW.example.com:443"}]}`,
	} {
		path := filepath.Join(dir, strings.ReplaceAll(name, " ", "-")+".json")
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadScenario(path); err == nil {
			t.Errorf("%s: a recording that cannot replay loaded", name)
		}
	}
}

func TestRecordedResponsesWriteJSONBodiesAsJSON(t *testing.T) {
	cases := []Response{
		{Operation: "x.get", Method: "GET", URL: "https://a.example/x?", Status: 200, Times: 1, Body: "{\n  \"b\": [1, 2],\n  \"a\": \"<&>\"\n}", RequestBody: `{"id": "1"}`, Header: http.Header{"Content-Type": {"application/json"}}},
		{URL: "https://a.example/plain", Body: "all systems normal"},
		{URL: "https://a.example/quoted", Body: `"ok"`},
		{URL: "https://a.example/empty"},
	}
	for _, r := range cases {
		raw, err := marshalJSON(r)
		if err != nil {
			t.Fatal(err)
		}
		var back Response
		if err := json.Unmarshal(raw, &back); err != nil {
			t.Fatal(err)
		}
		want := r
		if want.Body, err = unembedJSON(mustEmbed(t, r.Body)); err != nil {
			t.Fatal(err)
		}
		want.RequestBody, _ = unembedJSON(mustEmbed(t, r.RequestBody))
		if fmt.Sprint(back) != fmt.Sprint(want) {
			t.Errorf("%s came back as %+v, want %+v", raw, back, want)
		}
	}
	raw, _ := marshalJSON(cases[0])
	if want := `"request_body":{"id":"1"},"times":1,"status":200,"header":{"Content-Type":["application/json"]},"body":{"b":[1,2],"a":"<&>"}}`; !strings.HasSuffix(string(raw), want) {
		t.Errorf("a JSON body is written as %s, want JSON in place, ending %s", raw, want)
	}
	if raw, _ := marshalJSON(cases[2]); !strings.Contains(string(raw), `"body":"\"ok\""`) {
		t.Errorf("a body that is a JSON string is written as %s, want it kept a string", raw)
	}
}

func mustEmbed(t *testing.T, s string) json.RawMessage {
	t.Helper()
	raw, err := embedJSON(s)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestALoadedRecordingRunsAtItsOwnMoment(t *testing.T) {
	sc := demoScenario()
	path := filepath.Join(t.TempDir(), "clean.json")
	if err := writeRecording(path, recording{Name: "clean", RecordedAt: "2026-10-17T09:30:00Z", Responses: sc.Responses}); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadScenario(path)
	if err != nil {
		t.Fatal(err)
	}
	if want := time.Date(2026, 10, 17, 9, 30, 0, 0, time.UTC); !loaded.recordedAt.Equal(want) {
		t.Fatalf("recordedAt = %s, want %s", loaded.recordedAt, want)
	}
	result := "artifacts/demo.collector-result.json"
	startedAt := func(at string) map[string]map[string]any {
		return map[string]map[string]any{result: {"/run/started_at": at}}
	}
	built := demoScenario()
	built.Name = "built in code"
	built.Expect = startedAt("2026-10-17T09:30:00Z")
	loaded.Expect = startedAt("2026-10-17T09:30:00Z")
	s := demoSuite(demo{})
	s.Scenarios = []Scenario{loaded, built}
	for _, v := range checkSuite(t, s).Violations {
		t.Errorf("a first recording sets the clock of the scenarios built in code: %s/%s: %s", v.Check, v.Case, v.Message)
	}
	s.Clock = time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	s.Scenarios[1].Expect = startedAt("2026-03-01T00:00:00Z")
	for _, v := range checkSuite(t, s).Violations {
		t.Errorf("Suite.Clock sets the clock of the scenarios built in code, and the recording keeps its own: %s/%s: %s", v.Check, v.Case, v.Message)
	}
	s.Scenarios = []Scenario{s.Scenarios[1], s.Scenarios[0]}
	for _, v := range checkSuite(t, s).Violations {
		t.Errorf("a recording after a scenario built in code keeps its own clock: %s/%s: %s", v.Check, v.Case, v.Message)
	}
}

func TestALoadedRecordingRunsWithItsOwnConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "no-level.json")
	if err := writeRecording(path, recording{Name: "no level", Config: map[string]any{"note": "recorded without a level"}, Responses: demoScenario().Responses}); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadScenario(path)
	if err != nil {
		t.Fatal(err)
	}
	loaded.Expect = map[string]map[string]any{"artifacts/demo.json": {"/users": 4, "/user_mfa": Absent}}
	s := demoSuite(demo{})
	s.Scenarios = append(s.Scenarios, loaded)
	for _, v := range checkSuite(t, s).Violations {
		t.Errorf("the recording should run with its config alone, at the default level, not Suite.Config's audit: %s/%s: %s", v.Check, v.Case, v.Message)
	}
}

// timeoutResolver answers like its dnsServer, except that TXT lookups time
// out.
type timeoutResolver struct{ *dnsServer }

func (timeoutResolver) LookupTXT(context.Context, string) ([]string, error) {
	return nil, lookupTimeout("example.com")
}

func TestRecordedLookupsAnswerAsTheNetworkDid(t *testing.T) {
	network, err := newDNSServer(Scenario{DNS: []DNSRecord{
		{Name: "example.com", Type: "A", Values: []string{"192.0.2.10"}},
		{Name: "example.com", Type: "AAAA", Values: []string{"2001:db8::10"}},
		{Name: "example.com", Type: "NS", Values: []string{"ns1.example.net."}},
		{Name: "www.example.com", Type: "CNAME", Values: []string{"edge.example.net."}},
		{Name: "edge.example.net", Type: "A", Values: []string{"192.0.2.20"}},
		{Name: "broken.example.com", Type: "TXT", Rcode: "SERVFAIL"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	show := func(v any, err error) string { return fmt.Sprintf("%v %v", v, err) }
	lookups := []func(r componentsdk.DNSResolver) string{
		func(r componentsdk.DNSResolver) string { return show(r.LookupHost(ctx, "example.com")) },
		func(r componentsdk.DNSResolver) string { return show(r.LookupIPAddr(ctx, "www.example.com")) },
		func(r componentsdk.DNSResolver) string { return show(r.LookupCNAME(ctx, "www.example.com")) },
		func(r componentsdk.DNSResolver) string { return show(r.LookupCNAME(ctx, "example.com")) },
		func(r componentsdk.DNSResolver) string { return show(r.LookupHost(ctx, "198.51.100.7")) },
		func(r componentsdk.DNSResolver) string {
			ns, err := r.LookupNS(ctx, "example.com")
			return show(len(ns), err) + " " + ns[0].Host
		},
		func(r componentsdk.DNSResolver) string { return show(r.LookupTXT(ctx, "missing.example.com")) },
		func(r componentsdk.DNSResolver) string { return show(r.LookupTXT(ctx, "broken.example.com")) },
		func(r componentsdk.DNSResolver) string { return show(r.LookupMX(ctx, "example.com")) },
	}
	recorder := &dnsRecorder{base: network}
	var want []string
	for _, lookup := range lookups {
		want = append(want, lookup(recorder))
	}
	records, err := recorder.answered()
	if err != nil {
		t.Fatal(err)
	}
	replay, err := newDNSServer(Scenario{Name: "recorded", DNS: records})
	if err != nil {
		t.Fatal(err)
	}
	for i, lookup := range lookups {
		if got := lookup(replay); got != want[i] {
			t.Errorf("lookup %d: the recording answers %s, the network answered %s", i, got, want[i])
		}
	}
	for _, rec := range records {
		if rec.Name == "198.51.100.7" {
			t.Errorf("an address literal was recorded as a name: %+v", rec)
		}
	}

	timeouts := &dnsRecorder{base: timeoutResolver{network}}
	_, _ = timeouts.LookupTXT(componentsdk.WithOperation(ctx, componentsdk.Operation{Name: "dns.spf.lookup"}), "example.com")
	if _, err := timeouts.answered(); err == nil || !strings.Contains(err.Error(), "TXT lookup of example.com (operation dns.spf.lookup): timeout") {
		t.Errorf("err = %v, want the lookup that timed out named", err)
	}
}

func TestRecordingsKeepTheHeadersCollectorsRead(t *testing.T) {
	keep := headerFilter([]string{"X-Oauth-Scopes", "X-Vendor-*"})
	for name, want := range map[string]bool{
		"Content-Type": true, "Link": true, "Location": true, "Etag": true, "X-Ratelimit-Reset": true, "X-Rate-Limit-Remaining": true,
		"Ratelimit": true, "Ratelimit-Policy": true, "X-Sentry-Rate-Limit-Reset": true, "X-Total-Count": true, "X-Ms-Continuation": true,
		"X-Oauth-Scopes": true, "X-Vendor-Region": true, "X-Request-Id": false, "Set-Cookie": false, "Date": false, "X-Vendor": false,
	} {
		if got := keep(name); got != want {
			t.Errorf("keep(%s) = %v, want %v", name, got, want)
		}
	}
	s := newScrubber(nil, ScrubRules{})
	h := s.headers(http.Header{"Set-Cookie": {"session=abc"}, "X-Vendor-Region": {"52.94.236.248"}, "Date": {"today"}}, headerFilter([]string{"Set-Cookie", "X-Vendor-*"}))
	if fmt.Sprint(h) != "map[Set-Cookie:[REDACTED] X-Vendor-Region:[192.0.2.1]]" {
		t.Errorf("headers = %v, want a kept cookie redacted and other values scrubbed", h)
	}
}

func TestRecordKeepsSecretsOutOfAPanic(t *testing.T) {
	_, err := Record(RecordOptions{
		Spec:    componentsdk.CollectorSpec{Name: "panics"},
		Run:     func(ctx componentsdk.CollectorContext) error { panic("bad token " + ctx.Secret("TOKEN")) },
		Secrets: map[string]string{"TOKEN": realDemoToken},
		Out:     filepath.Join(t.TempDir(), "panics.json"),
	})
	if err == nil || err.Error() != "the collector panicked: bad token REDACTED" {
		t.Errorf("err = %v", err)
	}
}

// tlsNetwork serves endpoints as the network a recording reaches, with
// certificates for clock that its CA signs. The CA's pool stands in for the
// system's roots.
func tlsNetwork(t *testing.T, clock time.Time, endpoints ...Endpoint) (*endpointSet, *testCA) {
	t.Helper()
	ca, err := newTestCA(endpointMoments(clock, endpoints)...)
	if err != nil {
		t.Fatal(err)
	}
	set, err := newEndpointSet(Scenario{Name: "network", Endpoints: endpoints}, ca, clock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(set.hangUp)
	return set, ca
}

func recordTLSDemo(address, out string, dial dialFunc, roots *x509.CertPool) (RecordReport, error) {
	return Record(RecordOptions{
		Spec:   tlsDemoSuite(tlsDemo{}).Spec,
		Run:    tlsDemo{}.run,
		Config: map[string]any{"address": address, "level": "audit"},
		Out:    out,
		Scrub:  ScrubRules{Literals: map[string]string{"acme-sandbox.io": "example.com"}},
		dial:   dial,
		roots:  roots,
	})
}

func TestRecordedEndpointsReplayAsTheNetworkAnswered(t *testing.T) {
	clock := time.Now().UTC().Truncate(time.Second)
	network, ca := tlsNetwork(t, clock,
		Endpoint{Address: "www.acme-sandbox.io:443"},
		Endpoint{Address: "legacy.acme-sandbox.io:8443", MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS11, Cert: Cert{Untrusted: true}},
		Endpoint{Address: "expired.acme-sandbox.io:443", Cert: Cert{NotBefore: -90 * day, NotAfter: -day}},
		Endpoint{Address: "ancient.acme-sandbox.io:443", Cert: Cert{NotBefore: -4000 * day, NotAfter: -3990 * day}},
		Endpoint{Address: "mismatch.acme-sandbox.io:443", Cert: Cert{DNSNames: []string{"www.acme-sandbox.io"}}},
		Endpoint{Address: "plain.acme-sandbox.io:80", Plaintext: true},
		Endpoint{Address: "closed.acme-sandbox.io:443", Refused: true},
	)
	// Each case is the endpoint the recording of one address holds, with its
	// certificate's validity as offsets from the network's clock, and what
	// the demo reads from the replay. The demo's own handshake needs TLS 1.2,
	// so the legacy endpoint's trust is left out. The ancient endpoint's
	// certificate expired more than ten years before the recording, and its
	// chain still leads to the replay's root.
	cases := []struct {
		address string
		want    Endpoint
		pins    map[string]any
	}{
		{
			address: "www.acme-sandbox.io:443",
			want: Endpoint{Address: "www.example.com:443", MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS13,
				Cert: Cert{DNSNames: []string{"www.example.com"}, NotBefore: -30 * day, NotAfter: 60 * day}},
			pins: map[string]any{"/trusted": true, "/tls_1_0": false, "/tls_1_1": false, "/tls_1_2": true, "/tls_1_3": true},
		},
		{
			address: "legacy.acme-sandbox.io:8443",
			want: Endpoint{Address: "legacy.example.com:8443", MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS11,
				Cert: Cert{DNSNames: []string{"legacy.example.com"}, NotBefore: -30 * day, NotAfter: 60 * day, Untrusted: true}},
			pins: map[string]any{"/trusted": nil, "/tls_1_0": true, "/tls_1_1": true, "/tls_1_2": false, "/tls_1_3": false},
		},
		{
			address: "expired.acme-sandbox.io:443",
			want: Endpoint{Address: "expired.example.com:443", MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS13,
				Cert: Cert{DNSNames: []string{"expired.example.com"}, NotBefore: -90 * day, NotAfter: -day}},
			pins: map[string]any{"/trusted": true, "/expires_in_days": -1, "/tls_1_3": true},
		},
		{
			address: "ancient.acme-sandbox.io:443",
			want: Endpoint{Address: "ancient.example.com:443", MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS13,
				Cert: Cert{DNSNames: []string{"ancient.example.com"}, NotBefore: -4000 * day, NotAfter: -3990 * day}},
			pins: map[string]any{"/trusted": true, "/expires_in_days": -3990},
		},
		{
			address: "mismatch.acme-sandbox.io:443",
			want: Endpoint{Address: "mismatch.example.com:443", MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS13,
				Cert: Cert{DNSNames: []string{"www.example.com"}, NotBefore: -30 * day, NotAfter: 60 * day}},
			pins: map[string]any{"/trusted": false, "/tls_1_2": true},
		},
		{
			address: "plain.acme-sandbox.io:80",
			want:    Endpoint{Address: "plain.example.com:80", Plaintext: true},
			pins:    map[string]any{"/trusted": nil, "/tls_1_2": nil},
		},
		{
			address: "closed.acme-sandbox.io:443",
			want:    Endpoint{Address: "closed.example.com:443", Refused: true},
			pins:    map[string]any{"/trusted": nil, "/tls_1_2": nil},
		},
	}
	dir := t.TempDir()
	s := tlsDemoSuite(tlsDemo{})
	files := map[string]string{}
	for _, c := range cases {
		host, _, _ := net.SplitHostPort(c.address)
		out := filepath.Join(dir, strings.TrimSuffix(host, ".acme-sandbox.io")+".json")
		rec, err := recordTLSDemo(c.address, out, network.dial, ca.pool)
		if err != nil {
			t.Fatalf("%s: %v", c.address, err)
		}
		if rec.Endpoints != 1 || rec.Responses != 0 || rec.DNS != 0 {
			t.Errorf("%s: report = %+v, want one endpoint", c.address, rec)
		}
		raw, err := os.ReadFile(out)
		if err != nil {
			t.Fatal(err)
		}
		files[host] = string(raw)
		if strings.Contains(files[host], "acme-sandbox") {
			t.Errorf("%s: the recording still holds the domain:\n%s", c.address, raw)
		}
		loaded, err := LoadScenario(out)
		if err != nil {
			t.Fatal(err)
		}
		want := c.want
		if want.Cert.NotAfter != 0 {
			want.Cert.NotBefore = clock.Add(want.Cert.NotBefore).Sub(loaded.recordedAt)
			want.Cert.NotAfter = clock.Add(want.Cert.NotAfter).Sub(loaded.recordedAt)
		}
		if len(loaded.Endpoints) != 1 || fmt.Sprint(loaded.Endpoints[0]) != fmt.Sprint(want) {
			t.Errorf("%s: the recording holds %+v, want %+v", c.address, loaded.Endpoints, want)
		}
		loaded.Expect = map[string]map[string]any{tlsDemoPath: c.pins}
		s.Scenarios = append(s.Scenarios, loaded)
	}
	legacy := files["legacy.acme-sandbox.io"]
	for _, kept := range []string{
		`"address": "legacy.example.com:8443"`, `"min_version": "TLS 1.0"`, `"max_version": "TLS 1.1"`, `"untrusted": true`,
		`"not_after": "` + clock.Add(60*day).Format(time.RFC3339) + `"`,
	} {
		if !strings.Contains(legacy, kept) {
			t.Errorf("the legacy recording lacks %s:\n%s", kept, legacy)
		}
	}
	for _, v := range checkSuite(t, s).Violations {
		t.Errorf("%s/%s: %s", v.Check, v.Case, v.Message)
	}
}

func TestRecordFailsForAnEndpointItCannotReplay(t *testing.T) {
	clock := time.Now().UTC().Truncate(time.Second)
	network, ca := tlsNetwork(t, clock, Endpoint{Address: "www.acme-sandbox.io:443"})
	out := filepath.Join(t.TempDir(), "www.json")

	timesOut := func(_ context.Context, network, address string) (net.Conn, error) {
		return nil, &net.OpError{Op: "dial", Net: network, Addr: dialAddr(address), Err: os.ErrDeadlineExceeded}
	}
	_, err := recordTLSDemo("www.acme-sandbox.io:443", out, timesOut, ca.pool)
	if err == nil || !strings.Contains(err.Error(), "tcp www.acme-sandbox.io:443 (operation tls.handshake): timeout") {
		t.Errorf("err = %v, want the dial that timed out named", err)
	}

	// A certificate that names its host only in its subject fails Go's
	// hostname check, while the kit would sign one that names the host.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: serialFor("subject only"),
		Subject:      pkix.Name{CommonName: "www.acme-sandbox.io"},
		NotBefore:    clock.Add(-day),
		NotAfter:     clock.Add(30 * day),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}, ca.trusted.cert, &key.PublicKey, ca.trusted.key)
	if err != nil {
		t.Fatal(err)
	}
	subjectOnly := &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	var conns []net.Conn
	t.Cleanup(func() {
		for _, c := range conns {
			_ = c.Close()
		}
	})
	servesSubjectOnly := func(context.Context, string, string) (net.Conn, error) {
		client, server := net.Pipe()
		conns = append(conns, server)
		go serve(newServerConn(server), Endpoint{}, subjectOnly)
		return client, nil
	}
	_, err = recordTLSDemo("www.acme-sandbox.io:443", out, servesSubjectOnly, ca.pool)
	if err == nil || !strings.Contains(err.Error(), "answer the hostname check differently") {
		t.Errorf("err = %v, want the certificate with no DNS names refused", err)
	}

	_, err = Record(RecordOptions{
		Spec:   tlsDemoSuite(tlsDemo{}).Spec,
		Run:    tlsDemo{}.run,
		Config: map[string]any{"address": "www.acme-sandbox.io:443", "level": "audit"},
		Out:    out,
		Scrub:  ScrubRules{Literals: map[string]string{"www.acme-sandbox.io": "www.example.com", "acme-sandbox.io": "example.net"}},
		dial:   network.dial,
		roots:  ca.pool,
	})
	if err != nil {
		t.Errorf("rules that rewrite the host and its certificate's names alike should record: %v", err)
	}
	if _, statErr := os.Stat(out); statErr != nil {
		t.Errorf("the recording was not written: %v", statErr)
	}
}

func TestTheScrubCheckReadsEndpoints(t *testing.T) {
	token := "ghp_" + strings.Repeat("x9Y", 12)
	leaks := scanScenario(Scenario{Endpoints: []Endpoint{{Address: "www.example.com:443", Cert: Cert{DNSNames: []string{token + ".example.com"}}}}}, nil, nil)
	if len(leaks) != 1 || leaks[0].String() != "endpoints[0].cert.dns_names: a GitHub token" {
		t.Errorf("leaks = %v, want the token in the certificate's names", leaks)
	}
}

func TestIdentifiersAreReplacedWithStableFakes(t *testing.T) {
	srv := demoTenant(t)
	out := filepath.Join(t.TempDir(), "clean.json")
	rules := ScrubRules{Identifiers: map[string]string{"acme-sandbox": "example-org", "210987654321": "111122223333"}, Keep: []string{builtinRole}}
	rec, err := recordDemo(t, srv.URL, out, rules)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Replaced["identifier"] < 2 || rec.Replaced["aws_account"] != 0 {
		t.Errorf("replaced = %v, want the identifiers replaced and the account's fake left as it is", rec.Replaced)
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if strings.Contains(strings.ToLower(text), "acme-sandbox") || strings.Contains(text, "210987654321") || strings.Contains(text, "123456789012") {
		t.Errorf("the recording still holds an identifier, or faked the account another way:\n%s", text)
	}
	if !strings.Contains(text, "arn:aws:iam::111122223333:role/epack-reader") {
		t.Errorf("the account should become its fake wherever it appears:\n%s", text)
	}
	loaded, err := LoadScenario(out)
	if err != nil {
		t.Fatal(err)
	}
	srv.Close()
	loaded.Expect = map[string]map[string]any{"artifacts/demo.json": {"/org": "example-org", "/users": 4}}
	s := demoSuite(demo{api: srv.URL})
	s.Scenarios = []Scenario{loaded}
	for _, v := range checkSuite(t, s).Violations {
		t.Errorf("%s/%s: %s", v.Check, v.Case, v.Message)
	}
}

func TestRecordWritesNothingThatStillNamesTheTenant(t *testing.T) {
	out := filepath.Join(t.TempDir(), "clean.json")
	rules := ScrubRules{
		Identifiers: map[string]string{"acme-sandbox": "example-org"},
		// A pattern runs after the identifiers, so this one puts it back.
		Patterns: []ScrubPattern{{Pattern: regexp.MustCompile(`example-org`), Replace: "ACME-Sandbox"}},
		Keep:     []string{builtinRole},
	}
	_, err := recordDemo(t, demoTenant(t).URL, out, rules)
	if err == nil || !strings.Contains(err.Error(), "responses[0].body: the tenant identifier ScrubRules.Identifiers replaces with example-org") {
		t.Errorf("err = %v, want the identifier flagged by its fake", err)
	}
	if err != nil && strings.Contains(strings.ToLower(err.Error()), "acme-sandbox") {
		t.Error("the error repeats the identifier it flags")
	}
	if _, statErr := os.Stat(out); !errors.Is(statErr, os.ErrNotExist) {
		t.Errorf("the recording was written anyway: %v", statErr)
	}
	_, err = recordDemo(t, demoTenant(t).URL, out, ScrubRules{Identifiers: map[string]string{"acme": "acme-fake"}})
	if err == nil || !strings.Contains(err.Error(), "holds the identifier it replaces") {
		t.Errorf("err = %v, want a fake that holds its identifier refused", err)
	}
}
