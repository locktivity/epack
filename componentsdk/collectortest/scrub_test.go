package collectortest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// stdCursor is a page cursor in standard base64, with the + and / a URL
// escapes.
const stdCursor = "Ab3+Cd4/Ef5+Gh6/Ij7+Kl8/Mn9+Op0/Qr1+St2/Uv3+Wx4/Yz5+Ab6/Cd7+Ef8=="

func TestScrubbingIsDeterministicAndConsistentAcrossARecording(t *testing.T) {
	body := `{"owner":"Alice@Acme.io","id":"6F9619FF-8B86-D011-B42D-00C04FC964FF","arn":"arn:aws:iam::210987654321:root",` +
		`"ip":"52.94.236.248","next":"https://api.acme.io/v1/users?cursor=` + url.QueryEscape(stdCursor) + `","cursor":"` + stdCursor + `"}`
	target, err := url.Parse("https://API.ACME.IO/v1/users/6f9619ff-8b86-d011-b42d-00c04fc964ff?cursor=" + url.QueryEscape(stdCursor) + "&owner=alice%40acme.io&account=210987654321")
	if err != nil {
		t.Fatal(err)
	}
	requestBody := `{"filter":{"owner":"alice@acme.io","account":"210987654321"},"ip":"52.94.236.248"}`
	scrubAll := func() []string {
		s := newScrubber(nil, ScrubRules{Literals: map[string]string{"acme.io": "example.net"}})
		reqBody, err := s.requestBody("application/json", []byte(requestBody))
		if err != nil {
			t.Fatal(err)
		}
		return []string{s.text(body), s.url(target), reqBody}
	}
	first, second := scrubAll(), scrubAll()
	if strings.Join(first, "\n") != strings.Join(second, "\n") {
		t.Errorf("the same recording scrubbed two ways:\n%q\n%q", first, second)
	}
	want := []string{
		`{"owner":"user1@example.com","id":"00000000-0000-4000-8000-000000000001","arn":"arn:aws:iam::123456789012:root",` +
			`"ip":"192.0.2.1","next":"https://api.example.net/v1/users?cursor=scrubbed-token-1","cursor":"scrubbed-token-1"}`,
		"https://api.example.net/v1/users/00000000-0000-4000-8000-000000000001?account=123456789012&cursor=scrubbed-token-1&owner=user1%40example.com",
		`{"filter":{"account":"123456789012","owner":"user1@example.com"},"ip":"192.0.2.1"}`,
	}
	for i := range want {
		if first[i] != want[i] {
			t.Errorf("got  %s\nwant %s", first[i], want[i])
		}
	}
}

func TestScrubbingFakesDistinctValuesDistinctly(t *testing.T) {
	s := newScrubber(nil, ScrubRules{})
	got := s.text("a@x.io b@x.io A@X.IO 1b4e28ba-2fa1-11d2-883f-0016d3cca427 9e107d9d-372b-4c4b-a7a5-5f6c1e5b2a10 210987654321 310987654321")
	want := "user1@example.com user2@example.com user1@example.com 00000000-0000-4000-8000-000000000001 00000000-0000-4000-8000-000000000002 123456789012 123456789013"
	if got != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
	kept := "1b4e28ba-2fa1-11d2-883f-210987654321"
	s = newScrubber(nil, ScrubRules{Keep: []string{kept}})
	if got, want := s.text(kept+" logs-beef-210987654321"), kept+" logs-beef-123456789012"; got != want {
		t.Errorf("got  %s\nwant %s: a GUID's last group is no account, but a bucket name's number is", got, want)
	}
	// An account's fake looks like any 12-digit number, but an email's and a
	// GUID's are their own, so scrubbing leaves them be.
	fakes := "user1@example.com 00000000-0000-4000-8000-000000000002 00000000-0000-0000-0000-000000000000"
	if again := s.text(fakes); again != fakes {
		t.Errorf("scrubbing fakes changed them: %s", again)
	}
}

func TestScrubbingKeepsAddressesACollectorTellsApart(t *testing.T) {
	s := newScrubber(nil, ScrubRules{})
	in := "0.0.0.0/0 ::/0 10.1.2.3 172.16.5.4 192.168.1.1 127.0.0.1 169.254.169.254 100.64.0.1 255.255.255.0 192.0.2.10 fe80::1 2001:db8::5 " +
		"52.94.236.248/32 2600:1f18::7 v1.2.3.4 1.2.3.4.5 ec2-52-94-236-248.compute-1.amazonaws.com"
	want := "0.0.0.0/0 ::/0 10.1.2.3 172.16.5.4 192.168.1.1 127.0.0.1 169.254.169.254 100.64.0.1 255.255.255.0 192.0.2.10 fe80::1 2001:db8::5 " +
		"192.0.2.1/32 2001:db8::2 v1.2.3.4 1.2.3.4.5 ec2-192-0-2-1.compute-1.amazonaws.com"
	if got := s.text(in); got != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
}

func TestScrubbingRedactsCredentials(t *testing.T) {
	s := newScrubber(map[string]string{"API_TOKEN": "p@ss/word+123", "SHORT": "abc"}, ScrubRules{})
	in := `{"access_token":"abc123opaque","NextToken":"page-2","refresh_token":"r1","client_secret":"zz","password_last_used":"2026-01-01",` +
		`"has_password":true,"note":"p@ss/word+123 and p%40ss%2Fword%2B123 and abc"}` +
		`<Credentials><AccessKeyId>` + "ASIA" + "ABCDEFGHIJKLMNOP" + `</AccessKeyId><SecretAccessKey>` +
		"wJalrXUtnFEMI/K7MDENG/bPxRfiCY" + strings.Repeat("z", 10) + `</SecretAccessKey></Credentials>` +
		` https://x.example/a?sig=abc&page=2&api_key=k1&key=AIzaSyA1 Authorization: Bearer abcdef0123456789xyz SSWS 00abcdefghijklmnopqrstuvwxyz ` +
		"ghp_" + strings.Repeat("aB3", 12) + " xoxb-1234567890-abcdefghij AKIAIOSFODNN7EXAMPLE " + tenantJWT() +
		"\n-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----"
	want := `{"access_token":"REDACTED","NextToken":"page-2","refresh_token":"REDACTED","client_secret":"REDACTED","password_last_used":"2026-01-01",` +
		`"has_password":true,"note":"REDACTED and REDACTED and abc"}` +
		`<Credentials><AccessKeyId>ASIAEXAMPLE000000001</AccessKeyId><SecretAccessKey>REDACTED</SecretAccessKey></Credentials>` +
		` https://x.example/a?sig=REDACTED&page=2&api_key=REDACTED&key=REDACTED Authorization: Bearer REDACTED SSWS REDACTED ` +
		"REDACTED REDACTED AKIAIOSFODNN7EXAMPLE REDACTED\nREDACTED"
	if got := s.text(in); got != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
}

func TestScrubbingLooksInsideBase64Text(t *testing.T) {
	s := newScrubber(nil, ScrubRules{Literals: map[string]string{"Acme": "example-org"}})
	report := base64.StdEncoding.EncodeToString([]byte("user,arn\nalice,arn:aws:iam::210987654321:user/alice\n"))
	got := s.text("<Content>" + report + "</Content>")
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSuffix(strings.TrimPrefix(got, "<Content>"), "</Content>"))
	if err != nil || string(decoded) != "user,arn\nalice,arn:aws:iam::123456789012:user/alice\n" {
		t.Errorf("the report decodes to %q (%v)", decoded, err)
	}

	text := "* @acme/security alice@acme.io\n" + strings.Repeat("/docs/ @acme/writers\n", 4)
	body, err := json.Marshal(map[string]string{"encoding": "base64", "content": wrapBase64(text)})
	if err != nil {
		t.Fatal(err)
	}
	var got2 struct {
		Content string `json:"content"`
	}
	if err := json.Unmarshal([]byte(s.text(string(body))), &got2); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(got2.Content, "\n"), "\n")
	for _, line := range lines[:len(lines)-1] {
		if len(line) != 60 {
			t.Errorf("a line of %d characters, want the original width of 60: %q", len(line), got2.Content)
		}
	}
	decoded, err = base64.StdEncoding.DecodeString(strings.Join(lines, ""))
	if want := "* @example-org/security user1@example.com\n" + strings.Repeat("/docs/ @example-org/writers\n", 4); err != nil || string(decoded) != want {
		t.Errorf("the wrapped file decodes to %q (%v), want %q", decoded, err, want)
	}
}

// publicMaterialSamples returns a certificate and a public key as base64 DER,
// and the certificate as PEM.
func publicMaterialSamples(t *testing.T) (cert, key, certPEM string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "idp.example.com"}, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(der), base64.StdEncoding.EncodeToString(spki), string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestScrubbingKeepsWhatIsPublicOrKept(t *testing.T) {
	cert, key, certPEM := publicMaterialSamples(t)
	pemJSON, err := json.Marshal(certPEM)
	if err != nil {
		t.Fatal(err)
	}
	sha := sha512.Sum512_256([]byte("x"))
	commit := strings.Repeat("a1b2c3d4e5", 4)
	unsigned := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`)) + "." + base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"x"}`)) + "."
	kept := []string{
		`{"x5c":["` + cert + `"]}`, `{"pem":` + string(pemJSON) + `}`, "v=DKIM1; k=rsa; p=" + key, sshKey(), hex.EncodeToString(sha[:]), commit, unsigned,
		"AWSServiceRoleForAmazonGuardDutyMalwareProtection", "a-very-long-repository-name-for-the-2026-platform-migration",
		"https://login.example.com/api/v1/apps/0oa1b2c3d4e5f6g7h8i9/groups/00g1b2c3d4e5f6g7h8i9/users",
		"integrity sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=", "Bearer token is invalid",
	}
	s := newScrubber(nil, ScrubRules{})
	for _, in := range kept {
		if got := s.text(in); got != in {
			t.Errorf("scrubbing changed %q to %q", in, got)
		}
	}

	keep := []string{builtinRole, "noreply@vendor.example", "123456789012", "52.94.236.248"}
	s = newScrubber(nil, ScrubRules{Keep: keep})
	in := strings.Join(keep, " ") + " 9e107d9d-372b-4c4b-a7a5-5f6c1e5b2a10"
	if got, want := s.text(in), strings.Join(keep, " ")+" 00000000-0000-4000-8000-000000000001"; got != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
}

func TestScrubbingReplacesTokens(t *testing.T) {
	random := sha512.Sum512([]byte("token"))
	in := []string{
		base64.StdEncoding.EncodeToString(random[:]),
		hex.EncodeToString(random[:24]),
		"/repos/acme/app/actions/runs/" + base64.RawURLEncoding.EncodeToString(random[:36]),
	}
	want := []string{"scrubbed-token-1", "scrubbed-token-2", "/repos/acme/app/actions/runs/scrubbed-token-3"}
	s := newScrubber(nil, ScrubRules{})
	for i := range in {
		if got := s.text(in[i]); got != want[i] {
			t.Errorf("scrubbed %q to %q, want %q", in[i], got, want[i])
		}
	}
}

func TestScrubbedURLsMatchWhatTheReplaySends(t *testing.T) {
	s := newScrubber(map[string]string{"API_KEY": "supersecretvalue"}, ScrubRules{Literals: map[string]string{"Acme": "example-org"}})
	cases := map[string]string{
		"https://api.example.com/me":                                      "https://api.example.com/me?",
		"https://api.example.com/users?api_key=abc&page=2":                "https://api.example.com/users",
		"https://api.example.com/users?q=supersecretvalue&page=2":         "https://api.example.com/users",
		"https://api.example.com/orgs/acme/repos?page=2&per_page=100#top": "https://api.example.com/orgs/example-org/repos?page=2&per_page=100",
	}
	for raw, want := range cases {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		if got := s.url(u); got != want {
			t.Errorf("scrubbed %s to %s, want %s", raw, got, want)
		}
	}
	rp, err := NewReplay(Scenario{Name: "urls", Responses: []Response{{URL: "https://api.example.com/me?", Body: "exact"}, {URL: "https://api.example.com/me", Body: "any"}}})
	if err != nil {
		t.Fatal(err)
	}
	for target, want := range map[string]string{"https://api.example.com/me": "exact", "https://api.example.com/me?fields=id": "any"} {
		req, err := http.NewRequest(http.MethodGet, target, nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := rp.RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}
		got, _ := io.ReadAll(resp.Body)
		if string(got) != want {
			t.Errorf("%s got %q, want %q", target, got, want)
		}
	}
}

func TestScrubbedRequestBodiesLeaveOutCredentials(t *testing.T) {
	s := newScrubber(map[string]string{"CLIENT_SECRET": "xyz-secret-value"}, ScrubRules{})
	cases := []struct{ contentType, body, want string }{
		{"application/x-www-form-urlencoded", "grant_type=client_credentials&client_id=abc&client_secret=xyz-secret-value&scope=a+b", `{"client_id":"abc","grant_type":"client_credentials","scope":"a b"}`},
		{"application/json", `{"auth":{"password":"pw-123456","user":"alice@acme.io"},"tags":[{"Key":"Name","Value":"web"}],"tokens":["ghp_` + strings.Repeat("aB3", 12) + `"],"note":"xyz-secret-value"}`, `{"auth":{"user":"user1@example.com"},"tags":[{"Key":"Name","Value":"web"}]}`},
		{"application/x-amz-json-1.1", `{"NextToken":"` + stdCursor + `","MaxResults":50}`, `{"MaxResults":50,"NextToken":"scrubbed-token-1"}`},
		{"application/xml", `<Request><Name>x</Name></Request>`, ""},
		{"application/json", `["xyz-secret-value"]`, ""},
	}
	for _, tc := range cases {
		got, err := s.requestBody(tc.contentType, []byte(tc.body))
		if err != nil || got != tc.want {
			t.Errorf("scrubbed %s to %s (%v), want %s", tc.body, got, err, tc.want)
		}
	}
}

func TestTheScrubCheckFlagsEachPattern(t *testing.T) {
	random := sha512.Sum512([]byte("leak"))
	secret := "p@ss/word+1"
	cases := map[string]string{
		"hello supersecretvalue1":                               "the value of secret LONG",
		"q=" + url.QueryEscape(secret):                          "the value of secret ENCODED",
		`{"pw":"p@ss\/word+1"}`:                                 "the value of secret ENCODED",
		tenantJWT():                                             "a signed JWT",
		"Authorization: Bearer abcdef0123456789xyz":             "a bearer token",
		"AKIA" + "QWERTYUIOPASDFGH":                             "an AWS access key ID",
		"ASIA" + "QWERTYUIOPASDFGH":                             "an AWS access key ID",
		"ghp_" + strings.Repeat("aB3", 12):                      "a GitHub token",
		"gho_" + strings.Repeat("aB3", 12):                      "a GitHub token",
		"ghs_" + strings.Repeat("aB3", 12):                      "a GitHub token",
		"ghu_" + strings.Repeat("aB3", 12):                      "a GitHub token",
		"github_pat_11ABCDEFG0123456789_abcdefghijklmnop":       "a GitHub token",
		"SSWS 00abcdefghijklmnopqrstuvwxyz":                     "an Okta API token",
		"xoxb-1234567890-abcdefghij":                            "a Slack token",
		"-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXk=": "a private key",
		base64.StdEncoding.EncodeToString(random[:]):            "a long token",
		hex.EncodeToString(random[:24]):                         "a long token",
		base64.StdEncoding.EncodeToString([]byte("cfg: ghp_" + strings.Repeat("aB3", 12))): "a GitHub token",
	}
	secrets := []canary{{key: "LONG", value: "supersecretvalue1"}, {key: "ENCODED", value: secret}}
	for text, want := range cases {
		leaks := scanScenario(Scenario{Responses: []Response{{URL: "https://a.example/", Body: text}}}, secrets, nil)
		found := false
		for _, l := range leaks {
			found = found || l.where == "responses[0].body" && l.what == want
		}
		if !found {
			t.Errorf("%q: leaks = %v, want %q", text, leaks, want)
		}
	}
	cert, key, _ := publicMaterialSamples(t)
	sha := sha512.Sum512_256([]byte("x"))
	clean := []string{
		hex.EncodeToString(sha[:]), strings.Repeat("a1b2c3d4e5", 4), "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ4In0.", "Bearer REDACTED", "SSWS REDACTED",
		"AKIAEXAMPLE000000001", "AKIAIOSFODNN7EXAMPLE", cert, key, sshKey(), "scrubbed-token-12", "AWSServiceRoleForAmazonGuardDutyMalwareProtection",
		"sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=", "Bearer token is invalid", "abc",
	}
	for _, text := range clean {
		if leaks := scanScenario(Scenario{Responses: []Response{{URL: "https://a.example/", Body: text}}}, []canary{{key: "SHORT", value: "abc"}}, nil); len(leaks) > 0 {
			t.Errorf("%q: flagged %v", text, leaks)
		}
	}
}

func TestTheScrubCheckLooksEverywhereARecordingHoldsText(t *testing.T) {
	token := "ghp_" + strings.Repeat("aB3", 12)
	sc := Scenario{
		Config: map[string]any{"org": token},
		Responses: []Response{{
			URL: "https://a.example/?t=" + token, RequestBody: `{"t":"` + token + `"}`,
			Header: http.Header{"Link": {"<https://a.example/?t=" + token + ">"}}, Body: token,
		}},
		DNS: []DNSRecord{{Name: "example.com", Type: "TXT", Values: []string{token}}},
	}
	var got []string
	for _, l := range scanScenario(sc, nil, nil) {
		got = append(got, l.where)
	}
	want := "config responses[0].url responses[0].request_body responses[0].header.Link responses[0].body dns[0].values"
	if strings.Join(got, " ") != want {
		t.Errorf("flagged %v, want %s", got, want)
	}
}

func TestIdentifiersOfDigitsAreReplacedWhereNoDigitAdjoins(t *testing.T) {
	ids := map[string]string{"4242": "7777"}
	s := newScrubber(nil, ScrubRules{Identifiers: ids})
	got := s.text(`{"app_id":4242,"other":142424,"path":"/apps/4242/hooks","name":"v4242a"}`)
	if want := `{"app_id":7777,"other":142424,"path":"/apps/7777/hooks","name":"v7777a"}`; got != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
	body := func(text string) Scenario {
		return Scenario{Responses: []Response{{URL: "https://a.example/", Body: text}}}
	}
	if leaks := scanScenario(body(`{"other":142424}`), nil, ids); len(leaks) > 0 {
		t.Errorf("a longer number holding the digits was flagged: %v", leaks)
	}
	if leaks := scanScenario(body(`{"app_id":4242}`), nil, ids); len(leaks) != 1 {
		t.Errorf("leaks = %v, want the identifier flagged", leaks)
	}
}

func TestTheScrubCheckFindsIdentifiersInAnyCaseAndEncoding(t *testing.T) {
	ids := map[string]string{"Acme Sandbox": "Example Org"}
	for _, text := range []string{
		"hello ACME SANDBOX",
		"q=acme+sandbox",
		"/orgs/acme%20sandbox/repos",
		base64.StdEncoding.EncodeToString([]byte("the team at Acme Sandbox writes these notes")),
	} {
		leaks := scanScenario(Scenario{Responses: []Response{{URL: "https://a.example/", Body: text}}}, nil, ids)
		if len(leaks) != 1 || leaks[0].what != "the tenant identifier ScrubRules.Identifiers replaces with Example Org" {
			t.Errorf("%q: leaks = %v, want the identifier flagged", text, leaks)
		}
	}
	s := newScrubber(nil, ScrubRules{Identifiers: ids})
	if got := s.text("hello ACME SANDBOX, q=acme+sandbox"); got != "hello Example Org, q=Example+Org" {
		t.Errorf("got %q, want each form replaced with its fake in the same encoding", got)
	}
}

func TestEnvIdentifiersCoverEveryVariableWithThePrefix(t *testing.T) {
	t.Setenv("KITTEST_DOMAIN", "acme-sandbox.dev")
	t.Setenv("KITTEST_ACCOUNT", "210987654321")
	t.Setenv("KITTEST_REGION_NAME", "north-pole-9")
	t.Setenv("KITTEST_SHORT", "ab1")
	t.Setenv("KITTEST_APP", "12")
	t.Setenv("OTHER_DOMAIN", "other.example")
	got := EnvIdentifiers("KITTEST_", map[string]string{"KITTEST_DOMAIN": "example.com", "KITTEST_APP": "99"})
	account := fakeDigits("KITTEST_ACCOUNT", 12)
	want := map[string]string{"acme-sandbox.dev": "example.com", "12": "99", "210987654321": account, "north-pole-9": "kittest-region-name"}
	if len(got) != len(want) {
		t.Errorf("got %v, want %v", got, want)
	}
	for value, fake := range want {
		if got[value] != fake {
			t.Errorf("%s: got fake %q, want %q", value, got[value], fake)
		}
	}
	if len(account) != 12 || account[0] == '0' || !isDigits(account) || account != fakeDigits("KITTEST_ACCOUNT", 12) {
		t.Errorf("fake account %q should be 12 stable digits that do not start with 0", account)
	}
}
