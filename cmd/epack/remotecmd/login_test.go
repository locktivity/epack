//go:build components

package remotecmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/locktivity/epack/internal/cli/output"
	"github.com/locktivity/epack/internal/remote"
	"github.com/locktivity/epack/internal/userconfig"
)

// loginAdapter answers like an adapter that signs in through the browser,
// and saves each request it reads into dir.
func loginAdapter(dir string) string {
	return `#!/bin/sh
case "$1" in
  --capabilities)
    echo '{"name":"mock","kind":"remote_adapter","deploy_protocol_version":1,"version":"1.0.0","features":{"prepare_finalize":true,"auth_login":true,"auth_browser":true,"whoami":true}}'
    ;;
  auth.login)
    cat > '` + filepath.Join(dir, "auth.login.json") + `'
    echo '{"ok":true,"type":"auth.login.result","instructions":{"authorization_url":"https://app.example.com/oauth/authorize?state=state-123","state":"state-123","session":"session-456","expires_in_seconds":600}}'
    ;;
  auth.complete)
    cat > '` + filepath.Join(dir, "auth.complete.json") + `'
    echo '{"ok":true,"type":"auth.complete.result","identity":{"authenticated":true,"subject":"dana@example.com","issuer":"https://app.example.com"}}'
    ;;
  *)
    echo '{"ok":false,"error":{"code":"unknown_command","message":"unknown command"}}'
    exit 1
    ;;
esac
`
}

// loginSetup writes a project whose mock adapter signs in through the
// browser and returns where the adapter saves its requests.
func loginSetup(t *testing.T) (requests string) {
	t.Helper()
	isolateHome(t)
	requests = t.TempDir()
	writeMockAdapterProject(t, loginAdapter(requests))
	return requests
}

func freePort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("finding a free port: %v", err)
	}
	defer func() { _ = listener.Close() }()
	return listener.Addr().(*net.TCPAddr).Port
}

// startLogin runs the login in the background with --no-browser on port,
// so the test can play the browser, and returns what the command writes.
func startLogin(port int, flags ...string) (done <-chan error, stdout, stderr *bytes.Buffer) {
	args := append([]string{"mock", "--no-browser", "--port", strconv.Itoa(port)}, flags...)
	cmd, stdout, stderr := rootCommand(newLoginCommand(), args...)
	finished := make(chan error, 1)
	go func() { finished <- cmd.Execute() }()
	return finished, stdout, stderr
}

var browserClient = &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{DisableKeepAlives: true}}

// visit sends a request to the login's listener the way a browser would,
// retrying until the listener is up.
func visit(t *testing.T, method string, port int, path string) (int, string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		req, err := http.NewRequest(method, fmt.Sprintf("http://127.0.0.1:%d%s", port, path), nil)
		if err != nil {
			t.Fatalf("building request: %v", err)
		}
		resp, err := browserClient.Do(req)
		if err == nil {
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			return resp.StatusCode, string(body)
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s %s: %v", method, path, err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func loginResult(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(20 * time.Second):
		t.Fatal("login did not finish")
		return nil
	}
}

func savedRequest(t *testing.T, path string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading the adapter's request: %v", err)
	}
	var request map[string]any
	if err := json.Unmarshal(data, &request); err != nil {
		t.Fatalf("parsing %s: %v", data, err)
	}
	return request
}

func TestRunLogin_SignsInThroughTheBrowser(t *testing.T) {
	requests := loginSetup(t)
	port := freePort(t)

	done, stdout, stderr := startLogin(port)
	status, page := visit(t, http.MethodGet, port, "/callback?code=code-789&state=state-123")
	if err := loginResult(t, done); err != nil {
		t.Fatalf("login: %v (stderr: %s)", err, stderr.String())
	}

	if status != http.StatusOK || !strings.Contains(page, "Signed in to mock") || !strings.Contains(page, "You can close this tab and return to your terminal.") {
		t.Errorf("page = %d %s", status, page)
	}
	got := stdout.String()
	for _, want := range []string{
		"Sign in to mock",
		"Open this link in your browser:\n  https://app.example.com/oauth/authorize?state=state-123\n",
		"Waiting for approval",
		"Signed in to mock as dana@example.com",
		"Next:",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("output missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "Your browser is open") {
		t.Errorf("--no-browser must not claim the browser is open:\n%s", got)
	}
	for _, secret := range []string{"session-456", "code-789"} {
		if strings.Contains(got+stderr.String(), secret) {
			t.Errorf("output shows %q:\n%s%s", secret, got, stderr.String())
		}
	}

	if login := savedRequest(t, filepath.Join(requests, "auth.login.json")); login["redirect_uri"] != fmt.Sprintf("http://127.0.0.1:%d/callback", port) {
		t.Errorf("auth.login request = %v", login)
	}
	complete := savedRequest(t, filepath.Join(requests, "auth.complete.json"))
	if complete["session"] != "session-456" || complete["code"] != "code-789" || complete["state"] != "state-123" {
		t.Errorf("auth.complete request = %v", complete)
	}
	if remoteName, err := userconfig.DefaultRemote(); err != nil || remoteName != "mock" {
		t.Errorf("default remote = %q, %v; want mock", remoteName, err)
	}
	if _, err := browserClient.Get(fmt.Sprintf("http://127.0.0.1:%d/callback", port)); err == nil {
		t.Error("the listener is still up after the sign-in finished")
	}
}

func TestRunLogin_JSONOutput(t *testing.T) {
	loginSetup(t)
	port := freePort(t)

	done, stdout, stderr := startLogin(port, "--json")
	visit(t, http.MethodGet, port, "/callback?code=code-789&state=state-123")
	if err := loginResult(t, done); err != nil {
		t.Fatalf("login: %v", err)
	}

	var result struct {
		Remote        string `json:"remote"`
		Authenticated bool   `json:"authenticated"`
		Subject       string `json:"subject"`
		DefaultRemote string `json:"default_remote"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("stdout is not only the JSON result: %v (%s)", err, stdout.String())
	}
	if result.Remote != "mock" || !result.Authenticated || result.Subject != "dana@example.com" || result.DefaultRemote != "mock" {
		t.Errorf("result = %+v", result)
	}
	if !strings.Contains(stderr.String(), "https://app.example.com/oauth/authorize?state=state-123") {
		t.Errorf("the link must still reach the person on stderr:\n%s", stderr.String())
	}
}

func TestRunLogin_CanceledInTheBrowser(t *testing.T) {
	requests := loginSetup(t)
	port := freePort(t)

	done, _, _ := startLogin(port)
	status, page := visit(t, http.MethodGet, port, "/callback?error=access_denied&error_description=The+person+canceled&state=state-123")
	err := loginResult(t, done)

	if err == nil || !strings.Contains(err.Error(), "sign-in canceled") {
		t.Fatalf("err = %v", err)
	}
	if status != http.StatusOK || !strings.Contains(page, "Sign-in canceled") || !strings.Contains(page, "You can close this tab.") {
		t.Errorf("page = %d %s", status, page)
	}
	if _, statErr := os.Stat(filepath.Join(requests, "auth.complete.json")); !os.IsNotExist(statErr) {
		t.Error("a canceled sign-in must not reach auth.complete")
	}
}

func TestRunLogin_ErrorFromTheRemote(t *testing.T) {
	loginSetup(t)
	port := freePort(t)

	done, _, _ := startLogin(port)
	status, page := visit(t, http.MethodGet, port, "/callback?error=server_error&error_description=The+sign-in+service+is+down&state=state-123")
	err := loginResult(t, done)

	if err == nil || !strings.Contains(err.Error(), "The sign-in service is down") {
		t.Fatalf("err = %v", err)
	}
	if status != http.StatusOK || !strings.Contains(page, "Sign-in failed") || !strings.Contains(page, "Return to your terminal for details.") {
		t.Errorf("page = %d %s", status, page)
	}
}

func TestRunLogin_IgnoresACallbackForAnotherSignIn(t *testing.T) {
	requests := loginSetup(t)
	port := freePort(t)

	done, _, _ := startLogin(port)
	status, page := visit(t, http.MethodGet, port, "/callback?code=stray-code&state=someone-else")
	if status != http.StatusBadRequest || !strings.Contains(page, "This link doesn&#39;t match the sign-in in your terminal") {
		t.Errorf("stray callback page = %d %s", status, page)
	}
	if _, statErr := os.Stat(filepath.Join(requests, "auth.complete.json")); !os.IsNotExist(statErr) {
		t.Fatal("a stray callback reached auth.complete")
	}

	visit(t, http.MethodGet, port, "/callback?code=code-789&state=state-123")
	if err := loginResult(t, done); err != nil {
		t.Fatalf("login: %v", err)
	}
	if complete := savedRequest(t, filepath.Join(requests, "auth.complete.json")); complete["code"] != "code-789" {
		t.Errorf("auth.complete request = %v", complete)
	}
}

func TestRunLogin_ServesOnlyTheCallback(t *testing.T) {
	requests := loginSetup(t)
	port := freePort(t)

	done, _, _ := startLogin(port)
	for _, probe := range []struct{ method, path string }{
		{http.MethodGet, "/"},
		{http.MethodGet, "/favicon.ico"},
		{http.MethodGet, "/callback/extra?code=code-789&state=state-123"},
		{http.MethodPost, "/callback?code=code-789&state=state-123"},
	} {
		if status, _ := visit(t, probe.method, port, probe.path); status != http.StatusNotFound {
			t.Errorf("%s %s = %d, want 404", probe.method, probe.path, status)
		}
	}
	if _, statErr := os.Stat(filepath.Join(requests, "auth.complete.json")); !os.IsNotExist(statErr) {
		t.Fatal("a request other than GET /callback reached auth.complete")
	}

	visit(t, http.MethodGet, port, "/callback?code=code-789&state=state-123")
	if err := loginResult(t, done); err != nil {
		t.Fatalf("login: %v", err)
	}
}

func TestRunLogin_TimesOut(t *testing.T) {
	loginSetup(t)
	previous := maxLoginWait
	maxLoginWait = 300 * time.Millisecond
	t.Cleanup(func() { maxLoginWait = previous })

	done, _, _ := startLogin(freePort(t))
	err := loginResult(t, done)
	if err == nil || !strings.Contains(err.Error(), "timed out") || !strings.Contains(err.Error(), "Run 'epack remote login mock' again") {
		t.Fatalf("err = %v", err)
	}
}

func TestRunLogin_AdapterWithoutBrowserSignIn(t *testing.T) {
	isolateHome(t)
	writeMockAdapterProject(t, `#!/bin/sh
echo '{"name":"mock","kind":"remote_adapter","deploy_protocol_version":1,"version":"1.0.0","features":{"prepare_finalize":true,"auth_login":true,"auth_wait":true}}'
`)
	cmd, _, _ := rootCommand(newLoginCommand(), "mock", "--no-browser")
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "this version of the mock adapter can't sign in. Update the adapter and try again.") {
		t.Fatalf("err = %v", err)
	}
}

func TestRunLogin_AdapterWithoutState(t *testing.T) {
	isolateHome(t)
	writeMockAdapterProject(t, strings.Replace(loginAdapter(t.TempDir()), `"state":"state-123",`, "", 1))
	done, _, _ := startLogin(0)
	err := loginResult(t, done)
	if err == nil || !strings.Contains(err.Error(), "the mock adapter did not return a sign-in link and state") {
		t.Fatalf("err = %v", err)
	}
}

func TestRunLogin_RejectsAPortOutOfRange(t *testing.T) {
	done, _, _ := startLogin(70000)
	err := loginResult(t, done)
	if err == nil || !strings.Contains(err.Error(), "--port must be between 1 and 65535") {
		t.Fatalf("err = %v", err)
	}
}

func TestRunLogin_AdapterWithoutLogin(t *testing.T) {
	isolateHome(t)
	writeMockAdapterProject(t, `#!/bin/sh
echo '{"name":"mock","kind":"remote_adapter","deploy_protocol_version":1,"version":"1.0.0","features":{"prepare_finalize":true}}'
`)
	cmd, _, _ := rootCommand(newLoginCommand(), "mock")
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "does not support signing in") {
		t.Fatalf("err = %v", err)
	}
}

func callbackRequest(t *testing.T, callback *loginCallback, query string) *httptest.ResponseRecorder {
	t.Helper()
	recorder := httptest.NewRecorder()
	callback.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/callback?"+query, nil))
	return recorder
}

func TestLoginCallback_FirstMatchingCallbackDecides(t *testing.T) {
	calls := 0
	callback := newLoginCallback("mock", "state-123", func(code string) (*remote.IdentityResult, error) {
		calls++
		return &remote.IdentityResult{Authenticated: true, Subject: "dana@example.com"}, nil
	})

	first := callbackRequest(t, callback, "code=code-789&state=state-123")
	second := callbackRequest(t, callback, "code=code-789&state=state-123")

	if !strings.Contains(first.Body.String(), "Signed in to mock") {
		t.Errorf("first page = %s", first.Body.String())
	}
	if second.Code != http.StatusOK || !strings.Contains(second.Body.String(), "Sign-in already finished") {
		t.Errorf("second page = %d %s", second.Code, second.Body.String())
	}
	if calls != 1 {
		t.Errorf("auth.complete ran %d times, want once", calls)
	}
	if outcome := <-callback.outcome; outcome.err != nil || outcome.identity.Subject != "dana@example.com" {
		t.Errorf("outcome = %+v", outcome)
	}
}

func TestLoginCallback_AdapterFailureShowsTheFailedPage(t *testing.T) {
	callback := newLoginCallback("mock", "state-123", func(code string) (*remote.IdentityResult, error) {
		return nil, &remote.AdapterError{AdapterName: "mock", Code: "invalid_request", Message: "the sign-in expired"}
	})

	page := callbackRequest(t, callback, "code=code-789&state=state-123")
	if !strings.Contains(page.Body.String(), "Sign-in failed") {
		t.Errorf("page = %s", page.Body.String())
	}
	if outcome := <-callback.outcome; outcome.err == nil || !strings.Contains(outcome.err.Error(), "the sign-in expired") {
		t.Errorf("outcome = %+v", outcome)
	}
}

func TestLoginCallback_MissingCodeFails(t *testing.T) {
	callback := newLoginCallback("mock", "state-123", func(code string) (*remote.IdentityResult, error) {
		t.Fatal("auth.complete must not run without a code")
		return nil, nil
	})

	page := callbackRequest(t, callback, "state=state-123")
	if !strings.Contains(page.Body.String(), "Sign-in failed") {
		t.Errorf("page = %s", page.Body.String())
	}
	if outcome := <-callback.outcome; outcome.err == nil {
		t.Error("a callback without a code must fail the sign-in")
	}
}

func TestLoginCallback_PagesAreSelfContainedAndEscaped(t *testing.T) {
	callback := newLoginCallback(`<script>alert(1)</script>`, "state-123", func(code string) (*remote.IdentityResult, error) {
		return &remote.IdentityResult{Authenticated: true}, nil
	})

	page := callbackRequest(t, callback, "code=code-789&state=state-123")
	body := page.Body.String()
	if strings.Contains(body, "<script>") || !strings.Contains(body, "&lt;script&gt;") {
		t.Errorf("the remote name was not escaped:\n%s", body)
	}
	for _, external := range []string{"src=", "href=", "@import", "url("} {
		if strings.Contains(body, external) {
			t.Errorf("page loads something from outside (%q):\n%s", external, body)
		}
	}
	if !strings.Contains(body, "prefers-color-scheme: dark") {
		t.Error("page has no dark variant")
	}
	if got := page.Header().Get("Content-Type"); got != "text/html; charset=utf-8" {
		t.Errorf("Content-Type = %q", got)
	}
	if got := page.Header().Get("Content-Security-Policy"); !strings.Contains(got, "default-src 'none'") {
		t.Errorf("Content-Security-Policy = %q", got)
	}
}

func TestLoginCallback_WaitsForACallbackAlreadyBeingFinished(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	callback := newLoginCallback("mock", "state-123", func(code string) (*remote.IdentityResult, error) {
		close(started)
		<-release
		return &remote.IdentityResult{Authenticated: true}, nil
	})
	go callbackRequest(t, callback, "code=code-789&state=state-123")
	<-started
	time.AfterFunc(100*time.Millisecond, func() { close(release) })

	if outcome := callback.wait(context.Background(), time.Millisecond); outcome.err != nil {
		t.Fatalf("a sign-in the adapter was finishing was reported as %v", outcome.err)
	}
}

func TestLoginCallback_ContextEndsTheWait(t *testing.T) {
	callback := newLoginCallback("mock", "state-123", nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	outcome := callback.wait(ctx, time.Minute)
	if outcome.err == nil || !strings.Contains(outcome.err.Error(), "sign-in canceled") {
		t.Fatalf("outcome = %+v", outcome)
	}
	if page := callbackRequest(t, callback, "code=code-789&state=state-123"); !strings.Contains(page.Body.String(), "Sign-in already finished") {
		t.Errorf("a callback after the wait ended = %s", page.Body.String())
	}
}

func TestPrintLoginInstructions(t *testing.T) {
	var opened, printed bytes.Buffer
	printLoginInstructions(output.New(&opened, io.Discard, output.Options{}), "mock", "https://app.example.com/a", true)
	printLoginInstructions(output.New(&printed, io.Discard, output.Options{}), "mock", "https://app.example.com/a", false)

	if want := "\nSign in to mock\n  Your browser is open. Allow epack there.\n  If it didn't open, open this link in your browser:\n  https://app.example.com/a\n"; opened.String() != want {
		t.Errorf("with the browser open:\n%q\nwant:\n%q", opened.String(), want)
	}
	if want := "\nSign in to mock\n  Open this link in your browser:\n  https://app.example.com/a\n"; printed.String() != want {
		t.Errorf("without a browser:\n%q\nwant:\n%q", printed.String(), want)
	}
}

func TestLoginWait_BoundsWhatTheAdapterAsksFor(t *testing.T) {
	for expires, want := range map[int]time.Duration{
		600:   10 * time.Minute,
		90:    90 * time.Second,
		0:     defaultLoginWait,
		-1:    defaultLoginWait,
		86400: maxLoginWait,
	} {
		if got := loginWait(expires); got != want {
			t.Errorf("loginWait(%d) = %s, want %s", expires, got, want)
		}
	}
}

func TestDescribeCallbackError(t *testing.T) {
	if got := describeCallbackError("server_error", "The service\x1b[2J is down"); got != "The service[2J is down (server_error)" {
		t.Errorf("describeCallbackError = %q", got)
	}
	if got := describeCallbackError("temporarily_unavailable", ""); got != "the remote reported temporarily_unavailable" {
		t.Errorf("describeCallbackError = %q", got)
	}
}

func TestRecordTrustedPublisher_SeedsTheListOnce(t *testing.T) {
	isolateHome(t)
	var stdout, stderr bytes.Buffer
	w := output.New(&stdout, &stderr, output.Options{})

	if !recordTrustedPublisher(w, "Locktivity") {
		t.Fatal("first login should record the publisher")
	}
	if recordTrustedPublisher(w, "locktivity") {
		t.Fatal("second login must not report it as new")
	}
	if recordTrustedPublisher(w, "") {
		t.Fatal("an adapter run from a binary has no publisher to record")
	}
	if got, err := userconfig.GetConfigValue("trusted_publishers"); err != nil || got != "locktivity" {
		t.Fatalf("trusted_publishers = %q, %v", got, err)
	}
}

func TestPublisherOf(t *testing.T) {
	for source, want := range map[string]string{
		"locktivity/epack-remote-locktivity@^0.1":            "locktivity",
		"github.com/Locktivity/epack-remote-locktivity@v0.1": "locktivity",
		"":         "",
		"nonsense": "",
	} {
		if got := publisherOf(source); got != want {
			t.Errorf("publisherOf(%q) = %q, want %q", source, got, want)
		}
	}
}
