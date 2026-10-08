//go:build components

package remotecmd

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"time"

	"github.com/locktivity/epack/internal/cli/browser"
	"github.com/locktivity/epack/internal/cli/output"
	"github.com/locktivity/epack/internal/componenttypes"
	"github.com/locktivity/epack/internal/remote"
	"github.com/locktivity/epack/internal/userconfig"
	"github.com/spf13/cobra"
)

var (
	loginNoBrowser             bool
	loginPort                  int
	loginInsecureAllowUnpinned bool
)

const (
	callbackPath     = "/callback"
	defaultLoginWait = 10 * time.Minute
)

// maxLoginWait bounds the wait whatever lifetime the adapter reports. Tests
// shorten it to reach the timeout.
var maxLoginWait = 15 * time.Minute

func newLoginCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "login <remote>",
		Short: "Sign in to a remote from this machine",
		Long: `Sign in to a remote with your browser.

epack opens the remote's sign-in page in your browser. Once you allow epack
there, the browser returns to epack at 127.0.0.1 on this machine and the
adapter finishes the sign-in. The session is kept wherever the adapter
stores credentials, so later runs need no token.

With --no-browser, epack prints the link for you to open instead. Over SSH,
forward a fixed port when you connect and give epack the same port, then
open the link in the browser on your own computer:

  ssh -L 8400:127.0.0.1:8400 host
  epack remote login <remote> --port 8400 --no-browser

Outside a project, the adapter is installed for your user from the catalog
and verified before it runs. Inside a project that names the remote, the
project's pinned adapter is used.

Examples:
  epack remote login locktivity
  epack remote login locktivity --no-browser`,
		Args: cobra.ExactArgs(1),
		RunE: runLogin,
	}

	cmd.Flags().BoolVar(&loginNoBrowser, "no-browser", false, "print the link instead of opening a browser")
	cmd.Flags().IntVar(&loginPort, "port", 0, "port on 127.0.0.1 the browser returns to (0 picks a free one)")
	loginInsecureAllowUnpinned = componenttypes.InsecureAllowUnpinnedFromEnv()
	cmd.Flags().BoolVar(&loginInsecureAllowUnpinned, "insecure-allow-unpinned", loginInsecureAllowUnpinned,
		"allow using adapters not pinned in lockfile (NOT RECOMMENDED)")

	return cmd
}

func runLogin(cmd *cobra.Command, args []string) error {
	remoteName := args[0]
	out := getOutput(cmd)
	ctx := cmdContext(cmd)
	ui := newCommandUI(out, "", "", "Sign-in failed")

	if loginPort < 0 || loginPort > 65535 {
		return exitError("login failed: --port must be between 1 and 65535, or 0 for a free port")
	}

	prepared, err := PrepareRemote(ctx, remoteName, PrepareOptions{
		AllowUnpinned: loginInsecureAllowUnpinned,
		Step:          ui.onStep,
		PromptInstall: func(remoteName, adapterName string) bool {
			return ui.promptInstallAdapter(remoteName, adapterName, true)
		},
		Stderr: os.Stderr,
	})
	if err != nil {
		ui.fail()
		return exitError("login failed: %v", err)
	}
	defer prepared.Close()

	if !prepared.Caps.SupportsAuthLogin() {
		return exitError("login failed: the %s adapter does not support signing in", remoteName)
	}
	if !prepared.Caps.SupportsAuthBrowser() {
		update := "Update the adapter"
		if prepared.ProjectRoot == "" {
			update = fmt.Sprintf("Update it with 'epack remote update %s'", remoteName)
		}
		return exitError("login failed: this version of the %s adapter can't sign in. %s and try again.", remoteName, update)
	}

	ctx, stop := signal.NotifyContext(ctx, os.Interrupt)
	defer stop()
	identity, err := signIn(ctx, out, prepared.Exec, remoteName)
	if err != nil {
		return err
	}
	if err := userconfig.SetDefaultRemote(remoteName); err != nil {
		out.Warning("could not record %s as the default remote: %v", remoteName, err)
	}
	trustedNow := recordTrustedPublisher(out, prepared.Publisher)

	if out.IsJSON() {
		return out.JSON(map[string]interface{}{
			"remote":            remoteName,
			"authenticated":     identity.Authenticated,
			"subject":           identity.Subject,
			"issuer":            identity.Issuer,
			"expires_at":        identity.ExpiresAt,
			"default_remote":    remoteName,
			"trusted_publisher": prepared.Publisher,
		})
	}

	p := out.Palette()
	out.Print("\n%s Signed in to %s", p.Green("✓"), p.Bold(remoteName))
	if identity.Subject != "" {
		out.Print(" as %s", output.Printable(identity.Subject))
	}
	out.Print("\n")
	out.Print("  %s is now the remote that epack run <name> uses.\n", remoteName)
	if trustedNow {
		out.Print("  github.com/%s is now a trusted publisher for configurations you fetch.\n", prepared.Publisher)
	}
	out.Print("\n%s\n", p.Dim("Next:"))
	out.Print("%s  epack run <name>   %s\n", p.Dim("  •"), p.Dim("# Fetch a configuration and run it"))
	return nil
}

// signIn has the adapter start a browser sign-in that returns to a listener
// on 127.0.0.1, then hands what the browser brings back to the adapter to
// finish.
func signIn(ctx context.Context, out *output.Writer, exec *remote.Executor, remoteName string) (*remote.IdentityResult, error) {
	listener, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(loginPort)))
	if err != nil {
		return nil, exitError("login failed: could not listen on 127.0.0.1 for the browser to return to: %v", err)
	}
	defer func() { _ = listener.Close() }()
	redirectURI := fmt.Sprintf("http://127.0.0.1:%d%s", listener.Addr().(*net.TCPAddr).Port, callbackPath)

	resp, err := exec.AuthLogin(ctx, redirectURI)
	if err != nil {
		return nil, exitError("login failed: %v", adapterMessage(err))
	}
	instructions := resp.Instructions
	if instructions.AuthorizationURL == "" || instructions.State == "" {
		return nil, exitError("login failed: the %s adapter did not return a sign-in link and state", remoteName)
	}

	callback := newLoginCallback(remoteName, instructions.State, func(code string) (*remote.IdentityResult, error) {
		resp, err := exec.AuthComplete(ctx, instructions.Session, code, instructions.State)
		if err != nil {
			return nil, err
		}
		return &resp.Identity, nil
	})
	server := &http.Server{
		Handler:           callback,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       30 * time.Second,
		// Requests carry the code and state, so the server logs nothing.
		ErrorLog: log.New(io.Discard, "", 0),
	}
	go func() { _ = server.Serve(listener) }()
	defer shutdownCallbackServer(server)

	opened := false
	if !loginNoBrowser {
		switch err := browser.Open(ctx, instructions.AuthorizationURL); {
		case err == nil:
			opened = true
		case errors.Is(err, browser.ErrUnsupportedURL):
			out.Warning("the sign-in link is not an http or https URL, so it was not opened")
		}
	}
	printLoginInstructions(out, remoteName, output.Printable(instructions.AuthorizationURL), opened)

	spinner := out.StartSpinner("Waiting for approval")
	outcome := callback.wait(ctx, loginWait(instructions.ExpiresInSecs))
	if outcome.err != nil {
		spinner.Fail(outcome.summary)
		return nil, outcome.err
	}
	spinner.Success(outcome.summary)
	return outcome.identity, nil
}

// printLoginInstructions tells the person where to allow epack. Under --json
// they go to stderr, so stdout carries only the result.
func printLoginInstructions(out *output.Writer, remoteName, link string, opened bool) {
	write := out.Print
	if out.IsJSON() {
		write = out.Notice
	}
	write("\nSign in to %s\n", out.Palette().Bold(remoteName))
	if opened {
		write("  Your browser is open. Allow epack there.\n")
		write("  If it didn't open, open this link in your browser:\n")
	} else {
		write("  Open this link in your browser:\n")
	}
	write("  %s\n", link)
}

func loginWait(expiresInSecs int) time.Duration {
	wait := time.Duration(expiresInSecs) * time.Second
	if wait <= 0 {
		wait = defaultLoginWait
	}
	return min(wait, maxLoginWait)
}

// shutdownCallbackServer stops listening and lets a page still being written
// reach the browser before its connection closes.
func shutdownCallbackServer(server *http.Server) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		_ = server.Close()
	}
}

type loginOutcome struct {
	identity *remote.IdentityResult
	// summary is how the spinner ends.
	summary string
	err     error
}

// loginCallback answers the browser's return. The first callback that
// carries the sign-in's state decides the outcome; one without it belongs to
// some other sign-in and is turned away.
type loginCallback struct {
	remoteName string
	state      string
	complete   func(code string) (*remote.IdentityResult, error)
	outcome    chan loginOutcome

	mu      sync.Mutex
	decided bool
}

func newLoginCallback(remoteName, state string, complete func(code string) (*remote.IdentityResult, error)) *loginCallback {
	return &loginCallback{
		remoteName: remoteName,
		state:      state,
		complete:   complete,
		outcome:    make(chan loginOutcome, 1),
	}
}

func (c *loginCallback) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet || r.URL.Path != callbackPath {
		http.NotFound(w, r)
		return
	}
	query := r.URL.Query()
	if subtle.ConstantTimeCompare([]byte(query.Get("state")), []byte(c.state)) != 1 {
		writeLoginPage(w, http.StatusBadRequest, pageMismatch)
		return
	}
	if !c.claim() {
		writeLoginPage(w, http.StatusOK, pageFinished)
		return
	}
	outcome, page := c.finish(query)
	writeLoginPage(w, http.StatusOK, page)
	c.outcome <- outcome
}

// finish decides the sign-in from the callback: the error the browser
// brought back if there is one, otherwise the adapter's exchange of the code.
func (c *loginCallback) finish(query url.Values) (loginOutcome, loginPage) {
	switch reason := query.Get("error"); {
	case reason == "access_denied":
		return loginOutcome{summary: "Sign-in canceled", err: exitError("login failed: sign-in canceled in the browser")}, pageCanceled
	case reason != "":
		return loginOutcome{summary: "Sign-in failed", err: exitError("login failed: %s", describeCallbackError(reason, query.Get("error_description")))}, pageFailed
	}
	code := query.Get("code")
	if code == "" {
		return loginOutcome{summary: "Sign-in failed", err: exitError("login failed: the browser returned without a sign-in code")}, pageFailed
	}
	identity, err := c.complete(code)
	if err != nil {
		return loginOutcome{summary: "Sign-in failed", err: exitError("login failed: %v", adapterMessage(err))}, pageFailed
	}
	return loginOutcome{identity: identity, summary: "Approved"}, loginPage{
		Heading: "Signed in to " + c.remoteName,
		Text:    "You can close this tab and return to your terminal.",
	}
}

// wait returns what the browser decided, or ends the sign-in itself when the
// time runs out or ctx is done. A callback the adapter is still finishing is
// waited for, so a sign-in that went through is never reported as failed.
func (c *loginCallback) wait(ctx context.Context, limit time.Duration) loginOutcome {
	timer := time.NewTimer(limit)
	defer timer.Stop()
	select {
	case outcome := <-c.outcome:
		return outcome
	case <-timer.C:
		if c.claim() {
			return loginOutcome{summary: "Sign-in timed out", err: exitError("login failed: the sign-in timed out. Run 'epack remote login %s' again.", c.remoteName)}
		}
	case <-ctx.Done():
		if c.claim() {
			return loginOutcome{summary: "Sign-in canceled", err: exitError("login failed: sign-in canceled")}
		}
	}
	return <-c.outcome
}

func (c *loginCallback) claim() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.decided {
		return false
	}
	c.decided = true
	return true
}

func describeCallbackError(reason, description string) string {
	reason, description = output.Printable(reason), output.Printable(description)
	if description == "" {
		return "the remote reported " + reason
	}
	return description + " (" + reason + ")"
}

type loginPage struct {
	Heading string
	Text    string
}

var (
	pageCanceled = loginPage{Heading: "Sign-in canceled", Text: "You can close this tab."}
	pageFailed   = loginPage{Heading: "Sign-in failed", Text: "Return to your terminal for details."}
	pageMismatch = loginPage{Heading: "This link doesn't match the sign-in in your terminal", Text: "Return to your terminal and use the link it printed."}
	pageFinished = loginPage{Heading: "Sign-in already finished", Text: "You can close this tab."}
)

var loginPageTemplate = template.Must(template.New("login").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Heading}}</title>
<style>
:root { color-scheme: light dark; --bg: #f6f6f7; --card: #ffffff; --text: #18181b; --muted: #52525b; --border: #e4e4e7; }
@media (prefers-color-scheme: dark) {
  :root { --bg: #18181b; --card: #232327; --text: #f4f4f5; --muted: #a1a1aa; --border: #3f3f46; }
}
body { margin: 0; min-height: 100vh; display: flex; align-items: center; justify-content: center; background: var(--bg); color: var(--text); font: 16px/1.5 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; }
main { box-sizing: border-box; width: 100%; max-width: 28rem; margin: 16px; padding: 32px; background: var(--card); border: 1px solid var(--border); border-radius: 12px; }
h1 { margin: 0 0 8px; font-size: 20px; line-height: 1.3; }
p { margin: 0; color: var(--muted); }
</style>
</head>
<body>
<main>
<h1>{{.Heading}}</h1>
<p>{{.Text}}</p>
</main>
</body>
</html>
`))

func writeLoginPage(w http.ResponseWriter, status int, page loginPage) {
	header := w.Header()
	header.Set("Content-Type", "text/html; charset=utf-8")
	header.Set("Cache-Control", "no-store")
	header.Set("Referrer-Policy", "no-referrer")
	header.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'")
	w.WriteHeader(status)
	_ = loginPageTemplate.Execute(w, page)
}

// recordTrustedPublisher trusts the adapter's publisher for fetched
// configurations, since signing in already means trusting what that
// publisher's remote sends. It reports whether the name was new.
func recordTrustedPublisher(out *output.Writer, publisher string) bool {
	if publisher == "" {
		return false
	}
	added, err := userconfig.TrustPublisher(publisher)
	if err != nil {
		out.Warning("could not record github.com/%s as a trusted publisher: %v", publisher, err)
		return false
	}
	return added
}
