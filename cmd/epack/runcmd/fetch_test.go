//go:build components

package runcmd

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/locktivity/epack/cmd/epack/remotecmd"
	"github.com/locktivity/epack/internal/component/lockfile"
	componentsync "github.com/locktivity/epack/internal/component/sync"
	"github.com/locktivity/epack/internal/componenttypes"
	"github.com/locktivity/epack/internal/platform"
	"github.com/locktivity/epack/internal/remote"
	"github.com/locktivity/epack/internal/runflow"
	"github.com/locktivity/epack/internal/testutil/testhome"
	"github.com/locktivity/epack/internal/userconfig"
	"github.com/locktivity/epack/internal/version"
)

const testPipelineID = "0b9c7a52-6f2e-4d1a-9f3b-2c4d5e6f7a8b"

// fakeLocktivity stands in for the Locktivity adapter. It logs each request
// with the session it was handed and answers config.pull from files the
// test writes into HOME: the fallback when the request asks for one, an older
// one when it also names OLD_TOKEN, and the remote's reason none runs when
// the test wrote none. A test that writes fallback-error gets not_found.
const fakeLocktivity = `#!/bin/sh
if [ "$1" = "--capabilities" ]; then
  echo ran >> "$HOME/capabilities.log"
  echo '{"name":"locktivity","kind":"remote_adapter","deploy_protocol_version":1,"version":"1.0.0","features":{"prepare_finalize":true,"config_pull":true,"lock_report":true}}'
  exit 0
fi
request=$(cat)
printf '%s\t%s\t%s\n' "$1" "${LOCKTIVITY_ACCESS_TOKEN:-none}" "$request" >> "$HOME/adapter.log"
case "$1" in
  config.pull)
    case "$request" in
      *'"fallback"'*)
        case "$request" in
          *OLD_TOKEN*) answer="$HOME/fallback-older.json" ;;
          *) answer="$HOME/fallback.json" ;;
        esac
        if [ -f "$HOME/fallback-error" ]; then
          echo '{"ok":false,"type":"error","error":{"code":"not_found","message":"pipeline not found"}}'
          exit 1
        elif [ -f "$answer" ]; then
          cat "$answer"
        else
          echo '{"ok":true,"type":"config.pull.result","no_fallback":{"reason":"Every revision before 3 needs SENTRY_AUTH_TOKEN or OLD_TOKEN, or runs something a later revision removed."}}'
        fi ;;
      *) cat "$HOME/current.json" ;;
    esac ;;
  push.prepare) echo '{"ok":true,"type":"push.prepare.result","upload":{"method":"skip"},"finalize_token":"ft_1"}' ;;
  push.finalize) echo '{"ok":true,"type":"push.finalize.result","release":{"release_id":"rel_1","pack_digest":"sha256:0","created_at":"2026-10-15T00:00:00Z","canonical_ref":"rel_1"}}' ;;
  lock.report) echo '{"ok":true,"type":"lock.report.result","status":"recorded"}' ;;
  *) echo '{"ok":false,"type":"error","error":{"code":"unknown_command","message":"unknown command"}}'; exit 1 ;;
esac
`

const revisionOne = `stream: northwind/production
remotes:
  locktivity:
    source: locktivity/epack-remote-locktivity@v1.0.0
`

const revisionTwo = revisionOne + `collectors:
  sentry:
    source: locktivity/epack-collector-sentry@v0.3.1
    secrets:
      - SENTRY_AUTH_TOKEN
`

// fetchHarness is an empty workspace on a CI runner: an isolated home with
// the Locktivity adapter installed for the user, a credential broker, and
// the job's variables. Nothing in it names the remote or the pipeline's
// credential sets.
type fetchHarness struct {
	t      *testing.T
	home   string
	work   string
	digest string

	mu        sync.Mutex
	sessions  []string
	ranIn     []string
	ranConfig []string
}

func newFetchHarness(t *testing.T) *fetchHarness {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell script adapters are not available on Windows")
	}
	h := &fetchHarness{t: t, home: testhome.Isolate(t)}
	sum := sha256.Sum256([]byte(fakeLocktivity))
	h.digest = "sha256:" + hex.EncodeToString(sum[:])
	h.installUserAdapter()

	broker := httptest.NewTLSServer(http.HandlerFunc(h.serveBroker))
	t.Cleanup(broker.Close)
	previousTransport := http.DefaultTransport
	http.DefaultTransport = broker.Client().Transport
	t.Cleanup(func() { http.DefaultTransport = previousTransport })

	for name, value := range map[string]string{
		"EPACK_INSECURE_CREDENTIAL_BROKER_URL": broker.URL,
		"EPACK_PIPELINE_ID":                    testPipelineID,
		"EPACK_TRUSTED_PUBLISHERS":             "locktivity",
		"LOCKTIVITY_ID_TOKEN":                  "",
		"EPACK_SIGNING_KEY":                    "",
		"EPACK_CHECK":                          "",
		"SENTRY_AUTH_TOKEN":                    "",
		"CI":                                   "true",
	} {
		t.Setenv(name, value)
	}

	work, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	h.work = work
	oldWd, _ := os.Getwd()
	if err := os.Chdir(work); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldWd) })

	previousWorkflow := runWorkflow
	runWorkflow = h.workflow
	t.Cleanup(func() { runWorkflow = previousWorkflow; runKey = "" })
	return h
}

func (h *fetchHarness) installUserAdapter() {
	h.t.Helper()
	dir := filepath.Join(h.home, ".epack")
	h.installAdapter(dir)
	lf := lockfile.New()
	lf.Remotes["locktivity"] = lockfile.LockedRemote{
		Source:    "github.com/locktivity/epack-remote-locktivity",
		Version:   "v1.0.0",
		Platforms: map[string]componenttypes.LockedPlatform{platform.Key(runtime.GOOS, runtime.GOARCH): {Digest: h.digest}},
	}
	if err := userconfig.SaveRemotesLockToPath(filepath.Join(dir, userconfig.RemotesLockFile), lf); err != nil {
		h.t.Fatalf("saving the user lock: %v", err)
	}
}

func (h *fetchHarness) installAdapter(baseDir string) {
	h.t.Helper()
	path, err := componentsync.InstallPath(baseDir, componenttypes.KindRemote, "locktivity", "v1.0.0", "locktivity")
	if err != nil {
		h.t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		h.t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(fakeLocktivity), 0o755); err != nil {
		h.t.Fatal(err)
	}
}

func (h *fetchHarness) serveBroker(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.URL.Path != "/oidc/v1/pipelines/"+testPipelineID+"/session" {
		http.NotFound(w, r)
		return
	}
	h.mu.Lock()
	h.sessions = append(h.sessions, strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	h.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_, _ = io.WriteString(w, `{"env":{"LOCKTIVITY_ACCESS_TOKEN":"ltk_session"},"expires_at":"2030-01-01T00:00:00Z"}`)
}

// workflow runs the real stages. The pinned adapter is placed where the
// install stage would download it, and the pack goes unsigned, since
// signing reaches the Sigstore log.
func (h *fetchHarness) workflow(ctx context.Context, opts runflow.Options) (*runflow.Result, error) {
	config, err := os.ReadFile(filepath.Join(opts.WorkDir, "epack.yaml"))
	if err != nil {
		h.t.Fatalf("reading the configuration the run uses: %v", err)
	}
	h.ranIn = append(h.ranIn, opts.WorkDir)
	h.ranConfig = append(h.ranConfig, string(config))
	h.installAdapter(filepath.Join(opts.WorkDir, ".epack"))
	opts.Unsigned = true
	return runflow.Run(ctx, opts)
}

// offer writes the revision config.pull answers with: current.json for a
// fetch, fallback.json for a fallback.
func (h *fetchHarness) offer(file string, revision int, config string, extra map[string]any) {
	h.t.Helper()
	result := map[string]any{
		"id":       testPipelineID,
		"name":     "northwind-production",
		"title":    "Northwind production",
		"revision": revision,
		"files":    map[string]string{"epack.yaml": config},
		"lockfile": fmt.Sprintf("schema_version: 1\nremotes:\n  locktivity:\n    source: github.com/locktivity/epack-remote-locktivity\n    version: v1.0.0\n    platforms:\n      %s:\n        digest: %s\n", platform.Key(runtime.GOOS, runtime.GOARCH), h.digest),
	}
	for key, value := range extra {
		result[key] = value
	}
	body, err := json.Marshal(map[string]any{"ok": true, "type": "config.pull.result", "config": result})
	if err != nil {
		h.t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(h.home, file), body, 0o600); err != nil {
		h.t.Fatal(err)
	}
}

type adapterCall struct {
	command string
	session string
	request map[string]any
}

func (h *fetchHarness) calls() []adapterCall {
	h.t.Helper()
	data, err := os.ReadFile(filepath.Join(h.home, "adapter.log"))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		h.t.Fatal(err)
	}
	var calls []adapterCall
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	scanner.Buffer(make([]byte, 1<<20), 1<<20)
	for scanner.Scan() {
		parts := strings.SplitN(scanner.Text(), "\t", 3)
		if len(parts) != 3 {
			continue
		}
		call := adapterCall{command: parts[0], session: parts[1]}
		if err := json.Unmarshal([]byte(parts[2]), &call.request); err != nil {
			h.t.Fatalf("adapter request %q: %v", parts[2], err)
		}
		calls = append(calls, call)
	}
	return calls
}

func (h *fetchHarness) called(command string) []adapterCall {
	var out []adapterCall
	for _, call := range h.calls() {
		if call.command == command {
			out = append(out, call)
		}
	}
	return out
}

func (h *fetchHarness) run(args ...string) (string, error) {
	h.t.Helper()
	cmd := NewCommand()
	cmd.SetArgs(args)
	var err error
	stdout := captureStdout(h.t, func() { err = cmd.Execute() })
	return stdout, err
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	previous := os.Stdout
	os.Stdout = writer
	done := make(chan string)
	go func() {
		data, _ := io.ReadAll(reader)
		done <- string(data)
	}()
	defer func() { os.Stdout = previous }()
	fn()
	_ = writer.Close()
	return <-done
}

func writeTestKey(t *testing.T) (path, fingerprint string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	path = filepath.Join(t.TempDir(), "runner.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	public, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(public)
	return path, hex.EncodeToString(sum[:])
}

func jwtPart(t *testing.T, token string, index int) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWS: %q", token)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[index])
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestRun_EmptyWorkspaceSignsInWithTheGitLabIDTokenThenFetchesAndPushes(t *testing.T) {
	h := newFetchHarness(t)
	t.Setenv("LOCKTIVITY_ID_TOKEN", "gitlab-id-token")
	h.offer("current.json", 1, revisionOne, nil)

	out, err := h.run("northwind-production", "--remote", "locktivity", "--yes")
	if err != nil {
		t.Fatalf("run: %v\n%s", err, out)
	}

	if len(h.sessions) == 0 || h.sessions[0] != "gitlab-id-token" {
		t.Fatalf("broker sessions = %v, want the job's ID token", h.sessions)
	}
	pulls := h.called("config.pull")
	if len(pulls) != 1 {
		t.Fatalf("config.pull calls = %d, want 1", len(pulls))
	}
	if pulls[0].session != "ltk_session" {
		t.Errorf("the fetch signed in with %q, want the pipeline's session", pulls[0].session)
	}
	if purpose := pulls[0].request["config"].(map[string]any)["purpose"]; purpose != "run" {
		t.Errorf("purpose = %v, want run", purpose)
	}
	if len(h.called("push.finalize")) != 1 {
		t.Fatalf("expected one push, adapter saw %+v\n%s", h.calls(), out)
	}
	if want := filepath.Join(h.work, "northwind-production"); len(h.ranIn) != 1 || h.ranIn[0] != want {
		t.Errorf("ran in %v, want %s", h.ranIn, want)
	}
}

func TestRun_EmptyWorkspaceSignsInWithAKeyThenFetchesAndPushes(t *testing.T) {
	h := newFetchHarness(t)
	keyPath, fingerprint := writeTestKey(t)
	h.offer("current.json", 1, revisionOne, nil)

	out, err := h.run("northwind-production", "--remote", "locktivity", "--yes", "--key", keyPath)
	if err != nil {
		t.Fatalf("run: %v\n%s", err, out)
	}

	if len(h.sessions) == 0 {
		t.Fatal("the run never signed in at the broker")
	}
	header, claims := jwtPart(t, h.sessions[0], 0), jwtPart(t, h.sessions[0], 1)
	if header["kid"] != fingerprint {
		t.Errorf("kid = %v, want the key's fingerprint %s", header["kid"], fingerprint)
	}
	if claims["iss"] != "epack-key" || claims["sub"] != testPipelineID {
		t.Errorf("claims = %v, want iss epack-key naming the pipeline", claims)
	}
	pulls := h.called("config.pull")
	if len(pulls) != 1 || pulls[0].session != "ltk_session" {
		t.Fatalf("config.pull = %+v, want one fetch with the pipeline's session", pulls)
	}
	if len(h.called("push.finalize")) != 1 {
		t.Fatalf("expected one push, adapter saw %+v\n%s", h.calls(), out)
	}
}

func TestRun_FallsBackToAnEarlierRevisionWhenAVariableIsMissing(t *testing.T) {
	h := newFetchHarness(t)
	t.Setenv("LOCKTIVITY_ID_TOKEN", "gitlab-id-token")
	h.offer("current.json", 2, revisionTwo, map[string]any{
		"changes_since": 1,
		"changes":       []string{"Collectors added: Sentry"},
		"requirements": map[string]any{"hints": []map[string]string{{
			"name": "SENTRY_AUTH_TOKEN",
			"text": "Add it as a masked CI/CD variable in northwind/compliance",
			"url":  "https://gitlab.com/northwind/compliance/-/settings/ci_cd",
		}}},
	})
	h.offer("fallback.json", 1, revisionOne, nil)

	out, err := h.run("northwind-production", "--remote", "locktivity", "--yes")
	if err != nil {
		t.Fatalf("run: %v\n%s", err, out)
	}

	pulls := h.called("config.pull")
	if len(pulls) != 2 {
		t.Fatalf("config.pull calls = %d, want the fetch and the fallback", len(pulls))
	}
	fallback, _ := pulls[1].request["config"].(map[string]any)["fallback"].(map[string]any)
	if fallback == nil || fallback["revision"] != float64(2) {
		t.Fatalf("fallback request = %v, want one for revision 2", pulls[1].request)
	}
	missing, _ := json.Marshal(fallback["missing"])
	if string(missing) != `[{"kind":"variable","name":"SENTRY_AUTH_TOKEN"}]` {
		t.Errorf("fallback reported %s, want SENTRY_AUTH_TOKEN by name", missing)
	}
	if want := filepath.Join(h.work, "northwind-production", filepath.FromSlash(remotecmd.FallbackFolder)); len(h.ranIn) != 1 || h.ranIn[0] != want {
		t.Fatalf("ran in %v, want the fallback folder %s", h.ranIn, want)
	}
	if h.ranConfig[0] != revisionOne {
		t.Errorf("ran configuration:\n%s\nwant revision 1", h.ranConfig[0])
	}
	current, err := os.ReadFile(filepath.Join(h.work, "northwind-production", "epack.yaml"))
	if err != nil || string(current) != revisionTwo {
		t.Errorf("the fetched folder should keep revision 2 for the person to complete: %q, %v", current, err)
	}
	for _, want := range []string{
		"Collectors added: Sentry",
		"Revision 2 needs what this runner does not have",
		"SENTRY_AUTH_TOKEN is not set. Add it as a masked CI/CD variable in northwind/compliance: https://gitlab.com/northwind/compliance/-/settings/ci_cd",
		"Running revision 1, the newest earlier revision that runs here",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("job log missing %q:\n%s", want, out)
		}
	}
	if len(h.called("push.finalize")) != 1 {
		t.Errorf("the fallback run should still push, adapter saw %+v", h.calls())
	}
}

const revisionNeedsOldToken = revisionOne + `collectors:
  legacy:
    source: locktivity/epack-collector-legacy@v0.1.0
    secrets:
      - OLD_TOKEN
`

func TestRun_AsksAgainWhenTheEarlierRevisionLacksSomethingToo(t *testing.T) {
	h := newFetchHarness(t)
	t.Setenv("LOCKTIVITY_ID_TOKEN", "gitlab-id-token")
	h.offer("current.json", 3, revisionTwo, nil)
	h.offer("fallback.json", 2, revisionNeedsOldToken, nil)
	h.offer("fallback-older.json", 1, revisionOne, nil)

	out, err := h.run("northwind-production", "--remote", "locktivity", "--yes")
	if err != nil {
		t.Fatalf("run: %v\n%s", err, out)
	}

	pulls := h.called("config.pull")
	if len(pulls) != 3 {
		t.Fatalf("config.pull calls = %d, want the fetch and two fallbacks", len(pulls))
	}
	second, _ := pulls[2].request["config"].(map[string]any)["fallback"].(map[string]any)
	missing, _ := json.Marshal(second["missing"])
	if second["revision"] != float64(3) || string(missing) != `[{"kind":"variable","name":"SENTRY_AUTH_TOKEN"},{"kind":"variable","name":"OLD_TOKEN"}]` {
		t.Fatalf("second fallback = %v, want revision 3 and both names", second)
	}
	if len(h.ranConfig) != 1 || h.ranConfig[0] != revisionOne {
		t.Fatalf("ran %v, want revision 1", h.ranConfig)
	}
}

func TestRun_StopsWhenNoEarlierRevisionRunsHere(t *testing.T) {
	h := newFetchHarness(t)
	t.Setenv("LOCKTIVITY_ID_TOKEN", "gitlab-id-token")
	h.offer("current.json", 3, revisionTwo, nil)
	h.offer("fallback.json", 2, revisionNeedsOldToken, nil)

	out, err := h.run("northwind-production", "--remote", "locktivity", "--yes")
	if err == nil || !strings.Contains(err.Error(), "revision 3 needs SENTRY_AUTH_TOKEN, and no earlier revision runs here without it") {
		t.Fatalf("err = %v, want the run stopped", err)
	}
	if !strings.Contains(out, "Every revision before 3 needs SENTRY_AUTH_TOKEN or OLD_TOKEN, or runs something a later revision removed.") {
		t.Errorf("the job log should say why no earlier revision runs:\n%s", out)
	}
	if len(h.ranIn) != 0 {
		t.Fatalf("nothing should run, ran in %v", h.ranIn)
	}
	reports := h.called("lock.report")
	if len(reports) != 1 {
		t.Fatalf("the stop should be reported once, adapter saw %+v", h.calls())
	}
	provenance := reports[0].request["lock_provenance"].(map[string]any)
	requirements, _ := json.Marshal(provenance["metadata"].(map[string]any)["requirements"])
	if string(requirements) != `{"missing":[{"kind":"variable","name":"SENTRY_AUTH_TOKEN"},{"kind":"variable","name":"OLD_TOKEN"}],"revision":3}` {
		t.Errorf("reported requirements = %s, want everything the run lacked on the way back", requirements)
	}
}

func TestRun_StopsOnAnErrorWhenTheRemoteCannotAnswerTheFallback(t *testing.T) {
	h := newFetchHarness(t)
	t.Setenv("LOCKTIVITY_ID_TOKEN", "gitlab-id-token")
	h.offer("current.json", 2, revisionTwo, nil)
	if err := os.WriteFile(filepath.Join(h.home, "fallback-error"), nil, 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := h.run("northwind-production", "--remote", "locktivity", "--yes")
	if err == nil || !strings.Contains(err.Error(), "fetching an earlier revision: pipeline not found") {
		t.Fatalf("err = %v, want the adapter's error, not a missing-requirements stop", err)
	}
	if reports := h.called("lock.report"); len(reports) != 0 {
		t.Errorf("an error is not a stop for what the runner lacks, but %d report(s) went out", len(reports))
	}
}

func TestRun_StopsWhenTheRemoteOffersTheSameEarlierRevisionAgain(t *testing.T) {
	h := newFetchHarness(t)
	t.Setenv("LOCKTIVITY_ID_TOKEN", "gitlab-id-token")
	h.offer("current.json", 3, revisionTwo, nil)
	h.offer("fallback.json", 2, revisionNeedsOldToken, nil)
	h.offer("fallback-older.json", 2, revisionNeedsOldToken, nil)

	_, err := h.run("northwind-production", "--remote", "locktivity", "--yes")
	if err == nil || !strings.Contains(err.Error(), "no earlier revision runs here") {
		t.Fatalf("err = %v, want the run stopped", err)
	}
	if pulls := h.called("config.pull"); len(pulls) != 3 {
		t.Fatalf("config.pull calls = %d, want the fetch and two fallbacks, not one per attempt left", len(pulls))
	}
	if len(h.ranIn) != 0 {
		t.Fatalf("nothing should run, ran in %v", h.ranIn)
	}
}

func TestFetch_RunnableChecksOnlyTheFetchedRevisionWithPrompts(t *testing.T) {
	h := newFetchHarness(t)
	t.Setenv("LOCKTIVITY_ID_TOKEN", "gitlab-id-token")
	h.offer("current.json", 2, revisionTwo, nil)
	h.offer("fallback.json", 1, revisionOne, nil)
	target, err := remotecmd.ResolveConfigTarget("northwind-production", "locktivity")
	if err != nil {
		t.Fatal(err)
	}
	fetch, err := remotecmd.FetchConfig(t.Context(), target, remotecmd.FetchOptions{Purpose: remote.ConfigPurposeRun, Install: remotecmd.InstallTrustedPin})
	if err != nil {
		t.Fatalf("FetchConfig: %v", err)
	}
	defer fetch.Close()

	sentry := []runflow.MissingRequirement{{Requirement: remote.Requirement{Kind: remote.RequirementVariable, Name: "SENTRY_AUTH_TOKEN"}}}
	var prompted, quiet []string
	runnable, err := fetch.Runnable(t.Context(),
		func(dir string, _ *remote.ConfigRequirements) ([]runflow.MissingRequirement, error) {
			prompted = append(prompted, dir)
			return sentry, nil
		},
		func(dir string, _ *remote.ConfigRequirements) ([]runflow.MissingRequirement, error) {
			quiet = append(quiet, dir)
			return nil, nil
		})
	if err != nil {
		t.Fatalf("Runnable: %v", err)
	}

	if len(prompted) != 1 || prompted[0] != fetch.Dir {
		t.Errorf("checked with prompts: %v, want only the fetched revision", prompted)
	}
	if want := filepath.Join(fetch.Dir, filepath.FromSlash(remotecmd.FallbackFolder)); len(quiet) != 1 || quiet[0] != want {
		t.Errorf("checked quietly: %v, want the earlier revision in %s", quiet, want)
	}
	if runnable.Config.Revision != 1 || runnable.Dir != quiet[0] || len(runnable.Missing) != 1 {
		t.Errorf("runnable = %+v, want revision 1 with SENTRY_AUTH_TOKEN missing from revision 2", runnable)
	}
}

func TestRun_TakesTheNewRevisionOnceTheVariableIsSet(t *testing.T) {
	h := newFetchHarness(t)
	t.Setenv("LOCKTIVITY_ID_TOKEN", "gitlab-id-token")
	t.Setenv("SENTRY_AUTH_TOKEN", "sntrys_value")
	h.offer("current.json", 2, revisionTwo, nil)
	runWorkflow = func(_ context.Context, opts runflow.Options) (*runflow.Result, error) {
		h.ranIn = append(h.ranIn, opts.WorkDir)
		return &runflow.Result{PackPath: opts.PackPath}, nil
	}

	out, err := h.run("northwind-production", "--remote", "locktivity", "--yes")
	if err != nil {
		t.Fatalf("run: %v\n%s", err, out)
	}
	if pulls := h.called("config.pull"); len(pulls) != 1 {
		t.Fatalf("config.pull calls = %d, want only the fetch", len(pulls))
	}
	if want := filepath.Join(h.work, "northwind-production"); len(h.ranIn) != 1 || h.ranIn[0] != want {
		t.Fatalf("ran in %v, want revision 2 in %s", h.ranIn, want)
	}
	if strings.Contains(out, "needs what this runner does not have") {
		t.Errorf("nothing is missing, but the log says so:\n%s", out)
	}
}

func TestRun_FirstRunWithNothingToFallBackToStopsWithTheReport(t *testing.T) {
	h := newFetchHarness(t)
	t.Setenv("LOCKTIVITY_ID_TOKEN", "gitlab-id-token")
	h.offer("current.json", 1, revisionTwo, map[string]any{"requirements": map[string]any{"hints": []map[string]string{{
		"name": "SENTRY_AUTH_TOKEN",
		"text": "Add it as a masked CI/CD variable in northwind/compliance",
	}}}})

	out, err := h.run("northwind-production", "--remote", "locktivity", "--yes")
	if err == nil || !strings.Contains(err.Error(), "revision 1 needs SENTRY_AUTH_TOKEN") {
		t.Fatalf("err = %v, want the run stopped on SENTRY_AUTH_TOKEN\n%s", err, out)
	}
	if len(h.ranIn) != 0 {
		t.Fatalf("nothing should run, ran in %v", h.ranIn)
	}
	if !strings.Contains(out, "SENTRY_AUTH_TOKEN is not set. Add it as a masked CI/CD variable in northwind/compliance") {
		t.Errorf("job log does not name the variable and where to add it:\n%s", out)
	}
	reports := h.called("lock.report")
	if len(reports) != 1 {
		t.Fatalf("lock.report calls = %d, want the stop reported", len(reports))
	}
	if reports[0].session != "ltk_session" {
		t.Errorf("the report went out with %q, want the pipeline's session", reports[0].session)
	}
	provenance := reports[0].request["lock_provenance"].(map[string]any)
	if provenance["failure_code"] != runflow.FailureRequirements {
		t.Errorf("failure_code = %v", provenance["failure_code"])
	}
	requirements, _ := json.Marshal(provenance["metadata"].(map[string]any)["requirements"])
	if string(requirements) != `{"missing":[{"kind":"variable","name":"SENTRY_AUTH_TOKEN"}],"revision":1}` {
		t.Errorf("reported requirements = %s", requirements)
	}
	if runtime := provenance["runtime_context"].(map[string]any); runtime["pipeline_id"] != testPipelineID {
		t.Errorf("runtime_context = %v, want the pipeline named", runtime)
	}
}

func TestRun_RefusesToSignInForAnAdapterFromAnUntrustedPublisher(t *testing.T) {
	h := newFetchHarness(t)
	t.Setenv("LOCKTIVITY_ID_TOKEN", "gitlab-id-token")
	t.Setenv("EPACK_TRUSTED_PUBLISHERS", "someone-else")
	h.offer("current.json", 1, revisionOne, nil)

	_, err := h.run("northwind-production", "--remote", "locktivity", "--yes")
	if err == nil || !strings.Contains(err.Error(), "EPACK_TRUSTED_PUBLISHERS") {
		t.Fatalf("err = %v, want the publisher refused", err)
	}
	if len(h.sessions) != 0 || len(h.calls()) != 0 {
		t.Fatalf("nothing should be exchanged or fetched: sessions %v, calls %+v", h.sessions, h.calls())
	}
	if _, err := os.Stat(filepath.Join(h.home, "capabilities.log")); !os.IsNotExist(err) {
		t.Fatal("the adapter ran before its publisher was checked")
	}
}

func TestRun_SignsInWithTheKeyInsideGitHubActions(t *testing.T) {
	h := newFetchHarness(t)
	keyPath, fingerprint := writeTestKey(t)
	t.Setenv("GITHUB_ACTIONS", "true")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "https://github-oidc.invalid/token")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "github-request-token")
	h.offer("current.json", 1, revisionOne, nil)

	out, err := h.run("northwind-production", "--remote", "locktivity", "--yes", "--key", keyPath)
	if err != nil {
		t.Fatalf("run: %v\n%s", err, out)
	}

	if len(h.sessions) != 1 {
		t.Fatalf("broker sessions = %v, want one", h.sessions)
	}
	if header := jwtPart(t, h.sessions[0], 0); header["kid"] != fingerprint {
		t.Errorf("the session presented %v, want the key %s over GitHub's token", header, fingerprint)
	}
}

func TestRun_SignsInWithTheGitLabIDTokenOverAKeyThatSignsPacks(t *testing.T) {
	h := newFetchHarness(t)
	keyPath, _ := writeTestKey(t)
	t.Setenv("LOCKTIVITY_ID_TOKEN", "gitlab-id-token")
	h.offer("current.json", 1, revisionOne, nil)

	out, err := h.run("northwind-production", "--remote", "locktivity", "--yes", "--key", keyPath)
	if err != nil {
		t.Fatalf("run: %v\n%s", err, out)
	}

	if len(h.sessions) != 1 || h.sessions[0] != "gitlab-id-token" {
		t.Fatalf("broker sessions = %v, want the job's ID token", h.sessions)
	}
}

func TestRun_CheckNamesTheEpackTheRevisionNeeds(t *testing.T) {
	h := newFetchHarness(t)
	t.Setenv("LOCKTIVITY_ID_TOKEN", "gitlab-id-token")
	previous := version.Version
	version.Version = "0.4.9"
	t.Cleanup(func() { version.Version = previous })
	h.offer("current.json", 2, revisionOne, map[string]any{"requirements": map[string]any{"epack": "v0.5.0"}})

	out, _ := h.run("northwind-production", "--remote", "locktivity", "--yes", "--check")

	if !strings.Contains(out, "epack 0.5.0 or later is needed") {
		t.Errorf("the check should refuse what the run would:\n%s", out)
	}
}

func TestRun_ChecksTheCurrentRevisionWithoutFallingBack(t *testing.T) {
	h := newFetchHarness(t)
	t.Setenv("LOCKTIVITY_ID_TOKEN", "gitlab-id-token")
	h.offer("current.json", 2, revisionTwo, nil)
	h.offer("fallback.json", 1, revisionOne, nil)

	_, _ = h.run("northwind-production", "--remote", "locktivity", "--yes", "--check")
	pulls := h.called("config.pull")
	if len(pulls) != 1 {
		t.Fatalf("config.pull calls = %d, want the check to fetch once", len(pulls))
	}
	if purpose := pulls[0].request["config"].(map[string]any)["purpose"]; purpose != "check" {
		t.Errorf("purpose = %v, want check", purpose)
	}
	if len(h.ranIn) != 0 {
		t.Errorf("a check collects nothing, ran in %v", h.ranIn)
	}
}
