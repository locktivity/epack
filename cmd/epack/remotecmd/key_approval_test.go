//go:build components

package remotecmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/locktivity/epack/internal/cli/output"
	"github.com/locktivity/epack/internal/remote"
	"github.com/locktivity/epack/internal/safefile"
	"github.com/locktivity/epack/sign"
)

// fakeKeyLister answers key.list with one status or error per check,
// repeating the last, and counts the checks.
type fakeKeyLister struct {
	answers []fakeListAnswer
	checks  int
}

type fakeListAnswer struct {
	status string
	err    error
}

func (f *fakeKeyLister) KeyList(ctx context.Context, config string) (*remote.KeyListResponse, error) {
	answer := f.answers[min(f.checks, len(f.answers)-1)]
	f.checks++
	if answer.err != nil {
		return nil, answer.err
	}
	return &remote.KeyListResponse{OK: true, Keys: []remote.SigningKey{
		{ID: "key_old", Status: remote.KeyStatusUsable},
		{ID: "key_123", Status: answer.status},
	}}, nil
}

func listing(statuses ...string) *fakeKeyLister {
	lister := &fakeKeyLister{}
	for _, status := range statuses {
		lister.answers = append(lister.answers, fakeListAnswer{status: status})
	}
	return lister
}

// fakeApprovalClock makes each sleep in a wait move a clock forward instead
// of taking time, and records the sleeps.
func fakeApprovalClock(t *testing.T) (start time.Time, sleeps *[]time.Duration) {
	t.Helper()
	start = time.Date(2026, 10, 7, 18, 0, 0, 0, time.UTC)
	now := start
	var slept []time.Duration
	previousNow, previousSleep := approvalNow, approvalSleep
	approvalNow = func() time.Time { return now }
	approvalSleep = func(ctx context.Context, d time.Duration) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		slept = append(slept, d)
		now = now.Add(max(d, 0))
		return nil
	}
	t.Cleanup(func() { approvalNow, approvalSleep = previousNow, previousSleep })
	return start, &slept
}

func approvalUntil(start time.Time, window time.Duration, interval int) *remote.KeyApproval {
	return &remote.KeyApproval{
		Code: "WDJB-MJHT", URL: "https://app.example.com/approve/key_123",
		ExpiresAt: start.Add(window).Format(time.RFC3339), Interval: interval,
	}
}

func TestWaitForApproval_PendingThenUsable(t *testing.T) {
	start, sleeps := fakeApprovalClock(t)
	lister := listing(remote.KeyStatusPending, remote.KeyStatusPending, remote.KeyStatusUsable)

	status, err := waitForApproval(context.Background(), lister, "northwind-production", "key_123", approvalUntil(start, 15*time.Minute, 2))
	if err != nil || status != remote.KeyStatusUsable {
		t.Fatalf("status = %q, %v", status, err)
	}
	if want := []time.Duration{2 * time.Second, 2 * time.Second, 2 * time.Second}; lister.checks != 3 || !reflect.DeepEqual(*sleeps, want) {
		t.Errorf("checks = %d, sleeps = %v, want 3 checks %v apart", lister.checks, *sleeps, want)
	}
}

func TestWaitForApproval_PendingThenDenied(t *testing.T) {
	start, _ := fakeApprovalClock(t)
	lister := listing(remote.KeyStatusPending, remote.KeyStatusDenied)

	status, err := waitForApproval(context.Background(), lister, "northwind-production", "key_123", approvalUntil(start, 15*time.Minute, 5))
	if err != nil || status != remote.KeyStatusDenied || lister.checks != 2 {
		t.Fatalf("status = %q, %v after %d checks", status, err, lister.checks)
	}
}

func TestWaitForApproval_RemoteReportsLapsed(t *testing.T) {
	start, _ := fakeApprovalClock(t)
	lister := listing(remote.KeyStatusPending, remote.KeyStatusLapsed)

	status, err := waitForApproval(context.Background(), lister, "northwind-production", "key_123", approvalUntil(start, 15*time.Minute, 5))
	if err != nil || status != remote.KeyStatusLapsed {
		t.Fatalf("status = %q, %v", status, err)
	}
}

func TestWaitForApproval_LapsesWhenTheWindowCloses(t *testing.T) {
	start, sleeps := fakeApprovalClock(t)
	lister := listing(remote.KeyStatusPending)

	status, err := waitForApproval(context.Background(), lister, "northwind-production", "key_123", approvalUntil(start, 12*time.Second, 5))
	if err != nil || status != remote.KeyStatusLapsed {
		t.Fatalf("status = %q, %v", status, err)
	}
	if want := []time.Duration{5 * time.Second, 5 * time.Second, 2 * time.Second}; lister.checks != 3 || !reflect.DeepEqual(*sleeps, want) {
		t.Errorf("checks = %d, sleeps = %v; the last check should land on the deadline: %v", lister.checks, *sleeps, want)
	}
}

func TestWaitForApproval_DefaultsTheIntervalAndBoundsTheWait(t *testing.T) {
	start, sleeps := fakeApprovalClock(t)
	lister := listing(remote.KeyStatusPending)

	status, err := waitForApproval(context.Background(), lister, "northwind-production", "key_123", approvalUntil(start, 24*time.Hour, 0))
	if err != nil || status != remote.KeyStatusLapsed {
		t.Fatalf("status = %q, %v", status, err)
	}
	var waited time.Duration
	for _, d := range *sleeps {
		waited += d
	}
	if (*sleeps)[0] != defaultApprovalInterval || waited != maxApprovalWait {
		t.Errorf("first sleep %s, waited %s; want %s and %s", (*sleeps)[0], waited, defaultApprovalInterval, maxApprovalWait)
	}
}

func TestWaitForApproval_RetriesWhatTheRemoteSaysToRetry(t *testing.T) {
	start, _ := fakeApprovalClock(t)
	lister := &fakeKeyLister{answers: []fakeListAnswer{
		{err: &remote.AdapterError{AdapterName: "mock", Code: remote.ErrCodeNetworkError, Message: "timed out", Retryable: true}},
		{status: remote.KeyStatusUsable},
	}}

	status, err := waitForApproval(context.Background(), lister, "northwind-production", "key_123", approvalUntil(start, 15*time.Minute, 5))
	if err != nil || status != remote.KeyStatusUsable || lister.checks != 2 {
		t.Fatalf("status = %q, %v after %d checks", status, err, lister.checks)
	}
}

func TestWaitForApproval_StopsOnAnyOtherError(t *testing.T) {
	start, _ := fakeApprovalClock(t)
	signedOut := &remote.AdapterError{AdapterName: "mock", Code: remote.ErrCodeAuthRequired, Message: "sign in first"}
	lister := &fakeKeyLister{answers: []fakeListAnswer{{err: signedOut}}}

	if _, err := waitForApproval(context.Background(), lister, "northwind-production", "key_123", approvalUntil(start, 15*time.Minute, 5)); !errors.Is(err, signedOut) || lister.checks != 1 {
		t.Fatalf("err = %v after %d checks", err, lister.checks)
	}
}

func TestAwaitKeyApproval_CtrlCLeavesTheRequestOpenAndSaysHowToResume(t *testing.T) {
	start, _ := fakeApprovalClock(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var stdout, stderr bytes.Buffer
	lister := listing(remote.KeyStatusPending)
	approval := approvalUntil(start, 15*time.Minute, 5)

	_, err := AwaitKeyApproval(ctx, output.New(&stdout, &stderr, output.Options{}), PendingKey{
		Remote: "mock", Config: "northwind-production", Lister: lister, NoBrowser: true,
		Key:    remote.SigningKey{ID: "key_123", Status: remote.KeyStatusPending, Approval: approval},
		Resume: "run 'epack key create' again",
	})
	until := start.Add(15 * time.Minute).Local().Format("15:04")
	if err == nil || !strings.Contains(err.Error(), "stopped waiting for approval. The request stays open until "+until+"; run 'epack key create' again to resume") {
		t.Fatalf("err = %v", err)
	}
	if lister.checks != 0 {
		t.Errorf("checked %d times after Ctrl-C", lister.checks)
	}
	if !strings.Contains(stdout.String(), "Code: WDJB-MJHT") || !strings.Contains(stdout.String(), "Stopped waiting") {
		t.Errorf("output:\n%s", stdout.String())
	}
}

func TestAwaitKeyApproval_ShowsTheCodeEvenWhenQuiet(t *testing.T) {
	start, _ := fakeApprovalClock(t)
	var stdout bytes.Buffer
	status, err := AwaitKeyApproval(context.Background(), output.New(&stdout, &stdout, output.Options{Quiet: true}), PendingKey{
		Remote: "mock", Lister: listing(remote.KeyStatusUsable), NoBrowser: true,
		Key: remote.SigningKey{ID: "key_123", Status: remote.KeyStatusPending, Approval: approvalUntil(start, 15*time.Minute, 5)},
	})
	if err != nil || status != remote.KeyStatusUsable {
		t.Fatalf("status = %q, %v", status, err)
	}
	if !strings.Contains(stdout.String(), "Code: WDJB-MJHT") || !strings.Contains(stdout.String(), "https://app.example.com/approve/key_123") {
		t.Errorf("--quiet hid the code or link:\n%s", stdout.String())
	}
}

func TestAwaitKeyApproval_NeedsACodeAndALink(t *testing.T) {
	var stdout bytes.Buffer
	_, err := AwaitKeyApproval(context.Background(), output.New(&stdout, &stdout, output.Options{}), PendingKey{
		Remote: "mock", Lister: listing(remote.KeyStatusUsable), NoBrowser: true,
		Key: remote.SigningKey{ID: "key_123", Status: remote.KeyStatusPending, Approval: &remote.KeyApproval{URL: "https://app.example.com/approve"}},
	})
	if err == nil || !strings.Contains(err.Error(), "did not return an approval code and link") {
		t.Fatalf("err = %v", err)
	}
}

// keyAdapter answers like an adapter that manages signing keys. It saves
// each request it reads into dir and answers key.register with
// dir/register.json, and the nth key.list with dir/list-<n>.json when there
// is one and dir/list.json otherwise.
func keyAdapter(dir string) string {
	return `#!/bin/sh
dir='` + dir + `'
case "$1" in
  --capabilities)
    echo '{"name":"mock","kind":"remote_adapter","deploy_protocol_version":1,"version":"1.0.0","features":{"prepare_finalize":true,"keys":true}}'
    ;;
  key.register)
    cat > "$dir/key.register.json"
    cat "$dir/register.json"
    ;;
  key.retire)
    cat > "$dir/key.retire.json"
    echo '{"ok":true,"type":"key.retire.result","key":{"id":"key_old","fingerprint":"0a0a","status":"retired"}}'
    ;;
  key.list)
    cat > /dev/null
    n=$(( $(cat "$dir/list-count" 2>/dev/null || echo 0) + 1 ))
    echo "$n" > "$dir/list-count"
    if [ -f "$dir/list-$n.json" ]; then cat "$dir/list-$n.json"; else cat "$dir/list.json"; fi
    ;;
  *)
    echo '{"ok":false,"error":{"code":"unknown_command","message":"unknown command"}}'
    exit 1
    ;;
esac
`
}

// keySetup writes a project whose mock adapter manages keys and answers
// with register and lists, the last list repeating. Waits between checks
// take no time.
func keySetup(t *testing.T, register string, lists ...string) (dir string) {
	t.Helper()
	home := isolateHome(t)
	if err := safefile.MkdirAllPrivate(home, filepath.Join(home, ".epack")); err != nil {
		t.Fatal(err)
	}
	dir = t.TempDir()
	writeMockAdapterProject(t, keyAdapter(dir))
	setKeyAnswers(t, dir, register, lists...)
	previous := approvalSleep
	approvalSleep = func(ctx context.Context, d time.Duration) error { return ctx.Err() }
	t.Cleanup(func() { approvalSleep = previous })
	return dir
}

func setKeyAnswers(t *testing.T, dir, register string, lists ...string) {
	t.Helper()
	stale, _ := filepath.Glob(filepath.Join(dir, "list-*"))
	for _, path := range stale {
		_ = os.Remove(path)
	}
	answers := map[string]string{"register.json": register, "list.json": lists[len(lists)-1]}
	for i, list := range lists {
		answers["list-"+strconv.Itoa(i+1)+".json"] = list
	}
	for name, body := range answers {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func pendingRegistration() string {
	expires := time.Now().Add(10 * time.Minute).UTC().Format(time.RFC3339)
	return `{"ok":true,"type":"key.register.result","created":true,"key":{"id":"key_123","name":"laptop","fingerprint":"9f14322ec5bab3f5","status":"pending","expires_at":"2027-10-07T18:00:00Z",` +
		`"approval":{"code":"WDJB-MJHT","url":"https://app.example.com/approve/key_123","expires_at":"` + expires + `","interval":1}}}`
}

// withPipelinePage adds the pipeline page link a remote sends next to
// created in a key.register answer.
func withPipelinePage(register, link string) string {
	return strings.Replace(register, `"created":true`, `"created":true,"pipeline_url":"`+link+`"`, 1)
}

func keyListWith(status string) string {
	return `{"ok":true,"type":"key.list.result","keys":[{"id":"key_123","name":"laptop","fingerprint":"9f14322ec5bab3f5","status":"` + status + `"}]}`
}

func listChecks(t *testing.T, dir string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, "list-count"))
	if err != nil {
		return "0"
	}
	return strings.TrimSpace(string(data))
}

func machineKeyPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(os.Getenv("HOME"), ".epack", "keys", "mock.pem")
}

func TestKeyCreate_WaitsForApprovalInTheBrowser(t *testing.T) {
	dir := keySetup(t, pendingRegistration(), keyListWith("pending"), keyListWith("usable"))

	cmd, stdout, stderr := rootCommand(NewKeyCommand(), "create", "mock", "--for", "northwind-production", "--no-browser")
	if err := cmd.Execute(); err != nil {
		t.Fatalf("key create: %v (stderr: %s)", err, stderr.String())
	}
	got := stdout.String()
	for _, want := range []string{
		"Generated ~/.epack/keys/mock.pem",
		"Registered its public key with mock for northwind-production",
		"\nApprove the key on mock\n  Code: WDJB-MJHT\n  Open this link in your browser and enter the code to approve the key:\n  https://app.example.com/approve/key_123\n",
		"Approved\n",
		"Runs from this machine now sign with it.",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("output missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "Your browser is open") {
		t.Errorf("--no-browser must not claim the browser is open:\n%s", got)
	}
	if checks := listChecks(t, dir); checks != "2" {
		t.Errorf("key.list ran %s times, want 2", checks)
	}
	register := savedRequest(t, filepath.Join(dir, "key.register.json"))
	if publicPEM, _ := register["public_key_pem"].(string); register["config"] != "northwind-production" || !strings.HasPrefix(publicPEM, "-----BEGIN PUBLIC KEY-----") {
		t.Errorf("key.register request = %v", register)
	}
}

func TestKeyCreate_PointsAtThePipelinePageOnceTheKeyIsUsable(t *testing.T) {
	keySetup(t, withPipelinePage(pendingRegistration(), "https://app.example.com/pipelines/pipe_1"), keyListWith("pending"), keyListWith("usable"))

	cmd, stdout, stderr := rootCommand(NewKeyCommand(), "create", "mock", "--for", "northwind-production", "--no-browser")
	if err := cmd.Execute(); err != nil {
		t.Fatalf("key create: %v (stderr: %s)", err, stderr.String())
	}
	got := stdout.String()
	line := "See it on the pipeline page: https://app.example.com/pipelines/pipe_1\n"
	if !strings.Contains(got, "Approved\n") || strings.Count(got, line) != 1 ||
		!strings.HasSuffix(got, "Runs from this machine now sign with it. No browser needed.\n"+line) {
		t.Errorf("the pipeline page should come once, after the approval:\n%s", got)
	}
}

func TestKeyCreate_LeavesThePipelinePageOutUntilTheKeyIsUsable(t *testing.T) {
	dir := keySetup(t, withPipelinePage(pendingRegistration(), "https://app.example.com/pipelines/pipe_1"), keyListWith("pending"), keyListWith("denied"))

	cmd, stdout, _ := rootCommand(NewKeyCommand(), "create", "mock", "--for", "northwind-production", "--no-browser")
	if err := cmd.Execute(); err == nil || strings.Contains(stdout.String(), "pipeline page") {
		t.Errorf("a denied key must not point at the pipeline page (err %v):\n%s", err, stdout.String())
	}

	waiting := `{"ok":true,"type":"key.register.result","created":true,"key":{"id":"key_123","name":"laptop","fingerprint":"9f14322ec5bab3f5","status":"pending"}}`
	setKeyAnswers(t, dir, withPipelinePage(waiting, "https://app.example.com/pipelines/pipe_1"), keyListWith("pending"))
	cmd, stdout, stderr := rootCommand(NewKeyCommand(), "create", "mock", "--for", "northwind-production", "--no-browser")
	if err := cmd.Execute(); err != nil {
		t.Fatalf("key create: %v (stderr: %s)", err, stderr.String())
	}
	if got := stdout.String(); !strings.Contains(got, "Runs from this machine sign with it once mock approves it.") || strings.Contains(got, "pipeline page") {
		t.Errorf("a key still waiting must not point at the pipeline page:\n%s", got)
	}
}

func TestKeyCreate_OpensTheApprovalPage(t *testing.T) {
	keySetup(t, pendingRegistration(), keyListWith("usable"))
	var opened []string
	previous := openApprovalPage
	openApprovalPage = func(ctx context.Context, link string) error {
		opened = append(opened, link)
		return nil
	}
	t.Cleanup(func() { openApprovalPage = previous })

	cmd, stdout, stderr := rootCommand(NewKeyCommand(), "create", "mock", "--for", "northwind-production")
	if err := cmd.Execute(); err != nil {
		t.Fatalf("key create: %v (stderr: %s)", err, stderr.String())
	}
	if !reflect.DeepEqual(opened, []string{"https://app.example.com/approve/key_123"}) {
		t.Errorf("opened %v", opened)
	}
	if !strings.Contains(stdout.String(), "Your browser is open. Enter the code there to approve the key.") {
		t.Errorf("output:\n%s", stdout.String())
	}
}

func TestKeyCreate_DeniedInTheBrowser(t *testing.T) {
	keySetup(t, pendingRegistration(), keyListWith("pending"), keyListWith("denied"))

	cmd, stdout, _ := rootCommand(NewKeyCommand(), "create", "mock", "--for", "northwind-production", "--no-browser")
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "the key was denied on mock, so runs will not sign with it") {
		t.Fatalf("err = %v", err)
	}
	if !strings.Contains(stdout.String(), "Denied") || strings.Contains(stdout.String(), "now sign with it") {
		t.Errorf("output:\n%s", stdout.String())
	}
}

func TestKeyCreate_LapsedSaysToRunItAgainAndTheRerunResumes(t *testing.T) {
	dir := keySetup(t, pendingRegistration(), keyListWith("pending"), keyListWith("lapsed"))

	cmd, _, _ := rootCommand(NewKeyCommand(), "create", "mock", "--for", "northwind-production", "--no-browser")
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "the key was not approved in time; run 'epack key create' again for a new code") {
		t.Fatalf("err = %v", err)
	}
	first := savedRequest(t, filepath.Join(dir, "key.register.json"))["public_key_pem"]
	if _, statErr := os.Stat(machineKeyPath(t)); statErr != nil {
		t.Fatalf("the key file must stay for the next try: %v", statErr)
	}

	setKeyAnswers(t, dir, pendingRegistration(), keyListWith("usable"))
	cmd, stdout, stderr := rootCommand(NewKeyCommand(), "create", "mock", "--for", "northwind-production", "--no-browser")
	if err := cmd.Execute(); err != nil {
		t.Fatalf("key create again: %v (stderr: %s)", err, stderr.String())
	}
	if again := savedRequest(t, filepath.Join(dir, "key.register.json"))["public_key_pem"]; again != first {
		t.Error("running it again registered a different key")
	}
	if got := stdout.String(); !strings.Contains(got, "Using the key at ~/.epack/keys/mock.pem") || !strings.Contains(got, "Runs from this machine now sign with it.") {
		t.Errorf("output:\n%s", got)
	}
}

func TestKeyCreate_WithoutAnApprovalKeepsTheOldBehaviour(t *testing.T) {
	dir := keySetup(t, `{"ok":true,"type":"key.register.result","created":true,"key":{"id":"key_123","name":"laptop","fingerprint":"9f14322ec5bab3f5","status":"usable","expires_at":"2027-10-07T18:00:00Z"}}`, keyListWith("usable"))

	cmd, stdout, stderr := rootCommand(NewKeyCommand(), "create", "mock", "--for", "northwind-production", "--no-browser")
	if err := cmd.Execute(); err != nil {
		t.Fatalf("key create: %v (stderr: %s)", err, stderr.String())
	}
	got := stdout.String()
	if strings.Contains(got, "Approve the key") || !strings.Contains(got, "Registered its public key with mock") || !strings.Contains(got, "Runs from this machine now sign with it.") {
		t.Errorf("output:\n%s", got)
	}
	if checks := listChecks(t, dir); checks != "0" {
		t.Errorf("key.list ran %s times without an approval to wait for", checks)
	}
}

func TestKeyCreate_JSONKeepsStdoutForTheResult(t *testing.T) {
	keySetup(t, withPipelinePage(pendingRegistration(), "https://app.example.com/pipelines/pipe_1"), keyListWith("usable"))

	cmd, stdout, stderr := rootCommand(NewKeyCommand(), "create", "mock", "--for", "northwind-production", "--no-browser", "--json")
	if err := cmd.Execute(); err != nil {
		t.Fatalf("key create --json: %v (stderr: %s)", err, stderr.String())
	}
	var result struct {
		Registered  bool   `json:"registered"`
		Status      string `json:"status"`
		PipelineURL string `json:"pipeline_url"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("stdout is not only the JSON result: %v\n%s", err, stdout.String())
	}
	if !result.Registered || result.Status != remote.KeyStatusUsable || result.PipelineURL != "https://app.example.com/pipelines/pipe_1" {
		t.Errorf("result = %+v", result)
	}
	if !strings.Contains(stderr.String(), "Code: WDJB-MJHT") || !strings.Contains(stderr.String(), "https://app.example.com/approve/key_123") {
		t.Errorf("the code and link must still reach the person on stderr:\n%s", stderr.String())
	}
	if strings.Contains(stderr.String(), "pipeline page") {
		t.Errorf("--json carries the pipeline page in the result, not as a line:\n%s", stderr.String())
	}
}

func TestKeyRotate_ReplacesTheKeyOnlyOnceTheNewOneIsApproved(t *testing.T) {
	dir := keySetup(t, pendingRegistration(), keyListWith("lapsed"))
	old, err := generateKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := sign.SavePrivateKey(machineKeyPath(t), old.privatePEM); err != nil {
		t.Fatal(err)
	}

	cmd, _, _ := rootCommand(NewKeyCommand(), "rotate", "mock", "--for", "northwind-production", "--no-browser")
	err = cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "run 'epack key rotate' again for a new code. The old key stays.") {
		t.Fatalf("err = %v", err)
	}
	if kept, err := loadKey(machineKeyPath(t)); err != nil || kept.fingerprint != old.fingerprint {
		t.Fatalf("the old key was replaced before the new one was approved (%v)", err)
	}
	first := savedRequest(t, filepath.Join(dir, "key.register.json"))["public_key_pem"]

	setKeyAnswers(t, dir, pendingRegistration(), keyListWith("usable"))
	cmd, stdout, stderr := rootCommand(NewKeyCommand(), "rotate", "mock", "--for", "northwind-production", "--no-browser")
	if err := cmd.Execute(); err != nil {
		t.Fatalf("key rotate again: %v (stderr: %s)", err, stderr.String())
	}
	if again := savedRequest(t, filepath.Join(dir, "key.register.json"))["public_key_pem"]; again != first {
		t.Error("running the rotation again registered a different new key")
	}
	rotated, err := loadKey(machineKeyPath(t))
	if err != nil || rotated.fingerprint == old.fingerprint || rotated.publicPEM != first {
		t.Fatalf("the machine key is not the approved new key (%v)", err)
	}
	if _, err := os.Stat(nextKeyPath(machineKeyPath(t))); !os.IsNotExist(err) {
		t.Errorf("the new key's holding file is still there: %v", err)
	}
	if !strings.Contains(stdout.String(), "Registered a new key with mock") {
		t.Errorf("output:\n%s", stdout.String())
	}
}

func TestKeyRotate_RetiresTheOldKeySoWhatItSignedStaysTrusted(t *testing.T) {
	old, err := generateKey()
	if err != nil {
		t.Fatal(err)
	}
	usable := `{"ok":true,"type":"key.register.result","created":true,"key":{"id":"key_123","name":"laptop","fingerprint":"9f14322ec5bab3f5","status":"usable"}}`
	listing := `{"ok":true,"type":"key.list.result","keys":[{"id":"key_123","name":"laptop","fingerprint":"9f14322ec5bab3f5","status":"usable"},` +
		`{"id":"key_old","name":"laptop","fingerprint":"` + old.fingerprint + `","status":"usable"}]}`
	dir := keySetup(t, withPipelinePage(usable, "https://app.example.com/pipelines/pipe_1"), listing)
	if err := sign.SavePrivateKey(machineKeyPath(t), old.privatePEM); err != nil {
		t.Fatal(err)
	}

	cmd, stdout, stderr := rootCommand(NewKeyCommand(), "rotate", "mock", "--for", "northwind-production", "--no-browser")
	if err := cmd.Execute(); err != nil {
		t.Fatalf("key rotate: %v (stderr: %s)", err, stderr.String())
	}

	retired := savedRequest(t, filepath.Join(dir, "key.retire.json"))
	if retired["id"] != "key_old" || retired["config"] != "northwind-production" {
		t.Fatalf("retired %v, want the old key", retired)
	}
	if !strings.HasSuffix(stdout.String(), "Retired the old key "+shortFingerprint(old.fingerprint)+". Packs it already signed stay trusted.\n"+
		"See it on the pipeline page: https://app.example.com/pipelines/pipe_1\n") {
		t.Errorf("output:\n%s", stdout.String())
	}
}
