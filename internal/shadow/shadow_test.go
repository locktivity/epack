package shadow

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/locktivity/epack/internal/broker"
	"github.com/locktivity/epack/internal/component/config"
	"github.com/locktivity/epack/internal/component/github"
	"github.com/locktivity/epack/internal/component/sync"
	"github.com/locktivity/epack/internal/credentials"
	"github.com/locktivity/epack/pack"
)

// demoSchema declares the demo collector's fields. regions is a map keyed by
// region name, and user_count is audit-level in the candidate's schema.
const demoSchema = `{
  "type": "object",
  "properties": {
    "collected_at": {"type": "string"},
    "mfa_pct": {"type": "integer"},
    "users_present": {"type": "boolean"},
    "user_count": {"type": "integer"%s},
    "users": {"type": "array", "items": {"type": "object", "properties": {"name": {"type": "string"}, "mfa": {"type": "boolean"}}}},
    "regions": {"type": "object", "additionalProperties": {"type": "object", "properties": {"enabled": {"type": "boolean"}}}}
  }
}`

// demoScript prints a collector result: a detailed file, the build file
// with its schema, and the run record with gaps and operations. $$ makes
// collected_at differ on every run, as a timestamp would.
func demoScript(data, schema, gaps, operations string) string {
	build, _ := json.Marshal(map[string]any{
		"collector": map[string]string{"name": "demo"},
		"schemas":   map[string]json.RawMessage{"artifacts/demo.json": json.RawMessage(schema)},
	})
	result := `{"collector":{"name":"demo"},"outcome":{"status":"collected"},"gaps":[` + gaps + `],"calls":{"operations":[` + operations + `]},"run":{}}`
	return `#!/bin/sh
cat >/dev/null
cat <<EOF
{"type":"epack_result","protocol_version":1,"artifacts":[
{"path":"artifacts/demo.json","data":` + strings.ReplaceAll(data, "COLLECTED", `"$$"`) + `},
{"path":"artifacts/demo.collector-build.json","schema":"evidencepack/collector-build@v1","data":` + string(build) + `},
{"path":"artifacts/demo.collector-result.json","schema":"evidencepack/collector-result@v1","data":` + result + `}
]}
EOF
`
}

func testDirInCwd(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp(".", "shadow_test_*")
	if err != nil {
		t.Fatal(err)
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(abs) })
	return abs
}

func TestShadowReportsChangesWithoutValues(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the demo collectors are shell scripts")
	}
	dir := testDirInCwd(t)
	write := func(name, body string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
		return path
	}
	locked := write("locked", demoScript(
		`{"collected_at":COLLECTED,"mfa_pct":50,"user_count":2,"users":[{"name":"alice","mfa":true},{"name":"bob","mfa":false}],"regions":{"us-east-1":{"enabled":true}}}`,
		strings.Replace(demoSchema, "%s", "", 1),
		`{"pointer":"/regions","status":"partial","code":"vendor_error","owner":"vendor"}`,
		`{"name":"demo.users.list","calls":0,"attempts":0,"retries":0,"retried":false},{"name":"demo.old.get","calls":0,"attempts":0,"retries":0,"retried":false}`))
	candidate := write("candidate", demoScript(
		`{"collected_at":COLLECTED,"mfa_pct":100,"users_present":true,"users":[{"name":"alice","mfa":true},{"name":"bob","mfa":true}],"regions":{"us-east-1":{"enabled":false}}}`,
		strings.Replace(demoSchema, "%s", `, "x-epack-level": "audit"`, 1),
		`{"path":"artifacts/demo.json","pointer":"/regions/us-east-1/enabled","status":"not_collected","code":"permission_denied","owner":"customer","missing_permission":"demo:ReadRegions"}`,
		`{"name":"demo.users.list","calls":0,"attempts":0,"retries":0,"retried":false},{"name":"demo.audit.list","calls":0,"attempts":0,"retries":0,"retried":false,"permission":"demo:ReadAudit"}`))

	cfg := &config.JobConfig{Stream: "acme/test", Collectors: map[string]config.CollectorConfig{
		"demo": {Binary: locked, Config: map[string]any{"level": "trust"}},
	}}
	if _, err := sync.NewLocker(dir).Lock(context.Background(), cfg, sync.LockOpts{}); err != nil {
		t.Fatalf("locking the locked version: %v", err)
	}
	calls := 0
	validate := func(_ context.Context, packPath, _ string) (*Validation, error) {
		p, err := pack.Open(packPath)
		if err != nil {
			return nil, err
		}
		defer func() { _ = p.Close() }()
		raw, err := p.ReadArtifact("artifacts/demo.json")
		if err != nil {
			return nil, err
		}
		var doc struct {
			MFAPct int `json:"mfa_pct"`
		}
		if err := json.Unmarshal(raw.Bytes(), &doc); err != nil {
			return nil, err
		}
		status := "fail"
		if doc.MFAPct >= 100 {
			status = "pass"
		}
		noisy := "pass"
		if calls == 2 {
			noisy = "fail"
		}
		calls++
		v := &Validation{Requirements: []Requirement{
			{ID: "DEMO-1", Name: "Everyone uses MFA", Status: status, Actual: doc.MFAPct},
			{ID: "DEMO-2", Name: "Flaky", Status: noisy},
		}}
		v.Profile.ID = "demo-profile"
		return v, nil
	}
	rep, preview, err := Run(context.Background(), cfg, Options{WorkDir: dir, Collector: "demo", Binary: candidate, Validate: validate})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if calls != 3 {
		t.Errorf("validated %d packs, want the two locked runs and the candidate's", calls)
	}
	if len(rep.Controls) != 1 || rep.Controls[0] != (ControlChange{Profile: "demo-profile", ID: "DEMO-1", Name: "Everyone uses MFA", From: "fail", To: "pass"}) {
		t.Errorf("controls = %+v, want DEMO-1 from fail to pass", rep.Controls)
	}
	if len(rep.ControlNoise) != 1 || rep.ControlNoise[0] != "DEMO-2" {
		t.Errorf("control noise = %v, want DEMO-2, which differs between the locked runs", rep.ControlNoise)
	}
	if len(preview.Controls) != 1 || preview.Controls[0].From != float64(50) && preview.Controls[0].From != 50 {
		t.Errorf("preview controls = %+v, want the value DEMO-1 read", preview.Controls)
	}

	has := func(change, pointer string) bool {
		for _, f := range rep.Fields {
			if f.Change == change && f.Pointer == pointer {
				return true
			}
		}
		return false
	}
	for _, want := range [][2]string{
		{"changed", "/mfa_pct"},
		{"changed", "/users/*/mfa"},
		{"added", "/users_present"},
		{"removed", "/user_count"},
		{"changed", "/regions/{key}/enabled"},
	} {
		if !has(want[0], want[1]) {
			t.Errorf("fields = %+v, want %s %s", rep.Fields, want[0], want[1])
		}
	}
	for _, f := range rep.Fields {
		if f.Pointer == "/user_count" && f.Level != "audit" {
			t.Errorf("user_count = %+v, want it marked as now audit level", f)
		}
		if f.Pointer == "/users/*/name" || f.Pointer == "/collected_at" {
			t.Errorf("%s should not change: %+v", f.Pointer, f)
		}
	}
	if len(rep.Noise) != 1 || rep.Noise[0].Pointer != "/collected_at" {
		t.Errorf("noise = %+v, want collected_at, which differs between the locked runs", rep.Noise)
	}
	if len(rep.Gaps) != 2 {
		t.Errorf("gaps = %+v, want the new permission gap and the vendor gap that went away", rep.Gaps)
	}
	for _, g := range rep.Gaps {
		if g.Change == "added" && (g.Pointer != "/regions/{key}/enabled" || g.Code != "permission_denied" || g.MissingPermission != "demo:ReadRegions") {
			t.Errorf("new gap = %+v", g)
		}
	}
	ops := map[string]string{}
	for _, o := range rep.Operations {
		ops[o.Name] = o.Change + " " + o.Permission
	}
	if ops["demo.audit.list"] != "added demo:ReadAudit" || ops["demo.old.get"] != "removed " || len(ops) != 2 {
		t.Errorf("operations = %+v", rep.Operations)
	}

	raw, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"alice", "bob", "us-east-1", "50", "100", "artifacts/demo.json\",\"pointer\":\"/regions/us"} {
		if strings.Contains(string(raw), value) {
			t.Errorf("the report holds %q from the account: %s", value, raw)
		}
	}

	found := false
	for _, v := range preview.Values {
		if v.Pointer == "/users/1/mfa" && v.From == "false" && v.To == "true" {
			found = true
		}
	}
	if !found {
		t.Errorf("preview = %+v, want bob's MFA from false to true", preview.Values)
	}
	if _, err := os.Stat(filepath.Join(dir, "epack.lock.yaml")); err != nil {
		t.Errorf("the project's lockfile: %v", err)
	}
	entries, _ := os.ReadDir(filepath.Join(dir, ".epack"))
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "shadow-") {
			t.Errorf("the throwaway project %s was not removed", e.Name())
		}
	}
}

// staticBroker hands out the same credentials for every request, standing
// in for the Locktivity credential broker.
type staticBroker map[string]string

func (b staticBroker) Resolve(context.Context, broker.ResolveRequest, broker.RuntimeContext) (broker.ResolvedEnv, error) {
	return broker.ResolvedEnv{Env: b}, nil
}

func TestShadowRunsBothVersionsWithTheProjectsCredentials(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the demo collectors are shell scripts")
	}
	dir := testDirInCwd(t)
	script := demoScript(`{"collected_at":COLLECTED,"mfa_pct":50}`, strings.Replace(demoSchema, "%s", "", 1), "", "")
	var bins []string
	for _, name := range []string{"locked", "candidate"} {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
		bins = append(bins, path)
	}
	cfg := &config.JobConfig{
		Stream:         "acme/test",
		CredentialSets: map[string]string{"demo_api": "credset_demo"},
		Collectors: map[string]config.CollectorConfig{
			"demo": {Binary: bins[0], Credentials: []string{"demo_api"}, Config: map[string]any{"level": "trust"}},
		},
	}
	if _, err := sync.NewLocker(dir).Lock(context.Background(), cfg, sync.LockOpts{}); err != nil {
		t.Fatalf("locking the locked version: %v", err)
	}
	rep, _, err := Run(context.Background(), cfg, Options{
		WorkDir: dir, Collector: "demo", Binary: bins[1],
		Credentials: credentials.Resolver{Broker: staticBroker{"DEMO_TOKEN": "token"}},
		Validate:    func(context.Context, string, string) (*Validation, error) { return &Validation{}, nil },
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	for i, run := range append(rep.Locked.Runs, rep.Candidate.Outcome) {
		if run.Status != "collected" {
			t.Errorf("run %d = %+v, want collected: each version runs with the project's credential sets", i, run)
		}
	}
}

func TestStrictProductionRefusesAnUnpinnedCandidateOrBroker(t *testing.T) {
	t.Setenv("EPACK_STRICT_PRODUCTION", "1")
	cfg := &config.JobConfig{
		CredentialSets: map[string]string{"demo_api": "credset_demo"},
		Collectors: map[string]config.CollectorConfig{
			"demo": {Source: "acme/epack-collector-demo@v1.0.0", Credentials: []string{"demo_api"}},
		},
	}
	_, _, err := Run(context.Background(), cfg, Options{WorkDir: t.TempDir(), Collector: "demo", Binary: "/bin/true"})
	if err == nil || !strings.Contains(err.Error(), "strict production") {
		t.Errorf("Run with --binary = %v, want strict production to refuse a local build, as collect refuses an unpinned binary", err)
	}
	t.Setenv("EPACK_INSECURE_CREDENTIAL_BROKER_URL", "https://broker.example.test")
	_, _, err = Run(context.Background(), cfg, Options{WorkDir: t.TempDir(), Collector: "demo", Version: "v1.1.0"})
	if err == nil || !strings.Contains(err.Error(), "strict production") {
		t.Errorf("Run with a custom broker = %v, want strict production to refuse it, as collect does", err)
	}
}

func TestShadowNeedsOneCandidate(t *testing.T) {
	cfg := &config.JobConfig{Collectors: map[string]config.CollectorConfig{"demo": {Binary: "/bin/true"}}}
	for _, tc := range []struct {
		opts Options
		want string
	}{
		{Options{Collector: "demo"}, "--version <release> or --binary <path>"},
		{Options{Collector: "demo", Version: "v1.0.0", Binary: "/bin/true"}, "not both"},
		{Options{Collector: "demo", Version: "v1.0.0"}, "use --binary"},
		{Options{Collector: "missing", Binary: "/bin/true"}, `no collector named "missing"`},
	} {
		_, _, err := Run(context.Background(), cfg, tc.opts)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("Run(%+v) = %v, want an error containing %q", tc.opts, err, tc.want)
		}
	}
}

// acceptingVerifier passes every binary as signed by the identity the lock
// expects, standing in for Sigstore.
type acceptingVerifier struct{}

func (acceptingVerifier) Verify(_, _ string, want *sync.ExpectedIdentity) (*sync.SigstoreResult, error) {
	return &sync.SigstoreResult{
		Issuer:              "https://token.actions.githubusercontent.com",
		SourceRepositoryURI: want.SourceRepositoryURI,
		SourceRepositoryRef: want.SourceRepositoryRef,
	}, nil
}

func TestShadowLocksAndInstallsACandidateRelease(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the demo collectors are shell scripts")
	}
	asset := "demo-" + runtime.GOOS + "-" + runtime.GOARCH
	scripts := map[string]string{
		"v1.0.0": demoScript(`{"collected_at":COLLECTED,"mfa_pct":50}`, strings.Replace(demoSchema, "%s", "", 1), "", ""),
		"v2.0.0": demoScript(`{"collected_at":COLLECTED,"mfa_pct":100}`, strings.Replace(demoSchema, "%s", "", 1), "", ""),
	}
	var releases []github.Release
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, rel := range releases {
			switch r.URL.Path {
			case "/repos/owner/repo/releases/tags/" + rel.TagName:
				_ = json.NewEncoder(w).Encode(rel)
				return
			case "/assets/" + rel.TagName + "/" + asset, "/owner/repo/releases/download/" + rel.TagName + "/" + asset:
				_, _ = w.Write([]byte(scripts[rel.TagName]))
				return
			case "/assets/" + rel.TagName + "/" + asset + ".sigstore.json", "/owner/repo/releases/download/" + rel.TagName + "/" + asset + ".sigstore.json":
				_, _ = w.Write([]byte("{}"))
				return
			}
		}
		if r.URL.Path == "/repos/owner/repo/releases" {
			_ = json.NewEncoder(w).Encode(releases)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()
	for _, tag := range []string{"v2.0.0", "v1.0.0"} {
		releases = append(releases, github.Release{TagName: tag, Assets: []github.Asset{
			{Name: asset, BrowserDownloadURL: server.URL + "/assets/" + tag + "/" + asset},
			{Name: asset + ".sigstore.json", BrowserDownloadURL: server.URL + "/assets/" + tag + "/" + asset + ".sigstore.json"},
		}})
	}
	registry := sync.NewGitHubRegistryWithClient(github.NewClientForTest(server.Client(), server.URL))

	dir := testDirInCwd(t)
	cfg := &config.JobConfig{Stream: "acme/test", Collectors: map[string]config.CollectorConfig{
		"demo": {Source: "owner/repo@v1.0.0", Config: map[string]any{"level": "trust"}},
	}}
	locker := sync.NewLockerWithRegistry(registry, dir)
	locker.Verifier = acceptingVerifier{}
	if _, err := locker.Lock(context.Background(), cfg, sync.LockOpts{}); err != nil {
		t.Fatalf("locking v1.0.0: %v", err)
	}
	syncer := sync.NewSyncerWithRegistry(registry, dir)
	syncer.Verifier = acceptingVerifier{}
	if _, err := syncer.Sync(context.Background(), cfg, sync.SyncOpts{}); err != nil {
		t.Fatalf("installing v1.0.0: %v", err)
	}
	before, err := os.ReadFile(filepath.Join(dir, "epack.lock.yaml"))
	if err != nil {
		t.Fatal(err)
	}

	rep, _, err := Run(context.Background(), cfg, Options{
		WorkDir: dir, Collector: "demo", Version: "v2.0.0", Registry: registry, Verifier: acceptingVerifier{},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if rep.Locked.Version != "v1.0.0" || rep.Candidate.Version != "v2.0.0" {
		t.Errorf("versions = %q and %q, want v1.0.0 locked and v2.0.0 as the candidate", rep.Locked.Version, rep.Candidate.Version)
	}
	if len(rep.Fields) != 1 || rep.Fields[0].Pointer != "/mfa_pct" || rep.Fields[0].Change != "changed" {
		t.Errorf("fields = %+v, want mfa_pct changed", rep.Fields)
	}
	if rep.ControlsSkipped != "epack.yaml configures no validate tool" {
		t.Errorf("controls skipped = %q", rep.ControlsSkipped)
	}
	after, err := os.ReadFile(filepath.Join(dir, "epack.lock.yaml"))
	if err != nil || string(after) != string(before) {
		t.Errorf("the project's lockfile changed: %v", err)
	}
}

func TestShadowValidatesEachPackInTheOrderTheRunsRan(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the demo collectors are shell scripts")
	}
	dir := testDirInCwd(t)
	script := demoScript(`{"collected_at":COLLECTED,"mfa_pct":50}`, strings.Replace(demoSchema, "%s", "", 1), "", "")
	var bins []string
	for _, name := range []string{"locked", "candidate"} {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
		bins = append(bins, path)
	}
	cfg := &config.JobConfig{Stream: "acme/test", Collectors: map[string]config.CollectorConfig{
		"demo": {Binary: bins[0], Config: map[string]any{"level": "trust"}},
	}}
	if _, err := sync.NewLocker(dir).Lock(context.Background(), cfg, sync.LockOpts{}); err != nil {
		t.Fatalf("locking the locked version: %v", err)
	}
	var seen []string
	failOn := -1
	validate := func(_ context.Context, packPath, outputDir string) (*Validation, error) {
		seen = append(seen, filepath.Base(packPath)+" "+filepath.Base(outputDir))
		if len(seen)-1 == failOn {
			return nil, errors.New("boom")
		}
		return &Validation{}, nil
	}
	opts := Options{WorkDir: dir, Collector: "demo", Binary: bins[1], Validate: validate}
	rep, _, err := Run(context.Background(), cfg, opts)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if want := "locked-1.epack validation-0,candidate.epack validation-1,locked-2.epack validation-2"; strings.Join(seen, ",") != want {
		t.Errorf("validated %v, want %s", seen, want)
	}
	if rep.ControlsSkipped != "" {
		t.Errorf("controls skipped = %q, want none", rep.ControlsSkipped)
	}

	seen, failOn = nil, 1
	rep, _, err = Run(context.Background(), cfg, opts)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if rep.ControlsSkipped != "the validate tool failed: boom" || len(seen) != 2 || rep.Controls != nil {
		t.Errorf("controls skipped = %q after %v, controls = %+v, want the validate tool's error after the candidate's pack", rep.ControlsSkipped, seen, rep.Controls)
	}

	failing := filepath.Join(dir, "failing")
	if err := os.WriteFile(failing, []byte("#!/bin/sh\ncat >/dev/null\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	seen, failOn = nil, -1
	opts.Binary = failing
	rep, _, err = Run(context.Background(), cfg, opts)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if rep.Candidate.Status != "failed" || rep.ControlsSkipped != "a run failed, so there are no packs to validate" || len(seen) != 0 {
		t.Errorf("candidate = %+v, controls skipped = %q after %v, want no validation of a failed run", rep.Candidate, rep.ControlsSkipped, seen)
	}
}
