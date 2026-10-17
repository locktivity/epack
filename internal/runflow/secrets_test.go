package runflow

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	epackerrors "github.com/locktivity/epack/errors"
	"github.com/locktivity/epack/internal/collector"
	collectorexec "github.com/locktivity/epack/internal/collector/exec"
	"github.com/locktivity/epack/internal/component/config"
	"github.com/locktivity/epack/internal/exitcode"
	"github.com/locktivity/epack/internal/secrets"
	"github.com/locktivity/epack/internal/testutil/testhome"
	"github.com/locktivity/epack/internal/trustedpublishers"
)

// memStore stands in for the keychain.
type memStore struct {
	values map[string]string
	calls  int
}

func (m *memStore) Kind() string { return "keychain" }

func (m *memStore) Get(scope secrets.Scope, name string, _ bool) (string, error) {
	m.calls++
	value, ok := m.values[scope.Key()+"/"+name]
	if !ok {
		return "", &secrets.StoreError{Code: secrets.CodeNotFound}
	}
	return value, nil
}

func (m *memStore) Set(scope secrets.Scope, name, value string, _ bool) error {
	m.values[scope.Key()+"/"+name] = value
	return nil
}

func (m *memStore) Erase(scope secrets.Scope, name string, _ bool) error {
	delete(m.values, scope.Key()+"/"+name)
	return nil
}

const laptopConfig = "stream: northwind/production\ncollectors:\n  microsoft-cloud:\n    source: locktivity/epack-collector-microsoft-cloud@^0.1\n    config:\n      tenant: northwind.example\n    secrets: [AZURE_CLIENT_SECRET]\n  okta:\n    source: locktivity/epack-collector-okta@^0.1\n    secrets: [OKTA_PRIVATE_KEY]\n"

func writeFetchedProject(t *testing.T, cfg string, revision string) string {
	t.Helper()
	dir := writeCheckProject(t, cfg)
	if err := os.MkdirAll(filepath.Join(dir, ".epack"), 0o755); err != nil {
		t.Fatal(err)
	}
	record := `{"remote":"locktivity","id":"pl_8f3a2c","name":"northwind-laptop","revision":` + revision + `,"pulled_at":"2026-10-13T00:00:00Z","files":{}}`
	if err := os.WriteFile(filepath.Join(dir, ".epack", "remote-config.json"), []byte(record), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestCheck_CountsStoredSecretsAsReadyOnceApproved(t *testing.T) {
	testhome.Isolate(t)
	t.Setenv(trustedpublishers.EnvVar, "locktivity")
	t.Setenv("CI", "")
	t.Setenv("GITHUB_ACTIONS", "")
	t.Setenv("GITLAB_CI", "")
	t.Setenv("AZURE_CLIENT_SECRET", "")
	t.Setenv("OKTA_PRIVATE_KEY", "from-env")
	t.Setenv(PipelineIDEnvVar, "")
	oldWd, _ := os.Getwd()
	defer func() { _ = os.Chdir(oldWd) }()

	dir := writeFetchedProject(t, laptopConfig, "4")
	store := &memStore{values: map[string]string{}}
	paths := secrets.Paths{Root: t.TempDir()}
	conf, err := secrets.LoadConfiguration(dir)
	if err != nil {
		t.Fatal(err)
	}
	scope, err := secrets.ScopeFor(dir, "", os.Getenv)
	if err != nil || scope.Zero() {
		t.Fatalf("scope = %+v, %v", scope, err)
	}
	service := &secrets.Service{Paths: paths, Store: store}
	if _, err := service.Set(scope, "AZURE_CLIENT_SECRET", "keychain-value", conf, false, false); err != nil {
		t.Fatal(err)
	}

	result, err := Check(context.Background(), Options{WorkDir: dir, NonInteractive: true, SecretStore: store, SecretPaths: paths})
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if result.EnvTotal != 2 || result.EnvPresent != 2 || len(result.EnvMissing) != 0 {
		t.Errorf("env = %d/%d missing %v", result.EnvPresent, result.EnvTotal, result.EnvMissing)
	}
	if result.SecretStore.Status != secrets.StoreReady || result.SecretStore.Kind != "keychain" {
		t.Errorf("store = %+v", result.SecretStore)
	}
	rows := map[string]secrets.Row{}
	for _, row := range result.Variables {
		rows[row.Name] = row
	}
	if row := rows["AZURE_CLIENT_SECRET"]; row.Status != secrets.StatusPresent || row.Source != secrets.SourceKeychain || row.ApprovedRevision != 4 {
		t.Errorf("azure row = %+v", row)
	}
	if row := rows["OKTA_PRIVATE_KEY"]; row.Status != secrets.StatusPresent || row.Source != secrets.SourceEnv {
		t.Errorf("okta row = %+v", row)
	}
	for _, finding := range result.Findings {
		if strings.Contains(finding, "AZURE_CLIENT_SECRET") || strings.Contains(finding, "not set") {
			t.Errorf("unexpected finding %q", finding)
		}
	}
	if store.calls != 1 {
		t.Errorf("store asked %d times; a variable set in the environment must not be looked up", store.calls)
	}
}

func TestCheck_ReportsApprovalNeededAfterTheReaderChanged(t *testing.T) {
	testhome.Isolate(t)
	t.Setenv(trustedpublishers.EnvVar, "locktivity")
	t.Setenv("CI", "")
	t.Setenv("GITHUB_ACTIONS", "")
	t.Setenv("GITLAB_CI", "")
	t.Setenv("AZURE_CLIENT_SECRET", "")
	t.Setenv("OKTA_PRIVATE_KEY", "from-env")
	t.Setenv(PipelineIDEnvVar, "")
	oldWd, _ := os.Getwd()
	defer func() { _ = os.Chdir(oldWd) }()

	dir := writeFetchedProject(t, laptopConfig, "4")
	store := &memStore{values: map[string]string{}}
	paths := secrets.Paths{Root: t.TempDir()}
	conf, _ := secrets.LoadConfiguration(dir)
	scope, _ := secrets.ScopeFor(dir, "", os.Getenv)
	if _, err := (&secrets.Service{Paths: paths, Store: store}).Set(scope, "AZURE_CLIENT_SECRET", "keychain-value", conf, false, false); err != nil {
		t.Fatal(err)
	}
	changed := strings.Replace(laptopConfig, "northwind.example", "contoso.example", 1)
	if err := os.WriteFile(filepath.Join(dir, "epack.yaml"), []byte(changed), 0o644); err != nil {
		t.Fatal(err)
	}
	record := `{"remote":"locktivity","id":"pl_8f3a2c","name":"northwind-laptop","revision":5,"pulled_at":"2026-10-14T00:00:00Z","files":{}}`
	if err := os.WriteFile(filepath.Join(dir, ".epack", "remote-config.json"), []byte(record), 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := Check(context.Background(), Options{WorkDir: dir, NonInteractive: true, SecretStore: store, SecretPaths: paths})
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if result.EnvPresent != 1 || strings.Join(result.EnvMissing, ",") != "AZURE_CLIENT_SECRET" {
		t.Errorf("env = %d/%d missing %v", result.EnvPresent, result.EnvTotal, result.EnvMissing)
	}
	want := "AZURE_CLIENT_SECRET: microsoft-cloud changed since you approved it (revision 4 to 5); run epack secret approve AZURE_CLIENT_SECRET"
	if !strings.Contains(strings.Join(result.Findings, "\n"), want) {
		t.Errorf("findings = %v, want %q", result.Findings, want)
	}
	if strings.Contains(strings.Join(result.Findings, "\n"), "not set: AZURE") {
		t.Errorf("an unapproved secret is not reported as unset: %v", result.Findings)
	}
}

func TestCheck_LeavesTheStoreAloneInCI(t *testing.T) {
	testhome.Isolate(t)
	t.Setenv(trustedpublishers.EnvVar, "locktivity")
	t.Setenv("CI", "true")
	t.Setenv("AZURE_CLIENT_SECRET", "")
	t.Setenv("OKTA_PRIVATE_KEY", "from-env")
	t.Setenv(PipelineIDEnvVar, "")
	oldWd, _ := os.Getwd()
	defer func() { _ = os.Chdir(oldWd) }()

	dir := writeFetchedProject(t, laptopConfig, "4")
	store := &memStore{values: map[string]string{"locktivity:pl_8f3a2c/AZURE_CLIENT_SECRET": "keychain-value"}}
	result, err := Check(context.Background(), Options{WorkDir: dir, NonInteractive: true, SecretStore: store, SecretPaths: secrets.Paths{Root: t.TempDir()}})
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if store.calls != 0 || result.SecretStore.Status != secrets.StoreSkipped {
		t.Errorf("store consulted in CI: calls=%d status=%+v", store.calls, result.SecretStore)
	}
	if !strings.Contains(strings.Join(result.Findings, "\n"), "not set: AZURE_CLIENT_SECRET") {
		t.Errorf("findings = %v", result.Findings)
	}
}

func TestCheck_LeavesTheStoreAloneBeforePublishersAreTrusted(t *testing.T) {
	testhome.Isolate(t)
	t.Setenv(trustedpublishers.EnvVar, "")
	t.Setenv("CI", "")
	t.Setenv("GITHUB_ACTIONS", "")
	t.Setenv("GITLAB_CI", "")
	t.Setenv("AZURE_CLIENT_SECRET", "")
	t.Setenv("OKTA_PRIVATE_KEY", "")
	t.Setenv(PipelineIDEnvVar, "")
	oldWd, _ := os.Getwd()
	defer func() { _ = os.Chdir(oldWd) }()

	dir := writeFetchedProject(t, laptopConfig, "4")
	store := &memStore{values: map[string]string{}}
	result, err := Check(context.Background(), Options{WorkDir: dir, NonInteractive: true, SecretStore: store, SecretPaths: secrets.Paths{Root: t.TempDir()}})
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if result.PublishersTrusted {
		t.Fatal("expected untrusted publishers")
	}
	if store.calls != 0 {
		t.Errorf("the store was consulted before publishers were trusted (%d calls)", store.calls)
	}
}

func TestSecretsError_NamesEachVariableAndItsFix(t *testing.T) {
	err := &secretsError{rows: []secrets.Row{
		{Name: "AZURE_CLIENT_SECRET", Status: secrets.StatusApprovalNeeded, Reason: "microsoft-cloud changed since you approved it", Fix: "epack secret approve AZURE_CLIENT_SECRET"},
		{Name: "OKTA_PRIVATE_KEY", Status: secrets.StatusMissing, Fix: "epack secret set OKTA_PRIVATE_KEY"},
	}}
	want := "AZURE_CLIENT_SECRET: microsoft-cloud changed since you approved it; run epack secret approve AZURE_CLIENT_SECRET; not set: OKTA_PRIVATE_KEY; run epack secret set OKTA_PRIVATE_KEY"
	if err.Error() != want {
		t.Errorf("error = %q", err.Error())
	}
}

func TestRemoteOnlyNames(t *testing.T) {
	cfg, err := config.Parse([]byte("stream: a/b\ncollectors:\n  okta:\n    source: locktivity/epack-collector-okta@^0.1\n    secrets: [OKTA_PRIVATE_KEY, SHARED]\nremotes:\n  locktivity:\n    source: locktivity/epack-remote-locktivity@^0.2\n    secrets: [LOCKTIVITY_TOKEN, SHARED]\n"))
	if err != nil {
		t.Fatal(err)
	}
	covered := remoteOnlyNames(cfg)
	if !covered["LOCKTIVITY_TOKEN"] || covered["SHARED"] || covered["OKTA_PRIVATE_KEY"] {
		t.Errorf("remote-only = %v", covered)
	}
	if !coveredNames(cfg, true)["LOCKTIVITY_TOKEN"] || coveredNames(cfg, true)["SHARED"] {
		t.Error("a signed-in session should cover only the remote's own variables")
	}
	if coveredNames(cfg, false) != nil {
		t.Error("nothing is covered without a sign-in")
	}
}

func TestCollectFailures_NameTheCollectorsAndKeepTheirErrors(t *testing.T) {
	collected := &collector.CollectWorkflowResult{CollectorResults: []collector.RunResult{
		{Collector: "tls", Success: true},
		{Collector: "okta", Success: false, Error: &collectorexec.ExitError{Code: 3, Stderr: "401 Unauthorized"}},
	}}
	failures := collectFailures(collected)
	want := collectFailure{Collector: "okta", Error: "exited with code 3: 401 Unauthorized", Code: "auth_failed", Exit: 3, CodeSource: "exit_code"}
	if len(failures) != 1 || failures[0] != want {
		t.Fatalf("failures = %+v, want %+v", failures, want)
	}
	if got := collectFailureMessage(failures); got != "okta: exited with code 3: 401 Unauthorized" {
		t.Errorf("one failure message = %q", got)
	}
	encoded, err := json.Marshal(failures[0])
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) != `{"collector":"okta","error":"exited with code 3: 401 Unauthorized","code":"auth_failed","exit":3,"code_source":"exit_code"}` {
		t.Errorf("report entry = %s", encoded)
	}

	timedOut := epackerrors.WithHint(epackerrors.Timeout, exitcode.Timeout, `collector "sentry" timed out after 10m0s`, "Increase timeout", nil)
	collected.CollectorResults = append(collected.CollectorResults, collector.RunResult{Collector: "sentry", Error: timedOut})
	failures = collectFailures(collected)
	if got := collectFailureMessage(failures); got != "2 collectors failed: okta, sentry" {
		t.Errorf("two failures message = %q", got)
	}
	if len(failures) != 2 || failures[1].Code != "timeout" || failures[1].Exit != exitcode.Timeout || failures[1].CodeSource != "runner" {
		t.Errorf("timeout failure = %+v", failures[1])
	}
	if collectFailures(nil) != nil {
		t.Error("no collect result means no failures")
	}
}
