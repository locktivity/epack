//go:build components

package secretcmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/locktivity/epack/internal/cli/output"
	"github.com/locktivity/epack/internal/secrets"
	"github.com/locktivity/epack/internal/testutil/testhome"
	"github.com/spf13/cobra"
)

type memStore struct {
	values map[string]string
}

func (m *memStore) Kind() string { return "keychain" }

func (m *memStore) Get(scope secrets.Scope, name string, _ bool) (string, error) {
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

type harness struct {
	dir   string
	store *memStore
	out   *bytes.Buffer
}

func setup(t *testing.T) *harness {
	t.Helper()
	testhome.Isolate(t)
	t.Setenv("CI", "")
	t.Setenv("GITHUB_ACTIONS", "")
	t.Setenv("GITLAB_CI", "")
	t.Setenv(secrets.PipelineIDEnvVar, "")
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "epack.yaml"), []byte(laptopConfig), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, ".epack"), 0o755); err != nil {
		t.Fatal(err)
	}
	record := `{"remote":"locktivity","id":"pl_8f3a2c","name":"northwind-laptop","revision":4,"pulled_at":"2026-10-13T00:00:00Z","files":{}}`
	if err := os.WriteFile(filepath.Join(dir, ".epack", "remote-config.json"), []byte(record), 0o644); err != nil {
		t.Fatal(err)
	}
	oldWd, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldWd) })

	h := &harness{dir: dir, store: &memStore{values: map[string]string{}}, out: &bytes.Buffer{}}
	paths := secrets.Paths{Root: t.TempDir()}
	oldStore, oldPaths, oldStdin, oldStderr, oldReadAll, oldOutput := newStore, newPaths, stdinIsTerminal, stderrIsTerminal, readAllStdin, newOutput
	newStore = func() secrets.Store { return h.store }
	newPaths = func() (secrets.Paths, error) { return paths, nil }
	stdinIsTerminal = func() bool { return false }
	stderrIsTerminal = func() bool { return false }
	newOutput = func(*cobra.Command) *output.Writer { return output.New(h.out, h.out, output.Options{NoColor: true}) }
	t.Cleanup(func() {
		newStore, newPaths, stdinIsTerminal, stderrIsTerminal, readAllStdin, newOutput = oldStore, oldPaths, oldStdin, oldStderr, oldReadAll, oldOutput
	})
	return h
}

func (h *harness) run(t *testing.T, args ...string) error {
	t.Helper()
	h.out.Reset()
	cmd := NewCommand()
	cmd.SetArgs(args)
	cmd.SetOut(h.out)
	cmd.SetErr(h.out)
	return cmd.Execute()
}

func TestSet_FromStdinStoresAndApproves(t *testing.T) {
	h := setup(t)
	readAllStdin = func() ([]byte, error) { return []byte("azure-secret\n"), nil }
	if err := h.run(t, "set", "AZURE_CLIENT_SECRET", "--stdin"); err != nil {
		t.Fatalf("set: %v\n%s", err, h.out)
	}
	if got := h.store.values["locktivity:pl_8f3a2c/AZURE_CLIENT_SECRET"]; got != "azure-secret" {
		t.Errorf("stored %q", got)
	}
	if !strings.Contains(h.out.String(), "approved for microsoft-cloud") || !strings.Contains(h.out.String(), "Still needed: OKTA_PRIVATE_KEY.") {
		t.Errorf("output = %s", h.out)
	}
	readAllStdin = func() ([]byte, error) { return []byte("okta-key"), nil }
	if err := h.run(t, "set", "OKTA_PRIVATE_KEY", "--stdin"); err != nil {
		t.Fatalf("set: %v\n%s", err, h.out)
	}
	if !strings.Contains(h.out.String(), "Everything the configuration lists is in place. Next: epack run --check") {
		t.Errorf("output = %s", h.out)
	}
	if err := h.run(t, "list"); err != nil {
		t.Fatalf("list: %v", err)
	}
	if !strings.Contains(h.out.String(), "AZURE_CLIENT_SECRET") || !strings.Contains(h.out.String(), "approved at revision 4") || strings.Contains(h.out.String(), "azure-secret") {
		t.Errorf("list output = %s", h.out)
	}
}

func TestSet_RefusesAValueAsAnArgument(t *testing.T) {
	h := setup(t)
	err := h.run(t, "set", "AZURE_CLIENT_SECRET", "the-value")
	if err == nil || !strings.Contains(err.Error(), "not accepted as arguments") {
		t.Fatalf("err = %v", err)
	}
	if len(h.store.values) != 0 {
		t.Error("nothing may be stored")
	}
}

func TestSet_NeedsATerminalOrAFlag(t *testing.T) {
	h := setup(t)
	err := h.run(t, "set", "AZURE_CLIENT_SECRET")
	if err == nil || !strings.Contains(err.Error(), "no terminal") {
		t.Fatalf("err = %v", err)
	}
	stdinIsTerminal = func() bool { return true }
	err = h.run(t, "set", "AZURE_CLIENT_SECRET", "--stdin")
	if err == nil || !strings.Contains(err.Error(), "refusing to read a value from the terminal") {
		t.Fatalf("err = %v", err)
	}
}

func TestSet_FromFileStripsOneNewline(t *testing.T) {
	h := setup(t)
	path := filepath.Join(t.TempDir(), "okta.pem")
	if err := os.WriteFile(path, []byte("-----BEGIN KEY-----\nabc\n-----END KEY-----\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := h.run(t, "set", "OKTA_PRIVATE_KEY", "--from-file", path); err != nil {
		t.Fatalf("set: %v\n%s", err, h.out)
	}
	if got := h.store.values["locktivity:pl_8f3a2c/OKTA_PRIVATE_KEY"]; got != "-----BEGIN KEY-----\nabc\n-----END KEY-----" {
		t.Errorf("stored %q", got)
	}
}

func TestSet_UnlistedNameSuggestsRefreshingTheFolder(t *testing.T) {
	h := setup(t)
	readAllStdin = func() ([]byte, error) { return []byte("sentry-token"), nil }
	err := h.run(t, "set", "SENTRY_AUTH_TOKEN", "--stdin")
	want := "no component in revision 4 of northwind-laptop lists SENTRY_AUTH_TOKEN\n  Hint: This folder may be behind the current revision. Run 'epack remote clone' in this folder to update it, then run this command again. If the current revision does not list SENTRY_AUTH_TOKEN either, pass --unlisted to store it anyway"
	if err == nil || err.Error() != want {
		t.Fatalf("err = %v\nwant %s", err, want)
	}
	if len(h.store.values) != 0 {
		t.Error("nothing may be stored")
	}

	if err := os.Chdir(filepath.Join(h.dir, ".epack")); err != nil {
		t.Fatal(err)
	}
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	err = h.run(t, "set", "SENTRY_AUTH_TOKEN", "--stdin")
	if err == nil || !strings.Contains(err.Error(), "Run 'epack remote clone' in "+filepath.Dir(cwd)+" to update it") {
		t.Fatalf("from a folder below, the hint must name the folder: %v", err)
	}

	refreshed := laptopConfig + "  sentry:\n    source: locktivity/epack-collector-sentry@^0.1\n    secrets: [SENTRY_AUTH_TOKEN]\n"
	if err := os.WriteFile(filepath.Join(h.dir, "epack.yaml"), []byte(refreshed), 0o644); err != nil {
		t.Fatal(err)
	}
	record := `{"remote":"locktivity","id":"pl_8f3a2c","name":"northwind-laptop","revision":5,"pulled_at":"2026-10-15T00:00:00Z","files":{}}`
	if err := os.WriteFile(filepath.Join(h.dir, ".epack", "remote-config.json"), []byte(record), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := h.run(t, "set", "SENTRY_AUTH_TOKEN", "--stdin"); err != nil {
		t.Fatalf("after the refresh: %v\n%s", err, h.out)
	}
	if !strings.Contains(h.out.String(), "approved for sentry") {
		t.Errorf("output = %s", h.out)
	}
}

func TestSet_UnlistedNameWithoutAPullRecordOffersOnlyUnlisted(t *testing.T) {
	h := setup(t)
	t.Setenv(secrets.PipelineIDEnvVar, "pl_8f3a2c")
	withRemote := laptopConfig + "remotes:\n  locktivity:\n    source: locktivity/epack-remote-locktivity@^0.3\n"
	if err := os.WriteFile(filepath.Join(h.dir, "epack.yaml"), []byte(withRemote), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(h.dir, ".epack", "remote-config.json")); err != nil {
		t.Fatal(err)
	}
	readAllStdin = func() ([]byte, error) { return []byte("sentry-token"), nil }
	err := h.run(t, "set", "SENTRY_AUTH_TOKEN", "--stdin")
	if err == nil || err.Error() != "no component in this configuration lists SENTRY_AUTH_TOKEN; pass --unlisted to store it anyway" {
		t.Fatalf("err = %v", err)
	}
}

func TestApprove_ShowsTheChangeAndRecordsWithYes(t *testing.T) {
	h := setup(t)
	readAllStdin = func() ([]byte, error) { return []byte("azure-secret"), nil }
	if err := h.run(t, "set", "AZURE_CLIENT_SECRET", "--stdin"); err != nil {
		t.Fatal(err)
	}
	changed := strings.Replace(laptopConfig, "northwind.example", "contoso.example", 1)
	if err := os.WriteFile(filepath.Join(h.dir, "epack.yaml"), []byte(changed), 0o644); err != nil {
		t.Fatal(err)
	}
	record := `{"remote":"locktivity","id":"pl_8f3a2c","name":"northwind-laptop","revision":5,"pulled_at":"2026-10-14T00:00:00Z","files":{}}`
	if err := os.WriteFile(filepath.Join(h.dir, ".epack", "remote-config.json"), []byte(record), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := h.run(t, "list"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(h.out.String(), "needs approval: microsoft-cloud changed since you approved it") {
		t.Errorf("list output = %s", h.out)
	}
	err := h.run(t, "approve")
	if err == nil || !strings.Contains(err.Error(), "left unapproved") {
		t.Fatalf("approve without a terminal must leave it: %v\n%s", err, h.out)
	}
	text := h.out.String()
	for _, want := range []string{"AZURE_CLIENT_SECRET, approved at revision 4, now at revision 5.", "microsoft-cloud (github.com/locktivity) changed:", "contoso.example", "What this means: microsoft-cloud's settings changed, which may change where the credential is sent."} {
		if !strings.Contains(text, want) {
			t.Errorf("approve output missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "azure-secret") {
		t.Error("the value must never print")
	}
	if err := h.run(t, "approve", "--yes"); err != nil {
		t.Fatalf("approve --yes: %v\n%s", err, h.out)
	}
	if err := h.run(t, "approve"); err != nil || !strings.Contains(h.out.String(), "Nothing needs approval") {
		t.Errorf("after approval: %v %s", err, h.out)
	}
}

func TestRemove_ErasesValueAndRecord(t *testing.T) {
	h := setup(t)
	readAllStdin = func() ([]byte, error) { return []byte("azure-secret"), nil }
	if err := h.run(t, "set", "AZURE_CLIENT_SECRET", "--stdin"); err != nil {
		t.Fatal(err)
	}
	if err := h.run(t, "remove", "AZURE_CLIENT_SECRET"); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if len(h.store.values) != 0 {
		t.Error("value survived")
	}
	if err := h.run(t, "list"); err != nil || !strings.Contains(h.out.String(), "No secrets stored") {
		t.Errorf("list after remove: %v %s", err, h.out)
	}
	if err := h.run(t, "list", "--all"); err != nil || !strings.Contains(h.out.String(), "No secrets stored on this machine") {
		t.Errorf("list --all after remove: %v %s", err, h.out)
	}
}

func TestSetup_WalksMissingSecretsAndEndsWithTheNextCommand(t *testing.T) {
	h := setup(t)
	stdinIsTerminal = func() bool { return true }
	stderrIsTerminal = func() bool { return true }
	answers := [][]byte{[]byte("azure-value"), []byte("")}
	oldHidden := readHidden
	readHidden = func() ([]byte, error) {
		answer := answers[0]
		answers = answers[1:]
		return answer, nil
	}
	t.Cleanup(func() { readHidden = oldHidden })

	if err := h.run(t, "setup"); err != nil {
		t.Fatalf("setup: %v\n%s", err, h.out)
	}
	text := h.out.String()
	for _, want := range []string{
		"Secrets for northwind-laptop on locktivity, revision 4.",
		"AZURE_CLIENT_SECRET   read by microsoft-cloud (github.com/locktivity)",
		"Kept in your keychain and approved for microsoft-cloud.",
		"Skipped.",
		"Stored 1, approved 0, skipped 1.",
		"Skipped: OKTA_PRIVATE_KEY. For a file, run epack secret set OKTA_PRIVATE_KEY --from-file <path>.",
		"Next: epack run --check",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("setup output missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "azure-value") {
		t.Error("the value must never print")
	}
	if h.store.values["locktivity:pl_8f3a2c/AZURE_CLIENT_SECRET"] != "azure-value" {
		t.Error("the value was not stored")
	}
}

func TestSetup_NeedsATerminal(t *testing.T) {
	h := setup(t)
	err := h.run(t, "setup")
	if err == nil || !strings.Contains(err.Error(), "needs a terminal") {
		t.Fatalf("err = %v", err)
	}
}

func TestOpen_NeedsAPullRecord(t *testing.T) {
	h := setup(t)
	if err := os.Remove(filepath.Join(h.dir, ".epack", "remote-config.json")); err != nil {
		t.Fatal(err)
	}
	err := h.run(t, "list")
	if err == nil || !strings.Contains(err.Error(), "no pull record") {
		t.Fatalf("err = %v", err)
	}
}
