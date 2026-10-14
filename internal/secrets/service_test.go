package secrets

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestService_SetApprovesOnlyThatSecret(t *testing.T) {
	conf := parseConfig(t, baseConfig)
	store := newFakeStore()
	service := testService(t, store)
	if _, err := service.Set(testScope, "AZURE_CLIENT_SECRET", "azure", conf, false, false); err != nil {
		t.Fatal(err)
	}
	changed := parseConfig(t, strings.Replace(baseConfig, "northwind.example", "contoso.example", 1))
	if _, err := service.Set(testScope, "OKTA_PRIVATE_KEY", "okta", changed, false, false); err != nil {
		t.Fatal(err)
	}
	pending, err := service.Pending(testScope, changed, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 || pending[0].Name != "AZURE_CLIENT_SECRET" || pending[0].ApprovedRevision != 4 {
		t.Fatalf("pending = %+v, want only the Azure secret", pending)
	}
	if len(pending[0].Changes) != 1 || pending[0].Changes[0].Kind != "settings" || len(pending[0].Changes[0].Lines) == 0 {
		t.Errorf("changes = %+v", pending[0].Changes)
	}
	if err := service.Approve(testScope, "AZURE_CLIENT_SECRET", changed, false); err != nil {
		t.Fatal(err)
	}
	pending, err = service.Pending(testScope, changed, nil, false)
	if err != nil || len(pending) != 0 {
		t.Fatalf("after approve, pending = %+v (%v)", pending, err)
	}
	entries, err := service.List(testScope, changed)
	if err != nil || len(entries) != 2 || entries[0].Name != "AZURE_CLIENT_SECRET" || entries[0].NeedsApproval || entries[0].Readers[0].Name != "microsoft-cloud" {
		t.Fatalf("list = %+v (%v)", entries, err)
	}
	snapshots, _ := os.ReadDir(service.Paths.snapshotsDir())
	if len(snapshots) != 1 {
		t.Errorf("snapshots = %d, want only the one still referenced", len(snapshots))
	}
	info, err := os.Stat(service.Paths.metadataFile())
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Errorf("metadata mode = %v", info.Mode())
	}
}

func TestService_SetRefusesBadInput(t *testing.T) {
	conf := parseConfig(t, baseConfig)
	service := testService(t, newFakeStore())
	if _, err := service.Set(testScope, "AZURE_CLIENT_SECRET", "", conf, false, false); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Errorf("empty value: %v", err)
	}
	if _, err := service.Set(testScope, "NOT_LISTED", "x", conf, false, false); err == nil || !strings.Contains(err.Error(), "--unlisted") {
		t.Errorf("unlisted name: %v", err)
	}
	if _, err := service.Set(testScope, "NOT_LISTED", "x", conf, false, true); err != nil {
		t.Errorf("--unlisted should store: %v", err)
	}
	if _, err := service.Set(testScope, "EPACK_SIGNING_KEY", "x", conf, false, true); err == nil {
		t.Error("reserved prefixes must be refused")
	}
	if _, err := service.Set(testScope, "bad name", "x", conf, false, true); err == nil {
		t.Error("a name with a space must be refused")
	}
}

func TestService_RemoveErasesValueAndRecord(t *testing.T) {
	conf := parseConfig(t, baseConfig)
	store := newFakeStore()
	service := testService(t, store)
	if _, err := service.Set(testScope, "AZURE_CLIENT_SECRET", "azure", conf, false, false); err != nil {
		t.Fatal(err)
	}
	if err := service.Remove(testScope, "AZURE_CLIENT_SECRET", false); err != nil {
		t.Fatal(err)
	}
	if _, ok := store.values[testScope.Key()+"/AZURE_CLIENT_SECRET"]; ok {
		t.Error("value survived remove")
	}
	entries, _ := service.List(testScope, conf)
	if len(entries) != 0 {
		t.Errorf("record survived remove: %+v", entries)
	}
	all, _ := service.ListAll()
	if len(all) != 0 {
		t.Errorf("an empty scope should be dropped: %+v", all)
	}
}

func TestService_ApproveRecreatesAMissingRecord(t *testing.T) {
	conf := parseConfig(t, baseConfig)
	store := newFakeStore()
	store.values[testScope.Key()+"/AZURE_CLIENT_SECRET"] = "orphan"
	service := testService(t, store)
	if err := service.Approve(testScope, "AZURE_CLIENT_SECRET", conf, false); err != nil {
		t.Fatal(err)
	}
	entries, _ := service.List(testScope, conf)
	if len(entries) != 1 || entries[0].NeedsApproval {
		t.Fatalf("list = %+v", entries)
	}
	if err := service.Approve(testScope, "OKTA_PRIVATE_KEY", conf, false); CodeOf(err) != CodeNotFound {
		t.Errorf("approving a value the store lacks = %v, want not_found", err)
	}
}

func TestService_ListAllNamesEveryScope(t *testing.T) {
	conf := parseConfig(t, baseConfig)
	service := testService(t, newFakeStore())
	other := Scope{Remote: "locktivity", Configuration: "pl_other", Label: "other"}
	if _, err := service.Set(testScope, "AZURE_CLIENT_SECRET", "a", conf, false, false); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Set(other, "OKTA_PRIVATE_KEY", "b", conf, false, false); err != nil {
		t.Fatal(err)
	}
	all, err := service.ListAll()
	if err != nil || len(all) != 2 || all[0].Scope.Configuration != "pl_8f3a2c" || all[1].Names[0] != "OKTA_PRIVATE_KEY" {
		t.Fatalf("all = %+v (%v)", all, err)
	}
}

func TestService_LockIsExclusiveAcrossCommands(t *testing.T) {
	service := testService(t, newFakeStore())
	unlock, err := service.Paths.lockScope(testScope, true)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	done := make(chan error, 1)
	go func() {
		_, err := lockFile(filepath.Join(service.Paths.locksDir(), testScope.fileStem()+".lock"), true, 200000000)
		done <- err
	}()
	if err := <-done; CodeOf(err) != CodeBusy {
		t.Errorf("second command = %v, want busy", err)
	}
}

func TestReadValue(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key.pem")
	if err := os.WriteFile(path, []byte("-----BEGIN KEY-----\nabc\n-----END KEY-----\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	value, err := ReadValue(path, nil)
	if err != nil || value != "-----BEGIN KEY-----\nabc\n-----END KEY-----" {
		t.Errorf("file value = %q, %v", value, err)
	}
	value, err = ReadValue("", func() ([]byte, error) { return []byte("token\r\n"), nil })
	if err != nil || value != "token" {
		t.Errorf("stdin value = %q, %v", value, err)
	}
	if _, err := ReadValue("", func() ([]byte, error) { return nil, errors.New("closed") }); err == nil {
		t.Error("a stdin error must surface")
	}
}

func TestScopeFor(t *testing.T) {
	dir := t.TempDir()
	scope, err := ScopeFor(dir, "locktivity", envOf(nil))
	if err != nil || !scope.Zero() {
		t.Fatalf("no record: %+v, %v", scope, err)
	}
	scope, err = ScopeFor(dir, "locktivity", envOf(map[string]string{PipelineIDEnvVar: "pl_env"}))
	if err != nil || scope.Configuration != "pl_env" || scope.Remote != "locktivity" {
		t.Fatalf("env scope: %+v, %v", scope, err)
	}
	if err := os.MkdirAll(filepath.Join(dir, ".epack"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".epack", "remote-config.json"), []byte(`{"remote":"locktivity","id":"pl_rec","name":"northwind","revision":4,"pulled_at":"2026-10-13T00:00:00Z","files":{}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	scope, err = ScopeFor(dir, "", envOf(nil))
	if err != nil || scope.Configuration != "pl_rec" || scope.Label != "northwind" || scope.Revision != 4 || scope.Remote != "locktivity" {
		t.Fatalf("record scope: %+v, %v", scope, err)
	}
	if scope.String() != "northwind on locktivity" || scope.Service() != "epack:locktivity:pl_rec" {
		t.Errorf("names: %q %q", scope.String(), scope.Service())
	}
}
