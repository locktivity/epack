package secrets

import (
	"strings"
	"testing"
	"time"
)

type fakeStore struct {
	values map[string]string
	fail   error
	calls  int
}

func newFakeStore() *fakeStore { return &fakeStore{values: map[string]string{}} }

func (f *fakeStore) Kind() string { return "keychain" }

func (f *fakeStore) Get(scope Scope, name string, _ bool) (string, error) {
	f.calls++
	if f.fail != nil {
		return "", f.fail
	}
	value, ok := f.values[scope.Key()+"/"+name]
	if !ok {
		return "", notFound(name)
	}
	return value, nil
}

func (f *fakeStore) Set(scope Scope, name, value string, _ bool) error {
	if f.fail != nil {
		return f.fail
	}
	f.values[scope.Key()+"/"+name] = value
	return nil
}

func (f *fakeStore) Erase(scope Scope, name string, _ bool) error {
	delete(f.values, scope.Key()+"/"+name)
	return nil
}

func envOf(values map[string]string) func(string) string {
	return func(name string) string { return values[name] }
}

func testService(t *testing.T, store Store) *Service {
	t.Helper()
	return &Service{Paths: Paths{Root: t.TempDir()}, Store: store, Now: func() time.Time { return time.Date(2026, 10, 13, 18, 2, 11, 0, time.UTC) }}
}

func rowByName(rows []Row, name string) Row {
	for _, row := range rows {
		if row.Name == name {
			return row
		}
	}
	return Row{}
}

func TestResolve_EnvironmentWins(t *testing.T) {
	conf := parseConfig(t, baseConfig)
	store := newFakeStore()
	service := testService(t, store)
	if _, err := service.Set(testScope, "AZURE_CLIENT_SECRET", "from-keychain", conf, false, false); err != nil {
		t.Fatal(err)
	}
	resolver := Resolver{Paths: service.Paths, Store: store, Env: envOf(map[string]string{"AZURE_CLIENT_SECRET": "from-env"})}
	res, err := resolver.Resolve(conf.Config, testScope, nil)
	if err != nil {
		t.Fatal(err)
	}
	row := rowByName(res.Rows, "AZURE_CLIENT_SECRET")
	if row.Status != StatusPresent || row.Source != SourceEnv {
		t.Errorf("row = %+v", row)
	}
	if res.Getenv("AZURE_CLIENT_SECRET") != "from-env" {
		t.Error("the environment value must win")
	}
	if len(res.Values()) != 0 {
		t.Errorf("nothing came from the store, values = %v", res.Values())
	}
}

func TestResolve_SkipsTheStoreInCI(t *testing.T) {
	conf := parseConfig(t, baseConfig)
	store := newFakeStore()
	resolver := Resolver{Paths: Paths{Root: t.TempDir()}, Store: store, Env: envOf(nil), Skip: true, SkipReason: "CI"}
	res, err := resolver.Resolve(conf.Config, testScope, nil)
	if err != nil {
		t.Fatal(err)
	}
	if store.calls != 0 || res.Store.Status != StoreSkipped {
		t.Errorf("store consulted in CI: calls=%d status=%+v", store.calls, res.Store)
	}
	row := rowByName(res.Rows, "AZURE_CLIENT_SECRET")
	if row.Status != StatusMissing || row.Finding() != "not set: AZURE_CLIENT_SECRET" {
		t.Errorf("row = %+v, finding %q", row, row.Finding())
	}
	if !InCI(envOf(map[string]string{"GITLAB_CI": "true"})) || InCI(envOf(nil)) {
		t.Error("InCI detection")
	}
}

func TestResolve_NoScopeMeansEnvironmentOnly(t *testing.T) {
	conf := parseConfig(t, baseConfig)
	store := newFakeStore()
	resolver := Resolver{Paths: Paths{Root: t.TempDir()}, Store: store, Env: envOf(nil)}
	res, err := resolver.Resolve(conf.Config, Scope{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if store.calls != 0 || res.Store.Status != StoreSkipped {
		t.Errorf("store consulted without a scope: %+v", res.Store)
	}
}

func TestResolve_StoredAndApprovedIsReady(t *testing.T) {
	conf := parseConfig(t, baseConfig)
	store := newFakeStore()
	service := testService(t, store)
	if _, err := service.Set(testScope, "AZURE_CLIENT_SECRET", "from-keychain", conf, false, false); err != nil {
		t.Fatal(err)
	}
	resolver := Resolver{Paths: service.Paths, Store: store, Env: envOf(nil)}
	res, err := resolver.Resolve(conf.Config, testScope, nil)
	if err != nil {
		t.Fatal(err)
	}
	row := rowByName(res.Rows, "AZURE_CLIENT_SECRET")
	if row.Status != StatusPresent || row.Source != SourceKeychain || row.StoredAt != "2026-10-13T18:02:11Z" || row.ApprovedRevision != 4 {
		t.Errorf("row = %+v", row)
	}
	if res.Getenv("AZURE_CLIENT_SECRET") != "from-keychain" || strings.Join(res.Values(), ",") != "from-keychain" {
		t.Error("the stored value must be handed out and redacted")
	}
	missing := rowByName(res.Rows, "OKTA_PRIVATE_KEY")
	if missing.Status != StatusMissing || missing.Fix != "epack secret set OKTA_PRIVATE_KEY" {
		t.Errorf("missing row = %+v", missing)
	}
	if len(res.Blocking()) != 1 || res.Blocking()[0].Name != "OKTA_PRIVATE_KEY" {
		t.Errorf("blocking = %+v", res.Blocking())
	}
	if res.Store.Status != StoreReady {
		t.Errorf("store = %+v", res.Store)
	}
}

func TestResolve_ChangedReaderNeedsApprovalAndHandsOutNothing(t *testing.T) {
	conf := parseConfig(t, baseConfig)
	store := newFakeStore()
	service := testService(t, store)
	if _, err := service.Set(testScope, "AZURE_CLIENT_SECRET", "from-keychain", conf, false, false); err != nil {
		t.Fatal(err)
	}
	changed := parseConfig(t, strings.Replace(baseConfig, "northwind.example", "contoso.example", 1))
	later := testScope
	later.Revision = 5
	res, err := (Resolver{Paths: service.Paths, Store: store, Env: envOf(nil)}).Resolve(changed.Config, later, nil)
	if err != nil {
		t.Fatal(err)
	}
	row := rowByName(res.Rows, "AZURE_CLIENT_SECRET")
	if row.Status != StatusApprovalNeeded || row.Fix != "epack secret approve AZURE_CLIENT_SECRET" {
		t.Errorf("row = %+v", row)
	}
	if row.Finding() != "AZURE_CLIENT_SECRET: microsoft-cloud changed since you approved it (revision 4 to 5); run epack secret approve AZURE_CLIENT_SECRET" {
		t.Errorf("finding = %q", row.Finding())
	}
	if res.Getenv("AZURE_CLIENT_SECRET") != "" || len(res.Values()) != 0 {
		t.Error("an unapproved value must not be handed out")
	}
}

func TestResolve_OptionalUnapprovedIsLeftOutWithoutBlocking(t *testing.T) {
	conf := parseConfig(t, baseConfig)
	store := newFakeStore()
	service := testService(t, store)
	if _, err := service.Set(testScope, "SENTRY_AUTH_TOKEN", "token", conf, false, false); err != nil {
		t.Fatal(err)
	}
	changed := parseConfig(t, strings.Replace(baseConfig, "okta@^0.1", "okta@^0.2", 1))
	res, err := (Resolver{Paths: service.Paths, Store: store, Env: envOf(map[string]string{"AZURE_CLIENT_SECRET": "x", "OKTA_PRIVATE_KEY": "y"})}).Resolve(changed.Config, testScope, nil)
	if err != nil {
		t.Fatal(err)
	}
	row := rowByName(res.Rows, "SENTRY_AUTH_TOKEN")
	if row.Status != StatusApprovalNeeded || !row.Optional || res.Getenv("SENTRY_AUTH_TOKEN") != "" {
		t.Errorf("row = %+v value=%q", row, res.Getenv("SENTRY_AUTH_TOKEN"))
	}
	if len(res.Blocking()) != 0 {
		t.Errorf("an optional secret must not block: %+v", res.Blocking())
	}
}

func TestResolve_StopsAfterTheFirstLockedAnswer(t *testing.T) {
	conf := parseConfig(t, baseConfig)
	store := newFakeStore()
	store.fail = &StoreError{Code: CodeLocked, Message: "the login keyring is locked"}
	res, err := (Resolver{Paths: Paths{Root: t.TempDir()}, Store: store, Env: envOf(nil)}).Resolve(conf.Config, testScope, nil)
	if err != nil {
		t.Fatal(err)
	}
	if store.calls != 1 {
		t.Errorf("store asked %d times, want once", store.calls)
	}
	for _, row := range res.Rows {
		if row.Status != StatusLocked {
			t.Errorf("row %s = %s, want locked", row.Name, row.Status)
		}
	}
	if res.Store.Status != StoreLocked {
		t.Errorf("store = %+v", res.Store)
	}
}

func TestResolve_LeavesCoveredNamesOut(t *testing.T) {
	conf := parseConfig(t, baseConfig)
	res, err := (Resolver{Paths: Paths{Root: t.TempDir()}, Store: newFakeStore(), Env: envOf(nil)}).Resolve(conf.Config, testScope, map[string]bool{"OKTA_PRIVATE_KEY": true})
	if err != nil {
		t.Fatal(err)
	}
	if rowByName(res.Rows, "OKTA_PRIVATE_KEY").Name != "" {
		t.Error("a covered name must not be a row")
	}
}

func TestResolve_StoredWithoutARecordNeedsApproval(t *testing.T) {
	conf := parseConfig(t, baseConfig)
	store := newFakeStore()
	store.values[testScope.Key()+"/AZURE_CLIENT_SECRET"] = "orphan"
	res, err := (Resolver{Paths: Paths{Root: t.TempDir()}, Store: store, Env: envOf(nil)}).Resolve(conf.Config, testScope, nil)
	if err != nil {
		t.Fatal(err)
	}
	row := rowByName(res.Rows, "AZURE_CLIENT_SECRET")
	if row.Status != StatusApprovalNeeded || row.Reason != "nothing is approved yet" {
		t.Errorf("row = %+v", row)
	}
}
