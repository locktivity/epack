package secrets

import (
	"errors"
	"strings"
	"testing"

	"github.com/zalando/go-keyring"
)

func mockKeychain(t *testing.T) *Keychain {
	t.Helper()
	keyring.MockInit()
	return &Keychain{backend: libraryKeyring{}}
}

var testScope = Scope{Remote: "locktivity", Configuration: "pl_8f3a2c", Label: "northwind-laptop", Revision: 4}

func TestKeychain_InlineRoundTrip(t *testing.T) {
	k := mockKeychain(t)
	if err := k.Set(testScope, "AZURE_CLIENT_SECRET", "s3cr3t-value\nwith newline", false); err != nil {
		t.Fatal(err)
	}
	got, err := k.Get(testScope, "AZURE_CLIENT_SECRET", false)
	if err != nil || got != "s3cr3t-value\nwith newline" {
		t.Fatalf("Get = %q, %v", got, err)
	}
	if _, err := keyring.Get(testScope.Service(), chunkAccount("AZURE_CLIENT_SECRET", 1, 1)); !errors.Is(err, keyring.ErrNotFound) {
		t.Error("an inline value must not write chunk items")
	}
}

func TestKeychain_ChunkedRoundTripAndErase(t *testing.T) {
	k := mockKeychain(t)
	value := strings.Repeat("-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7\n", 60)
	if err := k.Set(testScope, "OKTA_PRIVATE_KEY", value, false); err != nil {
		t.Fatal(err)
	}
	got, err := k.Get(testScope, "OKTA_PRIVATE_KEY", false)
	if err != nil || got != value {
		t.Fatalf("Get mismatch: err=%v len=%d want %d", err, len(got), len(value))
	}
	header, err := k.readHeader(testScope, "OKTA_PRIVATE_KEY")
	if err != nil || !header.chunked() || header.Chunks < 2 {
		t.Fatalf("expected a chunked header, got %+v (%v)", header, err)
	}
	if err := k.Erase(testScope, "OKTA_PRIVATE_KEY", false); err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= header.Chunks; i++ {
		if _, err := keyring.Get(testScope.Service(), chunkAccount("OKTA_PRIVATE_KEY", header.Generation, i)); !errors.Is(err, keyring.ErrNotFound) {
			t.Errorf("chunk %d survived erase", i)
		}
	}
	if _, err := k.Get(testScope, "OKTA_PRIVATE_KEY", false); CodeOf(err) != CodeNotFound {
		t.Errorf("after erase, Get = %v, want not_found", err)
	}
	if err := k.Erase(testScope, "OKTA_PRIVATE_KEY", false); err != nil {
		t.Errorf("erasing an absent value must not fail: %v", err)
	}
}

func TestKeychain_ReplacementRemovesTheOldGeneration(t *testing.T) {
	k := mockKeychain(t)
	first := strings.Repeat("a", 5000)
	second := strings.Repeat("b", 3000)
	if err := k.Set(testScope, "GOOGLE_SERVICE_ACCOUNT_JSON", first, false); err != nil {
		t.Fatal(err)
	}
	old, _ := k.readHeader(testScope, "GOOGLE_SERVICE_ACCOUNT_JSON")
	if err := k.Set(testScope, "GOOGLE_SERVICE_ACCOUNT_JSON", second, false); err != nil {
		t.Fatal(err)
	}
	got, err := k.Get(testScope, "GOOGLE_SERVICE_ACCOUNT_JSON", false)
	if err != nil || got != second {
		t.Fatalf("Get = len %d, %v", len(got), err)
	}
	current, _ := k.readHeader(testScope, "GOOGLE_SERVICE_ACCOUNT_JSON")
	if current.Generation != old.Generation+1 || len(current.Stale) != 0 {
		t.Errorf("header after replacement = %+v", current)
	}
	for i := 1; i <= old.Chunks; i++ {
		if _, err := keyring.Get(testScope.Service(), chunkAccount("GOOGLE_SERVICE_ACCOUNT_JSON", old.Generation, i)); !errors.Is(err, keyring.ErrNotFound) {
			t.Errorf("old chunk %d survived replacement", i)
		}
	}
	if err := k.Set(testScope, "GOOGLE_SERVICE_ACCOUNT_JSON", "short", false); err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= current.Chunks; i++ {
		if _, err := keyring.Get(testScope.Service(), chunkAccount("GOOGLE_SERVICE_ACCOUNT_JSON", current.Generation, i)); !errors.Is(err, keyring.ErrNotFound) {
			t.Errorf("chunk %d survived the inline replacement", i)
		}
	}
}

// failingBackend fails the first write to a given account, standing in for
// a process killed mid-replacement.
type failingBackend struct {
	keyringAPI
	failOn string
	failed bool
}

func (f *failingBackend) Set(service, user, password string) error {
	if user == f.failOn && !f.failed {
		f.failed = true
		return errors.New("killed")
	}
	return f.keyringAPI.Set(service, user, password)
}

func TestKeychain_InterruptedBeforeTheHeaderKeepsThePreviousValue(t *testing.T) {
	k := mockKeychain(t)
	first := strings.Repeat("x", 4000)
	if err := k.Set(testScope, "KEY", first, false); err != nil {
		t.Fatal(err)
	}
	k.backend = &failingBackend{keyringAPI: libraryKeyring{}, failOn: "KEY"}
	if err := k.Set(testScope, "KEY", strings.Repeat("y", 4000), false); err == nil {
		t.Fatal("expected the interrupted set to fail")
	}
	k.backend = libraryKeyring{}
	got, err := k.Get(testScope, "KEY", false)
	if err != nil || got != first {
		t.Fatalf("previous value lost: len %d, %v", len(got), err)
	}
	if _, err := keyring.Get(testScope.Service(), chunkAccount("KEY", 2, 1)); !errors.Is(err, keyring.ErrNotFound) {
		t.Error("a failed replacement must remove the chunks it wrote")
	}
}

func TestKeychain_KilledReplacementIsSweptByTheNextSet(t *testing.T) {
	k := mockKeychain(t)
	first := strings.Repeat("x", 4000)
	if err := k.Set(testScope, "KEY", first, false); err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 3; i++ {
		if err := keyring.Set(testScope.Service(), chunkAccount("KEY", 2, i), "orphan"); err != nil {
			t.Fatal(err)
		}
	}
	if got, err := k.Get(testScope, "KEY", false); err != nil || got != first {
		t.Fatalf("orphan chunks must not affect the current value: len %d, %v", len(got), err)
	}
	if err := k.Set(testScope, "KEY", strings.Repeat("z", 3000), false); err != nil {
		t.Fatal(err)
	}
	if got, err := k.Get(testScope, "KEY", false); err != nil || got != strings.Repeat("z", 3000) {
		t.Fatalf("Get after sweep: len %d, %v", len(got), err)
	}
	header, _ := k.readHeader(testScope, "KEY")
	if header.Generation != 2 || header.Chunks >= 3 {
		t.Fatalf("header = %+v", header)
	}
	if _, err := keyring.Get(testScope.Service(), chunkAccount("KEY", 2, 3)); !errors.Is(err, keyring.ErrNotFound) {
		t.Error("the orphan chunk beyond the new count survived the sweep")
	}
	if _, err := keyring.Get(testScope.Service(), chunkAccount("KEY", 1, 1)); !errors.Is(err, keyring.ErrNotFound) {
		t.Error("the previous generation survived the replacement")
	}
}

func TestKeychain_TornChunksReadAsNotFound(t *testing.T) {
	k := mockKeychain(t)
	if err := k.Set(testScope, "KEY", strings.Repeat("q", 4000), false); err != nil {
		t.Fatal(err)
	}
	header, _ := k.readHeader(testScope, "KEY")
	if err := keyring.Set(testScope.Service(), chunkAccount("KEY", header.Generation, header.Chunks), "AAAA"); err != nil {
		t.Fatal(err)
	}
	_, err := k.Get(testScope, "KEY", false)
	if CodeOf(err) != CodeNotFound || !strings.Contains(err.Error(), "incomplete") {
		t.Fatalf("Get = %v, want an incomplete not_found", err)
	}
}

func TestKeychain_RefusesValuesOverTheLimit(t *testing.T) {
	k := mockKeychain(t)
	err := k.Set(testScope, "KEY", strings.Repeat("a", MaxValueBytes+1), false)
	if CodeOf(err) != CodeTooLarge {
		t.Fatalf("err = %v, want too_large", err)
	}
}

func TestKeychain_ProbeAnswersBeforeTheLibrary(t *testing.T) {
	k := mockKeychain(t)
	k.probe = func(interactive bool) error {
		if interactive {
			return nil
		}
		return &StoreError{Code: CodeLocked, Message: "the login keyring is locked"}
	}
	if _, err := k.Get(testScope, "KEY", false); CodeOf(err) != CodeLocked {
		t.Fatalf("non-interactive Get = %v, want locked", err)
	}
	if err := k.Set(testScope, "KEY", "value", true); err != nil {
		t.Fatalf("interactive Set = %v", err)
	}
}

func TestKeychain_MapsPlatformMessages(t *testing.T) {
	k := &Keychain{}
	cases := map[string]Code{
		"exit status 36: User interaction is not allowed.":                        CodeLocked,
		"The name org.freedesktop.secrets was not provided by any .service files": CodeUnavailable,
		"Cannot autolaunch D-Bus without X11 $DISPLAY":                            CodeUnavailable,
		"A specified logon session does not exist. no such logon session":         CodeUnavailable,
		"something else entirely":                                                 CodeUnavailable,
	}
	for text, want := range cases {
		if got := CodeOf(k.mapError(errors.New(text), "KEY")); got != want {
			t.Errorf("%q mapped to %s, want %s", text, got, want)
		}
	}
	if CodeOf(k.mapError(keyring.ErrNotFound, "KEY")) != CodeNotFound {
		t.Error("ErrNotFound must map to not_found")
	}
}
