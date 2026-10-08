//go:build components

package remotecmd

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/locktivity/epack/internal/remote"
)

func TestKeyFileIsTheMachineKeyUnlessOutIsGiven(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	keyOut = ""
	t.Cleanup(func() { keyOut = "" })

	path, machineKey, err := keyFile("locktivity")
	if err != nil {
		t.Fatal(err)
	}
	if !machineKey || path != filepath.Join(home, ".epack", "keys", "locktivity.pem") {
		t.Fatalf("machine key = %q (%v)", path, machineKey)
	}
	if displayPath(path) != "~/.epack/keys/locktivity.pem" {
		t.Fatalf("displayPath = %q", displayPath(path))
	}

	keyOut = "./key.pem"
	path, machineKey, err = keyFile("locktivity")
	if err != nil {
		t.Fatal(err)
	}
	wd, _ := os.Getwd()
	if machineKey || path != filepath.Join(wd, "key.pem") {
		t.Fatalf("out key = %q (%v)", path, machineKey)
	}
}

func TestGeneratedKeysCarryTheirPublicHalfAndFingerprint(t *testing.T) {
	key, err := generateKey()
	if err != nil {
		t.Fatal(err)
	}
	if len(key.fingerprint) != 64 || key.publicPEM == "" || len(key.privatePEM) == 0 {
		t.Fatalf("incomplete key: %+v", key)
	}
	path := filepath.Join(t.TempDir(), "k.pem")
	if err := os.WriteFile(path, key.privatePEM, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := loadKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.fingerprint != key.fingerprint {
		t.Fatalf("fingerprint changed on reload")
	}
}

func TestExpiryPhraseAndKeyNames(t *testing.T) {
	if got := expiryPhrase(""); got != "with no expiry" {
		t.Fatalf("expiryPhrase(\"\") = %q", got)
	}
	when := time.Date(2027, 10, 1, 12, 0, 0, 0, time.UTC)
	if got := expiryPhrase(when.Format(time.RFC3339)); got != "expiring "+when.Local().Format("2006-01-02") {
		t.Fatalf("expiryPhrase = %q", got)
	}
	if got := keyDisplayName(remote.SigningKey{Fingerprint: "9f14322ec5bab3f5"}); got != "9f14322e" {
		t.Fatalf("keyDisplayName = %q", got)
	}
	if got := keyDisplayName(remote.SigningKey{Name: "laptop", Fingerprint: "9f14322ec5bab3f5"}); got != "laptop" {
		t.Fatalf("keyDisplayName = %q", got)
	}
}
