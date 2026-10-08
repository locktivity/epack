package sign

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestLoadPublicKey(t *testing.T) {
	t.Parallel()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	pubPath := filepath.Join(dir, "signer.pub")
	if err := os.WriteFile(pubPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}

	loaded, err := LoadPublicKey(pubPath)
	if err != nil {
		t.Fatalf("LoadPublicKey: %v", err)
	}
	if !key.PublicKey.Equal(loaded) {
		t.Fatal("loaded key does not match")
	}

	privDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	privPath := filepath.Join(dir, "signer.pem")
	if err := os.WriteFile(privPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPublicKey(privPath); err == nil || !strings.Contains(err.Error(), "found a private key") {
		t.Fatalf("LoadPublicKey(private) = %v, want a refusal", err)
	}
}

func TestGenerateKeyRoundTripsThroughPEMAndFingerprints(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	privPEM, err := MarshalPrivateKeyPEM(key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "keys", "locktivity.pem")
	if err := SavePrivateKey(path, privPEM); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("key file mode = %o, want 600", info.Mode().Perm())
	}

	loaded, err := LoadPrivateKey(path)
	if err != nil {
		t.Fatal(err)
	}
	want, err := Fingerprint(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	got, err := Fingerprint(loaded.Public())
	if err != nil {
		t.Fatal(err)
	}
	if got != want || len(got) != 64 {
		t.Fatalf("fingerprint %q, want %q", got, want)
	}

	pubPEM, err := MarshalPublicKeyPEM(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ParsePublicKeyPEM(pubPEM)
	if err != nil {
		t.Fatal(err)
	}
	if fp, _ := Fingerprint(pub); fp != want {
		t.Fatalf("public PEM fingerprint %q, want %q", fp, want)
	}

	if err := SavePrivateKey(path, privPEM); err != nil {
		t.Fatalf("overwriting the key: %v", err)
	}
}
