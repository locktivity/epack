package verify

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/locktivity/epack/sign/sigstore"
	"github.com/sigstore/sigstore-go/pkg/root"
)

func keySignedBundle(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	signer, err := sigstore.NewSigner(context.Background(), sigstore.Options{PrivateKey: key, SkipTlog: true})
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	statement := []byte(`{"_type":"https://in-toto.io/Statement/v1","subject":[{"name":"manifest.json","digest":{"sha256":"` + strings.Repeat("ab", 32) + `"}}],"predicateType":"https://epack.dev/attestation/v1","predicate":{}}`)
	b, err := signer.Sign(context.Background(), statement)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	data, err := sigstore.MarshalBundle(b)
	if err != nil {
		t.Fatalf("MarshalBundle: %v", err)
	}
	return data
}

func newTestKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestSigstoreVerifier_VerifiesAKeySignatureWithTheProvidedKey(t *testing.T) {
	t.Parallel()

	key := newTestKey(t)
	other := newTestKey(t)
	bundleJSON := keySignedBundle(t, key)

	verifier, err := NewSigstoreVerifier(
		WithOffline(),
		WithTrustedRoot(mustLoadTestTrustedRoot(t)),
		WithTransparencyLogThreshold(0),
		WithPublicKeys(other.Public(), key.Public()),
	)
	if err != nil {
		t.Fatalf("NewSigstoreVerifier: %v", err)
	}

	result, err := verifier.Verify(context.Background(), bundleJSON)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if result == nil || !result.Verified {
		t.Fatal("expected a verified result")
	}
	der, _ := x509.MarshalPKIXPublicKey(key.Public())
	want := fmt.Sprintf("%x", sha256.Sum256(der))
	if result.Identity == nil || result.Identity.Method != "key" || result.Identity.Subject != want {
		t.Fatalf("Identity = %+v, want key %s", result.Identity, want)
	}
	if result.Identity.Issuer != "" {
		t.Fatalf("Issuer = %q, want empty for a key", result.Identity.Issuer)
	}
}

func TestSigstoreVerifier_RejectsAKeySignatureFromAnUnknownKey(t *testing.T) {
	t.Parallel()

	bundleJSON := keySignedBundle(t, newTestKey(t))

	verifier, err := NewSigstoreVerifier(
		WithOffline(),
		WithTrustedRoot(mustLoadTestTrustedRoot(t)),
		WithTransparencyLogThreshold(0),
		WithPublicKeys(newTestKey(t).Public()),
	)
	if err != nil {
		t.Fatalf("NewSigstoreVerifier: %v", err)
	}
	_, err = verifier.Verify(context.Background(), bundleJSON)
	if err == nil || !strings.Contains(err.Error(), "none of the 1 provided public keys") {
		t.Fatalf("Verify = %v, want a key mismatch", err)
	}
}

func TestSigstoreVerifier_NamesTheMissingKeyForAKeySignature(t *testing.T) {
	t.Parallel()

	bundleJSON := keySignedBundle(t, newTestKey(t))

	verifier, err := NewSigstoreVerifier(
		WithOffline(),
		WithTrustedRoot(mustLoadTestTrustedRoot(t)),
		WithTransparencyLogThreshold(0),
	)
	if err != nil {
		t.Fatalf("NewSigstoreVerifier: %v", err)
	}
	_, err = verifier.Verify(context.Background(), bundleJSON)
	if err == nil || !strings.Contains(err.Error(), "pass the signer's public key") {
		t.Fatalf("Verify = %v, want it to ask for the key", err)
	}
}

func TestSigstoreVerifier_KeySignatureCannotMeetAnIssuerPolicy(t *testing.T) {
	t.Parallel()

	key := newTestKey(t)
	bundleJSON := keySignedBundle(t, key)

	verifier, err := NewSigstoreVerifier(
		WithOffline(),
		WithTrustedRoot(mustLoadTestTrustedRoot(t)),
		WithTransparencyLogThreshold(0),
		WithIssuer("https://accounts.google.com"),
		WithSubject("ci@example.com"),
		WithPublicKeys(key.Public()),
	)
	if err != nil {
		t.Fatalf("NewSigstoreVerifier: %v", err)
	}
	_, err = verifier.Verify(context.Background(), bundleJSON)
	if err == nil || !strings.Contains(err.Error(), "cannot satisfy an issuer or subject policy") {
		t.Fatalf("Verify = %v", err)
	}
}

func TestSigstoreVerifier_NamesTheMissingLogEntryForAKeySignature(t *testing.T) {
	t.Parallel()

	key := newTestKey(t)
	bundleJSON := keySignedBundle(t, key)

	verifier, err := NewSigstoreVerifier(
		WithOffline(),
		WithTrustedRoot(mustLoadTestTrustedRoot(t)),
		WithPublicKeys(key.Public()),
	)
	if err != nil {
		t.Fatalf("NewSigstoreVerifier: %v", err)
	}
	_, err = verifier.Verify(context.Background(), bundleJSON)
	if err == nil || !strings.Contains(err.Error(), "not recorded in a transparency log") {
		t.Fatalf("Verify = %v, want it to name the missing log entry", err)
	}
}

func TestSigstoreVerifier_PublicKeysAreNoPolicyForACertificate(t *testing.T) {
	t.Parallel()

	bundleJSON, err := os.ReadFile("testdata/sigstore-js-provenance.sigstore.json")
	if err != nil {
		t.Fatal(err)
	}

	verifier, err := NewSigstoreVerifier(
		WithOffline(),
		WithTrustedRoot(mustLoadTestTrustedRoot(t)),
		WithPublicKeys(newTestKey(t).Public()),
	)
	if err != nil {
		t.Fatalf("NewSigstoreVerifier: %v", err)
	}
	_, err = verifier.Verify(context.Background(), bundleJSON)
	if err == nil || !strings.Contains(err.Error(), "identity policy required") {
		t.Fatalf("Verify = %v, want a certificate to still need an issuer or subject", err)
	}
}

func TestSigstoreVerifier_SkipsTheLogForKeySignaturesOnly(t *testing.T) {
	t.Parallel()

	key := newTestKey(t)
	certBundle, err := os.ReadFile("testdata/sigstore-js-provenance.sigstore.json")
	if err != nil {
		t.Fatal(err)
	}

	verifier, err := NewSigstoreVerifier(
		WithOffline(),
		WithTrustedRoot(mustLoadTestTrustedRoot(t)),
		WithInsecureSkipIdentityCheck(),
		WithPublicKeys(key.Public()),
		WithInsecureSkipTlogForKeys(),
	)
	if err != nil {
		t.Fatalf("NewSigstoreVerifier: %v", err)
	}
	if _, err := verifier.Verify(context.Background(), keySignedBundle(t, key)); err != nil {
		t.Fatalf("Verify(key signature without a log entry): %v", err)
	}
	result, err := verifier.Verify(context.Background(), certBundle)
	if err != nil {
		t.Fatalf("Verify(certificate signature): %v", err)
	}
	if len(result.Timestamps) == 0 {
		t.Fatal("certificate verified without its log timestamp, want the log still required")
	}
}

func TestNewSigstoreVerifier_FetchesTheTrustedRootOnlyWhenNeeded(t *testing.T) {
	orig := liveTrustedRoot
	t.Cleanup(func() { liveTrustedRoot = orig })
	var fetches int
	liveTrustedRoot = func() (root.TrustedMaterial, error) {
		fetches++
		return mustLoadTestTrustedRoot(t), nil
	}

	key := newTestKey(t)
	tests := []struct {
		name string
		opts []Option
		want int
	}{
		{name: "key, skipping the log", opts: []Option{WithPublicKeys(key.Public()), WithInsecureSkipTlogForKeys()}, want: 0},
		{name: "key, requiring the log", opts: []Option{WithPublicKeys(key.Public())}, want: 1},
		{name: "key, requiring a signed timestamp", opts: []Option{WithPublicKeys(key.Public()), WithInsecureSkipTlogForKeys(), WithTimestampAuthorityThreshold(1)}, want: 1},
		{name: "certificate identity", opts: []Option{WithIssuer("https://accounts.google.com"), WithPublicKeys(key.Public()), WithInsecureSkipTlogForKeys()}, want: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fetches = 0
			verifier, err := NewSigstoreVerifier(tt.opts...)
			if err != nil {
				t.Fatalf("NewSigstoreVerifier: %v", err)
			}
			if fetches != tt.want {
				t.Fatalf("fetched the trusted root %d times, want %d", fetches, tt.want)
			}
			if tt.want == 0 {
				if _, err := verifier.Verify(context.Background(), keySignedBundle(t, key)); err != nil {
					t.Fatalf("Verify: %v", err)
				}
			}
		})
	}
}
