package verify

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"strings"
	"testing"

	"github.com/locktivity/epack/sign/sigstore"
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
		WithInsecureSkipIdentityCheck(),
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
		WithInsecureSkipIdentityCheck(),
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
		WithInsecureSkipIdentityCheck(),
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
