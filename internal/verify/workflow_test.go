package verify

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/locktivity/epack/pack"
	"github.com/locktivity/epack/pack/builder"
	"github.com/locktivity/epack/pack/verify"
	"github.com/locktivity/epack/sign"
	"github.com/locktivity/epack/sign/sigstore"
)

func TestAttestationDetailCarriesTheLogEntryAndCertificate(t *testing.T) {
	signed := time.Date(2026, 10, 20, 6, 3, 52, 0, time.UTC)
	detail := attestationDetail("attestations/a.sigstore.json", &verify.Result{
		Identity:        &verify.Identity{Issuer: "https://token.actions.githubusercontent.com", Subject: "https://github.com/acme/evidence/.github/workflows/collect.yml@refs/heads/main", Method: "certificate"},
		Timestamps:      []time.Time{signed},
		TransparencyLog: &verify.TransparencyLogEntry{LogIndex: 3291447186, LogID: "c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d"},
		Certificate: &verify.CertificateClaims{
			RunInvocationURI:       "https://github.com/acme/evidence/actions/runs/18224519/attempts/1",
			SourceRepositoryURI:    "https://github.com/acme/evidence",
			SourceRepositoryDigest: "5d0c1e7f2a9b4c3d8e6f1a0b2c4d6e8f0a1b3c5d",
			SourceRepositoryRef:    "refs/heads/main",
			RunnerEnvironment:      "github-hosted",
		},
	})
	raw, err := json.Marshal(detail)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`"signed_at":"2026-10-20T06:03:52Z"`,
		`"log_index":3291447186`,
		`"log_id":"c0d23d6a`,
		`"certificate":{"run_invocation_uri":"https://github.com/acme/evidence/actions/runs/18224519/attempts/1","source_repository_uri":"https://github.com/acme/evidence","source_repository_digest":"5d0c1e7f2a9b4c3d8e6f1a0b2c4d6e8f0a1b3c5d","source_repository_ref":"refs/heads/main","runner_environment":"github-hosted"}`,
	} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("detail JSON %s lacks %s", raw, want)
		}
	}

	keyed, _ := json.Marshal(attestationDetail("attestations/b.sigstore.json", &verify.Result{
		Identity:        &verify.Identity{Subject: "SHA256:abc", Method: "key"},
		TransparencyLog: &verify.TransparencyLogEntry{LogIndex: 0, LogID: "log"},
	}))
	if !strings.Contains(string(keyed), `"log_index":0`) || strings.Contains(string(keyed), "certificate") {
		t.Errorf("a key signature recorded in the log = %s, want its log entry, even at index 0, and no certificate", keyed)
	}
	unlogged, _ := json.Marshal(attestationDetail("attestations/c.sigstore.json", &verify.Result{}))
	if strings.Contains(string(unlogged), "log_index") {
		t.Errorf("a signature with no log entry = %s", unlogged)
	}
}

func TestPackVerifiesAKeySignatureWithOnlyThePublicKey(t *testing.T) {
	key := newKey(t)
	p := keySignedPack(t, key)
	trustRoot := filepath.Join("..", "..", "pack", "verify", "testdata", "public-good.json")

	tests := []struct {
		name      string
		opts      PackOpts
		wantError string
	}{
		{
			name: "signer's key, skipping the log",
			opts: PackOpts{PublicKeys: []crypto.PublicKey{key.Public()}, InsecureSkipTlog: true},
		},
		{
			name:      "signer's key requiring a log entry",
			opts:      PackOpts{PublicKeys: []crypto.PublicKey{key.Public()}},
			wantError: "not recorded in a transparency log",
		},
		{
			name:      "another key",
			opts:      PackOpts{PublicKeys: []crypto.PublicKey{newKey(t).Public()}, InsecureSkipTlog: true},
			wantError: "none of the 1 provided public keys signed this attestation",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.opts.TrustRootPath = trustRoot
			result, err := Pack(context.Background(), p, tt.opts)
			if err != nil {
				t.Fatal(err)
			}
			if tt.wantError == "" {
				if !result.Verified || len(result.Attestations) != 1 || result.Attestations[0].Method != "key" {
					t.Fatalf("result = %+v, want one verified key attestation", result)
				}
				return
			}
			if result.Verified || len(result.AttestationErrors) != 1 || !strings.Contains(result.AttestationErrors[0], tt.wantError) {
				t.Fatalf("attestation errors = %q, want %q", result.AttestationErrors, tt.wantError)
			}
			if strings.Count(result.AttestationErrors[0], "verification failed") != 1 {
				t.Fatalf("attestation error %q, want one verification failed prefix", result.AttestationErrors[0])
			}
		})
	}
}

func keySignedPack(t *testing.T, key *ecdsa.PrivateKey) *pack.Pack {
	t.Helper()
	b := builder.New("test/key")
	if err := b.AddBytes("artifacts/a.json", []byte(`{"a":1}`)); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "key.epack")
	if err := b.Build(path); err != nil {
		t.Fatal(err)
	}
	signer, err := sigstore.NewSigner(context.Background(), sigstore.Options{PrivateKey: key, SkipTlog: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := sign.SignPackFile(context.Background(), path, signer); err != nil {
		t.Fatal(err)
	}
	p, err := pack.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })
	return p
}

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}
