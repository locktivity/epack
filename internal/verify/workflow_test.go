package verify

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/locktivity/epack/pack/verify"
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
