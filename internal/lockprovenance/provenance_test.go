package lockprovenance

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestBuildSuccessProvenance(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	raw := []byte(`schema_version: 1
collectors:
  github:
    source: github.com/acme/epack-collector-github
    version: v1.2.3
    commit: abc123
    locked_at: "2026-05-25T00:00:00Z"
    platforms:
      linux/amd64:
        digest: sha256:collector
tools:
  analyze:
    kind: external
    version: v0.1.0
    platforms:
      darwin/arm64:
        digest: sha256:tool
remotes:
  locktivity:
    source: github.com/locktivity/epack-remote-locktivity
    version: v1.0.0
    platforms:
      linux/amd64:
        digest: sha256:remote
`)
	if err := os.WriteFile(filepath.Join(root, "epack.lock.yaml"), raw, 0600); err != nil {
		t.Fatalf("writing lockfile: %v", err)
	}

	reportedAt := time.Date(2026, 5, 25, 12, 0, 0, 0, time.UTC)
	provenance, err := Build(Options{
		ProjectRoot: root,
		TriggerKind: TriggerBootstrap,
		Outcome:     OutcomeSuccess,
		ReportedAt:  reportedAt,
		Getenv: envGetter(map[string]string{
			"GITHUB_ACTIONS":    "true",
			"EPACK_PIPELINE_ID": "pipeline-123",
			"GITHUB_REPOSITORY": "acme/evidence",
			"GITHUB_REF":        "refs/heads/locktivity/setup",
		}),
	})
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	wantDigest := fmt.Sprintf("%x", sha256.Sum256(raw))
	if provenance.Lockfile != string(raw) {
		t.Fatal("Lockfile did not preserve raw YAML")
	}
	if provenance.LockfileSHA256 != wantDigest {
		t.Fatalf("LockfileSHA256 = %q, want %q", provenance.LockfileSHA256, wantDigest)
	}
	if provenance.TriggerKind != TriggerBootstrap || provenance.Outcome != OutcomeSuccess {
		t.Fatalf("trigger/outcome = %q/%q", provenance.TriggerKind, provenance.Outcome)
	}
	if provenance.ReportedAt != "2026-05-25T12:00:00Z" {
		t.Fatalf("ReportedAt = %q", provenance.ReportedAt)
	}
	if len(provenance.Summary.Collectors) != 1 || provenance.Summary.Collectors[0].Name != "github" {
		t.Fatalf("collector summary = %#v", provenance.Summary.Collectors)
	}
	if got := provenance.RuntimeContext["pipeline_id"]; got != "pipeline-123" {
		t.Fatalf("pipeline_id = %#v", got)
	}
}

func TestBuildFailureProvenance(t *testing.T) {
	t.Parallel()

	provenance, err := Build(Options{
		ProjectRoot:    t.TempDir(),
		TriggerKind:    TriggerFrozenCheck,
		Outcome:        OutcomeFailure,
		FailureCode:    "lock_config_mismatch",
		FailureMessage: "config changed without a lock refresh",
		Getenv:         envGetter(nil),
	})
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if provenance.Lockfile != "" {
		t.Fatal("failure provenance should not require raw lockfile")
	}
	if provenance.FailureCode != "lock_config_mismatch" {
		t.Fatalf("FailureCode = %q", provenance.FailureCode)
	}
}

func TestBuildFailureRequiresFailureCode(t *testing.T) {
	t.Parallel()

	if _, err := Build(Options{Outcome: OutcomeFailure}); err == nil {
		t.Fatal("Build() expected failure_code validation error")
	}
}

func envGetter(values map[string]string) func(string) string {
	return func(name string) string {
		return values[name]
	}
}
