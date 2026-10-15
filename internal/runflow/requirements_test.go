package runflow

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/locktivity/epack/internal/remote"
	"github.com/locktivity/epack/internal/testutil/testhome"
	"github.com/locktivity/epack/internal/trustedpublishers"
)

// fetchedFolder writes a folder as a fetch leaves it: the configuration and
// a pull record.
func fetchedFolder(t *testing.T, config string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "epack.yaml"), []byte(config), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, ".epack"), 0o755); err != nil {
		t.Fatal(err)
	}
	state := `{"remote":"locktivity","id":"pipe_1","name":"northwind-production","revision":2,"pulled_at":"2026-10-15T12:00:00Z","files":{}}`
	if err := os.WriteFile(filepath.Join(dir, ".epack", "remote-config.json"), []byte(state), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

const sentryRevision = `stream: northwind/production
collectors:
  sentry:
    source: locktivity/epack-collector-sentry@v0.3.1
    secrets:
      - SENTRY_AUTH_TOKEN
      - name: SENTRY_REGION
        optional: true
remotes:
  locktivity:
    source: locktivity/epack-remote-locktivity@v0.2.2
    secrets:
      - LOCKTIVITY_CLIENT_SECRET
`

func requirementsFor(t *testing.T, dir string, needs *remote.ConfigRequirements, running string) []MissingRequirement {
	t.Helper()
	missing, err := MissingRequirements(Options{WorkDir: dir, NonInteractive: true, SkipSecretStore: true, Requirements: needs, Version: running})
	if err != nil {
		t.Fatalf("MissingRequirements: %v", err)
	}
	return missing
}

func TestMissingRequirements_NamesARequiredVariableOnly(t *testing.T) {
	testhome.Isolate(t)
	t.Setenv(trustedpublishers.EnvVar, "locktivity")
	t.Setenv("SENTRY_AUTH_TOKEN", "")
	t.Setenv("SENTRY_REGION", "")
	t.Setenv("LOCKTIVITY_CLIENT_SECRET", "")

	missing := requirementsFor(t, fetchedFolder(t, sentryRevision), nil, "0.5.0")
	got, _ := json.Marshal(Requirements(missing))
	if string(got) != `[{"kind":"variable","name":"SENTRY_AUTH_TOKEN"}]` {
		t.Errorf("missing = %s, want only the required collector variable", got)
	}

	t.Setenv("SENTRY_AUTH_TOKEN", "sntrys_value")
	if missing := requirementsFor(t, fetchedFolder(t, sentryRevision), nil, "0.5.0"); len(missing) != 0 {
		t.Errorf("missing = %+v, want nothing once the variable is set", missing)
	}
}

func TestMissingRequirements_NamesAPublisherNobodyTrusted(t *testing.T) {
	testhome.Isolate(t)
	t.Setenv(trustedpublishers.EnvVar, "")
	t.Setenv("SENTRY_AUTH_TOKEN", "sntrys_value")

	missing := requirementsFor(t, fetchedFolder(t, sentryRevision), nil, "0.5.0")
	if len(missing) != 1 || missing[0].Kind != remote.RequirementPublisher || missing[0].Name != "locktivity" {
		t.Fatalf("missing = %+v, want the locktivity publisher", missing)
	}
	if missing[0].Fix != "add locktivity to "+trustedpublishers.EnvVar {
		t.Errorf("fix = %q", missing[0].Fix)
	}
}

func TestMissingRequirements_NamesTheEpackARevisionNeeds(t *testing.T) {
	testhome.Isolate(t)
	t.Setenv(trustedpublishers.EnvVar, "locktivity")
	t.Setenv("SENTRY_AUTH_TOKEN", "sntrys_value")

	missing := requirementsFor(t, fetchedFolder(t, sentryRevision), &remote.ConfigRequirements{Epack: "v0.5.0"}, "0.4.9")
	if len(missing) != 1 || missing[0].Kind != remote.RequirementEpack || missing[0].Name != "v0.5.0" {
		t.Fatalf("missing = %+v, want epack v0.5.0", missing)
	}
	if missing[0].Problem() != "epack 0.5.0 or later is needed" {
		t.Errorf("problem = %q", missing[0].Problem())
	}

	if missing := requirementsFor(t, fetchedFolder(t, sentryRevision), &remote.ConfigRequirements{Epack: "v0.5.0"}, "0.5.0"); len(missing) != 0 {
		t.Errorf("missing = %+v, want nothing on the release it needs", missing)
	}
}

func TestOlderEpack(t *testing.T) {
	cases := []struct {
		current, needed string
		older           bool
	}{
		{"0.4.9", "v0.5.0", true},
		{"0.5.0", "v0.5.0", false},
		{"v0.5.1", "0.5.0", false},
		{"0.5.0-rc.1", "v0.5.0", true},
		{"0.5.0-rc.9", "v0.5.0-rc.10", true},
		{"0.5.0-rc.10", "v0.5.0-rc.9", false},
		{"dev", "v0.5.0", false},
		{"0.4.0", "", false},
	}
	for _, tc := range cases {
		if got := olderEpack(tc.current, tc.needed); got != tc.older {
			t.Errorf("olderEpack(%q, %q) = %v, want %v", tc.current, tc.needed, got, tc.older)
		}
	}
}

func TestRequirementsReport_NamesWhatIsMissingWithoutValues(t *testing.T) {
	dir := fetchedFolder(t, sentryRevision)
	sentry := MissingRequirement{Requirement: remote.Requirement{Kind: remote.RequirementVariable, Name: "SENTRY_AUTH_TOKEN"}, Fix: "epack secret set SENTRY_AUTH_TOKEN"}
	older := MissingRequirement{Requirement: remote.Requirement{Kind: remote.RequirementVariable, Name: "OLD_TOKEN"}}
	t.Setenv(PipelineIDEnvVar, "")
	provenance, err := RequirementsReport(dir, "pipe_1", 2, []MissingRequirement{sentry}, []MissingRequirement{sentry, older})
	if err != nil {
		t.Fatalf("RequirementsReport: %v", err)
	}
	if got := provenance.RuntimeContext["pipeline_id"]; got != "pipe_1" {
		t.Errorf("pipeline_id = %v, want the run's pipeline without exporting it", got)
	}
	if os.Getenv(PipelineIDEnvVar) != "" {
		t.Errorf("%s was exported", PipelineIDEnvVar)
	}
	if provenance.FailureCode != FailureRequirements || provenance.FailureMessage != "revision 2 needs SENTRY_AUTH_TOKEN" {
		t.Errorf("failure = %s: %s", provenance.FailureCode, provenance.FailureMessage)
	}
	reported, _ := json.Marshal(provenance.Metadata["requirements"])
	if string(reported) != `{"missing":[{"kind":"variable","name":"SENTRY_AUTH_TOKEN"},{"kind":"variable","name":"OLD_TOKEN"}],"revision":2}` {
		t.Errorf("requirements = %s, want everything the run lacked, so the remote picks no revision that needs any of it", reported)
	}
	if provenance.Metadata["config_sha256"] == nil {
		t.Error("the report should carry the configuration's digest so the remote can match the revision")
	}
}
