//go:build components

package remotecmd

import (
	"strings"
	gosync "sync"
	"testing"

	"github.com/locktivity/epack/internal/broker"
	"github.com/locktivity/epack/internal/remote"
	"github.com/locktivity/epack/internal/trustedpublishers"
)

func TestInstallTrustedPin_InstallsOnlyFromATrustedPublisher(t *testing.T) {
	trusted := trustedpublishers.NewSet("locktivity")

	if !InstallTrustedPin("locktivity", "locktivity", "locktivity", trusted) {
		t.Error("a pinned adapter from a trusted publisher should install without asking")
	}
	if InstallTrustedPin("locktivity", "locktivity", "someone", trusted) {
		t.Error("an adapter from a publisher nobody trusted must not install without asking")
	}
	if InstallTrustedPin("locktivity", "locktivity", "", trusted) {
		t.Error("an adapter with no source has no publisher to trust")
	}
	if InstallTrustedPin("locktivity", "locktivity", "locktivity", nil) {
		t.Error("with publishers that can't be read, nothing installs without asking")
	}
}

func TestPrepareOptions_AsksOrInstallsFromTheTrustedSetBuiltOnce(t *testing.T) {
	builds := 0
	trusted := func() (trustedpublishers.Set, error) {
		builds++
		return trustedpublishers.NewSet("someone"), nil
	}
	prompt := PrepareOptions{Install: InstallTrustedPin}.promptInstall("someone", gosync.OnceValues(trusted))
	if !prompt("locktivity", "locktivity") || !prompt("locktivity", "locktivity") || builds != 1 {
		t.Errorf("installs = %v, builds = %d, want an install from the one trusted set", prompt("locktivity", "locktivity"), builds)
	}
	if (PrepareOptions{}).promptInstall("someone", trusted) != nil {
		t.Error("without a policy nothing installs, as before")
	}
	asked := false
	ask := PrepareOptions{Install: AskToInstall(func(string, string) bool { asked = true; return false })}.promptInstall("someone", trusted)
	if ask("locktivity", "locktivity") || !asked {
		t.Error("asking leaves the answer to the person")
	}
}

func TestUserRemoteEndpoints_PassesAnOperatorsOverrideToTheAdapter(t *testing.T) {
	t.Setenv(InsecureRemoteEndpointEnvVar, "https://dev.example.test")
	t.Setenv(InsecureRemoteAuthEndpointEnvVar, "https://dev-app.example.test")

	env, err := userRemoteEndpoints(nil, "locktivity")
	if err != nil {
		t.Fatalf("userRemoteEndpoints: %v", err)
	}
	if env[remote.RemoteEndpointEnvVar] != "https://dev.example.test" || env[remote.RemoteAuthEndpointEnvVar] != "https://dev-app.example.test" {
		t.Errorf("env = %v", env)
	}
}

func TestUserRemoteEndpoints_NothingWithoutAnOverride(t *testing.T) {
	t.Setenv(InsecureRemoteEndpointEnvVar, "")
	t.Setenv(InsecureRemoteAuthEndpointEnvVar, "")

	env, err := userRemoteEndpoints(nil, "locktivity")
	if err != nil || env != nil {
		t.Fatalf("env = %v, err = %v", env, err)
	}
}

func TestUserRemoteEndpoints_RefusesPlainHTTP(t *testing.T) {
	t.Setenv(InsecureRemoteEndpointEnvVar, "http://dev.example.test")

	if _, err := userRemoteEndpoints(nil, "locktivity"); err == nil || !strings.Contains(err.Error(), "HTTPS") {
		t.Fatalf("err = %v, want plain HTTP refused", err)
	}
}

func TestPipelineIdentity_NothingWithoutAJobIdentityOrForAClone(t *testing.T) {
	t.Setenv("LOCKTIVITY_ID_TOKEN", "")
	t.Setenv("EPACK_SIGNING_KEY", "")
	t.Setenv("EPACK_PIPELINE_ID", "0b9c7a52-6f2e-4d1a-9f3b-2c4d5e6f7a8b")
	if identity := pipelineIdentity(remote.ConfigPurposeRun); identity != nil {
		t.Fatalf("a laptop with no job identity signs in on its own, got %+v", identity)
	}

	t.Setenv("LOCKTIVITY_ID_TOKEN", "gitlab-id-token")
	if identity := pipelineIdentity(remote.ConfigPurposeClone); identity != nil {
		t.Fatalf("a setup clone signs in as a person, got %+v", identity)
	}
	if identity := pipelineIdentity(remote.ConfigPurposeCheck); identity == nil || identity.ID != "0b9c7a52-6f2e-4d1a-9f3b-2c4d5e6f7a8b" {
		t.Fatalf("a check signs in for its pipeline, got %+v", identity)
	}

	t.Setenv("EPACK_PIPELINE_ID", "")
	if identity := pipelineIdentity(remote.ConfigPurposeRun); identity != nil {
		t.Fatalf("no pipeline named, so nothing to sign in for, got %+v", identity)
	}
}

func TestValidateInsecureEndpointFlags_NamesEachEndpointItWarnsAbout(t *testing.T) {
	var stderr strings.Builder
	override := remote.CustomEndpointOverride{AuthEndpoint: "https://dev-app.example.test"}

	if err := validateInsecureEndpointFlags(&stderr, "locktivity", override, "test override"); err != nil {
		t.Fatalf("validateInsecureEndpointFlags: %v", err)
	}
	if got := stderr.String(); !strings.Contains(got, "custom remote auth endpoint https://dev-app.example.test") || strings.Contains(got, "pointed at  by") {
		t.Errorf("warning = %q, want the auth endpoint named", got)
	}
}

func TestPipelineSession_WarnsAboutACustomBrokerWithWhatTheJobSends(t *testing.T) {
	var stderr strings.Builder
	t.Setenv("EPACK_INSECURE_CREDENTIAL_BROKER_URL", "https://127.0.0.1:1")
	identity := broker.PipelineIdentity{ID: "pipe_1", Source: broker.GitLabCITokenSource{Getenv: func(string) string { return "" }}}

	_, _ = pipelineSession(t.Context(), "locktivity", identity, &stderr)

	if got := stderr.String(); !strings.Contains(got, "The job's GitLab ID token will be sent") || strings.Contains(got, "GitHub Actions") {
		t.Errorf("warning = %q, want what this job sends named", got)
	}
}
