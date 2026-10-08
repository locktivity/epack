package trustedpublishers

import (
	"errors"
	"strings"
	"testing"

	"github.com/locktivity/epack/internal/component/config"
)

func sampleConfig() *config.JobConfig {
	return &config.JobConfig{
		Collectors: map[string]config.CollectorConfig{
			"tls":    {Source: "locktivity/epack-collector-tls@^0.3"},
			"custom": {Source: "https://github.com/Acme/epack-collector-custom@^1.0"},
		},
		Tools:   map[string]config.ToolConfig{"validate": {Source: "locktivity/epack-tool-validate@^0.1"}},
		Remotes: map[string]config.RemoteConfig{"locktivity": {Source: "github.com/locktivity/epack-remote-locktivity@^0.1"}},
	}
}

func TestRequired_GroupsRepositoriesByPublisher(t *testing.T) {
	t.Parallel()

	required, err := Required(sampleConfig())
	if err != nil {
		t.Fatalf("Required: %v", err)
	}
	if len(required) != 2 {
		t.Fatalf("required = %+v, want two publishers", required)
	}
	if required[0].Publisher != "acme" || strings.Join(required[0].Repositories, ",") != "acme/epack-collector-custom" {
		t.Errorf("acme = %+v", required[0])
	}
	if required[1].Publisher != "locktivity" || strings.Join(required[1].Repositories, ",") != "locktivity/epack-collector-tls,locktivity/epack-remote-locktivity,locktivity/epack-tool-validate" {
		t.Errorf("locktivity = %+v", required[1])
	}
}

func TestRequired_RefusesLocalBinaries(t *testing.T) {
	t.Parallel()

	cfg := sampleConfig()
	cfg.Remotes["locktivity"] = config.RemoteConfig{Binary: "/opt/adapter"}
	_, err := Required(cfg)
	if err == nil || !strings.Contains(err.Error(), "remote locktivity runs a local binary") {
		t.Fatalf("Required = %v, want a refusal", err)
	}
}

func TestMissing_HonoursTheSetTheEnvironmentAndCase(t *testing.T) {
	t.Parallel()

	required, _ := Required(sampleConfig())
	trusted := NewSet("Locktivity")
	missing := Missing(required, trusted)
	if len(missing) != 1 || missing[0].Publisher != "acme" {
		t.Fatalf("missing = %+v, want acme", missing)
	}

	trusted.AddFromEnv(func(string) string { return "github.com/ACME, other" })
	if len(Missing(required, trusted)) != 0 {
		t.Fatalf("env grant not honoured: %+v", Missing(required, trusted))
	}
}

func TestError_NamesTheVariableAndTheFlag(t *testing.T) {
	t.Parallel()

	required, _ := Required(sampleConfig())
	err := error(&Error{Missing: Missing(required, NewSet())})
	var trustErr *Error
	if !errors.As(err, &trustErr) {
		t.Fatal("expected *Error")
	}
	for _, want := range []string{"github.com/acme: acme/epack-collector-custom", "EPACK_TRUSTED_PUBLISHERS=acme,locktivity", "--trust-publisher acme", "without --yes"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error missing %q:\n%s", want, err.Error())
		}
	}
}

func TestValidate(t *testing.T) {
	t.Parallel()

	if err := Validate("github.com/Locktivity"); err != nil {
		t.Errorf("Validate(locktivity) = %v", err)
	}
	for _, bad := range []string{"", "-acme", "acme/repo", "a b"} {
		if err := Validate(bad); err == nil {
			t.Errorf("Validate(%q) accepted", bad)
		}
	}
}
