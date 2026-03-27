package credentials

import (
	"context"
	"fmt"
	"testing"

	"github.com/locktivity/epack/internal/broker"
	"github.com/locktivity/epack/internal/component/config"
)

func TestResolverResolveComponentEnv(t *testing.T) {
	t.Parallel()

	cfg := &config.JobConfig{
		CredentialSets: map[string]string{
			"github_repo":     "credset_abc123",
			"locktivity_push": "credset_def456",
		},
		Collectors: map[string]config.CollectorConfig{
			"github": {
				Source:      "owner/repo@v1.0.0",
				Credentials: []string{"github_repo", "locktivity_push"},
			},
		},
	}

	resolver := Resolver{
		Broker: stubBroker{
			env: map[string]string{
				"GITHUB_TOKEN":            "ghs_broker",
				"LOCKTIVITY_ACCESS_TOKEN": "ltk_broker",
			},
		},
		Getenv: func(name string) string {
			switch name {
			case "GITHUB_ACTIONS":
				return "true"
			case "ACTIONS_ID_TOKEN_REQUEST_URL":
				return "https://token.actions.example"
			case "ACTIONS_ID_TOKEN_REQUEST_TOKEN":
				return "request-token"
			default:
				return ""
			}
		},
	}

	env, err := resolver.ResolveComponentEnv(context.Background(), cfg, cfg.Collectors["github"].Credentials)
	if err != nil {
		t.Fatalf("ResolveComponentEnv() error = %v", err)
	}
	if env["GITHUB_TOKEN"] != "ghs_broker" {
		t.Fatalf("GITHUB_TOKEN = %q, want %q", env["GITHUB_TOKEN"], "ghs_broker")
	}
	if env["LOCKTIVITY_ACCESS_TOKEN"] != "ltk_broker" {
		t.Fatalf("LOCKTIVITY_ACCESS_TOKEN = %q, want %q", env["LOCKTIVITY_ACCESS_TOKEN"], "ltk_broker")
	}
}

func TestResolverResolveComponentEnvErrorsWithoutOIDC(t *testing.T) {
	t.Parallel()

	cfg := &config.JobConfig{
		CredentialSets: map[string]string{
			"github_repo": "credset_abc123",
		},
	}

	resolver := Resolver{
		Broker: stubBroker{
			err: broker.ErrOIDCUnavailable,
		},
		Getenv: func(string) string { return "" },
	}

	if _, err := resolver.ResolveComponentEnv(context.Background(), cfg, []string{"github_repo"}); err == nil {
		t.Fatal("ResolveComponentEnv() expected error when OIDC is unavailable, got nil")
	}
}

type stubBroker struct {
	env map[string]string
	err error
}

func (s stubBroker) Resolve(context.Context, broker.ResolveRequest, broker.RuntimeContext) (broker.ResolvedEnv, error) {
	if s.err != nil {
		return broker.ResolvedEnv{}, s.err
	}
	if len(s.env) == 0 {
		return broker.ResolvedEnv{}, fmt.Errorf("stub broker missing env")
	}
	return broker.ResolvedEnv{Env: s.env}, nil
}
