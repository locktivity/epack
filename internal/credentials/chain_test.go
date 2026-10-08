package credentials

import (
	"context"
	"fmt"
	"strings"
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

func TestResolverExplainsWhichIdentityIsMissing(t *testing.T) {
	t.Parallel()

	cfg := &config.JobConfig{CredentialSets: map[string]string{"github_repo": "credset_abc123"}}
	cases := []struct {
		name string
		env  map[string]string
		want []string
	}{
		{"github actions", map[string]string{"GITHUB_ACTIONS": "true"}, []string{"id-token: write"}},
		{"gitlab ci", map[string]string{"GITLAB_CI": "true"}, []string{
			"declare id_tokens with LOCKTIVITY_ID_TOKEN",
			"a signing key in EPACK_SIGNING_KEY with EPACK_PIPELINE_ID",
		}},
		{"elsewhere", nil, []string{
			"a GitLab ID token in LOCKTIVITY_ID_TOKEN",
			"a signing key in EPACK_SIGNING_KEY with EPACK_PIPELINE_ID",
			"a sign-in with epack remote login",
		}},
	}
	for _, tc := range cases {
		resolver := Resolver{
			Broker: stubBroker{err: broker.ErrOIDCUnavailable},
			Getenv: func(name string) string { return tc.env[name] },
		}
		_, err := resolver.ResolveComponentEnv(context.Background(), cfg, []string{"github_repo"})
		for _, want := range tc.want {
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Errorf("%s: error = %v, want it to mention %q", tc.name, err, want)
			}
		}
	}
}

func TestDetectRuntimeContextSeesGitLabAndSigningKeys(t *testing.T) {
	t.Parallel()

	rt := DetectRuntimeContext(func(name string) string {
		return map[string]string{"GITLAB_CI": "true", "LOCKTIVITY_ID_TOKEN": "jwt"}[name]
	})
	if !rt.InGitLabCI || !rt.GitLabIDToken || rt.InGitHubActions || rt.SigningKey || !rt.IdentityAvailable() {
		t.Fatalf("gitlab runtime = %+v", rt)
	}

	rt = DetectRuntimeContext(func(name string) string {
		return map[string]string{"EPACK_SIGNING_KEY": "/keys/ci.pem"}[name]
	})
	if !rt.SigningKey || rt.GitLabIDToken || !rt.IdentityAvailable() {
		t.Fatalf("signing key runtime = %+v", rt)
	}

	rt = DetectRuntimeContext(func(name string) string { return map[string]string{"EPACK_SIGNING_KEY": "  "}[name] })
	if rt.SigningKey || rt.IdentityAvailable() {
		t.Fatalf("blank signing key = %+v", rt)
	}
}

func TestResolverNamesThePipelineFromTheEnvironment(t *testing.T) {
	t.Parallel()

	cfg := &config.JobConfig{CredentialSets: map[string]string{"github_repo": "credset_abc123"}}
	recorder := &recordingBroker{env: map[string]string{"LOCKTIVITY_ACCESS_TOKEN": "ltk"}}
	resolver := Resolver{
		Broker: recorder,
		Getenv: func(name string) string { return map[string]string{broker.PipelineIDEnvVar: " pipe_1 "}[name] },
	}

	if _, err := resolver.ResolveComponentEnv(context.Background(), cfg, []string{"github_repo"}); err != nil {
		t.Fatalf("ResolveComponentEnv() error = %v", err)
	}
	if recorder.request.PipelineID != "pipe_1" {
		t.Fatalf("PipelineID = %q, want pipe_1", recorder.request.PipelineID)
	}
}

type recordingBroker struct {
	env     map[string]string
	request broker.ResolveRequest
}

func (b *recordingBroker) Resolve(_ context.Context, req broker.ResolveRequest, _ broker.RuntimeContext) (broker.ResolvedEnv, error) {
	b.request = req
	return broker.ResolvedEnv{Env: b.env}, nil
}

func TestResolverUsesTheSessionOnlyWithoutACIIdentity(t *testing.T) {
	t.Parallel()

	cfg := &config.JobConfig{CredentialSets: map[string]string{"locktivity_documents": "credset_docs"}}
	session := &recordingBroker{env: map[string]string{"LOCKTIVITY_DOCUMENTS_TOKEN": "tok_docs"}}
	laptop := Resolver{Session: session, Getenv: func(name string) string {
		return map[string]string{broker.PipelineIDEnvVar: "pipe_1"}[name]
	}}

	env, err := laptop.ResolveComponentEnv(context.Background(), cfg, []string{"locktivity_documents"})
	if err != nil || env["LOCKTIVITY_DOCUMENTS_TOKEN"] != "tok_docs" {
		t.Fatalf("env = %v, err = %v", env, err)
	}
	if session.request.PipelineID != "pipe_1" || len(session.request.CredentialSets) != 1 || session.request.CredentialSets[0] != "credset_docs" {
		t.Fatalf("the session was asked for %+v", session.request)
	}

	keyed := Resolver{Session: session, Getenv: func(name string) string {
		return map[string]string{broker.SigningKeyEnvVar: "/keys/runner.pem"}[name]
	}}
	if keyed.broker(DetectRuntimeContext(keyed.getenv())) == session {
		t.Fatal("a run with its own identity resolves with that identity, not the sign-in")
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
