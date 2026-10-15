package broker

import (
	"context"
	"net/http"
	"testing"
)

func TestClientSessionExchangesTheJobIdentityForThePipeline(t *testing.T) {
	t.Parallel()

	var method, path, authHeader string
	client := &Client{
		APIBase: "https://api.locktivity.test",
		HTTPClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			method, path, authHeader = r.Method, r.URL.Path, r.Header.Get("Authorization")
			return jsonResponse(`{"env":{"LOCKTIVITY_ACCESS_TOKEN":"ltk_session"},"expires_at":"2026-01-01T12:00:00Z"}`), nil
		})},
		TokenSource: staticTokenSource{token: "gitlab-id-token"},
	}

	session, err := client.Session(context.Background(), "0b9c7a52-6f2e-4d1a-9f3b-2c4d5e6f7a8b")
	if err != nil {
		t.Fatalf("Session() error = %v", err)
	}
	if method != http.MethodPost || path != "/oidc/v1/pipelines/0b9c7a52-6f2e-4d1a-9f3b-2c4d5e6f7a8b/session" {
		t.Fatalf("request = %s %s", method, path)
	}
	if authHeader != "Bearer gitlab-id-token" {
		t.Fatalf("Authorization header = %q", authHeader)
	}
	if session.Env["LOCKTIVITY_ACCESS_TOKEN"] != "ltk_session" {
		t.Fatalf("env = %v", session.Env)
	}
}

func TestClientSessionKeepsThePipelineToOnePathSegment(t *testing.T) {
	t.Parallel()

	client := &Client{
		HTTPClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			t.Fatalf("no request expected, got %s", r.URL)
			return nil, nil
		})},
		TokenSource: staticTokenSource{token: "gitlab-id-token"},
	}
	for _, id := range []string{"", "../credential_sets", "a/b", "pipe 1", "pipe%2F1"} {
		if _, err := client.Session(context.Background(), id); err == nil {
			t.Errorf("Session(%q) accepted a pipeline ID that is not one segment", id)
		}
	}
}

func TestPipelineIdentityPresentsTheGitLabIDTokenThenTheKeyAndNothingElse(t *testing.T) {
	t.Parallel()

	env := envOf(map[string]string{PipelineIDEnvVar: " pipe_1 "})
	everything := RuntimeContext{InGitHubActions: true, OIDCAvailable: true, InGitLabCI: true, GitLabIDToken: true, SigningKey: true}
	identity, ok := PipelineIdentityFor(everything, env)
	if _, gitlab := identity.Source.(GitLabCITokenSource); !ok || !gitlab || identity.ID != "pipe_1" {
		t.Errorf("with a key, a GitLab ID token, and GitHub OIDC, the session presents %+v, want the GitLab ID token for pipe_1", identity)
	}

	identity, ok = PipelineIdentityFor(RuntimeContext{InGitHubActions: true, OIDCAvailable: true, SigningKey: true}, env)
	key, isKey := identity.Source.(SigningKeyTokenSource)
	if !ok || !isKey || key.PipelineID != "pipe_1" {
		t.Errorf("with a key and GitHub OIDC, the session presents %+v, want the key naming pipe_1", identity)
	}

	if _, ok := PipelineIdentityFor(RuntimeContext{InGitHubActions: true, OIDCAvailable: true}, env); ok {
		t.Error("GitHub's token alone never signs in for a pipeline")
	}
	if _, ok := PipelineIdentityFor(everything, envOf(nil)); ok {
		t.Error("without a pipeline named there is nothing to sign in for")
	}
}
