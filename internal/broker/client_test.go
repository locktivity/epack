package broker

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestClientResolve(t *testing.T) {
	t.Parallel()

	var authHeader string
	var requestBody string
	clientTransport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		authHeader = r.Header.Get("Authorization")
		body, _ := io.ReadAll(r.Body)
		requestBody = string(body)
		return jsonResponse(`{"env":{"GITHUB_TOKEN":"ghs_test","LOCKTIVITY_ACCESS_TOKEN":"ltk_test"},"expires_at":"2026-01-01T12:00:00Z"}`), nil
	})

	client := &Client{
		APIBase:    "https://api.locktivity.test",
		HTTPClient: &http.Client{Transport: clientTransport},
		TokenSource: staticTokenSource{
			token: "oidc-token",
		},
	}

	resolved, err := client.Resolve(context.Background(), ResolveRequest{
		CredentialSets: []string{"credset_abc123", "credset_def456"},
	}, RuntimeContext{
		InGitHubActions: true,
		OIDCAvailable:   true,
	})
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if authHeader != "Bearer oidc-token" {
		t.Fatalf("Authorization header = %q, want %q", authHeader, "Bearer oidc-token")
	}
	if requestBody != `{"credential_sets":["credset_abc123","credset_def456"]}` {
		t.Fatalf("request body = %s", requestBody)
	}
	if got := resolved.Env["GITHUB_TOKEN"]; got != "ghs_test" {
		t.Fatalf("resolved GITHUB_TOKEN = %q, want %q", got, "ghs_test")
	}
	if resolved.ExpiresAt.IsZero() {
		t.Fatal("resolved ExpiresAt should be set")
	}
}

func TestClientResolveRejectsMissingOIDC(t *testing.T) {
	t.Parallel()

	client := &Client{}
	_, err := client.Resolve(context.Background(), ResolveRequest{
		CredentialSets: []string{"credset_abc123"},
	}, RuntimeContext{})
	if err == nil {
		t.Fatal("Resolve() expected error when OIDC is unavailable, got nil")
	}
}

func TestGitHubActionsTokenSource(t *testing.T) {
	t.Parallel()

	var authHeader string
	var audience string
	httpClient := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		authHeader = r.Header.Get("Authorization")
		audience = r.URL.Query().Get("audience")
		return jsonResponse(`{"value":"jwt-token"}`), nil
	})}

	source := GitHubActionsTokenSource{
		HTTPClient: httpClient,
		Getenv: func(name string) string {
			switch name {
			case "ACTIONS_ID_TOKEN_REQUEST_URL":
				return "https://token.actions.example"
			case "ACTIONS_ID_TOKEN_REQUEST_TOKEN":
				return "request-token"
			default:
				return ""
			}
		},
	}

	token, err := source.Token(context.Background(), "https://api.locktivity.com")
	if err != nil {
		t.Fatalf("Token() error = %v", err)
	}
	if token != "jwt-token" {
		t.Fatalf("Token() = %q, want %q", token, "jwt-token")
	}
	if authHeader != "Bearer request-token" {
		t.Fatalf("Authorization header = %q, want %q", authHeader, "Bearer request-token")
	}
	if audience != "https://api.locktivity.com" {
		t.Fatalf("audience = %q, want %q", audience, "https://api.locktivity.com")
	}
}

type staticTokenSource struct {
	token string
	err   error
}

func (s staticTokenSource) Token(context.Context, string) (string, error) {
	return s.token, s.err
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return fn(r)
}

func jsonResponse(body string) *http.Response {
	return &http.Response{
		StatusCode: http.StatusOK,
		Status:     "200 OK",
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}
