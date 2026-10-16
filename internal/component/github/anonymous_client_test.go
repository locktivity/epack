package github

import (
	"net/http"
	"testing"
)

func TestNewAnonymousClient_SendsNoTokenAndKeepsTheHostCheck(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "ghp_example")

	client, err := NewAnonymousClient("https://api.github.com")
	if err != nil {
		t.Fatalf("NewAnonymousClient: %v", err)
	}
	req, err := http.NewRequest(http.MethodGet, "https://api.github.com/repos/locktivity/epack/releases/latest", nil)
	if err != nil {
		t.Fatal(err)
	}
	client.setHeaders(req)
	if got := req.Header.Get("Authorization"); got != "" {
		t.Errorf("Authorization = %q, want none", got)
	}

	if _, err := NewAnonymousClient("https://evil.example.com"); err == nil {
		t.Error("an untrusted host should be refused")
	}
}
