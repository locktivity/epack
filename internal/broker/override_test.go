package broker

import (
	"strings"
	"testing"
)

func TestResolveCustomCredentialBrokerURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		env      string
		wantURL  string
		wantUsed bool
		wantErr  string
	}{
		{
			name:     "unset env returns empty",
			env:      "",
			wantURL:  "",
			wantUsed: false,
		},
		{
			name:     "valid override",
			env:      "https://dev.example.com/broker",
			wantURL:  "https://dev.example.com/broker",
			wantUsed: true,
		},
		{
			name:    "invalid URL rejected",
			env:     "http://insecure.example.com",
			wantErr: "must use HTTPS",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotURL, gotUsed, err := ResolveCustomCredentialBrokerURL(func(string) string {
				return tt.env
			})
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("ResolveCustomCredentialBrokerURL() error = %v, want substring %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ResolveCustomCredentialBrokerURL() error = %v", err)
			}
			if gotURL != tt.wantURL {
				t.Fatalf("ResolveCustomCredentialBrokerURL() url = %q, want %q", gotURL, tt.wantURL)
			}
			if gotUsed != tt.wantUsed {
				t.Fatalf("ResolveCustomCredentialBrokerURL() used = %v, want %v", gotUsed, tt.wantUsed)
			}
		})
	}
}

func TestValidateCustomCredentialBrokerURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		rawURL  string
		wantErr string
	}{
		{name: "valid", rawURL: "https://dev.example.com"},
		{name: "valid with path", rawURL: "https://dev.example.com/base/path"},
		{name: "reject http", rawURL: "http://dev.example.com", wantErr: "must use HTTPS"},
		{name: "reject missing host", rawURL: "https://", wantErr: "missing host"},
		{name: "reject userinfo", rawURL: "https://user:pass@dev.example.com", wantErr: "userinfo is not allowed"},
		{name: "reject query", rawURL: "https://dev.example.com?x=1", wantErr: "query is not allowed"},
		{name: "reject fragment", rawURL: "https://dev.example.com#frag", wantErr: "fragment is not allowed"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateCustomCredentialBrokerURL(tt.rawURL)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("ValidateCustomCredentialBrokerURL() error = %v, want substring %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ValidateCustomCredentialBrokerURL() error = %v", err)
			}
		})
	}
}
