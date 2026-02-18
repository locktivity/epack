package netpolicy

import (
	"net/url"
	"testing"
)

func TestGitHubPolicy(t *testing.T) {
	p := GitHubPolicy()

	// Check API hosts
	if !p.IsTrustedAPIHost("api.github.com") {
		t.Error("expected api.github.com to be trusted API host")
	}
	if p.IsTrustedAPIHost("github.com") {
		t.Error("github.com should not be trusted API host")
	}

	// Check asset hosts
	for _, host := range []string{"github.com", "api.github.com", "objects.githubusercontent.com", "github-releases.githubusercontent.com"} {
		if !p.IsTrustedAssetHost(host) {
			t.Errorf("expected %s to be trusted asset host", host)
		}
	}

	// Check untrusted hosts
	if p.IsTrustedAssetHost("evil.com") {
		t.Error("evil.com should not be trusted")
	}
}

func TestValidateAPIURL(t *testing.T) {
	p := GitHubPolicy()

	tests := []struct {
		name    string
		url     string
		wantErr bool
		errMsg  string
	}{
		{
			name:    "valid https api.github.com",
			url:     "https://api.github.com/repos/owner/repo",
			wantErr: false,
		},
		{
			name:    "http to api.github.com rejected",
			url:     "http://api.github.com/repos/owner/repo",
			wantErr: true,
			errMsg:  "HTTP scheme only allowed for localhost",
		},
		{
			name:    "untrusted host rejected",
			url:     "https://evil.com/api",
			wantErr: true,
			errMsg:  "not in trusted API hosts",
		},
		{
			name:    "http to localhost rejected without flag",
			url:     "http://localhost:8080/api",
			wantErr: true,
			errMsg:  "HTTP to loopback",
		},
		{
			name:    "https to localhost allowed",
			url:     "https://localhost:8080/api",
			wantErr: false,
		},
		{
			name:    "ftp scheme rejected",
			url:     "ftp://api.github.com/file",
			wantErr: true,
			errMsg:  "scheme",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := p.ValidateAPIURL(tt.url)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error containing %q, got nil", tt.errMsg)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestValidateAssetURL(t *testing.T) {
	p := GitHubPolicy()

	tests := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{
			name:    "valid https github.com",
			url:     "https://github.com/owner/repo/releases/download/v1.0.0/binary",
			wantErr: false,
		},
		{
			name:    "valid https objects.githubusercontent.com",
			url:     "https://objects.githubusercontent.com/github-production-release-asset/12345",
			wantErr: false,
		},
		{
			name:    "untrusted host rejected",
			url:     "https://evil.com/malware.exe",
			wantErr: true,
		},
		{
			name:    "http rejected",
			url:     "http://github.com/download",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := p.ValidateAssetURL(tt.url)
			if tt.wantErr && err == nil {
				t.Error("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestWithLoopbackHTTP(t *testing.T) {
	p := GitHubPolicy().WithLoopbackHTTP()

	// HTTP to localhost now allowed
	if err := p.ValidateAPIURL("http://localhost:8080/api"); err != nil {
		t.Errorf("expected http to localhost to be allowed with flag, got: %v", err)
	}

	// HTTP to 127.0.0.1 also allowed
	if err := p.ValidateAssetURL("http://127.0.0.1:9090/asset"); err != nil {
		t.Errorf("expected http to 127.0.0.1 to be allowed with flag, got: %v", err)
	}

	// HTTP to other hosts still rejected
	if err := p.ValidateAPIURL("http://api.github.com/api"); err == nil {
		t.Error("expected http to non-loopback to be rejected")
	}
}

func TestShouldSendAuth(t *testing.T) {
	p := GitHubPolicy()

	tests := []struct {
		name     string
		url      string
		wantAuth bool
	}{
		{
			name:     "https trusted host",
			url:      "https://github.com/download",
			wantAuth: true,
		},
		{
			name:     "https api.github.com",
			url:      "https://api.github.com/repos",
			wantAuth: true,
		},
		{
			name:     "http trusted host - no auth",
			url:      "http://github.com/download",
			wantAuth: false,
		},
		{
			name:     "https untrusted host - no auth",
			url:      "https://evil.com/api",
			wantAuth: false,
		},
		{
			name:     "http localhost - no auth",
			url:      "http://localhost:8080/api",
			wantAuth: false,
		},
		{
			name:     "https localhost - no auth (not in allowlist)",
			url:      "https://localhost:8080/api",
			wantAuth: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed, err := url.Parse(tt.url)
			if err != nil {
				t.Fatalf("failed to parse URL: %v", err)
			}

			got := p.ShouldSendAuth(parsed)
			if got != tt.wantAuth {
				t.Errorf("ShouldSendAuth(%s) = %v, want %v", tt.url, got, tt.wantAuth)
			}
		})
	}
}

func TestShouldSendAPIAuth(t *testing.T) {
	p := GitHubPolicy()

	tests := []struct {
		name     string
		url      string
		wantAuth bool
	}{
		{
			name:     "https api.github.com",
			url:      "https://api.github.com/repos",
			wantAuth: true,
		},
		{
			name:     "https github.com - not API host",
			url:      "https://github.com/download",
			wantAuth: false,
		},
		{
			name:     "http api.github.com - no auth over http",
			url:      "http://api.github.com/repos",
			wantAuth: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed, err := url.Parse(tt.url)
			if err != nil {
				t.Fatalf("failed to parse URL: %v", err)
			}

			got := p.ShouldSendAPIAuth(parsed)
			if got != tt.wantAuth {
				t.Errorf("ShouldSendAPIAuth(%s) = %v, want %v", tt.url, got, tt.wantAuth)
			}
		})
	}
}

func TestIsLoopback(t *testing.T) {
	tests := []struct {
		hostname string
		want     bool
	}{
		{"localhost", true},
		{"127.0.0.1", true},
		{"::1", true},   // IPv6 loopback
		{"[::1]", true}, // IPv6 loopback with brackets
		{"github.com", false},
		{"localhost.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.hostname, func(t *testing.T) {
			if got := IsLoopback(tt.hostname); got != tt.want {
				t.Errorf("IsLoopback(%q) = %v, want %v", tt.hostname, got, tt.want)
			}
		})
	}
}

func TestNewPolicy(t *testing.T) {
	p := NewPolicy(
		[]string{"api.example.com"},
		[]string{"api.example.com", "cdn.example.com"},
	)

	if !p.IsTrustedAPIHost("api.example.com") {
		t.Error("expected api.example.com to be trusted API host")
	}
	if p.IsTrustedAPIHost("cdn.example.com") {
		t.Error("cdn.example.com should not be trusted API host")
	}
	if !p.IsTrustedAssetHost("cdn.example.com") {
		t.Error("expected cdn.example.com to be trusted asset host")
	}
}

func TestSecureTransport(t *testing.T) {
	transport := SecureTransport()

	if transport == nil {
		t.Fatal("SecureTransport returned nil")
	}

	if transport.TLSClientConfig == nil {
		t.Fatal("TLSClientConfig is nil")
	}

	// TLS 1.2 = 0x0303 = 771
	const tls12 = 0x0303
	if transport.TLSClientConfig.MinVersion != tls12 {
		t.Errorf("MinVersion = %d, want %d (TLS 1.2)", transport.TLSClientConfig.MinVersion, tls12)
	}
}
