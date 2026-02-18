package execsafe

import (
	"testing"
)

func TestStripProxyCredentials(t *testing.T) {
	tests := []struct {
		name     string
		environ  []string
		expected []string
	}{
		{
			name: "no proxy vars",
			environ: []string{
				"HOME=/home/user",
				"PATH=/usr/bin",
			},
			expected: []string{
				"HOME=/home/user",
				"PATH=/usr/bin",
			},
		},
		{
			name: "proxy without credentials",
			environ: []string{
				"HTTP_PROXY=http://proxy.example.com:8080",
				"HTTPS_PROXY=https://proxy.example.com:8443",
			},
			expected: []string{
				"HTTP_PROXY=http://proxy.example.com:8080",
				"HTTPS_PROXY=https://proxy.example.com:8443",
			},
		},
		{
			name: "proxy with credentials - stripped",
			environ: []string{
				"HTTP_PROXY=http://user:password@proxy.example.com:8080",
				"HTTPS_PROXY=https://admin:secret123@proxy.example.com:8443",
			},
			expected: []string{
				"HTTP_PROXY=http://proxy.example.com:8080",
				"HTTPS_PROXY=https://proxy.example.com:8443",
			},
		},
		{
			name: "lowercase proxy vars with credentials",
			environ: []string{
				"http_proxy=http://user:pass@proxy.local:3128",
				"https_proxy=https://user:pass@proxy.local:3129",
			},
			expected: []string{
				"http_proxy=http://proxy.local:3128",
				"https_proxy=https://proxy.local:3129",
			},
		},
		{
			name: "mixed proxy and non-proxy vars",
			environ: []string{
				"HOME=/home/user",
				"HTTP_PROXY=http://user:pass@proxy.example.com:8080",
				"PATH=/usr/bin",
				"NO_PROXY=localhost,127.0.0.1",
			},
			expected: []string{
				"HOME=/home/user",
				"HTTP_PROXY=http://proxy.example.com:8080",
				"PATH=/usr/bin",
				"NO_PROXY=localhost,127.0.0.1",
			},
		},
		{
			name: "empty proxy value",
			environ: []string{
				"HTTP_PROXY=",
			},
			expected: []string{
				"HTTP_PROXY=",
			},
		},
		{
			name: "non-URL proxy value preserved",
			environ: []string{
				"HTTP_PROXY=proxy.example.com:8080", // Not a full URL
			},
			expected: []string{
				"HTTP_PROXY=proxy.example.com:8080", // Preserved as-is
			},
		},
		{
			name: "complex password with special chars",
			environ: []string{
				"HTTP_PROXY=http://user:p%40ss%3Aword@proxy.example.com:8080",
			},
			expected: []string{
				"HTTP_PROXY=http://proxy.example.com:8080",
			},
		},
		{
			name: "username only no password",
			environ: []string{
				"HTTP_PROXY=http://user@proxy.example.com:8080",
			},
			expected: []string{
				"HTTP_PROXY=http://proxy.example.com:8080",
			},
		},
		{
			name: "proxy with path",
			environ: []string{
				"HTTP_PROXY=http://user:pass@proxy.example.com:8080/path",
			},
			expected: []string{
				"HTTP_PROXY=http://proxy.example.com:8080/path",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := StripProxyCredentials(tt.environ)
			if len(got) != len(tt.expected) {
				t.Errorf("StripProxyCredentials() returned %d vars, want %d", len(got), len(tt.expected))
				return
			}
			for i := range got {
				if got[i] != tt.expected[i] {
					t.Errorf("StripProxyCredentials()[%d] = %q, want %q", i, got[i], tt.expected[i])
				}
			}
		})
	}
}

func TestStripURLCredentials(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "no credentials",
			input:    "http://proxy.example.com:8080",
			expected: "http://proxy.example.com:8080",
		},
		{
			name:     "with user and password",
			input:    "http://user:password@proxy.example.com:8080",
			expected: "http://proxy.example.com:8080",
		},
		{
			name:     "with user only",
			input:    "http://user@proxy.example.com:8080",
			expected: "http://proxy.example.com:8080",
		},
		{
			name:     "https with credentials",
			input:    "https://admin:secret@secure.proxy.com:443",
			expected: "https://secure.proxy.com:443",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "not a URL - hostname only",
			input:    "proxy.example.com",
			expected: "proxy.example.com",
		},
		{
			name:     "not a URL - host:port",
			input:    "proxy.example.com:8080",
			expected: "proxy.example.com:8080",
		},
		{
			name:     "socks proxy with credentials",
			input:    "socks5://user:pass@localhost:1080",
			expected: "socks5://localhost:1080",
		},
		{
			name:     "URL with path and query",
			input:    "http://user:pass@proxy.com:8080/path?query=value",
			expected: "http://proxy.com:8080/path?query=value",
		},
		{
			name:     "URL with encoded special chars in password",
			input:    "http://user:p%40ssw%3Ard@proxy.com:8080",
			expected: "http://proxy.com:8080",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := stripURLCredentials(tt.input)
			if got != tt.expected {
				t.Errorf("stripURLCredentials(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestBuildRestrictedEnvSafe(t *testing.T) {
	environ := []string{
		"HOME=/home/user",
		"USER=testuser",
		"HTTP_PROXY=http://user:secret@proxy.example.com:8080",
		"HTTPS_PROXY=https://admin:password@proxy.example.com:8443",
		"PATH=/usr/local/bin:/usr/bin",
		"AWS_SECRET_KEY=should-not-appear", // Not in allowed list
		"LD_PRELOAD=/tmp/evil.so",          // Not in allowed list
	}

	result := BuildRestrictedEnvSafe(environ, false)

	// Check that HOME and USER are present
	foundHome := false
	foundUser := false
	foundHTTPProxy := false
	foundHTTPSProxy := false
	foundPath := false

	for _, env := range result {
		switch {
		case env == "HOME=/home/user":
			foundHome = true
		case env == "USER=testuser":
			foundUser = true
		case env == "HTTP_PROXY=http://proxy.example.com:8080":
			foundHTTPProxy = true
		case env == "HTTPS_PROXY=https://proxy.example.com:8443":
			foundHTTPSProxy = true
		case env == "PATH="+SafePATH():
			foundPath = true
		}

		// Check that sensitive vars are NOT present
		if env == "AWS_SECRET_KEY=should-not-appear" {
			t.Error("AWS_SECRET_KEY should not be in filtered environment")
		}
		if env == "LD_PRELOAD=/tmp/evil.so" {
			t.Error("LD_PRELOAD should not be in filtered environment")
		}
		// Check credentials are stripped
		if env == "HTTP_PROXY=http://user:secret@proxy.example.com:8080" {
			t.Error("HTTP_PROXY credentials should be stripped")
		}
		if env == "HTTPS_PROXY=https://admin:password@proxy.example.com:8443" {
			t.Error("HTTPS_PROXY credentials should be stripped")
		}
	}

	if !foundHome {
		t.Error("HOME should be in filtered environment")
	}
	if !foundUser {
		t.Error("USER should be in filtered environment")
	}
	if !foundHTTPProxy {
		t.Error("HTTP_PROXY (without credentials) should be in filtered environment")
	}
	if !foundHTTPSProxy {
		t.Error("HTTPS_PROXY (without credentials) should be in filtered environment")
	}
	if !foundPath {
		t.Errorf("PATH should be safe PATH %q", SafePATH())
	}
}
