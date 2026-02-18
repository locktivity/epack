package redact

import (
	"testing"
)

func TestEnableDisable(t *testing.T) {
	// Start disabled
	Disable()
	if IsEnabled() {
		t.Error("expected redaction to be disabled")
	}

	// Enable
	Enable()
	if !IsEnabled() {
		t.Error("expected redaction to be enabled")
	}

	// Disable again
	Disable()
	if IsEnabled() {
		t.Error("expected redaction to be disabled")
	}
}

func TestValue(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		enabled  bool
		expected string
	}{
		{"disabled - returns original", "secret-token-123", false, "secret-token-123"},
		{"enabled - returns placeholder", "secret-token-123", true, Placeholder},
		{"enabled - empty returns empty", "", true, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.enabled {
				Enable()
			} else {
				Disable()
			}
			defer Disable()

			result := Value(tt.value)
			if result != tt.expected {
				t.Errorf("Value(%q) = %q, want %q", tt.value, result, tt.expected)
			}
		})
	}
}

func TestSensitive(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		enabled  bool
		expected string
	}{
		// Disabled - no changes
		{
			name:     "disabled - returns original",
			input:    "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
			enabled:  false,
			expected: "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
		},

		// JWT tokens
		{
			name:     "enabled - redacts JWT token",
			input:    "token: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
			enabled:  true,
			expected: "token: " + Placeholder,
		},
		{
			name:     "enabled - redacts multiple JWTs",
			input:    "old: eyJhbGciOiJIUzI1NiJ9.eyJvbGQiOiJ0cnVlIn0.abc new: eyJhbGciOiJIUzI1NiJ9.eyJuZXciOiJ0cnVlIn0.xyz",
			enabled:  true,
			expected: "old: " + Placeholder + " new: " + Placeholder,
		},

		// Bearer tokens
		{
			name:     "enabled - redacts bearer token",
			input:    "Authorization: Bearer abc123def456",
			enabled:  true,
			expected: "Authorization: Bearer " + Placeholder,
		},
		{
			name:     "enabled - case insensitive bearer",
			input:    "auth: bearer MySecretToken123",
			enabled:  true,
			expected: "auth: bearer " + Placeholder,
		},

		// API keys
		{
			name:     "enabled - redacts api_key",
			input:    "config: api_key=supersecretkey123",
			enabled:  true,
			expected: "config: api_key=" + Placeholder,
		},
		{
			name:     "enabled - redacts secret",
			input:    "the secret:verylongsecretvalue",
			enabled:  true,
			expected: "the secret:" + Placeholder,
		},
		{
			name:     "enabled - redacts password",
			input:    "password=hunter2hunter2",
			enabled:  true,
			expected: "password=" + Placeholder,
		},
		{
			name:     "enabled - redacts quoted token",
			input:    `token="mysupersecrettoken"`,
			enabled:  true,
			expected: `token="` + Placeholder + `"`,
		},

		// CI provider tokens (GitHub, GitLab)
		{
			name:     "enabled - redacts GitHub installation token",
			input:    "token: ghs_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
			enabled:  true,
			expected: "token: " + Placeholder,
		},
		{
			name:     "enabled - redacts GitHub OAuth token",
			input:    "auth: gho_abcdefghijklmnopqrstuvwxyz123456",
			enabled:  true,
			expected: "auth: " + Placeholder,
		},
		{
			name:     "enabled - redacts GitHub PAT",
			input:    "GITHUB_TOKEN=ghp_1234567890abcdefghijklmnopqrstuv",
			enabled:  true,
			expected: "GITHUB_TOKEN=" + Placeholder,
		},
		{
			name:     "enabled - redacts GitLab PAT",
			input:    "token: glpat-xxxxxxxxxxxxxxxxxxxx",
			enabled:  true,
			expected: "token: " + Placeholder,
		},
		{
			name:     "enabled - redacts GitLab CI job token",
			input:    "CI_JOB_TOKEN=glcbt-64_abcdefghijklmnop",
			enabled:  true,
			expected: "CI_JOB_TOKEN=" + Placeholder,
		},

		// Long base64 strings
		{
			name:     "enabled - redacts long base64",
			input:    "key: ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnop==",
			enabled:  true,
			expected: "key: " + Placeholder,
		},

		// Should NOT redact
		{
			name:     "enabled - preserves sha256 hex digest",
			input:    "sha256:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
			enabled:  true,
			expected: "sha256:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
		},
		{
			name:     "enabled - preserves file paths",
			input:    "failed to open /home/user/file.txt: no such file",
			enabled:  true,
			expected: "failed to open /home/user/file.txt: no such file",
		},
		{
			name:     "enabled - preserves short strings",
			input:    "error code: ABC123",
			enabled:  true,
			expected: "error code: ABC123",
		},
		{
			name:     "enabled - preserves URLs",
			input:    "fetch from https://example.com/api failed",
			enabled:  true,
			expected: "fetch from https://example.com/api failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.enabled {
				Enable()
			} else {
				Disable()
			}
			defer Disable()

			result := Sensitive(tt.input)
			if result != tt.expected {
				t.Errorf("Sensitive(%q) =\n  %q\nwant:\n  %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestError(t *testing.T) {
	// Error is an alias for Sensitive
	Enable()
	defer Disable()

	input := "auth failed: Bearer secret123token"
	result := Error(input)
	expected := "auth failed: Bearer " + Placeholder

	if result != expected {
		t.Errorf("Error(%q) = %q, want %q", input, result, expected)
	}
}

func TestIsHexString(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"a1b2c3d4", true},
		{"A1B2C3D4", true},
		{"0123456789abcdef", true},
		{"0123456789ABCDEF", true},
		{"abc123xyz", false}, // contains non-hex
		{"abc+def", false},   // contains +
		{"", true},           // empty is technically valid
	}

	for _, tt := range tests {
		result := isHexString(tt.input)
		if result != tt.expected {
			t.Errorf("isHexString(%q) = %v, want %v", tt.input, result, tt.expected)
		}
	}
}

func TestSensitiveURLQueryParams(t *testing.T) {
	Enable()
	defer Disable()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "redacts token query param",
			input:    "request to https://api.example.com/v1/data?token=secret123&page=1 failed",
			expected: "request to https://api.example.com/v1/data?page=1&token=" + Placeholder + " failed",
		},
		{
			name:     "redacts access_token query param",
			input:    "https://example.com/callback?access_token=eyJhbGciOiJIUzI1NiJ9.xyz&state=abc",
			expected: "https://example.com/callback?access_token=" + Placeholder + "&state=abc",
		},
		{
			name:     "redacts api_key query param",
			input:    "GET https://api.service.com/users?api_key=sk_live_123456789",
			expected: "GET https://api.service.com/users?api_key=" + Placeholder,
		},
		{
			name:     "redacts multiple sensitive params",
			input:    "https://example.com?token=abc&secret=def&normal=123",
			expected: "https://example.com?normal=123&secret=" + Placeholder + "&token=" + Placeholder,
		},
		{
			name:     "preserves non-sensitive params",
			input:    "https://example.com/search?q=golang&page=2&limit=10",
			expected: "https://example.com/search?q=golang&page=2&limit=10",
		},
		{
			name:     "handles URL without query params",
			input:    "request to https://example.com/api/v1/users failed",
			expected: "request to https://example.com/api/v1/users failed",
		},
		{
			name:     "handles multiple URLs in text",
			input:    "first: https://a.com?token=x then: https://b.com?key=y",
			expected: "first: https://a.com?token=" + Placeholder + " then: https://b.com?key=" + Placeholder,
		},
		{
			name:     "case insensitive param matching",
			input:    "https://example.com?TOKEN=secret&API_KEY=abc",
			expected: "https://example.com?API_KEY=" + Placeholder + "&TOKEN=" + Placeholder,
		},
		{
			name:     "handles URL-encoded values",
			input:    "https://example.com?token=hello%20world&x=1",
			expected: "https://example.com?token=" + Placeholder + "&x=1",
		},
		{
			name:     "redacts params containing sensitive words",
			input:    "https://example.com?my_auth_token=abc&x_api_key_2=def",
			expected: "https://example.com?my_auth_token=" + Placeholder + "&x_api_key_2=" + Placeholder,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Sensitive(tt.input)
			if result != tt.expected {
				t.Errorf("Sensitive(%q) =\n  %q\nwant:\n  %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestIsSensitiveParam(t *testing.T) {
	tests := []struct {
		param    string
		expected bool
	}{
		{"token", true},
		{"TOKEN", true},
		{"access_token", true},
		{"api_key", true},
		{"apikey", true},
		{"secret", true},
		{"password", true},
		{"auth", true},
		{"my_auth_token", true}, // contains "auth" and "token"
		{"page", false},
		{"limit", false},
		{"query", false},
		{"id", false},
	}

	for _, tt := range tests {
		result := isSensitiveParam(tt.param)
		if result != tt.expected {
			t.Errorf("isSensitiveParam(%q) = %v, want %v", tt.param, result, tt.expected)
		}
	}
}
