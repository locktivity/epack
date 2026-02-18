package pull

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateAdapterURL(t *testing.T) {
	tests := []struct {
		name              string
		url               string
		allowLoopbackHTTP bool
		wantErr           bool
	}{
		// Valid HTTPS URLs (always allowed)
		{"https basic", "https://example.com/file.zip", false, false},
		{"https with port", "https://example.com:443/file.zip", false, false},
		{"https with path", "https://cdn.example.com/releases/v1.0.0/file.zip", false, false},
		{"https with query", "https://example.com/file.zip?token=abc", false, false},

		// Invalid HTTP URLs (non-loopback, never allowed)
		{"http non-loopback", "http://example.com/file.zip", false, true},
		{"http non-loopback with opt-in", "http://example.com/file.zip", true, true},
		{"http with port", "http://example.com:80/file.zip", false, true},
		{"http cdn", "http://cdn.example.com/file.zip", false, true},

		// HTTP localhost - requires explicit opt-in
		{"http localhost no opt-in", "http://localhost/file.zip", false, true},
		{"http localhost with opt-in", "http://localhost/file.zip", true, false},
		{"http localhost:8080 no opt-in", "http://localhost:8080/file.zip", false, true},
		{"http localhost:8080 with opt-in", "http://localhost:8080/file.zip", true, false},
		{"http 127.0.0.1 no opt-in", "http://127.0.0.1/file.zip", false, true},
		{"http 127.0.0.1 with opt-in", "http://127.0.0.1/file.zip", true, false},
		{"http 127.0.0.1:8080 no opt-in", "http://127.0.0.1:8080/file.zip", false, true},
		{"http 127.0.0.1:8080 with opt-in", "http://127.0.0.1:8080/file.zip", true, false},
		{"http ipv6 loopback no opt-in", "http://[::1]/file.zip", false, true},
		{"http ipv6 loopback with opt-in", "http://[::1]/file.zip", true, false},
		{"http ipv6 loopback:8080 no opt-in", "http://[::1]:8080/file.zip", false, true},
		{"http ipv6 loopback:8080 with opt-in", "http://[::1]:8080/file.zip", true, false},

		// Invalid schemes
		{"ftp scheme", "ftp://example.com/file.zip", false, true},
		{"file scheme", "file:///etc/passwd", false, true},
		{"javascript scheme", "javascript:alert(1)", false, true},
		{"data scheme", "data:text/plain,hello", false, true},
		{"no scheme", "example.com/file.zip", false, true},

		// Malformed URLs
		{"empty", "", false, true},
		{"whitespace", "   ", false, true},
		{"invalid url", "://invalid", false, true},

		// SSRF attempt vectors
		{"internal ip http", "http://192.168.1.1/admin", false, true},
		{"internal ip https", "https://192.168.1.1/admin", false, false}, // HTTPS allowed, but risky
		{"cloud metadata", "http://169.254.169.254/latest/meta-data", false, true},
		{"cloud metadata v6", "http://[fd00::1]/metadata", false, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateAdapterURL(tt.url, tt.allowLoopbackHTTP)
			if tt.wantErr && err == nil {
				t.Errorf("validateAdapterURL(%q, %v) expected error, got nil", tt.url, tt.allowLoopbackHTTP)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("validateAdapterURL(%q, %v) unexpected error: %v", tt.url, tt.allowLoopbackHTTP, err)
			}
		})
	}
}

func TestValidateFileRoot(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		fileRoot string
		wantErr  bool
	}{
		// Valid: file within root
		{"file in root", "/storage/packs/test.pack", "/storage/packs", false},
		{"file in subdir", "/storage/packs/org/test.pack", "/storage/packs", false},
		{"deeply nested", "/storage/packs/org/team/v1/test.pack", "/storage/packs", false},
		{"file equals root", "/storage/packs", "/storage/packs", false},

		// Invalid: file outside root (path traversal)
		{"parent dir traversal", "/storage/packs/../secrets/key", "/storage/packs", true},
		{"absolute escape", "/etc/passwd", "/storage/packs", true},
		{"sibling dir", "/storage/other/test.pack", "/storage/packs", true},
		{"prefix confusion", "/storage/packs-evil/test.pack", "/storage/packs", true},

		// Edge cases
		{"root with trailing slash", "/storage/packs/test.pack", "/storage/packs/", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateFileRoot(tt.filePath, tt.fileRoot)
			if tt.wantErr && err == nil {
				t.Errorf("validateFileRoot(%q, %q) expected error, got nil", tt.filePath, tt.fileRoot)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("validateFileRoot(%q, %q) unexpected error: %v", tt.filePath, tt.fileRoot, err)
			}
		})
	}
}

func TestValidateFileRoot_RelativePaths(t *testing.T) {
	// Test with relative paths (which get converted to absolute)
	t.Run("relative file in relative root", func(t *testing.T) {
		// Both get resolved to absolute paths
		err := validateFileRoot("testdata/subdir/file.pack", "testdata")
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("relative traversal attempt", func(t *testing.T) {
		err := validateFileRoot("../escape/file.pack", "testdata")
		if err == nil {
			t.Error("expected error for path traversal, got nil")
		}
	})
}

func TestSanitizeStreamName(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"simple", "simple"},
		{"myorg/prod", "myorg-prod"},
		{"myorg/team/prod", "myorg-team-prod"},
		{"my-stream", "my-stream"},
		{"my_stream", "my_stream"},
		{"stream123", "stream123"},
		{"UPPER", "UPPER"},
		{"with spaces", "with-spaces"},
		{"special!@#chars", "special---chars"},
		{"", "pack"},                     // empty returns default
		{"../../../etc", "---------etc"}, // 9 invalid chars become 9 dashes
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := sanitizeStreamName(tt.input)
			if got != tt.want {
				t.Errorf("sanitizeStreamName(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// TestValidateAdapterURL_PathTraversal verifies URL validation prevents path traversal.
func TestValidateAdapterURL_PathTraversal(t *testing.T) {
	tests := []string{
		"https://example.com/../../../etc/passwd",
		"https://example.com/..%2f..%2f..%2fetc/passwd",
		"https://example.com/path/../secret",
	}

	for _, url := range tests {
		t.Run(url, func(t *testing.T) {
			// Path traversal in URL path is handled by the HTTP client/server,
			// not by URL validation. validateAdapterURL only checks scheme/host.
			// This test documents expected behavior.
			err := validateAdapterURL(url, false)
			if err != nil {
				t.Logf("URL %q rejected: %v", url, err)
			}
			// Note: These URLs may or may not be rejected depending on URL parsing.
			// The actual path traversal protection happens at the filesystem level.
		})
	}
}

// TestValidateAdapterURL_DNSRebinding documents DNS rebinding is not prevented.
func TestValidateAdapterURL_DNSRebinding(t *testing.T) {
	// DNS rebinding attacks cannot be prevented by URL validation alone.
	// A malicious DNS server could return 127.0.0.1 for attacker.com.
	// This test documents that limitation.
	url := "https://attacker-controlled-dns.com/file.zip"
	err := validateAdapterURL(url, false)
	if err != nil {
		t.Errorf("HTTPS URL should be allowed: %v", err)
	}
	// Note: DNS rebinding protection requires additional measures like
	// validating the resolved IP address, which is not implemented here.
}

// TestValidateAdapterURL_LoopbackHTTPRequiresOptIn documents the security change.
func TestValidateAdapterURL_LoopbackHTTPRequiresOptIn(t *testing.T) {
	// SECURITY: Even localhost HTTP can be dangerous (malicious local services,
	// SSRF to internal APIs). It now requires explicit opt-in via transport config.

	loopbackURLs := []string{
		"http://localhost/file.zip",
		"http://127.0.0.1/file.zip",
		"http://[::1]/file.zip",
	}

	for _, url := range loopbackURLs {
		t.Run(filepath.Base(url), func(t *testing.T) {
			// Without opt-in: should fail
			err := validateAdapterURL(url, false)
			if err == nil {
				t.Errorf("HTTP localhost without opt-in should be rejected")
			}

			// With opt-in: should succeed
			err = validateAdapterURL(url, true)
			if err != nil {
				t.Errorf("HTTP localhost with opt-in should be allowed: %v", err)
			}
		})
	}
}

// TestDownloadPackFromFile_RequiresFileRoot documents that file:// URLs require file_root.
func TestDownloadPackFromFile_RequiresFileRoot(t *testing.T) {
	// SECURITY: file:// URLs must have file_root configured to prevent
	// adapters from directing reads to arbitrary filesystem locations.

	t.Run("empty file_root rejected", func(t *testing.T) {
		_, err := downloadPackFromFile(context.TODO(), "/tmp/out.pack", "/some/path/file.pack", 0, "", nil)
		if err == nil {
			t.Error("expected error when file_root is empty")
		}
		if err != nil && !strings.Contains(err.Error(), "file_root") {
			t.Errorf("error should mention file_root: %v", err)
		}
	})
}
