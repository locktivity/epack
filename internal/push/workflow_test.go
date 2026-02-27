package push

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
		{"https basic", "https://example.com/upload", false, false},
		{"https with port", "https://example.com:443/upload", false, false},
		{"https s3", "https://my-bucket.s3.amazonaws.com/key", false, false},
		{"https gcs", "https://storage.googleapis.com/bucket/object", false, false},
		{"https azure", "https://myaccount.blob.core.windows.net/container/blob", false, false},

		// Invalid HTTP URLs (non-loopback, never allowed)
		{"http non-loopback", "http://example.com/upload", false, true},
		{"http non-loopback with opt-in", "http://example.com/upload", true, true},
		{"http s3", "http://my-bucket.s3.amazonaws.com/key", false, true},

		// HTTP localhost - requires explicit opt-in
		{"http localhost no opt-in", "http://localhost/upload", false, true},
		{"http localhost with opt-in", "http://localhost/upload", true, false},
		{"http localhost:9000 no opt-in", "http://localhost:9000/upload", false, true},
		{"http localhost:9000 with opt-in", "http://localhost:9000/upload", true, false},
		{"http 127.0.0.1 no opt-in", "http://127.0.0.1/upload", false, true},
		{"http 127.0.0.1 with opt-in", "http://127.0.0.1/upload", true, false},
		{"http 127.0.0.1:9000 no opt-in", "http://127.0.0.1:9000/bucket/key", false, true},
		{"http 127.0.0.1:9000 with opt-in", "http://127.0.0.1:9000/bucket/key", true, false},
		{"http ipv6 loopback no opt-in", "http://[::1]/upload", false, true},
		{"http ipv6 loopback with opt-in", "http://[::1]/upload", true, false},

		// Invalid schemes
		{"ftp scheme", "ftp://example.com/upload", false, true},
		{"file scheme", "file:///tmp/upload", false, true},
		{"s3 scheme", "s3://bucket/key", false, true}, // S3 URIs are not HTTP URLs
		{"gs scheme", "gs://bucket/object", false, true},

		// Malformed URLs
		{"empty", "", false, true},
		{"no scheme", "example.com/upload", false, true},
		{"invalid", "not-a-url", false, true},

		// SSRF vectors - HTTP blocked, HTTPS allowed
		{"internal http", "http://192.168.1.1/admin", false, true},
		{"internal https", "https://192.168.1.1/admin", false, false},
		{"metadata http", "http://169.254.169.254/latest", false, true},
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
		{"file in root", "/storage/packs/test.epack", "/storage/packs", false},
		{"file in subdir", "/storage/packs/org/test.epack", "/storage/packs", false},
		{"deeply nested", "/storage/packs/org/team/v1/test.epack", "/storage/packs", false},
		{"file equals root", "/storage/packs", "/storage/packs", false},

		// Invalid: file outside root (path traversal)
		{"parent dir traversal", "/storage/packs/../secrets/key", "/storage/packs", true},
		{"absolute escape", "/etc/passwd", "/storage/packs", true},
		{"sibling dir", "/storage/other/test.epack", "/storage/packs", true},
		{"prefix confusion", "/storage/packs-evil/test.epack", "/storage/packs", true},

		// Edge cases
		{"root with trailing slash", "/storage/packs/test.epack", "/storage/packs/", false},
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

func TestComputeSHA256(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want string
	}{
		{
			name: "empty",
			data: []byte{},
			want: "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
		{
			name: "hello",
			data: []byte("hello"),
			want: "sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
		},
		{
			name: "hello world",
			data: []byte("hello world"),
			want: "sha256:b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := computeSHA256(tt.data)
			if got != tt.want {
				t.Errorf("computeSHA256(%q) = %q, want %q", tt.data, got, tt.want)
			}
		})
	}
}

// TestValidateAdapterURL_AuthHeaders documents that auth headers should not be sent over HTTP.
func TestValidateAdapterURL_AuthHeaders(t *testing.T) {
	// Even though HTTP localhost can be allowed with opt-in for the URL itself,
	// auth headers (Bearer tokens, etc.) should NEVER be sent over HTTP.
	// This is enforced by netpolicy.ShouldSendAuth, not validateAdapterURL.

	// validateAdapterURL allows HTTP localhost with opt-in
	err := validateAdapterURL("http://localhost:9000/upload", true)
	if err != nil {
		t.Errorf("HTTP localhost with opt-in should be allowed: %v", err)
	}

	// But code that sends requests must NOT include auth headers for HTTP URLs.
	// This behavior is tested in netpolicy_test.go.
}

// TestValidateAdapterURL_LoopbackHTTPRequiresOptIn documents the security change.
func TestValidateAdapterURL_LoopbackHTTPRequiresOptIn(t *testing.T) {
	// SECURITY: Even localhost HTTP can be dangerous (malicious local services,
	// SSRF to internal APIs). It now requires explicit opt-in via transport config.

	loopbackURLs := []string{
		"http://localhost/upload",
		"http://127.0.0.1/upload",
		"http://[::1]/upload",
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

// TestUploadPackToFile_RequiresFileRoot documents that file:// URLs require file_root.
func TestUploadPackToFile_RequiresFileRoot(t *testing.T) {
	// SECURITY: file:// URLs must have file_root configured to prevent
	// adapters from directing writes to arbitrary filesystem locations.

	t.Run("empty file_root rejected", func(t *testing.T) {
		err := uploadPackToFile(context.TODO(), "/tmp/source.epack", "/some/path/dest.epack", "", nil)
		if err == nil {
			t.Error("expected error when file_root is empty")
		}
		if err != nil && !strings.Contains(err.Error(), "file_root") {
			t.Errorf("error should mention file_root: %v", err)
		}
	})
}

// TestUploadSkip documents that when the adapter returns Upload.Method == "skip",
// the upload step is bypassed. This happens when the pack already exists on the remote.
func TestUploadSkip(t *testing.T) {
	// The skip logic is: if prepResp.Upload.Method != "skip" { uploadPack... }
	// When Method == "skip", no upload is performed and we proceed directly to finalize.

	testCases := []struct {
		method     string
		shouldSkip bool
	}{
		{"PUT", false},
		{"POST", false},
		{"skip", true},
		{"SKIP", false}, // case-sensitive
		{"", false},
	}

	for _, tc := range testCases {
		t.Run(tc.method, func(t *testing.T) {
			// Simulate the condition in Push workflow
			shouldUpload := tc.method != "skip"
			if shouldUpload == tc.shouldSkip {
				t.Errorf("method=%q: shouldUpload=%v, shouldSkip=%v - mismatch",
					tc.method, shouldUpload, tc.shouldSkip)
			}
		})
	}
}

// TestUploadSkip_Integration documents the expected behavior when pack already exists.
// This is tested by the e2e tests with actual adapters that return "skip" method.
func TestUploadSkip_Integration(t *testing.T) {
	t.Skip("integration test - run with e2e suite")
	// When a pack with the same digest already exists on the remote:
	// 1. Adapter returns PushPrepareResponse with Upload.Method = "skip"
	// 2. Push workflow skips the HTTP upload step entirely
	// 3. Push.finalize is still called to create the release
	// 4. User sees success without re-uploading bytes
}
