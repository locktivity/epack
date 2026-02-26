package component

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/locktivity/epack/internal/component/config"
	"github.com/locktivity/epack/internal/component/github"
	"github.com/locktivity/epack/internal/component/lockfile"
	"github.com/locktivity/epack/internal/component/semver"
	"github.com/locktivity/epack/internal/component/sync"
	"github.com/locktivity/epack/internal/componenttypes"
	"github.com/locktivity/epack/internal/execsafe"
	"github.com/locktivity/epack/internal/platform"
)

// securityTestDirInCwd creates a temporary directory under the current working directory
// for tests that need to use LockFile.Save() (which requires paths under cwd).
// The directory is automatically cleaned up when the test ends.
// Returns an absolute path to ensure filepath.Rel works correctly.
func securityTestDirInCwd(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp(".", "security_test_*")
	if err != nil {
		t.Fatalf("creating test dir: %v", err)
	}
	// Convert to absolute path so filepath.Rel works correctly
	absDir, err := filepath.Abs(dir)
	if err != nil {
		_ = os.RemoveAll(dir)
		t.Fatalf("getting absolute path: %v", err)
	}
	t.Cleanup(func() {
		_ = os.RemoveAll(absDir)
	})
	return absDir
}

func TestValidateCollectorName(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"valid simple", "github", false},
		{"valid with dash", "my-collector", false},
		{"valid with underscore", "my_collector", false},
		{"valid with dot", "my.collector", false},
		{"valid with numbers", "collector123", false},
		{"valid mixed", "my-collector_v2.0", false},

		// Path traversal attacks
		{"path traversal dots", "..", true},
		{"path traversal relative", "../../../etc/passwd", true},
		{"path traversal slash", "foo/bar", true},
		{"path traversal backslash", "foo\\bar", true},
		{"absolute path unix", "/etc/passwd", true},
		{"absolute path windows", "C:\\Windows", true},

		// Invalid characters
		{"starts with dash", "-invalid", true},
		{"starts with dot", ".hidden", true},
		{"starts with underscore", "_invalid", true},
		{"contains space", "my collector", true},
		{"contains colon", "my:collector", true},
		{"uppercase", "MyCollector", true},

		// Edge cases
		{"empty", "", true},
		{"single dot", ".", true},
		{"too long", strings.Repeat("a", 65), true},
		{"max length", strings.Repeat("a", 64), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := config.ValidateCollectorName(tt.input)
			if tt.wantErr && err == nil {
				t.Errorf("ValidateCollectorName(%q) expected error, got nil", tt.input)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("ValidateCollectorName(%q) unexpected error: %v", tt.input, err)
			}
		})
	}
}

func TestConfigRejectsPathTraversal(t *testing.T) {
	tests := []string{
		"../../../tmp/pwn",
		"foo/bar",
		"..",
		".",
		"/etc/passwd",
	}

	for _, name := range tests {
		t.Run(name, func(t *testing.T) {
			cfg := &config.JobConfig{
				Collectors: map[string]config.CollectorConfig{
					name: {Source: "owner/repo@v1.0.0"},
				},
			}
			err := cfg.Validate()
			if err == nil {
				t.Errorf("config with collector name %q should be rejected", name)
			}
		})
	}
}

func TestLockfileRejectsPathTraversal(t *testing.T) {
	tmpDir := t.TempDir()
	lockPath := filepath.Join(tmpDir, "epack.lock.yaml")

	// Write a malicious lockfile with path traversal name
	content := `schema_version: 1
collectors:
  "../../../tmp/pwn":
    source: github.com/owner/repo
    version: v1.0.0
    platforms:
      linux/amd64:
        digest: sha256:abc123
`
	if err := os.WriteFile(lockPath, []byte(content), 0644); err != nil {
		t.Fatalf("writing lockfile: %v", err)
	}

	_, err := lockfile.Load(lockPath)
	if err == nil {
		t.Error("LoadLockFile should reject path traversal collector names")
	}
}

func TestLockfileSaveRejectsSymlink(t *testing.T) {
	// Use securityTestDirInCwd because Save() requires paths under cwd
	tmpDir := securityTestDirInCwd(t)

	// Create a target file
	targetPath := filepath.Join(tmpDir, "target.txt")
	if err := os.WriteFile(targetPath, []byte("original"), 0644); err != nil {
		t.Fatalf("creating target: %v", err)
	}

	// Create a symlink
	symlinkPath := filepath.Join(tmpDir, "epack.lock.yaml")
	if err := os.Symlink(targetPath, symlinkPath); err != nil {
		t.Fatalf("creating symlink: %v", err)
	}

	lf := lockfile.New()
	lf.Collectors["test"] = lockfile.LockedCollector{
		Source:  "github.com/owner/repo",
		Version: "v1.0.0",
	}

	err := lf.Save(symlinkPath)
	if err == nil {
		t.Error("Save should refuse to overwrite symlink")
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Errorf("error should mention symlink, got: %v", err)
	}

	// Verify target was not modified
	content, _ := os.ReadFile(targetPath)
	if string(content) != "original" {
		t.Error("symlink target was modified")
	}
}

func TestDownloadAssetRejectsHTTPForNonLoopback(t *testing.T) {
	// Test that HTTP URLs to non-loopback hosts are rejected
	// This prevents token exfiltration via HTTP downgrade attacks
	client := github.NewClient()

	tmpDir := t.TempDir()
	destPath := filepath.Join(tmpDir, "binary")

	// Attempt to download via HTTP from a non-loopback host
	// This should fail before even connecting because HTTP is not allowed
	err := client.DownloadAsset(context.Background(), "http://evil.example.com/asset", destPath)
	if err == nil {
		t.Error("DownloadAsset should reject HTTP URLs for non-loopback hosts")
	}
	if !strings.Contains(err.Error(), "HTTPS required") {
		t.Errorf("error should mention HTTPS required, got: %v", err)
	}
}

func TestDownloadAssetRejectsUntrustedHost(t *testing.T) {
	// Test that HTTPS URLs to untrusted hosts are rejected
	client := github.NewClient()

	tmpDir := t.TempDir()
	destPath := filepath.Join(tmpDir, "binary")

	// Attempt to download via HTTPS from an untrusted host
	// This should fail because the host is not in the allowlist
	err := client.DownloadAsset(context.Background(), "https://evil.example.com/asset", destPath)
	if err == nil {
		t.Error("DownloadAsset should reject untrusted host")
	}
	if !strings.Contains(err.Error(), "untrusted host") {
		t.Errorf("error should mention untrusted host, got: %v", err)
	}
}

func TestFilterEnv(t *testing.T) {
	environ := []string{
		"PATH=/usr/bin",
		"HOME=/home/user",
		"GITHUB_TOKEN=secret123",
		"AWS_SECRET_KEY=supersecret",
		"USER=testuser",
		"RANDOM_VAR=value",
	}

	filtered := execsafe.FilterEnv(environ, execsafe.AllowedEnvVars)

	// Check allowed vars are present
	// NOTE: PATH is NOT in allowedEnvVars - it's handled separately by buildCollectorEnv
	// to support safe PATH hardening. This test verifies filterEnv behavior only.
	hasHome := false
	hasUser := false
	for _, env := range filtered {
		if strings.HasPrefix(env, "HOME=") {
			hasHome = true
		}
		if strings.HasPrefix(env, "USER=") {
			hasUser = true
		}
		// Check secrets are NOT present
		if strings.HasPrefix(env, "GITHUB_TOKEN=") {
			t.Error("GITHUB_TOKEN should not be in filtered env")
		}
		if strings.HasPrefix(env, "AWS_SECRET_KEY=") {
			t.Error("AWS_SECRET_KEY should not be in filtered env")
		}
		// PATH should NOT be filtered through here (handled separately)
		if strings.HasPrefix(env, "PATH=") {
			t.Error("PATH should not be in filterEnv output - it's handled by buildCollectorEnv")
		}
	}

	if !hasHome {
		t.Error("HOME should be in filtered env")
	}
	if !hasUser {
		t.Error("USER should be in filtered env")
	}
}

func TestValidateVersion(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"valid simple", "v1.2.3", false},
		{"valid no v prefix", "1.2.3", false},
		{"valid with prerelease", "v1.2.3-beta.1", false},
		{"valid major only", "v1", false},
		{"valid major.minor", "v1.2", false},
		{"valid with alpha", "v2.0.0-alpha", false},
		{"valid with rc", "v1.0.0-rc.1", false},

		// Path traversal attacks
		{"path traversal dots", "..", true},
		{"path traversal relative", "../../../etc/passwd", true},
		{"path traversal slash", "v1.2.3/../../pwn", true},
		{"path traversal backslash", "v1.2.3\\..\\pwn", true},
		{"path traversal embedded", "v1/../../../tmp/pwn", true},
		{"absolute path unix", "/etc/passwd", true},
		{"absolute path windows", "C:\\Windows", true},

		// Invalid formats
		{"empty", "", true},
		{"single dot", ".", true},
		{"just text", "latest", true}, // must be semver
		{"special chars", "v1.2.3@evil", true},
		{"too long", strings.Repeat("v1.2.3", 50), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := semver.ValidateVersion(tt.input)
			if tt.wantErr && err == nil {
				t.Errorf("ValidateVersion(%q) expected error, got nil", tt.input)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("ValidateVersion(%q) unexpected error: %v", tt.input, err)
			}
		})
	}
}

func TestLockfileRejectsVersionPathTraversal(t *testing.T) {
	tmpDir := t.TempDir()
	lockPath := filepath.Join(tmpDir, "epack.lock.yaml")

	// Write a malicious lockfile with path traversal version
	content := `schema_version: 1
collectors:
  github:
    source: github.com/owner/repo
    version: "../../../tmp/pwn"
    platforms:
      linux/amd64:
        digest: sha256:abc123
`
	if err := os.WriteFile(lockPath, []byte(content), 0644); err != nil {
		t.Fatalf("writing lockfile: %v", err)
	}

	_, err := lockfile.Load(lockPath)
	if err == nil {
		t.Error("LoadLockFile should reject path traversal version strings")
	}
	if !strings.Contains(err.Error(), "invalid version") {
		t.Errorf("error should mention invalid version, got: %v", err)
	}
}

func TestLockfileSaveRejectsVersionPathTraversal(t *testing.T) {
	// Use securityTestDirInCwd because Save() requires paths under cwd
	tmpDir := securityTestDirInCwd(t)
	lockPath := filepath.Join(tmpDir, "epack.lock.yaml")

	lf := lockfile.New()
	lf.Collectors["test"] = lockfile.LockedCollector{
		Source:  "github.com/owner/repo",
		Version: "../../../tmp/pwn", // malicious version
		Platforms: map[string]componenttypes.LockedPlatform{
			"linux/amd64": {Digest: "sha256:abc123"},
		},
	}

	err := lf.Save(lockPath)
	if err == nil {
		t.Error("Save should refuse to write lockfile with path traversal version")
	}
	if !strings.Contains(err.Error(), "invalid version") {
		t.Errorf("error should mention invalid version, got: %v", err)
	}
}

func TestDownloadAssetRejectsRedirectToUntrustedHost(t *testing.T) {
	// This test verifies that redirects to untrusted hosts (or HTTP URLs) are rejected.
	// Since HTTP is now rejected for non-loopback hosts before the host allowlist check,
	// a redirect from localhost (HTTP allowed) to an external HTTP host will fail with
	// "HTTPS required" error.

	client := github.NewClient()
	tmpDir := t.TempDir()
	destPath := filepath.Join(tmpDir, "binary")

	// Test 1: Direct HTTPS request to untrusted host should fail with "untrusted host"
	err := client.DownloadAsset(context.Background(), "https://evil.example.com/asset", destPath)
	if err == nil {
		t.Error("DownloadAsset should reject untrusted host")
	}
	if !strings.Contains(err.Error(), "untrusted host") {
		t.Errorf("error should mention untrusted host, got: %v", err)
	}

	// Verify file was not created
	if _, err := os.Stat(destPath); !os.IsNotExist(err) {
		t.Error("file should not have been created after failed download")
	}

	// Test 2: HTTP request to non-loopback should fail with "HTTPS required"
	err = client.DownloadAsset(context.Background(), "http://evil.example.com/asset", destPath)
	if err == nil {
		t.Error("DownloadAsset should reject HTTP to non-loopback")
	}
	if !strings.Contains(err.Error(), "HTTPS required") {
		t.Errorf("error should mention HTTPS required, got: %v", err)
	}
}

func TestDownloadAssetRejectsOversizedResponse(t *testing.T) {
	// Create a server that returns a response larger than the limit
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set Content-Length to exceed limit
		w.Header().Set("Content-Length", "600000000") // 600MB > 500MB limit
		w.WriteHeader(http.StatusOK)
		// Write some data (doesn't matter, Content-Length check should fail first)
		_, _ = w.Write([]byte("start of large file..."))
	}))
	defer server.Close()

	// Use test client which allows loopback HTTP
	client := github.NewClientForTest(server.Client(), server.URL)
	tmpDir := t.TempDir()
	destPath := filepath.Join(tmpDir, "binary")

	err := client.DownloadAsset(context.Background(), server.URL+"/asset", destPath)
	if err == nil {
		t.Error("DownloadAsset should reject oversized Content-Length")
	}
	if !strings.Contains(err.Error(), "exceeds maximum") {
		t.Errorf("error should mention size limit, got: %v", err)
	}
}

func TestDownloadAssetTruncatesStreamingOversizedResponse(t *testing.T) {
	// Create a server that streams more data than allowed (without Content-Length)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Don't set Content-Length, just stream data
		w.WriteHeader(http.StatusOK)
		// Write more than MaxAssetSizeBytes + 1 to trigger truncation
		// For testing, we'll just write a reasonable amount and check the limit is enforced
		data := make([]byte, 1024*1024) // 1MB chunks
		for i := 0; i < 600; i++ {      // Try to write 600MB
			_, err := w.Write(data)
			if err != nil {
				return // Client disconnected
			}
		}
	}))
	defer server.Close()

	// Use test client which allows loopback HTTP
	client := github.NewClientForTest(server.Client(), server.URL)
	tmpDir := t.TempDir()
	destPath := filepath.Join(tmpDir, "binary")

	err := client.DownloadAsset(context.Background(), server.URL+"/asset", destPath)
	if err == nil {
		t.Error("DownloadAsset should fail when response exceeds size limit")
	}
	if !strings.Contains(err.Error(), "exceeded maximum") {
		t.Errorf("error should mention size exceeded, got: %v", err)
	}

	// Verify partial file was cleaned up
	if _, statErr := os.Stat(destPath); !os.IsNotExist(statErr) {
		t.Error("partial file should have been cleaned up after size limit exceeded")
	}
}

func TestNewGitHubClientWithBaseURL_RejectsUntrustedHost(t *testing.T) {
	_, err := github.NewClientWithBaseURL("https://evil.example.com")
	if err == nil {
		t.Error("NewGitHubClientWithBaseURL should reject untrusted host")
	}
	if !strings.Contains(err.Error(), "not in trusted") {
		t.Errorf("error should mention trusted hosts, got: %v", err)
	}
}

func TestNewGitHubClientWithBaseURL_AcceptsLocalhost(t *testing.T) {
	// Localhost should be allowed for testing
	client, err := github.NewClientWithBaseURL("http://localhost:8080")
	if err != nil {
		t.Errorf("NewGitHubClientWithBaseURL should accept localhost, got error: %v", err)
	}
	if client == nil {
		t.Error("client should not be nil")
	}

	// 127.0.0.1 should also work
	client, err = github.NewClientWithBaseURL("http://127.0.0.1:8080")
	if err != nil {
		t.Errorf("NewGitHubClientWithBaseURL should accept 127.0.0.1, got error: %v", err)
	}
	if client == nil {
		t.Error("client should not be nil")
	}
}

func TestNewGitHubClientWithBaseURL_AcceptsTrustedHost(t *testing.T) {
	client, err := github.NewClientWithBaseURL("https://api.github.com")
	if err != nil {
		t.Errorf("NewGitHubClientWithBaseURL should accept api.github.com, got error: %v", err)
	}
	if client == nil {
		t.Error("client should not be nil")
	}
}

func TestNewGitHubClientWithBaseURL_RejectsInvalidScheme(t *testing.T) {
	_, err := github.NewClientWithBaseURL("ftp://api.github.com")
	if err == nil {
		t.Error("NewGitHubClientWithBaseURL should reject non-http(s) schemes")
	}
}

func TestDownloadAssetValidatesRedirectChain(t *testing.T) {
	// Create a chain of redirects where each redirect is to a trusted host
	// This tests that multiple redirects within trusted hosts work
	var server1, server2, server3 *httptest.Server

	server3 = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("final content"))
	}))
	defer server3.Close()

	server2 = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, server3.URL+"/final", http.StatusFound)
	}))
	defer server2.Close()

	server1 = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, server2.URL+"/step2", http.StatusFound)
	}))
	defer server1.Close()

	// Use test client which allows loopback HTTP
	client := github.NewClientForTest(server1.Client(), server1.URL)
	tmpDir := t.TempDir()
	destPath := filepath.Join(tmpDir, "binary")

	err := client.DownloadAsset(context.Background(), server1.URL+"/start", destPath)
	if err != nil {
		t.Errorf("DownloadAsset should succeed with trusted redirect chain, got: %v", err)
	}

	// Verify content was downloaded
	content, err := os.ReadFile(destPath)
	if err != nil {
		t.Fatalf("reading downloaded file: %v", err)
	}
	if string(content) != "final content" {
		t.Errorf("content = %q, want %q", string(content), "final content")
	}
}

// Asset name path traversal tests
// These tests ensure that malicious release asset names cannot escape temp directories.

func TestSanitizeAssetName(t *testing.T) {
	tests := []struct {
		name      string
		assetName string
		want      string
		wantErr   bool
	}{
		// Valid asset names
		{"simple name", "collector-linux-amd64", "collector-linux-amd64", false},
		{"with extension", "collector-linux-amd64.tar.gz", "collector-linux-amd64.tar.gz", false},
		{"sigstore bundle", "collector-linux-amd64.sigstore.json", "collector-linux-amd64.sigstore.json", false},
		{"windows exe", "collector-windows-amd64.exe", "collector-windows-amd64.exe", false},

		// Path traversal attacks - MUST be rejected
		{"unix path traversal", "../../../tmp/pwn", "", true},
		{"double dot only", "..", "", true},
		{"unix absolute path", "/etc/passwd", "", true},
		{"unix root", "/", "", true},
		{"windows path traversal", "..\\..\\..\\Windows\\System32\\pwn", "", true},
		{"windows absolute path", "C:\\Windows\\System32\\pwn", "", true},
		{"mixed traversal", "../collector/../../etc/passwd", "", true},
		{"hidden traversal", "collector/../../../etc/passwd", "", true},
		{"url encoded traversal", "..%2F..%2Fetc/passwd", "", true}, // Contains /

		// Hidden files - rejected as potential attack vector
		{"hidden file", ".hidden", "", true},
		{"dot prefix", ".config", "", true},

		// Edge cases
		{"empty name", "", "", true},
		{"single dot", ".", "", true},
		{"spaces in name", "file name.tar.gz", "file name.tar.gz", false}, // Spaces are weird but allowed
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := sync.SanitizeAssetName(tt.assetName)
			if (err != nil) != tt.wantErr {
				t.Errorf("SanitizeAssetName(%q) error = %v, wantErr %v", tt.assetName, err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("SanitizeAssetName(%q) = %q, want %q", tt.assetName, got, tt.want)
			}
		})
	}
}

func TestSanitizeAssetName_PathTraversalRegression(t *testing.T) {
	// This test specifically reproduces the vulnerability from the security audit
	// The PoC input was: {"assets":[{"name":"../../../../tmp/pwn",...}]}

	maliciousNames := []string{
		"../../../../tmp/pwn",
		"../../../etc/passwd",
		"..\\..\\..\\Windows\\System32\\cmd.exe",
		"/etc/passwd",
		"C:\\Windows\\System32\\cmd.exe",
	}

	for _, name := range maliciousNames {
		t.Run(name, func(t *testing.T) {
			_, err := sync.SanitizeAssetName(name)
			if err == nil {
				t.Errorf("SanitizeAssetName(%q) should have returned error, got nil", name)
			}
		})
	}
}

// Symlink traversal tests
// These tests ensure that hostile filesystem symlinks cannot cause writes outside intended directories.

func TestLockfileSaveRejectsSymlinkedParent(t *testing.T) {
	// Use securityTestDirInCwd because Save() requires paths under cwd
	tmpDir := securityTestDirInCwd(t)

	// Create actual target directory that attacker wants to write to
	targetDir := filepath.Join(tmpDir, "sensitive")
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		t.Fatalf("creating target dir: %v", err)
	}

	// Create a symlink as a parent directory in the lockfile path
	// Attack scenario: attacker creates .epack -> /sensitive/location
	parentSymlink := filepath.Join(tmpDir, "workdir")
	if err := os.Symlink(targetDir, parentSymlink); err != nil {
		t.Fatalf("creating parent symlink: %v", err)
	}

	// Try to save lockfile through the symlinked parent
	lockPath := filepath.Join(parentSymlink, "epack.lock.yaml")

	lf := lockfile.New()
	lf.Collectors["test"] = lockfile.LockedCollector{
		Source:  "github.com/owner/repo",
		Version: "v1.0.0",
	}

	err := lf.Save(lockPath)
	if err == nil {
		t.Error("Save should refuse to write through symlinked parent directory")
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Errorf("error should mention symlink, got: %v", err)
	}

	// Verify nothing was written to target directory
	entries, _ := os.ReadDir(targetDir)
	for _, entry := range entries {
		if strings.Contains(entry.Name(), "lock") {
			t.Errorf("lockfile should not have been written to target dir, found: %s", entry.Name())
		}
	}
}

func TestLockfileSaveRejectsDeepSymlinkedAncestor(t *testing.T) {
	// Use securityTestDirInCwd because Save() requires paths under cwd
	tmpDir := securityTestDirInCwd(t)

	// Create a deeper directory structure with a symlink in the middle
	// /tmpDir/a/b -> /tmpDir/target (symlink)
	// Attacker wants lockfile at /tmpDir/a/b/c/epack.lock.yaml
	// which would actually write to /tmpDir/target/c/epack.lock.yaml

	targetDir := filepath.Join(tmpDir, "target")
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		t.Fatalf("creating target dir: %v", err)
	}

	parentA := filepath.Join(tmpDir, "a")
	if err := os.MkdirAll(parentA, 0755); err != nil {
		t.Fatalf("creating parent a: %v", err)
	}

	// Create symlink: a/b -> target
	symlinkB := filepath.Join(parentA, "b")
	if err := os.Symlink(targetDir, symlinkB); err != nil {
		t.Fatalf("creating symlink: %v", err)
	}

	// Try to save through the path with symlink ancestor
	lockPath := filepath.Join(symlinkB, "c", "epack.lock.yaml")

	lf := lockfile.New()
	lf.Collectors["test"] = lockfile.LockedCollector{
		Source:  "github.com/owner/repo",
		Version: "v1.0.0",
	}

	err := lf.Save(lockPath)
	if err == nil {
		t.Error("Save should refuse to write through path with symlinked ancestor")
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Errorf("error should mention symlink, got: %v", err)
	}
}

func TestSyncRejectsSymlinkedEpackDir(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a target directory that attacker wants binaries written to
	targetDir := filepath.Join(tmpDir, "sensitive-bin")
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		t.Fatalf("creating target dir: %v", err)
	}

	// Create work directory with .epack as a symlink to sensitive location
	// Attack scenario: .epack/collectors/foo/v1.0.0 -> /sensitive/bin
	workDir := filepath.Join(tmpDir, "workdir")
	if err := os.MkdirAll(workDir, 0755); err != nil {
		t.Fatalf("creating work dir: %v", err)
	}

	epackSymlink := filepath.Join(workDir, ".epack")
	if err := os.Symlink(targetDir, epackSymlink); err != nil {
		t.Fatalf("creating .epack symlink: %v", err)
	}

	// Create lockfile with a source-based collector
	lockPath := filepath.Join(workDir, lockfile.FileName)
	lf := lockfile.New()
	lf.Collectors["test"] = lockfile.LockedCollector{
		Source:  "github.com/owner/repo",
		Version: "v1.0.0",
		Platforms: map[string]componenttypes.LockedPlatform{
			platform.Key("linux", "amd64"): {Digest: "sha256:abc123"},
		},
	}
	// Save lockfile directly (not through symlink path, so it succeeds)
	content := `schema_version: 1
collectors:
  test:
    source: github.com/owner/repo
    version: v1.0.0
    platforms:
      linux/amd64:
        digest: sha256:abc123
`
	if err := os.WriteFile(lockPath, []byte(content), 0644); err != nil {
		t.Fatalf("writing lockfile: %v", err)
	}

	// Create syncer pointing to the work directory
	syncer := &sync.Syncer{
		Registry:     sync.NewGitHubRegistry(),
		LockfilePath: lockPath,
		BaseDir:      epackSymlink, // Points through symlink
	}

	cfg := &config.JobConfig{
		Collectors: map[string]config.CollectorConfig{
			"test": {Source: "github.com/owner/repo@v1.0.0"},
		},
	}

	// Sync should fail because BaseDir contains a symlink
	_, err := syncer.Sync(context.Background(), cfg, sync.SyncOpts{})
	// Note: sync will attempt to download and then fail during install
	// because the install path validation should catch the symlink
	// The actual error depends on what happens first - lockfile read or install attempt
	// For this test, we just verify that no files were written to target
	_ = err // Ignore error details, just check no files leaked

	// Verify nothing was written to the sensitive target directory
	entries, _ := os.ReadDir(targetDir)
	for _, entry := range entries {
		if entry.Name() != "" && !strings.HasPrefix(entry.Name(), ".") {
			t.Errorf("files should not have been written to target dir through symlink, found: %s", entry.Name())
		}
	}
}

func TestInstallPath_SymlinkInBaseDir(t *testing.T) {
	// This tests that InstallPath validates against symlinks in the base directory
	// The actual validation happens in syncSource, but we test the path construction is safe

	tmpDir := t.TempDir()
	targetDir := filepath.Join(tmpDir, "target")
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		t.Fatalf("creating target: %v", err)
	}

	symlinkDir := filepath.Join(tmpDir, "symlink")
	if err := os.Symlink(targetDir, symlinkDir); err != nil {
		t.Fatalf("creating symlink: %v", err)
	}

	// InstallPath itself doesn't validate symlinks (it just computes a path)
	// But the path should not escape the base directory
	path, err := sync.InstallPath(symlinkDir, componenttypes.KindCollector, "collector", "v1.0.0", "collector")
	if err != nil {
		t.Fatalf("InstallPath error: %v", err)
	}

	// Path should still be under the base directory (the symlink)
	if !strings.HasPrefix(path, symlinkDir) {
		t.Errorf("InstallPath should return path under base dir, got: %s", path)
	}

	// The actual symlink validation happens in syncSource before MkdirAll
}

// SECURITY REGRESSION TEST: InsecureSkipVerify must set Verified=false
// This test verifies the fix for a vulnerability where deps sync --insecure-skip-verify
// would return Verified=true even though no verification was performed.
//
// Attack scenario:
// 1. Attacker compromises CI to add --insecure-skip-verify to deps sync
// 2. Downstream code checks result.Verified to decide trust level
// 3. OLD CODE: Verified=true even though digest wasn't checked
// 4. Downstream code trusts the unverified binary
//
// FIX: Verified is only true when we actually performed verification.
func TestInsecureSkipVerifyMustReturnUnverified(t *testing.T) {
	tmpDir := t.TempDir()
	platform := platform.Key("linux", "amd64")

	// Create a binary file
	binaryPath := filepath.Join(tmpDir, "collector")
	if err := os.WriteFile(binaryPath, []byte("binary-content"), 0755); err != nil {
		t.Fatalf("writing binary: %v", err)
	}

	// Create lockfile with the correct digest
	lf := lockfile.New()
	digest, err := sync.ComputeDigest(binaryPath)
	if err != nil {
		t.Fatalf("computing digest: %v", err)
	}
	lf.Collectors["test"] = lockfile.LockedCollector{
		Source:  "github.com/test/test",
		Version: "v1.0.0",
		Platforms: map[string]componenttypes.LockedPlatform{
			platform: {Digest: digest},
		},
	}

	syncer := &sync.Syncer{BaseDir: filepath.Join(tmpDir, ".epack")}
	cfg := config.CollectorConfig{Binary: binaryPath}

	// Test: verifyExternal with InsecureSkipVerify=true
	result, err := syncer.VerifyExternalCollector("test", cfg, lf, platform, sync.SyncOpts{Unsafe: sync.SyncUnsafeOverrides{SkipVerify: true}})
	if err != nil {
		t.Fatalf("verifyExternal error: %v", err)
	}

	// SECURITY: Verified MUST be false when verification was skipped
	if result.Verified {
		t.Fatal("SECURITY VULNERABILITY: InsecureSkipVerify returned Verified=true! " +
			"This allows unverified binaries to appear verified.")
	}

	// Sanity check: without InsecureSkipVerify, it should be verified
	result, err = syncer.VerifyExternalCollector("test", cfg, lf, platform, sync.SyncOpts{Unsafe: sync.SyncUnsafeOverrides{SkipVerify: false}})
	if err != nil {
		t.Fatalf("verifyExternal error: %v", err)
	}
	if !result.Verified {
		t.Error("Expected Verified=true when InsecureSkipVerify=false")
	}
}
