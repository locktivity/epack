package component

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/locktivity/epack/internal/component/lockfile"
	"github.com/locktivity/epack/internal/componenttypes"
)

// testDirInCwd creates a temporary directory under the current working directory
// for tests that need to use LockFile.Save() (which requires paths under cwd).
// The directory is automatically cleaned up when the test ends.
// Returns an absolute path to ensure filepath.Rel works correctly.
func testDirInCwd(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp(".", "lockfile_test_*")
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

func TestNewLockFile(t *testing.T) {
	lf := lockfile.New()

	if lf.SchemaVersion != 1 {
		t.Errorf("SchemaVersion = %d, want 1", lf.SchemaVersion)
	}
	if lf.Collectors == nil {
		t.Error("Collectors should be initialized, got nil")
	}
	if len(lf.Collectors) != 0 {
		t.Errorf("Collectors should be empty, got %d entries", len(lf.Collectors))
	}
}

func TestLockFile_GetCollector(t *testing.T) {
	lf := lockfile.New()
	lf.Collectors["existing"] = lockfile.LockedCollector{
		Version: "v1.0.0",
		Source:  "owner/repo",
	}

	// Existing collector
	c, ok := lf.GetCollector("existing")
	if !ok {
		t.Error("GetCollector should find 'existing'")
	}
	if c.Version != "v1.0.0" {
		t.Errorf("Version = %q, want %q", c.Version, "v1.0.0")
	}

	// Non-existing collector
	_, ok = lf.GetCollector("nonexistent")
	if ok {
		t.Error("GetCollector should not find 'nonexistent'")
	}
}

func TestLockFile_GetPlatformDigest(t *testing.T) {
	lf := lockfile.New()
	lf.Collectors["test"] = lockfile.LockedCollector{
		Version: "v1.0.0",
		Platforms: map[string]componenttypes.LockedPlatform{
			"linux/amd64":  {Digest: "sha256:abc123", Asset: "test-linux-amd64"},
			"darwin/arm64": {Digest: "sha256:def456", Asset: "test-darwin-arm64"},
		},
	}

	tests := []struct {
		name       string
		collector  string
		platform   string
		wantDigest string
		wantOK     bool
	}{
		{
			name:       "existing platform",
			collector:  "test",
			platform:   "linux/amd64",
			wantDigest: "sha256:abc123",
			wantOK:     true,
		},
		{
			name:       "another existing platform",
			collector:  "test",
			platform:   "darwin/arm64",
			wantDigest: "sha256:def456",
			wantOK:     true,
		},
		{
			name:       "missing platform",
			collector:  "test",
			platform:   "windows/amd64",
			wantDigest: "",
			wantOK:     false,
		},
		{
			name:       "missing collector",
			collector:  "nonexistent",
			platform:   "linux/amd64",
			wantDigest: "",
			wantOK:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			digest, ok := lf.GetPlatformDigest(tt.collector, tt.platform)
			if ok != tt.wantOK {
				t.Errorf("ok = %v, want %v", ok, tt.wantOK)
			}
			if digest != tt.wantDigest {
				t.Errorf("digest = %q, want %q", digest, tt.wantDigest)
			}
		})
	}
}

func TestLockFile_GetPlatformDigest_EmptyDigest(t *testing.T) {
	lf := lockfile.New()
	lf.Collectors["test"] = lockfile.LockedCollector{
		Version: "v1.0.0",
		Platforms: map[string]componenttypes.LockedPlatform{
			"linux/amd64": {Digest: "", Asset: "test-linux-amd64"}, // Empty digest
		},
	}

	digest, ok := lf.GetPlatformDigest("test", "linux/amd64")
	if ok {
		t.Error("GetPlatformDigest should return false for empty digest")
	}
	if digest != "" {
		t.Errorf("digest = %q, want empty string", digest)
	}
}

func TestLoadLockFile_Valid(t *testing.T) {
	tmpDir := t.TempDir()
	lockPath := filepath.Join(tmpDir, "epack.lock.yaml")

	content := `schema_version: 1
collectors:
  github:
    source: github.com/owner/repo
    version: v1.2.3
    signer:
      issuer: https://token.actions.githubusercontent.com
      source_repository_uri: https://github.com/owner/repo
      source_repository_ref: refs/tags/v1.2.3
    platforms:
      linux/amd64:
        digest: sha256:abc123
        asset: github-linux-amd64
`
	if err := os.WriteFile(lockPath, []byte(content), 0644); err != nil {
		t.Fatalf("writing lockfile: %v", err)
	}

	lf, err := lockfile.Load(lockPath)
	if err != nil {
		t.Fatalf("lockfile.Load() error: %v", err)
	}

	if lf.SchemaVersion != 1 {
		t.Errorf("SchemaVersion = %d, want 1", lf.SchemaVersion)
	}

	c, ok := lf.GetCollector("github")
	if !ok {
		t.Fatal("missing github collector")
	}
	if c.Version != "v1.2.3" {
		t.Errorf("Version = %q, want %q", c.Version, "v1.2.3")
	}
	if c.Signer == nil {
		t.Fatal("Signer is nil")
	}
	if c.Signer.Issuer != "https://token.actions.githubusercontent.com" {
		t.Errorf("Issuer = %q, want GitHub Actions issuer", c.Signer.Issuer)
	}

	digest, ok := lf.GetPlatformDigest("github", "linux/amd64")
	if !ok {
		t.Error("missing linux/amd64 platform")
	}
	if digest != "sha256:abc123" {
		t.Errorf("digest = %q, want %q", digest, "sha256:abc123")
	}
}

func TestLoadLockFile_FileNotFound(t *testing.T) {
	_, err := lockfile.Load("/nonexistent/path/epack.lock.yaml")
	if err == nil {
		t.Error("lockfile.Load() expected error for missing file, got nil")
	}
}

func TestLoadLockFile_InvalidYAML(t *testing.T) {
	tmpDir := t.TempDir()
	lockPath := filepath.Join(tmpDir, "epack.lock.yaml")

	content := `not: valid: yaml: here`
	if err := os.WriteFile(lockPath, []byte(content), 0644); err != nil {
		t.Fatalf("writing lockfile: %v", err)
	}

	_, err := lockfile.Load(lockPath)
	if err == nil {
		t.Error("lockfile.Load() expected error for invalid YAML, got nil")
	}
}

func TestLoadLockFile_DefaultSchemaVersion(t *testing.T) {
	tmpDir := t.TempDir()
	lockPath := filepath.Join(tmpDir, "epack.lock.yaml")

	// No schema_version specified
	content := `collectors:
  test:
    version: v1.0.0
    platforms:
      linux/amd64:
        digest: sha256:abc
`
	if err := os.WriteFile(lockPath, []byte(content), 0644); err != nil {
		t.Fatalf("writing lockfile: %v", err)
	}

	lf, err := lockfile.Load(lockPath)
	if err != nil {
		t.Fatalf("lockfile.Load() error: %v", err)
	}

	if lf.SchemaVersion != 1 {
		t.Errorf("SchemaVersion = %d, want 1 (default)", lf.SchemaVersion)
	}
}

func TestLockFile_SaveAndLoad(t *testing.T) {
	// Use testDirInCwd because Save() requires paths under cwd
	tmpDir := testDirInCwd(t)
	lockPath := filepath.Join(tmpDir, "epack.lock.yaml")

	lf := lockfile.New()
	lf.Collectors["myapp"] = lockfile.LockedCollector{
		Source:  "github.com/owner/repo",
		Version: "v2.0.0",
		Signer: &componenttypes.LockedSigner{
			Issuer:              "https://accounts.google.com",
			SourceRepositoryURI: "https://github.com/owner/repo",
			SourceRepositoryRef: "refs/tags/v2.0.0",
		},
		Platforms: map[string]componenttypes.LockedPlatform{
			"darwin/arm64": {Digest: "sha256:xyz789", Asset: "myapp-darwin-arm64"},
		},
	}

	// Save
	if err := lf.Save(lockPath); err != nil {
		t.Fatalf("Save() error: %v", err)
	}

	// Load and verify
	loaded, err := lockfile.Load(lockPath)
	if err != nil {
		t.Fatalf("lockfile.Load() error: %v", err)
	}

	c, ok := loaded.GetCollector("myapp")
	if !ok {
		t.Fatal("missing myapp collector after reload")
	}
	if c.Version != "v2.0.0" {
		t.Errorf("Version = %q, want %q", c.Version, "v2.0.0")
	}
	if c.Signer.Issuer != "https://accounts.google.com" {
		t.Errorf("Issuer = %q, want Google issuer", c.Signer.Issuer)
	}

	digest, ok := loaded.GetPlatformDigest("myapp", "darwin/arm64")
	if !ok {
		t.Error("missing darwin/arm64 platform")
	}
	if digest != "sha256:xyz789" {
		t.Errorf("digest = %q, want %q", digest, "sha256:xyz789")
	}
}

func TestLockFile_SaveCreatesDirectory(t *testing.T) {
	// Use testDirInCwd because Save() requires paths under cwd
	tmpDir := testDirInCwd(t)
	lockPath := filepath.Join(tmpDir, "subdir", "nested", "epack.lock.yaml")

	lf := lockfile.New()
	lf.Collectors["test"] = lockfile.LockedCollector{
		Version: "v1.0.0",
		Platforms: map[string]componenttypes.LockedPlatform{
			"linux/amd64": {Digest: "sha256:abc"},
		},
	}

	if err := lf.Save(lockPath); err != nil {
		t.Fatalf("Save() error: %v", err)
	}

	// Verify file exists
	if _, err := os.Stat(lockPath); err != nil {
		t.Errorf("lockfile not created: %v", err)
	}
}

func TestLockFile_ExternalCollector(t *testing.T) {
	lf := lockfile.New()
	lf.Collectors["external"] = lockfile.LockedCollector{
		Kind: "external",
		Platforms: map[string]componenttypes.LockedPlatform{
			"linux/amd64": {Digest: "sha256:extdigest"},
		},
	}

	c, ok := lf.GetCollector("external")
	if !ok {
		t.Fatal("missing external collector")
	}
	if c.Kind != "external" {
		t.Errorf("Kind = %q, want %q", c.Kind, "external")
	}
	if c.Version != "" {
		t.Errorf("Version = %q, want empty for external", c.Version)
	}

	digest, ok := lf.GetPlatformDigest("external", "linux/amd64")
	if !ok {
		t.Error("missing platform for external collector")
	}
	if digest != "sha256:extdigest" {
		t.Errorf("digest = %q, want %q", digest, "sha256:extdigest")
	}
}
