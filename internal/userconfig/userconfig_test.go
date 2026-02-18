package userconfig

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/locktivity/epack/internal/componenttypes"
	"github.com/locktivity/epack/internal/limits"
)

func TestParseUtilitiesLock_ValidEmpty(t *testing.T) {
	data := []byte(`schema_version: 1
utilities: {}
`)
	lf, err := ParseUtilitiesLock(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if lf.SchemaVersion != 1 {
		t.Errorf("SchemaVersion = %d, want 1", lf.SchemaVersion)
	}
	if len(lf.Utilities) != 0 {
		t.Errorf("len(Utilities) = %d, want 0", len(lf.Utilities))
	}
}

func TestParseUtilitiesLock_ValidUtility(t *testing.T) {
	data := []byte(`schema_version: 1
utilities:
  myutil:
    source: github.com/example/myutil
    version: v1.2.3
    locked_at: "2024-01-15T10:30:00Z"
`)
	lf, err := ParseUtilitiesLock(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(lf.Utilities) != 1 {
		t.Fatalf("len(Utilities) = %d, want 1", len(lf.Utilities))
	}
	u, ok := lf.Utilities["myutil"]
	if !ok {
		t.Fatal("expected 'myutil' utility")
	}
	if u.Version != "v1.2.3" {
		t.Errorf("Version = %q, want %q", u.Version, "v1.2.3")
	}
}

func TestParseUtilitiesLock_RejectsPathTraversalInName(t *testing.T) {
	tests := []struct {
		name string
		yaml string
	}{
		{"dotdot", `schema_version: 1
utilities:
  "..":
    version: v1.0.0
`},
		{"dotdot-prefix", `schema_version: 1
utilities:
  "../escape":
    version: v1.0.0
`},
		{"slash", `schema_version: 1
utilities:
  "foo/bar":
    version: v1.0.0
`},
		{"backslash", `schema_version: 1
utilities:
  "foo\\bar":
    version: v1.0.0
`},
		{"uppercase", `schema_version: 1
utilities:
  "UPPERCASE":
    version: v1.0.0
`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseUtilitiesLock([]byte(tt.yaml))
			if err == nil {
				t.Error("expected error for path traversal, got nil")
			}
		})
	}
}

func TestParseUtilitiesLock_RejectsInvalidVersion(t *testing.T) {
	data := []byte(`schema_version: 1
utilities:
  myutil:
    source: github.com/example/myutil
    version: "../escape"
`)
	_, err := ParseUtilitiesLock(data)
	if err == nil {
		t.Error("expected error for invalid version, got nil")
	}
}

func TestParseUtilitiesLock_RejectsInvalidTimestamp(t *testing.T) {
	data := []byte(`schema_version: 1
utilities:
  myutil:
    source: github.com/example/myutil
    version: v1.0.0
    locked_at: "not-a-timestamp"
`)
	_, err := ParseUtilitiesLock(data)
	if err == nil {
		t.Error("expected error for invalid timestamp, got nil")
	}
}

func TestParseUtilitiesLock_EnforcesMaxUtilityCount(t *testing.T) {
	// Build YAML with too many utilities
	yaml := "schema_version: 1\nutilities:\n"
	for i := 0; i <= limits.MaxUtilityCount; i++ {
		yaml += "  util" + string(rune('a'+i%26)) + string(rune('0'+i/26)) + ":\n"
		yaml += "    version: v1.0.0\n"
	}

	_, err := ParseUtilitiesLock([]byte(yaml))
	if err == nil {
		t.Error("expected error for exceeding MaxUtilityCount, got nil")
	}
}

func TestParseUtilitiesLock_EnforcesMaxPlatformCount(t *testing.T) {
	// Build YAML with too many platforms
	yaml := "schema_version: 1\nutilities:\n  myutil:\n    version: v1.0.0\n    platforms:\n"
	for i := 0; i <= limits.MaxPlatformCount; i++ {
		yaml += "      platform" + string(rune('a'+i%26)) + string(rune('0'+i/26)) + ":\n"
		yaml += "        digest: sha256:abc123\n"
	}

	_, err := ParseUtilitiesLock([]byte(yaml))
	if err == nil {
		t.Error("expected error for exceeding MaxPlatformCount, got nil")
	}
}

func TestListUtilities_ReturnsSorted(t *testing.T) {
	lf := NewUtilitiesLock()
	lf.Utilities["zebra"] = componenttypes.LockedUtility{Version: "v1.0.0"}
	lf.Utilities["alpha"] = componenttypes.LockedUtility{Version: "v1.0.0"}
	lf.Utilities["middle"] = componenttypes.LockedUtility{Version: "v1.0.0"}

	names := lf.ListUtilities()
	if len(names) != 3 {
		t.Fatalf("len(names) = %d, want 3", len(names))
	}
	if names[0] != "alpha" || names[1] != "middle" || names[2] != "zebra" {
		t.Errorf("names = %v, want [alpha middle zebra]", names)
	}
}

func TestGetUtility_ReturnsDefensiveCopy(t *testing.T) {
	lf := NewUtilitiesLock()
	lf.Utilities["myutil"] = componenttypes.LockedUtility{
		Version: "v1.0.0",
		Platforms: map[string]componenttypes.LockedPlatform{
			"linux-amd64": {Digest: "sha256:original"},
		},
	}

	// Get a copy
	copy, ok := lf.GetUtility("myutil")
	if !ok {
		t.Fatal("expected to find utility")
	}

	// Modify the copy's platforms
	copy.Platforms["linux-amd64"] = componenttypes.LockedPlatform{Digest: "sha256:modified"}

	// Verify original is unchanged
	original := lf.Utilities["myutil"]
	if original.Platforms["linux-amd64"].Digest != "sha256:original" {
		t.Error("original utility was modified through defensive copy")
	}
}

func TestSaveToPath_RefusesSymlink(t *testing.T) {
	// Create temp directory under home to avoid symlink issues on macOS
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("getting home dir: %v", err)
	}
	tmpDir, err := os.MkdirTemp(home, "epack-test-symlink-*")
	if err != nil {
		t.Fatalf("creating temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	// Create a target file
	targetPath := filepath.Join(tmpDir, "target.yaml")
	if err := os.WriteFile(targetPath, []byte("original"), 0644); err != nil {
		t.Fatalf("creating target file: %v", err)
	}

	// Create a symlink
	symlinkPath := filepath.Join(tmpDir, "symlink.yaml")
	if err := os.Symlink(targetPath, symlinkPath); err != nil {
		t.Fatalf("creating symlink: %v", err)
	}

	// Try to save through the symlink
	lf := NewUtilitiesLock()
	err = lf.SaveToPath(symlinkPath)
	if err == nil {
		t.Error("expected error when saving through symlink, got nil")
	}

	// Verify target file wasn't modified
	content, _ := os.ReadFile(targetPath)
	if string(content) != "original" {
		t.Error("target file was modified through symlink")
	}
}

func TestSaveToPath_AtomicWrite(t *testing.T) {
	// Create temp directory under home to avoid symlink issues on macOS
	// (where /var -> /private/var is a symlink)
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("getting home dir: %v", err)
	}
	tmpDir, err := os.MkdirTemp(home, "epack-test-*")
	if err != nil {
		t.Fatalf("creating temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	path := filepath.Join(tmpDir, "utilities.lock")

	lf := NewUtilitiesLock()
	lf.Utilities["myutil"] = componenttypes.LockedUtility{
		Version: "v1.0.0",
	}

	if err := lf.SaveToPath(path); err != nil {
		t.Fatalf("SaveToPath failed: %v", err)
	}

	// Verify file exists and contains expected content
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading saved file: %v", err)
	}

	// Parse it back
	lf2, err := ParseUtilitiesLock(content)
	if err != nil {
		t.Fatalf("parsing saved file: %v", err)
	}

	if _, ok := lf2.Utilities["myutil"]; !ok {
		t.Error("saved utility not found in parsed file")
	}

	// Verify no temp files left behind
	entries, _ := os.ReadDir(tmpDir)
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) == ".tmp" {
			t.Errorf("temp file left behind: %s", entry.Name())
		}
	}
}

func TestSaveToPath_RejectsInvalidUtilityName(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "utilities.lock")

	lf := NewUtilitiesLock()
	// Bypass type safety by directly setting an invalid name
	lf.Utilities["../escape"] = componenttypes.LockedUtility{
		Version: "v1.0.0",
	}

	err := lf.SaveToPath(path)
	if err == nil {
		t.Error("expected error when saving with invalid utility name, got nil")
	}
}

func TestMarshalDeterministic_ConsistentOutput(t *testing.T) {
	lf := NewUtilitiesLock()
	lf.Utilities["zebra"] = componenttypes.LockedUtility{Version: "v2.0.0"}
	lf.Utilities["alpha"] = componenttypes.LockedUtility{Version: "v1.0.0"}

	// Marshal multiple times
	data1, err := lf.marshalDeterministic()
	if err != nil {
		t.Fatalf("first marshal: %v", err)
	}

	data2, err := lf.marshalDeterministic()
	if err != nil {
		t.Fatalf("second marshal: %v", err)
	}

	if string(data1) != string(data2) {
		t.Error("marshal output is not deterministic")
	}
}

func TestParseUtilitiesLock_DefaultsSchemaVersion(t *testing.T) {
	data := []byte(`utilities:
  myutil:
    version: v1.0.0
`)
	lf, err := ParseUtilitiesLock(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if lf.SchemaVersion != 1 {
		t.Errorf("SchemaVersion = %d, want 1 (default)", lf.SchemaVersion)
	}
}

func TestNewUtilitiesLock_InitializesCorrectly(t *testing.T) {
	lf := NewUtilitiesLock()
	if lf.SchemaVersion != 1 {
		t.Errorf("SchemaVersion = %d, want 1", lf.SchemaVersion)
	}
	if lf.Utilities == nil {
		t.Error("Utilities map should not be nil")
	}
	if len(lf.Utilities) != 0 {
		t.Errorf("len(Utilities) = %d, want 0", len(lf.Utilities))
	}
}

func TestSetUtility_AddsUtility(t *testing.T) {
	lf := NewUtilitiesLock()
	lf.SetUtility("myutil", componenttypes.LockedUtility{Version: "v1.0.0"})

	if len(lf.Utilities) != 1 {
		t.Fatalf("len(Utilities) = %d, want 1", len(lf.Utilities))
	}
	if lf.Utilities["myutil"].Version != "v1.0.0" {
		t.Errorf("Version = %q, want %q", lf.Utilities["myutil"].Version, "v1.0.0")
	}
}

func TestRemoveUtility_RemovesUtility(t *testing.T) {
	lf := NewUtilitiesLock()
	lf.Utilities["myutil"] = componenttypes.LockedUtility{Version: "v1.0.0"}

	lf.RemoveUtility("myutil")

	if len(lf.Utilities) != 0 {
		t.Errorf("len(Utilities) = %d, want 0 after removal", len(lf.Utilities))
	}
}

func TestGetUtility_NotFound(t *testing.T) {
	lf := NewUtilitiesLock()

	_, ok := lf.GetUtility("nonexistent")
	if ok {
		t.Error("expected ok=false for nonexistent utility")
	}
}

// TestValidateUtilitiesForParse_Deterministic verifies that validation errors
// are deterministic across multiple calls. This is important for debuggability
// and test stability.
func TestValidateUtilitiesForParse_Deterministic(t *testing.T) {
	// Create lockfile with multiple invalid utility names
	// validateUtilitiesForParse should fail on the first one alphabetically
	lf := &UtilitiesLock{
		SchemaVersion: 1,
		Utilities: map[string]componenttypes.LockedUtility{
			"../bad-z": {Version: "1.0.0"},
			"../bad-a": {Version: "1.0.0"},
			"../bad-m": {Version: "1.0.0"},
		},
	}

	// Call validation multiple times and verify consistent error
	var firstErr string
	for i := 0; i < 10; i++ {
		err := lf.validateUtilitiesForParse()
		if err == nil {
			t.Fatal("expected validation error, got nil")
		}
		errStr := err.Error()
		if firstErr == "" {
			firstErr = errStr
		} else if errStr != firstErr {
			t.Errorf("non-deterministic error on iteration %d:\nfirst: %s\ngot:   %s", i, firstErr, errStr)
		}
	}

	// Verify it fails on the alphabetically first invalid name
	if firstErr == "" {
		t.Fatal("expected error but got none")
	}
	// The error should mention "../bad-a" since it comes first alphabetically
	if !contains(firstErr, "../bad-a") {
		t.Errorf("expected error to mention '../bad-a' (first alphabetically), got: %s", firstErr)
	}
}

func contains(s, substr string) bool {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestUtilityDigest_Success(t *testing.T) {
	lf := NewUtilitiesLock()
	lf.Utilities["myutil"] = componenttypes.LockedUtility{
		Version: "v1.0.0",
		Platforms: map[string]componenttypes.LockedPlatform{
			"darwin-arm64": {Digest: "sha256:abc123"},
			"linux-amd64":  {Digest: "sha256:def456"},
		},
	}

	// This test uses runtime.GOOS and runtime.GOARCH, so we test that
	// the function returns a digest for the current platform
	digest, err := lf.UtilityDigest("myutil")
	if err != nil {
		// If current platform is not in the test data, that's expected
		// Check that it's a "not available" error
		if !contains(err.Error(), "not available for platform") {
			t.Errorf("unexpected error: %v", err)
		}
		return
	}

	// If we got a digest, verify it's one of the expected ones
	if digest != "sha256:abc123" && digest != "sha256:def456" {
		t.Errorf("unexpected digest: %s", digest)
	}
}

func TestUtilityDigest_NotInstalled(t *testing.T) {
	lf := NewUtilitiesLock()

	_, err := lf.UtilityDigest("nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent utility")
	}
	if !contains(err.Error(), "not installed") {
		t.Errorf("expected 'not installed' error, got: %v", err)
	}
}

func TestUtilityDigest_NoPlatform(t *testing.T) {
	lf := NewUtilitiesLock()
	lf.Utilities["myutil"] = componenttypes.LockedUtility{
		Version:   "v1.0.0",
		Platforms: map[string]componenttypes.LockedPlatform{
			// Platform that doesn't match current
			"windows-amd64": {Digest: "sha256:xyz789"},
		},
	}

	_, err := lf.UtilityDigest("myutil")
	if err == nil {
		t.Error("expected error for missing platform")
	}
	if !contains(err.Error(), "not available for platform") {
		t.Errorf("expected 'not available for platform' error, got: %v", err)
	}
}

func TestUtilityDigest_EmptyDigest(t *testing.T) {
	lf := NewUtilitiesLock()
	// Use both common platforms to ensure test works
	lf.Utilities["myutil"] = componenttypes.LockedUtility{
		Version: "v1.0.0",
		Platforms: map[string]componenttypes.LockedPlatform{
			"darwin-arm64": {Digest: ""},
			"darwin-amd64": {Digest: ""},
			"linux-amd64":  {Digest: ""},
			"linux-arm64":  {Digest: ""},
		},
	}

	_, err := lf.UtilityDigest("myutil")
	if err == nil {
		t.Error("expected error for empty digest")
	}
	if !contains(err.Error(), "no digest") {
		t.Errorf("expected 'no digest' error, got: %v", err)
	}
}
