package lockfile

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/locktivity/epack/internal/componenttypes"
)

func TestLockFile_DeterministicMarshaling(t *testing.T) {
	// Create a lockfile with multiple collectors, tools, and platforms
	// to ensure map ordering doesn't affect output
	lf := New()

	// Add collectors in non-alphabetical order
	lf.Collectors["zebra"] = LockedCollector{
		Source:  "owner/zebra",
		Version: "v1.0.0",
		Platforms: map[string]componenttypes.LockedPlatform{
			"windows/amd64": {Digest: "sha256:win"},
			"linux/amd64":   {Digest: "sha256:linux"},
			"darwin/arm64":  {Digest: "sha256:darwin"},
		},
	}
	lf.Collectors["alpha"] = LockedCollector{
		Source:  "owner/alpha",
		Version: "v2.0.0",
		Platforms: map[string]componenttypes.LockedPlatform{
			"linux/arm64": {Digest: "sha256:arm"},
			"linux/amd64": {Digest: "sha256:amd"},
		},
	}
	lf.Collectors["middle"] = LockedCollector{
		Source:  "owner/middle",
		Version: "v3.0.0",
		Platforms: map[string]componenttypes.LockedPlatform{
			"darwin/amd64": {Digest: "sha256:mac"},
		},
	}

	// Add tools in non-alphabetical order
	lf.Tools["zulu"] = LockedTool{
		Source:  "owner/zulu",
		Version: "v1.0.0",
		Platforms: map[string]componenttypes.LockedPlatform{
			"linux/amd64": {Digest: "sha256:zulu"},
		},
	}
	lf.Tools["bravo"] = LockedTool{
		Source:  "owner/bravo",
		Version: "v2.0.0",
		Platforms: map[string]componenttypes.LockedPlatform{
			"darwin/arm64": {Digest: "sha256:bravo"},
		},
	}

	// Marshal multiple times and verify output is identical
	var outputs [][]byte
	for i := 0; i < 10; i++ {
		data, err := lf.marshalDeterministic()
		if err != nil {
			t.Fatalf("marshalDeterministic() error: %v", err)
		}
		outputs = append(outputs, data)
	}

	// All outputs should be identical
	for i := 1; i < len(outputs); i++ {
		if string(outputs[0]) != string(outputs[i]) {
			t.Errorf("marshaling is non-deterministic: iteration 0 != iteration %d\nfirst:\n%s\nlater:\n%s",
				i, string(outputs[0]), string(outputs[i]))
		}
	}

	// Verify ordering: collectors should be alphabetical (alpha, middle, zebra)
	output := string(outputs[0])
	alphaIdx := indexOf(output, "alpha")
	middleIdx := indexOf(output, "middle")
	zebraIdx := indexOf(output, "zebra")

	if alphaIdx == -1 || middleIdx == -1 || zebraIdx == -1 {
		t.Fatalf("missing expected collector names in output:\n%s", output)
	}
	if alphaIdx >= middleIdx || middleIdx >= zebraIdx {
		t.Errorf("collectors not in alphabetical order: alpha=%d, middle=%d, zebra=%d",
			alphaIdx, middleIdx, zebraIdx)
	}

	// Verify platforms within zebra are sorted: darwin/arm64, linux/amd64, windows/amd64
	darwinIdx := indexOf(output[zebraIdx:], "darwin/arm64")
	linuxIdx := indexOf(output[zebraIdx:], "linux/amd64")
	windowsIdx := indexOf(output[zebraIdx:], "windows/amd64")

	if darwinIdx == -1 || linuxIdx == -1 || windowsIdx == -1 {
		t.Fatalf("missing expected platform names in zebra section:\n%s", output[zebraIdx:])
	}
	if darwinIdx >= linuxIdx || linuxIdx >= windowsIdx {
		t.Errorf("platforms not in alphabetical order: darwin=%d, linux=%d, windows=%d",
			darwinIdx, linuxIdx, windowsIdx)
	}
}

// indexOf returns the index of substr in s, or -1 if not found.
func indexOf(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

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

func TestLockFile_SaveAndLoad(t *testing.T) {
	// Use testDirInCwd because Save() requires paths under cwd
	tmpDir := testDirInCwd(t)
	lockPath := filepath.Join(tmpDir, "epack.lock.yaml")

	lf := New()
	lf.Collectors["myapp"] = LockedCollector{
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
	loaded, err := Load(lockPath)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
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

func TestGetComponentInfo_IsolatesPointers(t *testing.T) {
	// Verify that GetComponentInfo returns defensive copies of pointer fields
	// to prevent callers from mutating internal lockfile state.

	lf := New()
	lf.Collectors["test"] = LockedCollector{
		Source:  "github.com/owner/repo",
		Version: "v1.0.0",
		Signer: &componenttypes.LockedSigner{
			Issuer:              "original-issuer",
			Subject:             "original-subject",
			SourceRepositoryURI: "https://github.com/owner/repo",
		},
		ResolvedFrom: &componenttypes.ResolvedFrom{
			Registry:   "original-registry",
			Descriptor: "original-descriptor",
		},
		Verification: &componenttypes.Verification{
			Status:     "verified",
			VerifiedAt: "2024-01-15T10:30:00Z",
		},
		Platforms: map[string]componenttypes.LockedPlatform{
			"linux/amd64": {Digest: "sha256:original"},
		},
	}

	// Get component info
	info, ok := lf.GetComponentInfo(componenttypes.KindCollector, "test")
	if !ok {
		t.Fatal("GetComponentInfo returned false for existing collector")
	}

	// Mutate the returned Signer
	info.Signer.Issuer = "modified-issuer"
	info.Signer.Subject = "modified-subject"

	// Mutate the returned ResolvedFrom
	info.ResolvedFrom.Registry = "modified-registry"

	// Mutate the returned Verification
	info.Verification.Status = "modified-status"

	// Mutate the returned Platforms map
	info.Platforms["linux/amd64"] = componenttypes.LockedPlatform{Digest: "sha256:modified"}

	// Verify original lockfile data is unchanged
	original := lf.Collectors["test"]

	if original.Signer.Issuer != "original-issuer" {
		t.Errorf("Signer.Issuer was mutated: got %q, want %q",
			original.Signer.Issuer, "original-issuer")
	}
	if original.Signer.Subject != "original-subject" {
		t.Errorf("Signer.Subject was mutated: got %q, want %q",
			original.Signer.Subject, "original-subject")
	}
	if original.ResolvedFrom.Registry != "original-registry" {
		t.Errorf("ResolvedFrom.Registry was mutated: got %q, want %q",
			original.ResolvedFrom.Registry, "original-registry")
	}
	if original.Verification.Status != "verified" {
		t.Errorf("Verification.Status was mutated: got %q, want %q",
			original.Verification.Status, "verified")
	}
	if original.Platforms["linux/amd64"].Digest != "sha256:original" {
		t.Errorf("Platforms was mutated: got %q, want %q",
			original.Platforms["linux/amd64"].Digest, "sha256:original")
	}
}

func TestGetComponentInfo_HandlesNilPointers(t *testing.T) {
	// Verify that GetComponentInfo handles nil pointer fields correctly

	lf := New()
	lf.Collectors["minimal"] = LockedCollector{
		Source:  "github.com/owner/repo",
		Version: "v1.0.0",
		// Signer, ResolvedFrom, Verification are all nil
		Platforms: map[string]componenttypes.LockedPlatform{
			"linux/amd64": {Digest: "sha256:abc"},
		},
	}

	info, ok := lf.GetComponentInfo(componenttypes.KindCollector, "minimal")
	if !ok {
		t.Fatal("GetComponentInfo returned false for existing collector")
	}

	if info.Signer != nil {
		t.Errorf("Signer should be nil, got %+v", info.Signer)
	}
	if info.ResolvedFrom != nil {
		t.Errorf("ResolvedFrom should be nil, got %+v", info.ResolvedFrom)
	}
	if info.Verification != nil {
		t.Errorf("Verification should be nil, got %+v", info.Verification)
	}
}
