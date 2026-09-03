package lockfile

import (
	"path/filepath"
	"testing"
)

func TestLockFile_MappingRoundTrip(t *testing.T) {
	tmpDir := testDirInCwd(t)
	lockPath := filepath.Join(tmpDir, "epack.lock.yaml")

	lf := New()
	lf.Mappings["mappings/control-mappings.yaml"] = LockedMapping{
		Source:   "mappings/control-mappings.yaml",
		Digest:   "sha256:abc123",
		LockedAt: "2026-08-28T14:02:11Z",
	}

	if err := lf.Save(lockPath); err != nil {
		t.Fatalf("Save() error: %v", err)
	}

	loaded, err := Load(lockPath)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	m, ok := loaded.GetMapping("mappings/control-mappings.yaml")
	if !ok {
		t.Fatal("missing mapping after reload")
	}
	if m.Digest != "sha256:abc123" {
		t.Errorf("Digest = %q", m.Digest)
	}

	digest, ok := loaded.GetMappingDigest("mappings/control-mappings.yaml")
	if !ok || digest != "sha256:abc123" {
		t.Errorf("GetMappingDigest = %q, %v", digest, ok)
	}
}

func TestParse_RejectsEmptyMappingSource(t *testing.T) {
	_, err := Parse([]byte("schema_version: 1\nmappings:\n  \"\":\n    source: \"\"\n    digest: sha256:abc\n"))
	if err == nil {
		t.Error("empty mapping source should fail parse")
	}
}

func TestParse_LockfileWithoutMappingsStillLoads(t *testing.T) {
	lf, err := Parse([]byte("schema_version: 1\ncollectors: {}\n"))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if lf.Mappings == nil {
		t.Error("Mappings map should be initialized")
	}
}
