package sync

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/locktivity/epack/internal/component/config"
	"github.com/locktivity/epack/internal/component/lockfile"
)

func writeMappingFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("writing mapping file: %v", err)
	}
	return path
}

func TestLockProfilesIncludesMappings(t *testing.T) {
	tempDir := t.TempDir()
	writeMappingFile(t, tempDir, "control-mappings.yaml", "schema_version: \"1.0.0\"\nprofile: {id: a/b@v1}\nmappings: []\n")

	cfg := &config.JobConfig{
		Mappings: []config.MappingConfig{{Path: "control-mappings.yaml"}},
	}
	lf := lockfile.New()

	results, err := LockProfiles(cfg, lf, tempDir)
	if err != nil {
		t.Fatalf("LockProfiles: %v", err)
	}

	var mappingResult *ProfileLockResult
	for i := range results {
		if results[i].Kind == "mapping" {
			mappingResult = &results[i]
		}
	}
	if mappingResult == nil {
		t.Fatal("no mapping lock result")
	}
	if !mappingResult.IsNew {
		t.Error("first lock should be new")
	}

	locked, ok := lf.GetMapping("control-mappings.yaml")
	if !ok {
		t.Fatal("mapping not in lockfile")
	}
	if locked.Digest == "" || locked.LockedAt == "" {
		t.Errorf("locked mapping incomplete: %+v", locked)
	}

	// Re-locking unchanged content is neither new nor updated
	results, err = LockProfiles(cfg, lf, tempDir)
	if err != nil {
		t.Fatalf("LockProfiles (second): %v", err)
	}
	for _, r := range results {
		if r.Kind == "mapping" && (r.IsNew || r.Updated) {
			t.Errorf("unchanged mapping should not report new or updated: %+v", r)
		}
	}
}

func TestHasProfileDigestDriftDetectsMappingEdit(t *testing.T) {
	tempDir := t.TempDir()
	path := writeMappingFile(t, tempDir, "control-mappings.yaml", "schema_version: \"1.0.0\"\nprofile: {id: a/b@v1}\nmappings: []\n")

	cfg := &config.JobConfig{
		Mappings: []config.MappingConfig{{Path: "control-mappings.yaml"}},
	}
	lf := lockfile.New()
	if _, err := LockProfiles(cfg, lf, tempDir); err != nil {
		t.Fatalf("LockProfiles: %v", err)
	}

	if HasProfileDigestDrift(cfg, lf, tempDir) {
		t.Error("freshly locked mapping should not drift")
	}

	if err := os.WriteFile(path, []byte("schema_version: \"1.0.0\"\nprofile: {id: a/b@v1}\nmappings: [{control: CC1, evidence: {artifact: artifacts/x.json}}]\n"), 0644); err != nil {
		t.Fatalf("editing mapping file: %v", err)
	}

	if !HasProfileDigestDrift(cfg, lf, tempDir) {
		t.Error("edited mapping should drift")
	}
}

func TestValidateProfileAlignmentCoversMappings(t *testing.T) {
	cfg := &config.JobConfig{
		Mappings: []config.MappingConfig{{Path: "control-mappings.yaml"}},
	}
	lf := lockfile.New()

	if err := ValidateProfileAlignment(cfg, lf, false); err == nil {
		t.Error("mapping missing from lockfile should fail alignment")
	}

	lf.Mappings["control-mappings.yaml"] = lockfile.LockedMapping{Source: "control-mappings.yaml", Digest: "sha256:abc"}
	if err := ValidateProfileAlignment(cfg, lf, false); err != nil {
		t.Errorf("aligned mapping should pass: %v", err)
	}

	// Stale lockfile entry with no config counterpart fails
	empty := &config.JobConfig{}
	if err := ValidateProfileAlignment(empty, lf, false); err == nil {
		t.Error("stale mapping lock entry should fail alignment")
	}
}

func TestSyncMappingsVerifiesAgainstLockfile(t *testing.T) {
	tempDir := t.TempDir()
	writeMappingFile(t, tempDir, "control-mappings.yaml", "schema_version: \"1.0.0\"\nprofile: {id: a/b@v1}\nmappings: []\n")

	cfg := &config.JobConfig{
		Mappings: []config.MappingConfig{{Path: "control-mappings.yaml"}},
	}
	lf := lockfile.New()
	if _, err := LockProfiles(cfg, lf, tempDir); err != nil {
		t.Fatalf("LockProfiles: %v", err)
	}

	syncer := NewSyncer(tempDir)
	results, err := syncer.SyncMappings(cfg, lf, SyncOpts{})
	if err != nil {
		t.Fatalf("SyncMappings: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("results = %d, want 1", len(results))
	}
	if !results[0].Verified || results[0].Kind != "mapping" || !results[0].IsLocal {
		t.Errorf("unexpected result: %+v", results[0])
	}
}
