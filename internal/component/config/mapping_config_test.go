package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseMappings(t *testing.T) {
	cfg, err := Parse([]byte(`
stream: acme/prod
collectors:
  demo:
    binary: ./demo
mappings:
  - path: mappings/control-mappings.yaml
`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(cfg.Mappings) != 1 {
		t.Fatalf("mappings = %d, want 1", len(cfg.Mappings))
	}
	if cfg.Mappings[0].Key() != "mappings/control-mappings.yaml" {
		t.Errorf("key = %q", cfg.Mappings[0].Key())
	}
	if !cfg.HasMappings() || !cfg.NeedsLocking() {
		t.Error("mappings should require locking")
	}
}

func TestParseMappingsRejectsEmptyPath(t *testing.T) {
	_, err := Parse([]byte(`
stream: acme/prod
collectors:
  demo:
    binary: ./demo
mappings:
  - path: ""
`))
	if err == nil || !strings.Contains(err.Error(), "mapping[0]") {
		t.Errorf("empty mapping path should fail, got %v", err)
	}
}

func TestNormalizeResolvesMappingPaths(t *testing.T) {
	tempDir := t.TempDir()
	mappingsDir := filepath.Join(tempDir, "mappings")
	if err := os.MkdirAll(mappingsDir, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	target := filepath.Join(mappingsDir, "control-mappings.yaml")
	if err := os.WriteFile(target, []byte("{}"), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	cfg := &JobConfig{Mappings: []MappingConfig{{Path: "mappings/control-mappings.yaml"}}}
	if err := cfg.Normalize(tempDir); err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if cfg.Mappings[0].ResolvedPath == "" || !filepath.IsAbs(cfg.Mappings[0].ResolvedPath) {
		t.Errorf("ResolvedPath = %q", cfg.Mappings[0].ResolvedPath)
	}
	if cfg.Mappings[0].FilePath() != cfg.Mappings[0].ResolvedPath {
		t.Errorf("FilePath should prefer ResolvedPath")
	}
}

func TestNormalizeRejectsMappingTraversal(t *testing.T) {
	cfg := &JobConfig{Mappings: []MappingConfig{{Path: "../outside.yaml"}}}
	if err := cfg.Normalize(t.TempDir()); err == nil {
		t.Error("path traversal should fail Normalize")
	}
}
