package pack

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"testing"
)

// createTestPackMulti creates a test pack with multiple artifacts.
// artifacts is a map of path -> content.
func createTestPackMulti(t *testing.T, stream string, artifacts map[string][]byte) string {
	t.Helper()

	// Build artifacts with correct digests
	var artifactList []Artifact
	for path, content := range artifacts {
		digest := computeSHA256(content)
		size := json.Number(strconv.Itoa(len(content)))
		artifactList = append(artifactList, Artifact{
			Type:   "embedded",
			Path:   path,
			Digest: digest,
			Size:   &size,
		})
	}

	// Sort for deterministic order
	sort.Slice(artifactList, func(i, j int) bool {
		return artifactList[i].Path < artifactList[j].Path
	})

	// Build canonical list and compute pack_digest
	tmpManifest := &Manifest{Artifacts: artifactList}
	canonical := BuildCanonicalArtifactList(tmpManifest)
	packDigest := HashCanonicalList(canonical)

	manifest := Manifest{
		SpecVersion: "1.0",
		Stream:      stream,
		GeneratedAt: "2024-01-15T10:30:00Z",
		PackDigest:  packDigest,
		Sources:     []Source{{Name: "test-source", Version: "1.0.0"}},
		Artifacts:   artifactList,
	}

	manifestData, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("failed to marshal manifest: %v", err)
	}

	// Create zip
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)

	fw, _ := w.Create("manifest.json")
	_, _ = fw.Write(manifestData)

	for path, content := range artifacts {
		fw, _ = w.Create(path)
		_, _ = fw.Write(content)
	}

	_ = w.Close()

	dir := t.TempDir()
	path := filepath.Join(dir, "extract-test.zip")
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatalf("failed to write zip file: %v", err)
	}

	return path
}

func TestExtract_SingleArtifact(t *testing.T) {
	content := []byte(`{"extracted": true}`)
	packPath := createTestPackMulti(t, "test/extract", map[string][]byte{
		"artifacts/data.json": content,
	})

	p, err := Open(packPath)
	if err != nil {
		t.Fatalf("Failed to open pack: %v", err)
	}
	defer func() { _ = p.Close() }()

	outputDir := t.TempDir()
	result, err := p.Extract(ExtractOptions{
		OutputDir: outputDir,
		All:       true,
	})
	if err != nil {
		t.Fatalf("Extract failed: %v", err)
	}

	if len(result.Extracted) != 1 {
		t.Fatalf("Expected 1 extracted file, got %d", len(result.Extracted))
	}

	// Verify extracted content
	extractedPath := filepath.Join(outputDir, "artifacts", "data.json")
	extracted, err := os.ReadFile(extractedPath)
	if err != nil {
		t.Fatalf("Failed to read extracted file: %v", err)
	}
	if string(extracted) != string(content) {
		t.Errorf("Extracted content = %q, want %q", string(extracted), string(content))
	}
}

func TestExtract_MultipleArtifacts(t *testing.T) {
	packPath := createTestPackMulti(t, "test/extract-multi", map[string][]byte{
		"artifacts/a.json": []byte(`{"a": 1}`),
		"artifacts/b.json": []byte(`{"b": 2}`),
		"artifacts/c.txt":  []byte("text content"),
	})

	p, err := Open(packPath)
	if err != nil {
		t.Fatalf("Failed to open pack: %v", err)
	}
	defer func() { _ = p.Close() }()

	outputDir := t.TempDir()
	result, err := p.Extract(ExtractOptions{
		OutputDir: outputDir,
		All:       true,
	})
	if err != nil {
		t.Fatalf("Extract failed: %v", err)
	}

	if len(result.Extracted) != 3 {
		t.Fatalf("Expected 3 extracted files, got %d", len(result.Extracted))
	}

	// Verify all files exist
	expectedFiles := []string{
		filepath.Join(outputDir, "artifacts", "a.json"),
		filepath.Join(outputDir, "artifacts", "b.json"),
		filepath.Join(outputDir, "artifacts", "c.txt"),
	}

	for _, path := range expectedFiles {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			t.Errorf("Expected file %s does not exist", path)
		}
	}
}

func TestExtract_WithFilter(t *testing.T) {
	packPath := createTestPackMulti(t, "test/extract-filter", map[string][]byte{
		"artifacts/data1.json": []byte(`{}`),
		"artifacts/data2.json": []byte(`{}`),
		"artifacts/readme.md":  []byte(`# README`),
	})

	p, err := Open(packPath)
	if err != nil {
		t.Fatalf("Failed to open pack: %v", err)
	}
	defer func() { _ = p.Close() }()

	outputDir := t.TempDir()
	result, err := p.Extract(ExtractOptions{
		OutputDir: outputDir,
		Filter:    "*.json",
	})
	if err != nil {
		t.Fatalf("Extract failed: %v", err)
	}

	if len(result.Extracted) != 2 {
		t.Errorf("Filter matched %d artifacts, want 2", len(result.Extracted))
	}
}

func TestExtract_SpecificPaths(t *testing.T) {
	packPath := createTestPackMulti(t, "test/extract-paths", map[string][]byte{
		"artifacts/a.json": []byte(`{"a": 1}`),
		"artifacts/b.json": []byte(`{"b": 2}`),
		"artifacts/c.json": []byte(`{"c": 3}`),
	})

	p, err := Open(packPath)
	if err != nil {
		t.Fatalf("Failed to open pack: %v", err)
	}
	defer func() { _ = p.Close() }()

	outputDir := t.TempDir()
	result, err := p.Extract(ExtractOptions{
		OutputDir: outputDir,
		Paths:     []string{"artifacts/a.json", "artifacts/c.json"},
	})
	if err != nil {
		t.Fatalf("Extract failed: %v", err)
	}

	if len(result.Extracted) != 2 {
		t.Errorf("Expected 2 extracted files, got %d", len(result.Extracted))
	}

	// Verify only requested files exist
	if _, err := os.Stat(filepath.Join(outputDir, "artifacts", "a.json")); err != nil {
		t.Error("a.json should exist")
	}
	if _, err := os.Stat(filepath.Join(outputDir, "artifacts", "b.json")); !os.IsNotExist(err) {
		t.Error("b.json should NOT exist")
	}
	if _, err := os.Stat(filepath.Join(outputDir, "artifacts", "c.json")); err != nil {
		t.Error("c.json should exist")
	}
}

func TestExtract_PathNotFound(t *testing.T) {
	packPath := createTestPackMulti(t, "test/extract-notfound", map[string][]byte{
		"artifacts/a.json": []byte(`{}`),
	})

	p, err := Open(packPath)
	if err != nil {
		t.Fatalf("Failed to open pack: %v", err)
	}
	defer func() { _ = p.Close() }()

	outputDir := t.TempDir()
	_, err = p.Extract(ExtractOptions{
		OutputDir: outputDir,
		Paths:     []string{"artifacts/nonexistent.json"},
	})
	if err == nil {
		t.Error("Expected error for nonexistent path")
	}
}

func TestExtract_PreservesContent(t *testing.T) {
	testCases := []struct {
		name    string
		content []byte
	}{
		{"json", []byte(`{"key": "value", "nested": {"a": 1}}`)},
		{"text", []byte("line1\nline2\nline3")},
		{"binary", []byte{0x00, 0x01, 0x02, 0xff, 0xfe}},
		{"unicode", []byte("Hello, 世界! 🌍")},
		{"empty", []byte{}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			packPath := createTestPackMulti(t, "test/"+tc.name, map[string][]byte{
				"artifacts/test": tc.content,
			})

			p, err := Open(packPath)
			if err != nil {
				t.Fatalf("Failed to open pack: %v", err)
			}
			defer func() { _ = p.Close() }()

			outputDir := t.TempDir()
			_, err = p.Extract(ExtractOptions{
				OutputDir: outputDir,
				All:       true,
			})
			if err != nil {
				t.Fatalf("Extract failed: %v", err)
			}

			extracted, err := os.ReadFile(filepath.Join(outputDir, "artifacts", "test"))
			if err != nil {
				t.Fatalf("Failed to read extracted file: %v", err)
			}

			if string(extracted) != string(tc.content) {
				t.Errorf("Content mismatch: got %v, want %v", extracted, tc.content)
			}
		})
	}
}

func TestExtract_Force(t *testing.T) {
	packPath := createTestPackMulti(t, "test/extract-force", map[string][]byte{
		"artifacts/data.json": []byte(`{"new": true}`),
	})

	p, err := Open(packPath)
	if err != nil {
		t.Fatalf("Failed to open pack: %v", err)
	}
	defer func() { _ = p.Close() }()

	outputDir := t.TempDir()

	// Create existing file
	existingPath := filepath.Join(outputDir, "artifacts", "data.json")
	if err := os.MkdirAll(filepath.Dir(existingPath), 0755); err != nil {
		t.Fatalf("Failed to create dir: %v", err)
	}
	if err := os.WriteFile(existingPath, []byte(`{"old": true}`), 0644); err != nil {
		t.Fatalf("Failed to create existing file: %v", err)
	}

	// Without Force, should fail
	_, err = p.Extract(ExtractOptions{
		OutputDir: outputDir,
		All:       true,
		Force:     false,
	})
	if err == nil {
		t.Error("Expected error when file exists without Force")
	}

	// With Force, should succeed
	_, err = p.Extract(ExtractOptions{
		OutputDir: outputDir,
		All:       true,
		Force:     true,
	})
	if err != nil {
		t.Fatalf("Extract with Force failed: %v", err)
	}

	// Verify content was overwritten
	content, _ := os.ReadFile(existingPath)
	if string(content) != `{"new": true}` {
		t.Errorf("File was not overwritten: got %s", content)
	}
}

func TestExtract_RejectsSymlinkInPath(t *testing.T) {
	packPath := createTestPackMulti(t, "test/extract-symlink", map[string][]byte{
		"artifacts/data.json": []byte(`{}`),
	})

	p, err := Open(packPath)
	if err != nil {
		t.Fatalf("Failed to open pack: %v", err)
	}
	defer func() { _ = p.Close() }()

	// Create output dir with a symlink in the artifacts path
	baseDir := t.TempDir()
	realDir := filepath.Join(baseDir, "real")
	if err := os.MkdirAll(realDir, 0755); err != nil {
		t.Fatalf("Failed to create real dir: %v", err)
	}

	// Create symlink: artifacts -> real
	symlinkDir := filepath.Join(baseDir, "artifacts")
	if err := os.Symlink(realDir, symlinkDir); err != nil {
		t.Skipf("Cannot create symlink (may need elevated privileges): %v", err)
	}

	// Extract should fail due to symlink in path
	_, err = p.Extract(ExtractOptions{
		OutputDir: baseDir,
		All:       true,
	})
	if err == nil {
		t.Error("Extract should reject paths with symlinks")
	}
}

func TestExtract_NoOptionsError(t *testing.T) {
	packPath := createTestPackMulti(t, "test/extract-noopts", map[string][]byte{
		"artifacts/data.json": []byte(`{}`),
	})

	p, err := Open(packPath)
	if err != nil {
		t.Fatalf("Failed to open pack: %v", err)
	}
	defer func() { _ = p.Close() }()

	outputDir := t.TempDir()
	_, err = p.Extract(ExtractOptions{
		OutputDir: outputDir,
		// No Paths, All, or Filter specified
	})
	if err == nil {
		t.Error("Expected error when no extraction options specified")
	}
}

func TestMatchPath(t *testing.T) {
	tests := []struct {
		path    string
		pattern string
		want    bool
	}{
		{"artifacts/data.json", "*.json", true},
		{"artifacts/subdir/data.json", "*.json", true},
		{"artifacts/data.txt", "*.json", false},
		{"artifacts/data.json", "data.json", true},
		{"artifacts/subdir/data.json", "data.json", true},
		{"artifacts/other.json", "data.json", false},
	}

	for _, tt := range tests {
		t.Run(tt.path+"_"+tt.pattern, func(t *testing.T) {
			got := matchPath(tt.path, tt.pattern)
			if got != tt.want {
				t.Errorf("matchPath(%q, %q) = %v, want %v", tt.path, tt.pattern, got, tt.want)
			}
		})
	}
}

func TestExtract_DefaultOutputDir(t *testing.T) {
	// Test that empty OutputDir defaults to "."
	packPath := createTestPackMulti(t, "test/default-dir", map[string][]byte{
		"artifacts/data.json": []byte(`{}`),
	})

	p, err := Open(packPath)
	if err != nil {
		t.Fatalf("Failed to open pack: %v", err)
	}
	defer func() { _ = p.Close() }()

	// Change to temp dir for this test
	originalDir, _ := os.Getwd()
	tmpDir := t.TempDir()
	_ = os.Chdir(tmpDir)
	defer func() { _ = os.Chdir(originalDir) }()

	result, err := p.Extract(ExtractOptions{
		OutputDir: "", // Empty should default to "."
		All:       true,
	})
	if err != nil {
		t.Fatalf("Extract failed: %v", err)
	}

	if len(result.Extracted) != 1 {
		t.Errorf("Expected 1 extracted file, got %d", len(result.Extracted))
	}

	// Verify file was created in current directory
	if _, err := os.Stat(filepath.Join(tmpDir, "artifacts", "data.json")); os.IsNotExist(err) {
		t.Error("File should be extracted to current directory")
	}
}

func TestExtract_EmptyFilter(t *testing.T) {
	// Filter that matches nothing should return empty result
	packPath := createTestPackMulti(t, "test/empty-filter", map[string][]byte{
		"artifacts/data.json": []byte(`{}`),
	})

	p, err := Open(packPath)
	if err != nil {
		t.Fatalf("Failed to open pack: %v", err)
	}
	defer func() { _ = p.Close() }()

	outputDir := t.TempDir()
	result, err := p.Extract(ExtractOptions{
		OutputDir: outputDir,
		Filter:    "*.xyz", // No files match this pattern
	})
	if err != nil {
		t.Fatalf("Extract failed: %v", err)
	}

	if len(result.Extracted) != 0 {
		t.Errorf("Expected 0 extracted files, got %d", len(result.Extracted))
	}
}

func TestExtract_NestedDirectories(t *testing.T) {
	packPath := createTestPackMulti(t, "test/nested-dirs", map[string][]byte{
		"artifacts/level1/level2/level3/deep.json": []byte(`{"deep": true}`),
		"artifacts/level1/shallow.json":            []byte(`{"shallow": true}`),
	})

	p, err := Open(packPath)
	if err != nil {
		t.Fatalf("Failed to open pack: %v", err)
	}
	defer func() { _ = p.Close() }()

	outputDir := t.TempDir()
	result, err := p.Extract(ExtractOptions{
		OutputDir: outputDir,
		All:       true,
	})
	if err != nil {
		t.Fatalf("Extract failed: %v", err)
	}

	if len(result.Extracted) != 2 {
		t.Errorf("Expected 2 extracted files, got %d", len(result.Extracted))
	}

	// Verify deeply nested file exists
	deepPath := filepath.Join(outputDir, "artifacts", "level1", "level2", "level3", "deep.json")
	if _, err := os.Stat(deepPath); os.IsNotExist(err) {
		t.Error("Deeply nested file should exist")
	}

	// Verify content
	content, _ := os.ReadFile(deepPath)
	if string(content) != `{"deep": true}` {
		t.Errorf("Deep file content = %q, want %q", content, `{"deep": true}`)
	}
}

func TestExtract_MultiplePathsPartialMatch(t *testing.T) {
	// When requesting multiple paths and one doesn't exist, should error
	packPath := createTestPackMulti(t, "test/partial-paths", map[string][]byte{
		"artifacts/a.json": []byte(`{"a": 1}`),
		"artifacts/b.json": []byte(`{"b": 2}`),
	})

	p, err := Open(packPath)
	if err != nil {
		t.Fatalf("Failed to open pack: %v", err)
	}
	defer func() { _ = p.Close() }()

	outputDir := t.TempDir()
	_, err = p.Extract(ExtractOptions{
		OutputDir: outputDir,
		Paths:     []string{"artifacts/a.json", "artifacts/nonexistent.json"},
	})
	if err == nil {
		t.Error("Should error when one of multiple paths doesn't exist")
	}
}

func TestExtract_ExtractedPathsList(t *testing.T) {
	packPath := createTestPackMulti(t, "test/paths-list", map[string][]byte{
		"artifacts/a.json": []byte(`{}`),
		"artifacts/b.json": []byte(`{}`),
	})

	p, err := Open(packPath)
	if err != nil {
		t.Fatalf("Failed to open pack: %v", err)
	}
	defer func() { _ = p.Close() }()

	outputDir := t.TempDir()
	result, err := p.Extract(ExtractOptions{
		OutputDir: outputDir,
		All:       true,
	})
	if err != nil {
		t.Fatalf("Extract failed: %v", err)
	}

	// Verify the returned paths are absolute and exist
	for _, extractedPath := range result.Extracted {
		if !filepath.IsAbs(extractedPath) {
			t.Errorf("Extracted path %q is not absolute", extractedPath)
		}
		if _, err := os.Stat(extractedPath); os.IsNotExist(err) {
			t.Errorf("Extracted path %q does not exist", extractedPath)
		}
	}
}

func TestExtract_RefuseOverwriteSymlink(t *testing.T) {
	packPath := createTestPackMulti(t, "test/symlink-overwrite", map[string][]byte{
		"artifacts/data.json": []byte(`{"new": true}`),
	})

	p, err := Open(packPath)
	if err != nil {
		t.Fatalf("Failed to open pack: %v", err)
	}
	defer func() { _ = p.Close() }()

	outputDir := t.TempDir()

	// Create target file and symlink to it
	targetDir := filepath.Join(outputDir, "target")
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		t.Fatalf("Failed to create target dir: %v", err)
	}
	targetFile := filepath.Join(targetDir, "real.json")
	if err := os.WriteFile(targetFile, []byte(`{"target": true}`), 0644); err != nil {
		t.Fatalf("Failed to create target file: %v", err)
	}

	// Create symlink at the extraction path
	artifactsDir := filepath.Join(outputDir, "artifacts")
	if err := os.MkdirAll(artifactsDir, 0755); err != nil {
		t.Fatalf("Failed to create artifacts dir: %v", err)
	}
	symlinkPath := filepath.Join(artifactsDir, "data.json")
	if err := os.Symlink(targetFile, symlinkPath); err != nil {
		t.Skipf("Cannot create symlink: %v", err)
	}

	// Even with Force=true, should refuse to overwrite symlink
	_, err = p.Extract(ExtractOptions{
		OutputDir: outputDir,
		All:       true,
		Force:     true,
	})
	if err == nil {
		t.Error("Should refuse to overwrite symlink even with Force=true")
	}
}

func TestExtract_FilterMatchesFullPath(t *testing.T) {
	packPath := createTestPackMulti(t, "test/filter-fullpath", map[string][]byte{
		"artifacts/subdir/data.json": []byte(`{}`),
		"artifacts/other.json":       []byte(`{}`),
	})

	p, err := Open(packPath)
	if err != nil {
		t.Fatalf("Failed to open pack: %v", err)
	}
	defer func() { _ = p.Close() }()

	outputDir := t.TempDir()

	// Filter should match both full path and base name
	result, err := p.Extract(ExtractOptions{
		OutputDir: outputDir,
		Filter:    "artifacts/subdir/*.json",
	})
	if err != nil {
		t.Fatalf("Extract failed: %v", err)
	}

	// Should match only the file in subdir
	if len(result.Extracted) != 1 {
		t.Errorf("Expected 1 extracted file (full path match), got %d", len(result.Extracted))
	}
}
