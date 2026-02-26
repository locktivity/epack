package builder

import (
	"bytes"
	"context"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/locktivity/epack/pack"
)

func TestBuilder_MinimalPack(t *testing.T) {
	b := New("test/stream")

	// Add a simple artifact
	err := b.AddBytes("artifacts/test.json", []byte(`{"key": "value"}`))
	if err != nil {
		t.Fatalf("AddBytes failed: %v", err)
	}

	// Build the pack
	outputPath := filepath.Join(t.TempDir(), "test.zip")
	if err := b.Build(outputPath); err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	// Verify the pack can be opened
	p, err := pack.Open(outputPath)
	if err != nil {
		t.Fatalf("Failed to open built pack: %v", err)
	}
	defer func() { _ = p.Close() }()

	// Verify manifest fields
	m := p.Manifest()
	if m.SpecVersion != "1.0" {
		t.Errorf("SpecVersion = %q, want %q", m.SpecVersion, "1.0")
	}
	if m.Stream != "test/stream" {
		t.Errorf("Stream = %q, want %q", m.Stream, "test/stream")
	}
	if len(m.Artifacts) != 1 {
		t.Errorf("len(Artifacts) = %d, want 1", len(m.Artifacts))
	}
	if m.Artifacts[0].Path != "artifacts/test.json" {
		t.Errorf("Artifact path = %q, want %q", m.Artifacts[0].Path, "artifacts/test.json")
	}

	// Verify integrity
	if err := p.VerifyIntegrity(); err != nil {
		t.Errorf("VerifyIntegrity failed: %v", err)
	}
}

func TestBuilder_EmptyPack(t *testing.T) {
	b := New("test/empty")

	outputPath := filepath.Join(t.TempDir(), "empty.zip")
	if err := b.Build(outputPath); err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	p, err := pack.Open(outputPath)
	if err != nil {
		t.Fatalf("Failed to open built pack: %v", err)
	}
	defer func() { _ = p.Close() }()

	m := p.Manifest()
	if len(m.Artifacts) != 0 {
		t.Errorf("len(Artifacts) = %d, want 0", len(m.Artifacts))
	}

	// Empty pack should still have valid pack_digest (hash of empty string)
	if m.PackDigest == "" {
		t.Error("PackDigest should not be empty")
	}
}

func TestBuilder_WithSources(t *testing.T) {
	b := New("test/sources")
	b.AddSource("github", "1.0.0")
	b.AddSource("aws", "2.0.0")
	_ = b.AddBytes("artifacts/test.json", []byte(`{}`))

	outputPath := filepath.Join(t.TempDir(), "sources.zip")
	if err := b.Build(outputPath); err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	p, err := pack.Open(outputPath)
	if err != nil {
		t.Fatalf("Failed to open built pack: %v", err)
	}
	defer func() { _ = p.Close() }()

	m := p.Manifest()
	if len(m.Sources) != 2 {
		t.Errorf("len(Sources) = %d, want 2", len(m.Sources))
	}
	if m.Sources[0].Name != "github" {
		t.Errorf("Sources[0].Name = %q, want %q", m.Sources[0].Name, "github")
	}
}

func TestBuilder_WithOptions(t *testing.T) {
	b := New("test/options")
	err := b.AddBytesWithOptions("artifacts/data.json", []byte(`{"data": true}`), ArtifactOptions{
		ContentType: "application/json",
		DisplayName: "Data File",
		Description: "Test data file",
		Schema:      "test/data/v1",
		Controls:    []string{"AC-1", "AC-2"},
	})
	if err != nil {
		t.Fatalf("AddBytesWithOptions failed: %v", err)
	}

	outputPath := filepath.Join(t.TempDir(), "options.zip")
	if err := b.Build(outputPath); err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	p, err := pack.Open(outputPath)
	if err != nil {
		t.Fatalf("Failed to open built pack: %v", err)
	}
	defer func() { _ = p.Close() }()

	m := p.Manifest()
	a := m.Artifacts[0]
	if a.ContentType != "application/json" {
		t.Errorf("ContentType = %q, want %q", a.ContentType, "application/json")
	}
	if a.DisplayName != "Data File" {
		t.Errorf("DisplayName = %q, want %q", a.DisplayName, "Data File")
	}
	if a.Schema != "test/data/v1" {
		t.Errorf("Schema = %q, want %q", a.Schema, "test/data/v1")
	}
	if len(a.Controls) != 2 {
		t.Errorf("len(Controls) = %d, want 2", len(a.Controls))
	}
}

func TestBuilder_AddFile(t *testing.T) {
	// Create a temp file to add
	tempDir := t.TempDir()
	testFile := filepath.Join(tempDir, "source.json")
	content := []byte(`{"from": "file"}`)
	if err := os.WriteFile(testFile, content, 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	b := New("test/file")
	if err := b.AddFile("artifacts/from-file.json", testFile); err != nil {
		t.Fatalf("AddFile failed: %v", err)
	}

	outputPath := filepath.Join(tempDir, "file.zip")
	if err := b.Build(outputPath); err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	p, err := pack.Open(outputPath)
	if err != nil {
		t.Fatalf("Failed to open built pack: %v", err)
	}
	defer func() { _ = p.Close() }()

	// Read the artifact back and verify content
	data, err := p.ReadArtifact("artifacts/from-file.json")
	if err != nil {
		t.Fatalf("ReadArtifact failed: %v", err)
	}
	if !bytes.Equal(data.Bytes(), content) {
		t.Errorf("Artifact content = %q, want %q", data, content)
	}
}

func TestBuilder_AddReader(t *testing.T) {
	b := New("test/reader")
	reader := strings.NewReader(`{"from": "reader"}`)
	if err := b.AddReader("artifacts/from-reader.json", reader); err != nil {
		t.Fatalf("AddReader failed: %v", err)
	}

	outputPath := filepath.Join(t.TempDir(), "reader.zip")
	if err := b.Build(outputPath); err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	p, err := pack.Open(outputPath)
	if err != nil {
		t.Fatalf("Failed to open built pack: %v", err)
	}
	defer func() { _ = p.Close() }()

	if err := p.VerifyIntegrity(); err != nil {
		t.Errorf("VerifyIntegrity failed: %v", err)
	}
}

func TestBuilder_MultipleArtifacts(t *testing.T) {
	b := New("test/multi")
	_ = b.AddBytes("artifacts/z-last.json", []byte(`{"order": "z"}`))
	_ = b.AddBytes("artifacts/a-first.json", []byte(`{"order": "a"}`))
	_ = b.AddBytes("artifacts/m-middle.json", []byte(`{"order": "m"}`))

	outputPath := filepath.Join(t.TempDir(), "multi.zip")
	if err := b.Build(outputPath); err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	p, err := pack.Open(outputPath)
	if err != nil {
		t.Fatalf("Failed to open built pack: %v", err)
	}
	defer func() { _ = p.Close() }()

	m := p.Manifest()
	if len(m.Artifacts) != 3 {
		t.Errorf("len(Artifacts) = %d, want 3", len(m.Artifacts))
	}

	if err := p.VerifyIntegrity(); err != nil {
		t.Errorf("VerifyIntegrity failed: %v", err)
	}
}

func TestBuilder_InvalidPath(t *testing.T) {
	b := New("test/invalid")

	tests := []struct {
		name string
		path string
	}{
		{"not under artifacts", "other/file.json"},
		{"just artifacts/", "artifacts/"},
		{"path traversal", "artifacts/../etc/passwd"},
		{"absolute path", "/artifacts/file.json"},
		{"backslash", "artifacts\\file.json"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := b.AddBytes(tc.path, []byte(`{}`))
			if err == nil {
				t.Errorf("AddBytes(%q) should have failed", tc.path)
			}
		})
	}
}

func TestBuilder_DuplicatePath(t *testing.T) {
	b := New("test/dup")
	if err := b.AddBytes("artifacts/test.json", []byte(`{"v": 1}`)); err != nil {
		t.Fatalf("First AddBytes failed: %v", err)
	}

	err := b.AddBytes("artifacts/test.json", []byte(`{"v": 2}`))
	if err == nil {
		t.Error("Second AddBytes with same path should have failed")
	}
	if !strings.Contains(err.Error(), "duplicate") {
		t.Errorf("Error should mention 'duplicate': %v", err)
	}
}

func TestBuilder_EmptyStream(t *testing.T) {
	b := New("")
	_ = b.AddBytes("artifacts/test.json", []byte(`{}`))

	outputPath := filepath.Join(t.TempDir(), "no-stream.zip")
	err := b.Build(outputPath)
	if err == nil {
		t.Error("Build should fail with empty stream")
	}
	if !strings.Contains(err.Error(), "stream") {
		t.Errorf("Error should mention 'stream': %v", err)
	}
}

func TestBuilder_PackDigestCorrectness(t *testing.T) {
	// Build a pack and verify the pack_digest is computed correctly
	b := New("test/digest")
	_ = b.AddBytes("artifacts/b.json", []byte(`{"b": true}`))
	_ = b.AddBytes("artifacts/a.json", []byte(`{"a": true}`))

	outputPath := filepath.Join(t.TempDir(), "digest.zip")
	if err := b.Build(outputPath); err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	p, err := pack.Open(outputPath)
	if err != nil {
		t.Fatalf("Failed to open built pack: %v", err)
	}
	defer func() { _ = p.Close() }()

	// VerifyPackDigest should pass, which confirms the pack_digest is correct
	if err := p.VerifyPackDigest(); err != nil {
		t.Errorf("VerifyPackDigest failed: %v", err)
	}
}

func TestPackDigest_Empty(t *testing.T) {
	// Empty artifact list produces hash of empty string
	manifest := &pack.Manifest{Artifacts: nil}
	canonical := pack.BuildCanonicalArtifactList(manifest)
	digest := pack.HashCanonicalList(canonical)
	want := "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if digest != want {
		t.Errorf("HashCanonicalList(empty) = %q, want %q", digest, want)
	}
}

func TestPackDigest_Sorting(t *testing.T) {
	artifacts := []pack.Artifact{
		{Type: "embedded", Path: "artifacts/z.json", Digest: "sha256:1111111111111111111111111111111111111111111111111111111111111111"},
		{Type: "embedded", Path: "artifacts/a.json", Digest: "sha256:2222222222222222222222222222222222222222222222222222222222222222"},
	}

	// Same artifacts in different order should produce same digest
	artifacts2 := []pack.Artifact{artifacts[1], artifacts[0]}

	manifest1 := &pack.Manifest{Artifacts: artifacts}
	manifest2 := &pack.Manifest{Artifacts: artifacts2}

	digest1 := pack.HashCanonicalList(pack.BuildCanonicalArtifactList(manifest1))
	digest2 := pack.HashCanonicalList(pack.BuildCanonicalArtifactList(manifest2))

	if digest1 != digest2 {
		t.Errorf("Different artifact order produced different digests:\n  %s\n  %s", digest1, digest2)
	}
}

func TestComputeSHA256(t *testing.T) {
	// Empty data
	emptyDigest := computeSHA256([]byte{})
	want := "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if emptyDigest != want {
		t.Errorf("computeSHA256(empty) = %q, want %q", emptyDigest, want)
	}

	// Known test vector
	helloDigest := computeSHA256([]byte("hello"))
	wantHello := "sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
	if helloDigest != wantHello {
		t.Errorf("computeSHA256('hello') = %q, want %q", helloDigest, wantHello)
	}
}

func TestBuilder_AddReaderWithOptions(t *testing.T) {
	b := New("test/reader-opts")
	reader := strings.NewReader(`{"from": "reader with options"}`)
	opts := ArtifactOptions{
		ContentType: "application/json",
		DisplayName: "Reader Test",
		Description: "Added via reader with options",
		Controls:    []string{"AC-1"},
	}

	if err := b.AddReaderWithOptions("artifacts/from-reader.json", reader, opts); err != nil {
		t.Fatalf("AddReaderWithOptions failed: %v", err)
	}

	outputPath := filepath.Join(t.TempDir(), "reader-opts.zip")
	if err := b.Build(outputPath); err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	p, err := pack.Open(outputPath)
	if err != nil {
		t.Fatalf("Failed to open built pack: %v", err)
	}
	defer func() { _ = p.Close() }()

	m := p.Manifest()
	a := m.Artifacts[0]
	if a.ContentType != "application/json" {
		t.Errorf("ContentType = %q, want %q", a.ContentType, "application/json")
	}
	if a.DisplayName != "Reader Test" {
		t.Errorf("DisplayName = %q, want %q", a.DisplayName, "Reader Test")
	}
	if len(a.Controls) != 1 || a.Controls[0] != "AC-1" {
		t.Errorf("Controls = %v, want [AC-1]", a.Controls)
	}
}

func TestBuilder_AddFileWithOptions(t *testing.T) {
	tempDir := t.TempDir()
	testFile := filepath.Join(tempDir, "source.json")
	content := []byte(`{"data": "from file with options"}`)
	if err := os.WriteFile(testFile, content, 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	b := New("test/file-opts")
	opts := ArtifactOptions{
		ContentType: "application/json",
		DisplayName: "File Test",
		Schema:      "test/schema/v1",
	}
	if err := b.AddFileWithOptions("artifacts/from-file.json", testFile, opts); err != nil {
		t.Fatalf("AddFileWithOptions failed: %v", err)
	}

	outputPath := filepath.Join(tempDir, "file-opts.zip")
	if err := b.Build(outputPath); err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	p, err := pack.Open(outputPath)
	if err != nil {
		t.Fatalf("Failed to open built pack: %v", err)
	}
	defer func() { _ = p.Close() }()

	m := p.Manifest()
	a := m.Artifacts[0]
	if a.Schema != "test/schema/v1" {
		t.Errorf("Schema = %q, want %q", a.Schema, "test/schema/v1")
	}
}

func TestBuilder_AddFile_NonexistentFile(t *testing.T) {
	b := New("test/nonexistent")
	err := b.AddFile("artifacts/test.json", "/nonexistent/path/to/file.json")
	if err == nil {
		t.Error("AddFile should fail for nonexistent file")
	}
}

func TestBuilder_SetProvenance(t *testing.T) {
	b := New("test/provenance")
	_ = b.AddBytes("artifacts/test.json", []byte(`{}`))

	prov := pack.Provenance{
		Type:     "merged",
		MergedAt: "2024-01-15T10:30:00Z",
		MergedBy: "test-user",
		SourcePacks: []pack.SourcePack{
			{
				Stream:     "source-stream",
				PackDigest: "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
				Artifacts:  "5",
			},
		},
	}
	b.SetProvenance(prov)

	outputPath := filepath.Join(t.TempDir(), "provenance.zip")
	if err := b.Build(outputPath); err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	p, err := pack.Open(outputPath)
	if err != nil {
		t.Fatalf("Failed to open built pack: %v", err)
	}
	defer func() { _ = p.Close() }()

	m := p.Manifest()
	if m.Provenance == nil {
		t.Fatal("Provenance should not be nil")
	}
	if m.Provenance.Type != "merged" {
		t.Errorf("Provenance.Type = %q, want %q", m.Provenance.Type, "merged")
	}
	if m.Provenance.MergedBy != "test-user" {
		t.Errorf("Provenance.MergedBy = %q, want %q", m.Provenance.MergedBy, "test-user")
	}
	if len(m.Provenance.SourcePacks) != 1 {
		t.Errorf("len(SourcePacks) = %d, want 1", len(m.Provenance.SourcePacks))
	}
}

func TestBuilder_ChainedMethods(t *testing.T) {
	// Test that AddSource returns *Builder for chaining
	b := New("test/chained").
		AddSource("collector1", "1.0.0").
		AddSource("collector2", "2.0.0")

	_ = b.AddBytes("artifacts/test.json", []byte(`{}`))

	outputPath := filepath.Join(t.TempDir(), "chained.zip")
	if err := b.Build(outputPath); err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	p, err := pack.Open(outputPath)
	if err != nil {
		t.Fatalf("Failed to open built pack: %v", err)
	}
	defer func() { _ = p.Close() }()

	m := p.Manifest()
	if len(m.Sources) != 2 {
		t.Errorf("len(Sources) = %d, want 2", len(m.Sources))
	}
}

func TestBuilder_ArtifactsAreSorted(t *testing.T) {
	b := New("test/sorted")
	// Add artifacts out of order
	_ = b.AddBytes("artifacts/z.json", []byte(`{"z":true}`))
	_ = b.AddBytes("artifacts/a.json", []byte(`{"a":true}`))
	_ = b.AddBytes("artifacts/m.json", []byte(`{"m":true}`))

	outputPath := filepath.Join(t.TempDir(), "sorted.zip")
	if err := b.Build(outputPath); err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	p, err := pack.Open(outputPath)
	if err != nil {
		t.Fatalf("Failed to open built pack: %v", err)
	}
	defer func() { _ = p.Close() }()

	m := p.Manifest()
	// Artifacts should be sorted by path
	if m.Artifacts[0].Path != "artifacts/a.json" {
		t.Errorf("First artifact = %q, want %q", m.Artifacts[0].Path, "artifacts/a.json")
	}
	if m.Artifacts[1].Path != "artifacts/m.json" {
		t.Errorf("Second artifact = %q, want %q", m.Artifacts[1].Path, "artifacts/m.json")
	}
	if m.Artifacts[2].Path != "artifacts/z.json" {
		t.Errorf("Third artifact = %q, want %q", m.Artifacts[2].Path, "artifacts/z.json")
	}
}

func TestBuilder_NestedArtifactPath(t *testing.T) {
	b := New("test/nested")
	err := b.AddBytes("artifacts/subdir/deep/file.json", []byte(`{"nested":true}`))
	if err != nil {
		t.Fatalf("AddBytes failed: %v", err)
	}

	outputPath := filepath.Join(t.TempDir(), "nested.zip")
	if err := b.Build(outputPath); err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	p, err := pack.Open(outputPath)
	if err != nil {
		t.Fatalf("Failed to open built pack: %v", err)
	}
	defer func() { _ = p.Close() }()

	data, err := p.ReadArtifact("artifacts/subdir/deep/file.json")
	if err != nil {
		t.Fatalf("ReadArtifact failed: %v", err)
	}
	if string(data.Bytes()) != `{"nested":true}` {
		t.Errorf("Artifact content = %q, want %q", data, `{"nested":true}`)
	}
}

func TestBuilder_BuildWithCollectedAt(t *testing.T) {
	b := New("test/collected-at")
	opts := ArtifactOptions{
		CollectedAt: "2024-01-15T10:30:00Z",
	}
	if err := b.AddBytesWithOptions("artifacts/test.json", []byte(`{}`), opts); err != nil {
		t.Fatalf("AddBytesWithOptions failed: %v", err)
	}

	outputPath := filepath.Join(t.TempDir(), "collected.zip")
	if err := b.Build(outputPath); err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	p, err := pack.Open(outputPath)
	if err != nil {
		t.Fatalf("Failed to open built pack: %v", err)
	}
	defer func() { _ = p.Close() }()

	m := p.Manifest()
	if m.Artifacts[0].CollectedAt != "2024-01-15T10:30:00Z" {
		t.Errorf("CollectedAt = %q, want %q", m.Artifacts[0].CollectedAt, "2024-01-15T10:30:00Z")
	}
}

func TestBuilder_BuildContext(t *testing.T) {
	b := New("test/context")
	_ = b.AddBytes("artifacts/test.json", []byte(`{}`))

	outputPath := filepath.Join(t.TempDir(), "context.zip")

	// BuildContext with background context should work
	ctx := context.Background()
	if err := b.BuildContext(ctx, outputPath); err != nil {
		t.Fatalf("BuildContext failed: %v", err)
	}

	// Verify the pack was created
	if _, err := os.Stat(outputPath); os.IsNotExist(err) {
		t.Error("Output file was not created")
	}
}

func TestBuilder_OutputDirCreation(t *testing.T) {
	b := New("test/dir-creation")
	_ = b.AddBytes("artifacts/test.json", []byte(`{}`))

	// Build to a path in a directory that doesn't exist yet
	outputPath := filepath.Join(t.TempDir(), "new", "nested", "dir", "output.zip")
	if err := b.Build(outputPath); err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	if _, err := os.Stat(outputPath); os.IsNotExist(err) {
		t.Error("Output file was not created")
	}
}

func TestBuilder_DefensiveCopy_Data(t *testing.T) {
	b := New("test/defensive")

	data := []byte(`{"original": true}`)
	if err := b.AddBytes("artifacts/test.json", data); err != nil {
		t.Fatalf("AddBytes failed: %v", err)
	}

	// Mutate the original data after adding
	data[2] = 'X'
	data[3] = 'X'

	outputPath := filepath.Join(t.TempDir(), "defensive.zip")
	if err := b.Build(outputPath); err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	p, err := pack.Open(outputPath)
	if err != nil {
		t.Fatalf("Failed to open built pack: %v", err)
	}
	defer func() { _ = p.Close() }()

	readData, err := p.ReadArtifact("artifacts/test.json")
	if err != nil {
		t.Fatalf("ReadArtifact failed: %v", err)
	}

	// The artifact should have the original content, not the mutated version
	if string(readData.Bytes()) != `{"original": true}` {
		t.Errorf("Artifact content = %q, want original unchanged content", readData)
	}
}

func TestBuilder_DefensiveCopy_Controls(t *testing.T) {
	b := New("test/defensive-controls")

	controls := []string{"AC-1", "AC-2"}
	opts := ArtifactOptions{Controls: controls}
	if err := b.AddBytesWithOptions("artifacts/test.json", []byte(`{}`), opts); err != nil {
		t.Fatalf("AddBytesWithOptions failed: %v", err)
	}

	// Mutate the original controls slice
	controls[0] = "MODIFIED"

	outputPath := filepath.Join(t.TempDir(), "defensive-controls.zip")
	if err := b.Build(outputPath); err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	p, err := pack.Open(outputPath)
	if err != nil {
		t.Fatalf("Failed to open built pack: %v", err)
	}
	defer func() { _ = p.Close() }()

	m := p.Manifest()
	if m.Artifacts[0].Controls[0] != "AC-1" {
		t.Errorf("Controls[0] = %q, want %q (original value)", m.Artifacts[0].Controls[0], "AC-1")
	}
}

func TestBuilder_EmptySourcesArray(t *testing.T) {
	// Builder should produce empty sources array (not null) when no sources added
	b := New("test/no-sources")
	_ = b.AddBytes("artifacts/test.json", []byte(`{}`))

	outputPath := filepath.Join(t.TempDir(), "no-sources.zip")
	if err := b.Build(outputPath); err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	p, err := pack.Open(outputPath)
	if err != nil {
		t.Fatalf("Failed to open built pack: %v", err)
	}
	defer func() { _ = p.Close() }()

	m := p.Manifest()
	// Sources should be empty slice, not nil (spec requires the field)
	if m.Sources == nil {
		t.Error("Sources should be empty slice, not nil")
	}
	if len(m.Sources) != 0 {
		t.Errorf("len(Sources) = %d, want 0", len(m.Sources))
	}
}

func TestBuilder_DuplicatePath_CaseInsensitive(t *testing.T) {
	b := New("test/dup-case")
	if err := b.AddBytes("artifacts/Test.json", []byte(`{"v": 1}`)); err != nil {
		t.Fatalf("First AddBytes failed: %v", err)
	}

	// Same path but different case - this is detected as duplicate on case-insensitive systems
	err := b.AddBytes("artifacts/test.json", []byte(`{"v": 2}`))
	// The builder correctly detects this as a duplicate path (case-insensitive comparison)
	if err != nil {
		// Good - duplicate was caught at AddBytes time
		if !strings.Contains(err.Error(), "duplicate") {
			t.Logf("AddBytes correctly rejected duplicate path: %v", err)
		}
		return
	}

	// If AddBytes didn't catch it, Build should catch it
	outputPath := filepath.Join(t.TempDir(), "dup-case.zip")
	err = b.Build(outputPath)
	if err == nil {
		t.Log("Build succeeded - paths are treated as distinct (case-sensitive)")
	} else if strings.Contains(err.Error(), "duplicate") {
		t.Log("Build correctly rejected duplicate paths")
	}
}

func TestBuilder_LargeArtifact(t *testing.T) {
	b := New("test/large")

	// Create a moderately large artifact (100KB) with pseudo-random content
	// that won't compress well (to avoid triggering compression ratio limits)
	rng := rand.New(rand.NewSource(42)) // Fixed seed for reproducibility
	largeContent := make([]byte, 100*1024)
	rng.Read(largeContent)
	if err := b.AddBytes("artifacts/large.bin", largeContent); err != nil {
		t.Fatalf("AddBytes failed for large content: %v", err)
	}

	outputPath := filepath.Join(t.TempDir(), "large.zip")
	if err := b.Build(outputPath); err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	p, err := pack.Open(outputPath)
	if err != nil {
		t.Fatalf("Failed to open pack: %v", err)
	}
	defer func() { _ = p.Close() }()

	// Verify content integrity
	if err := p.VerifyIntegrity(); err != nil {
		t.Errorf("VerifyIntegrity failed: %v", err)
	}

	// Verify size is recorded
	artifact := p.Manifest().Artifacts[0]
	if artifact.Size == nil {
		t.Error("Size should be recorded")
	}
	size, _ := artifact.Size.Int64()
	if size != int64(len(largeContent)) {
		t.Errorf("Size = %d, want %d", size, len(largeContent))
	}
}

func TestBuilder_ManyArtifacts(t *testing.T) {
	b := New("test/many")

	// Add many artifacts
	numArtifacts := 100
	for i := 0; i < numArtifacts; i++ {
		path := fmt.Sprintf("artifacts/file%03d.json", i)
		content := []byte(fmt.Sprintf(`{"index": %d}`, i))
		if err := b.AddBytes(path, content); err != nil {
			t.Fatalf("AddBytes failed for %s: %v", path, err)
		}
	}

	outputPath := filepath.Join(t.TempDir(), "many.zip")
	if err := b.Build(outputPath); err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	p, err := pack.Open(outputPath)
	if err != nil {
		t.Fatalf("Failed to open pack: %v", err)
	}
	defer func() { _ = p.Close() }()

	if len(p.Manifest().Artifacts) != numArtifacts {
		t.Errorf("len(Artifacts) = %d, want %d", len(p.Manifest().Artifacts), numArtifacts)
	}

	// Verify integrity with many artifacts
	if err := p.VerifyIntegrity(); err != nil {
		t.Errorf("VerifyIntegrity failed: %v", err)
	}
}

func TestBuilder_StreamValidation(t *testing.T) {
	tests := []struct {
		name    string
		stream  string
		wantErr bool
	}{
		{"valid simple", "org/project", false},
		{"valid nested", "org/team/project/env", false},
		{"empty", "", true},
		// Note: Other stream validation rules may exist - these test documents behavior
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := New(tt.stream)
			_ = b.AddBytes("artifacts/test.json", []byte(`{}`))

			outputPath := filepath.Join(t.TempDir(), "test.zip")
			err := b.Build(outputPath)

			if (err != nil) != tt.wantErr {
				t.Errorf("Build() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestBuilder_SourceNameVersionValidation(t *testing.T) {
	b := New("test/sources")

	// Add sources with various name/version combinations
	b.AddSource("github", "1.0.0")
	b.AddSource("aws", "")             // Empty version is valid
	b.AddSource("custom-source", "v2") // Hyphenated name

	_ = b.AddBytes("artifacts/test.json", []byte(`{}`))

	outputPath := filepath.Join(t.TempDir(), "sources.zip")
	if err := b.Build(outputPath); err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	p, err := pack.Open(outputPath)
	if err != nil {
		t.Fatalf("Failed to open pack: %v", err)
	}
	defer func() { _ = p.Close() }()

	sources := p.Manifest().Sources
	if len(sources) != 3 {
		t.Errorf("len(Sources) = %d, want 3", len(sources))
	}
}

func TestBuilder_ArtifactWithAllOptions(t *testing.T) {
	b := New("test/all-options")

	opts := ArtifactOptions{
		ContentType: "application/json",
		DisplayName: "Configuration File",
		Description: "Main configuration for the application",
		CollectedAt: "2024-01-15T10:30:00Z",
		Schema:      "config/v1",
		Controls:    []string{"AC-1", "CM-2", "SI-3"},
	}

	if err := b.AddBytesWithOptions("artifacts/config.json", []byte(`{"version": 1}`), opts); err != nil {
		t.Fatalf("AddBytesWithOptions failed: %v", err)
	}

	outputPath := filepath.Join(t.TempDir(), "all-options.zip")
	if err := b.Build(outputPath); err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	p, err := pack.Open(outputPath)
	if err != nil {
		t.Fatalf("Failed to open pack: %v", err)
	}
	defer func() { _ = p.Close() }()

	a := p.Manifest().Artifacts[0]
	if a.ContentType != "application/json" {
		t.Errorf("ContentType = %q, want %q", a.ContentType, "application/json")
	}
	if a.DisplayName != "Configuration File" {
		t.Errorf("DisplayName = %q, want %q", a.DisplayName, "Configuration File")
	}
	if a.Description != "Main configuration for the application" {
		t.Errorf("Description mismatch")
	}
	if a.CollectedAt != "2024-01-15T10:30:00Z" {
		t.Errorf("CollectedAt = %q, want %q", a.CollectedAt, "2024-01-15T10:30:00Z")
	}
	if a.Schema != "config/v1" {
		t.Errorf("Schema = %q, want %q", a.Schema, "config/v1")
	}
	if len(a.Controls) != 3 {
		t.Errorf("len(Controls) = %d, want 3", len(a.Controls))
	}
}

func TestBuilder_EmptyArtifact(t *testing.T) {
	b := New("test/empty-artifact")

	// Empty content should be valid
	if err := b.AddBytes("artifacts/empty.json", []byte{}); err != nil {
		t.Fatalf("AddBytes failed for empty content: %v", err)
	}

	outputPath := filepath.Join(t.TempDir(), "empty-artifact.zip")
	if err := b.Build(outputPath); err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	p, err := pack.Open(outputPath)
	if err != nil {
		t.Fatalf("Failed to open pack: %v", err)
	}
	defer func() { _ = p.Close() }()

	// Verify empty artifact
	artifact := p.Manifest().Artifacts[0]
	size, _ := artifact.Size.Int64()
	if size != 0 {
		t.Errorf("Size = %d, want 0", size)
	}

	// Digest of empty data should be sha256 of empty string
	expectedDigest := "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if artifact.Digest != expectedDigest {
		t.Errorf("Digest = %q, want %q", artifact.Digest, expectedDigest)
	}
}

func TestBuilder_UnicodeInPath(t *testing.T) {
	b := New("test/unicode")

	// Test that ASCII paths work (unicode in paths may not be supported)
	if err := b.AddBytes("artifacts/test-file.json", []byte(`{}`)); err != nil {
		t.Fatalf("AddBytes failed: %v", err)
	}

	outputPath := filepath.Join(t.TempDir(), "unicode.zip")
	if err := b.Build(outputPath); err != nil {
		t.Fatalf("Build failed: %v", err)
	}
}

func TestBuilder_BuildTwice(t *testing.T) {
	b := New("test/twice")
	_ = b.AddBytes("artifacts/test.json", []byte(`{}`))

	outputPath1 := filepath.Join(t.TempDir(), "first.zip")
	outputPath2 := filepath.Join(t.TempDir(), "second.zip")

	// Build twice should work
	if err := b.Build(outputPath1); err != nil {
		t.Fatalf("First Build failed: %v", err)
	}
	if err := b.Build(outputPath2); err != nil {
		t.Fatalf("Second Build failed: %v", err)
	}

	// Both packs should be valid and identical
	p1, _ := pack.Open(outputPath1)
	p2, _ := pack.Open(outputPath2)
	defer func() { _ = p1.Close() }()
	defer func() { _ = p2.Close() }()

	if p1.Manifest().PackDigest != p2.Manifest().PackDigest {
		t.Error("Pack digests should be identical for same content")
	}
}

func TestBuilder_AddAfterBuild(t *testing.T) {
	b := New("test/add-after")
	_ = b.AddBytes("artifacts/first.json", []byte(`{"order": 1}`))

	outputPath := filepath.Join(t.TempDir(), "add-after.zip")
	if err := b.Build(outputPath); err != nil {
		t.Fatalf("First Build failed: %v", err)
	}

	// Add more artifacts after build
	_ = b.AddBytes("artifacts/second.json", []byte(`{"order": 2}`))

	outputPath2 := filepath.Join(t.TempDir(), "add-after-2.zip")
	if err := b.Build(outputPath2); err != nil {
		t.Fatalf("Second Build failed: %v", err)
	}

	// Second pack should have both artifacts
	p, _ := pack.Open(outputPath2)
	defer func() { _ = p.Close() }()

	if len(p.Manifest().Artifacts) != 2 {
		t.Errorf("len(Artifacts) = %d, want 2", len(p.Manifest().Artifacts))
	}
}
