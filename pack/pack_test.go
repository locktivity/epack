package pack

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/locktivity/epack/errors"
)

// testHelper provides utilities for creating test zip archives.
type testHelper struct {
	t *testing.T
}

func newTestHelper(t *testing.T) *testHelper {
	return &testHelper{t: t}
}

// createZip creates a zip file with the given files and returns its path.
// The file is automatically cleaned up when the test ends via t.TempDir().
func (h *testHelper) createZip(files map[string][]byte) string {
	h.t.Helper()

	var buf bytes.Buffer
	w := zip.NewWriter(&buf)

	// Add files in sorted order for determinism
	for name, content := range files {
		fw, err := w.Create(name)
		if err != nil {
			h.t.Fatalf("failed to create file %s in zip: %v", name, err)
		}
		if _, err := fw.Write(content); err != nil {
			h.t.Fatalf("failed to write file %s to zip: %v", name, err)
		}
	}

	if err := w.Close(); err != nil {
		h.t.Fatalf("failed to close zip writer: %v", err)
	}

	dir := h.t.TempDir()
	path := filepath.Join(dir, "test.zip")
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		h.t.Fatalf("failed to write zip file: %v", err)
	}

	return path
}

// validManifest returns a valid manifest JSON with the given artifacts.
func validManifest(artifacts ...Artifact) []byte {
	m := Manifest{
		SpecVersion: "1.0",
		Stream:      "test-stream",
		GeneratedAt: "2024-01-15T10:30:00Z",
		PackDigest:  "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
		Sources:     []Source{{Name: "test-source", Version: "1.0.0"}},
		Artifacts:   artifacts,
	}
	data, _ := json.Marshal(m)
	return data
}

// validArtifact creates a valid embedded artifact.
func validArtifact(path string) Artifact {
	size := json.Number("100")
	return Artifact{
		Type:   "embedded",
		Path:   path,
		Digest: "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
		Size:   &size,
	}
}

func TestOpen_ValidPack(t *testing.T) {
	h := newTestHelper(t)

	artifact := validArtifact("artifacts/test.json")
	files := map[string][]byte{
		"manifest.json":       validManifest(artifact),
		"artifacts/test.json": []byte(`{"data": "test"}`),
	}

	path := h.createZip(files)
	pack, err := Open(path)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer func() { _ = pack.reader.Close() }()

	if pack.manifest == nil {
		t.Fatal("Open() returned nil manifest")
	}
	if pack.manifest.Stream != "test-stream" {
		t.Errorf("manifest.Stream = %q, want %q", pack.manifest.Stream, "test-stream")
	}
	if len(pack.manifest.Artifacts) != 1 {
		t.Errorf("len(manifest.Artifacts) = %d, want 1", len(pack.manifest.Artifacts))
	}
}

func TestOpen_ValidPackWithAttestation(t *testing.T) {
	h := newTestHelper(t)

	artifact := validArtifact("artifacts/test.json")
	files := map[string][]byte{
		"manifest.json":                   validManifest(artifact),
		"artifacts/test.json":             []byte(`{"data": "test"}`),
		"attestations/main.sigstore.json": []byte(`{"attestation": "data"}`),
	}

	path := h.createZip(files)
	pack, err := Open(path)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer func() { _ = pack.reader.Close() }()

	if pack.manifest == nil {
		t.Fatal("Open() returned nil manifest")
	}
}

func TestOpen_EmptyArtifacts(t *testing.T) {
	// Create manifest with empty artifacts array explicitly
	m := Manifest{
		SpecVersion: "1.0",
		Stream:      "test-stream",
		GeneratedAt: "2024-01-15T10:30:00Z",
		PackDigest:  "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
		Sources:     []Source{{Name: "test-source", Version: "1.0.0"}},
		Artifacts:   []Artifact{}, // Empty but non-nil
	}
	manifestData, _ := json.Marshal(m)

	// Create zip with directory entry (not a file)
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)

	// Add manifest
	fw, _ := w.Create("manifest.json")
	_, _ = fw.Write(manifestData)

	// Add artifacts/ as a directory entry (trailing slash)
	_, _ = w.Create("artifacts/")

	_ = w.Close()

	dir := t.TempDir()
	path := filepath.Join(dir, "empty-artifacts.zip")
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatalf("failed to write zip file: %v", err)
	}

	pack, err := Open(path)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer func() { _ = pack.reader.Close() }()

	if len(pack.manifest.Artifacts) != 0 {
		t.Errorf("len(Manifest.Artifacts) = %d, want 0", len(pack.manifest.Artifacts))
	}
}

func TestOpen_FileNotFound(t *testing.T) {
	_, err := Open("/nonexistent/path/to/pack.zip")
	if err == nil {
		t.Fatal("Open() expected error for nonexistent file")
	}
}

func TestOpen_InvalidZip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "invalid.zip")
	if err := os.WriteFile(path, []byte("not a zip file"), 0o600); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}

	_, err := Open(path)
	if err == nil {
		t.Fatal("Open() expected error for invalid zip")
	}
}

func TestOpen_MissingManifest(t *testing.T) {
	h := newTestHelper(t)

	files := map[string][]byte{
		"artifacts/test.json": []byte(`{"data": "test"}`),
	}

	path := h.createZip(files)
	_, err := Open(path)

	if err == nil {
		t.Fatal("Open() expected error for missing manifest")
	}
	if errors.CodeOf(err) != errors.MissingRequiredField {
		t.Errorf("error code = %q, want %q", errors.CodeOf(err), errors.MissingRequiredField)
	}
}

func TestOpen_MissingArtifactsDirectory(t *testing.T) {
	h := newTestHelper(t)

	files := map[string][]byte{
		"manifest.json": validManifest(),
	}

	path := h.createZip(files)
	_, err := Open(path)

	if err == nil {
		t.Fatal("Open() expected error for missing artifacts directory")
	}
	if errors.CodeOf(err) != errors.MissingRequiredField {
		t.Errorf("error code = %q, want %q", errors.CodeOf(err), errors.MissingRequiredField)
	}
}

func TestOpen_InvalidManifestJSON(t *testing.T) {
	h := newTestHelper(t)

	files := map[string][]byte{
		"manifest.json":   []byte(`{invalid json}`),
		"artifacts/.keep": []byte{},
	}

	path := h.createZip(files)
	_, err := Open(path)

	if err == nil {
		t.Fatal("Open() expected error for invalid manifest JSON")
	}
}

func TestOpen_DuplicatePath(t *testing.T) {
	// Create zip with duplicate entries manually
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)

	// Add first file
	fw, _ := w.Create("artifacts/test.json")
	_, _ = fw.Write([]byte(`{"data": 1}`))

	// Add duplicate
	fw, _ = w.Create("artifacts/test.json")
	_, _ = fw.Write([]byte(`{"data": 2}`))

	_ = w.Close()

	dir := t.TempDir()
	path := filepath.Join(dir, "dup.zip")
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatalf("failed to write zip file: %v", err)
	}

	_, err := Open(path)
	if err == nil {
		t.Fatal("Open() expected error for duplicate path")
	}
	if errors.CodeOf(err) != errors.DuplicatePath {
		t.Errorf("error code = %q, want %q", errors.CodeOf(err), errors.DuplicatePath)
	}
}

func TestOpen_PathTraversal(t *testing.T) {
	tests := []struct {
		name string
		path string
	}{
		{"dot dot in path", "artifacts/../etc/passwd"},
		{"leading slash", "/artifacts/test.json"},
		{"dot dot only", "../test.json"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			w := zip.NewWriter(&buf)
			fw, _ := w.Create(tt.path)
			_, _ = fw.Write([]byte(`{}`))
			_ = w.Close()

			dir := t.TempDir()
			path := filepath.Join(dir, "traversal.zip")
			if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
				t.Fatalf("failed to write zip file: %v", err)
			}

			_, err := Open(path)
			if err == nil {
				t.Fatalf("Open() expected error for path %q", tt.path)
			}
			if errors.CodeOf(err) != errors.InvalidPath {
				t.Errorf("error code = %q, want %q", errors.CodeOf(err), errors.InvalidPath)
			}
		})
	}
}

func TestOpen_UnexpectedTopLevelEntry(t *testing.T) {
	h := newTestHelper(t)

	artifact := validArtifact("artifacts/test.json")
	files := map[string][]byte{
		"manifest.json":       validManifest(artifact),
		"artifacts/test.json": []byte(`{"data": "test"}`),
		"extra.txt":           []byte("unexpected file"),
	}

	path := h.createZip(files)
	_, err := Open(path)

	if err == nil {
		t.Fatal("Open() expected error for unexpected top-level entry")
	}
	if errors.CodeOf(err) != errors.InvalidPath {
		t.Errorf("error code = %q, want %q", errors.CodeOf(err), errors.InvalidPath)
	}
}

func TestOpen_InvalidAttestationPath(t *testing.T) {
	tests := []struct {
		name string
		path string
	}{
		{"nested attestation", "attestations/subdir/test.sigstore.json"},
		{"wrong extension", "attestations/test.json"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newTestHelper(t)

			artifact := validArtifact("artifacts/test.json")
			files := map[string][]byte{
				"manifest.json":       validManifest(artifact),
				"artifacts/test.json": []byte(`{}`),
				tt.path:               []byte(`{}`),
			}

			path := h.createZip(files)
			_, err := Open(path)

			if err == nil {
				t.Fatalf("Open() expected error for attestation path %q", tt.path)
			}
			if errors.CodeOf(err) != errors.InvalidPath {
				t.Errorf("error code = %q, want %q", errors.CodeOf(err), errors.InvalidPath)
			}
		})
	}
}

func TestOpen_ArtifactInManifestNotInZip(t *testing.T) {
	h := newTestHelper(t)

	artifact := validArtifact("artifacts/missing.json")
	files := map[string][]byte{
		"manifest.json":   validManifest(artifact),
		"artifacts/.keep": []byte{},
	}

	path := h.createZip(files)
	_, err := Open(path)

	if err == nil {
		t.Fatal("Open() expected error for artifact in manifest not in zip")
	}
	if errors.CodeOf(err) != errors.MissingEntry {
		t.Errorf("error code = %q, want %q", errors.CodeOf(err), errors.MissingEntry)
	}
}

func TestOpen_ArtifactInZipNotInManifest(t *testing.T) {
	h := newTestHelper(t)

	// Create manifest with empty artifacts array explicitly
	m := Manifest{
		SpecVersion: "1.0",
		Stream:      "test-stream",
		GeneratedAt: "2024-01-15T10:30:00Z",
		PackDigest:  "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
		Sources:     []Source{{Name: "test-source", Version: "1.0.0"}},
		Artifacts:   []Artifact{}, // Empty but non-nil
	}
	manifestData, _ := json.Marshal(m)

	files := map[string][]byte{
		"manifest.json":        manifestData,
		"artifacts/extra.json": []byte(`{}`), // This artifact is not in manifest
	}

	path := h.createZip(files)
	_, err := Open(path)

	if err == nil {
		t.Fatal("Open() expected error for artifact in zip not in manifest")
	}
	if errors.CodeOf(err) != errors.InvalidPath {
		t.Errorf("error code = %q, want %q", errors.CodeOf(err), errors.InvalidPath)
	}
}

func TestOpen_MultipleArtifacts(t *testing.T) {
	h := newTestHelper(t)

	artifacts := []Artifact{
		validArtifact("artifacts/one.json"),
		validArtifact("artifacts/two.json"),
		validArtifact("artifacts/three.json"),
	}

	files := map[string][]byte{
		"manifest.json":        validManifest(artifacts...),
		"artifacts/one.json":   []byte(`{"id": 1}`),
		"artifacts/two.json":   []byte(`{"id": 2}`),
		"artifacts/three.json": []byte(`{"id": 3}`),
	}

	path := h.createZip(files)
	pack, err := Open(path)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer func() { _ = pack.reader.Close() }()

	if len(pack.manifest.Artifacts) != 3 {
		t.Errorf("len(manifest.Artifacts) = %d, want 3", len(pack.manifest.Artifacts))
	}
}

func TestOpen_NestedArtifactDirectories(t *testing.T) {
	h := newTestHelper(t)

	artifact := validArtifact("artifacts/subdir/nested/test.json")
	files := map[string][]byte{
		"manifest.json":                     validManifest(artifact),
		"artifacts/subdir/nested/test.json": []byte(`{}`),
	}

	path := h.createZip(files)
	pack, err := Open(path)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer func() { _ = pack.reader.Close() }()
}

func TestValidateArtifactsMatch(t *testing.T) {
	tests := []struct {
		name        string
		indexPaths  []string
		artifacts   []Artifact
		wantErr     errors.Code
		wantContain string
	}{
		{
			name:       "exact match",
			indexPaths: []string{"manifest.json", "artifacts/a.json", "artifacts/b.json"},
			artifacts: []Artifact{
				validArtifact("artifacts/a.json"),
				validArtifact("artifacts/b.json"),
			},
		},
		{
			name:       "missing from zip",
			indexPaths: []string{"manifest.json", "artifacts/a.json"},
			artifacts: []Artifact{
				validArtifact("artifacts/a.json"),
				validArtifact("artifacts/missing.json"),
			},
			wantErr:     errors.MissingEntry,
			wantContain: "artifacts/missing.json",
		},
		{
			name:       "extra in zip",
			indexPaths: []string{"manifest.json", "artifacts/a.json", "artifacts/extra.json"},
			artifacts: []Artifact{
				validArtifact("artifacts/a.json"),
			},
			wantErr:     errors.InvalidPath,
			wantContain: "artifacts/extra.json",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			index := make(map[string]*zip.File)
			for _, p := range tt.indexPaths {
				index[p] = &zip.File{}
			}

			manifest := &Manifest{Artifacts: tt.artifacts}
			err := validateArtifactsMatch(index, manifest)

			if tt.wantErr == "" {
				if err != nil {
					t.Errorf("validateArtifactsMatch() unexpected error = %v", err)
				}
				return
			}

			if err == nil {
				t.Fatal("validateArtifactsMatch() expected error")
			}
			if errors.CodeOf(err) != tt.wantErr {
				t.Errorf("error code = %q, want %q", errors.CodeOf(err), tt.wantErr)
			}
			if !containsSubstring(err.Error(), tt.wantContain) {
				t.Errorf("error message %q does not contain %q", err.Error(), tt.wantContain)
			}
		})
	}
}

func TestReadFileWithLimit(t *testing.T) {
	// Create a test zip with a file
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	fw, _ := w.Create("test.txt")
	_, _ = fw.Write([]byte("hello world"))
	_ = w.Close()

	r, _ := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	file := r.File[0]

	// Test normal read
	content, err := readFileWithLimits(file, 1000, 1000)
	if err != nil {
		t.Fatalf("readFileWithLimits() error = %v", err)
	}
	if string(content) != "hello world" {
		t.Errorf("content = %q, want %q", string(content), "hello world")
	}

	// Test exceeding artifact limit
	_, err = readFileWithLimits(file, 5, 1000)
	if err == nil {
		t.Fatal("readFileWithLimits() expected error for exceeding artifact limit")
	}
	if errors.CodeOf(err) != errors.ArtifactTooLarge {
		t.Errorf("error code = %q, want %q", errors.CodeOf(err), errors.ArtifactTooLarge)
	}

	// Test exceeding pack limit
	_, err = readFileWithLimits(file, 1000, 5)
	if err == nil {
		t.Fatal("readFileWithLimits() expected error for exceeding pack limit")
	}
	if errors.CodeOf(err) != errors.ZipBomb {
		t.Errorf("error code = %q, want %q", errors.CodeOf(err), errors.ZipBomb)
	}
}

func TestIndexZip(t *testing.T) {
	tests := []struct {
		name    string
		files   []string
		wantErr errors.Code
	}{
		{
			name:  "valid files",
			files: []string{"manifest.json", "artifacts/test.json"},
		},
		{
			name:    "path traversal",
			files:   []string{"../outside.txt"},
			wantErr: errors.InvalidPath,
		},
		{
			name:    "absolute path",
			files:   []string{"/etc/passwd"},
			wantErr: errors.InvalidPath,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			w := zip.NewWriter(&buf)
			for _, name := range tt.files {
				fw, _ := w.Create(name)
				_, _ = fw.Write([]byte("content"))
			}
			_ = w.Close()

			r, _ := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
			_, err := indexZip(r)

			if tt.wantErr == "" {
				if err != nil {
					t.Errorf("indexZip() unexpected error = %v", err)
				}
				return
			}

			if err == nil {
				t.Fatal("indexZip() expected error")
			}
			if errors.CodeOf(err) != tt.wantErr {
				t.Errorf("error code = %q, want %q", errors.CodeOf(err), tt.wantErr)
			}
		})
	}
}

func TestValidateStructure(t *testing.T) {
	tests := []struct {
		name    string
		files   []string
		wantErr errors.Code
	}{
		{
			name:  "valid structure",
			files: []string{"manifest.json", "artifacts/test.json"},
		},
		{
			name:  "with attestations",
			files: []string{"manifest.json", "artifacts/test.json", "attestations/main.sigstore.json"},
		},
		{
			name:    "missing artifacts",
			files:   []string{"manifest.json"},
			wantErr: errors.MissingRequiredField,
		},
		{
			name:    "unexpected file",
			files:   []string{"manifest.json", "artifacts/test.json", "readme.txt"},
			wantErr: errors.InvalidPath,
		},
		{
			name:    "nested attestation",
			files:   []string{"manifest.json", "artifacts/test.json", "attestations/sub/test.sigstore.json"},
			wantErr: errors.InvalidPath,
		},
		{
			name:    "wrong attestation extension",
			files:   []string{"manifest.json", "artifacts/test.json", "attestations/test.json"},
			wantErr: errors.InvalidPath,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			w := zip.NewWriter(&buf)
			for _, name := range tt.files {
				fw, _ := w.Create(name)
				_, _ = fw.Write([]byte("content"))
			}
			_ = w.Close()

			r, _ := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))

			err := validateStructure(r)

			if tt.wantErr == "" {
				if err != nil {
					t.Errorf("validateStructure() unexpected error = %v", err)
				}
				return
			}

			if err == nil {
				t.Fatal("validateStructure() expected error")
			}
			if errors.CodeOf(err) != tt.wantErr {
				t.Errorf("error code = %q, want %q", errors.CodeOf(err), tt.wantErr)
			}
		})
	}
}

func TestPack_ReadFile(t *testing.T) {
	h := newTestHelper(t)

	artifact := validArtifact("artifacts/test.json")
	artifactContent := []byte(`{"data": "test content"}`)
	files := map[string][]byte{
		"manifest.json":       validManifest(artifact),
		"artifacts/test.json": artifactContent,
	}

	path := h.createZip(files)
	pack, err := Open(path)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer func() { _ = pack.Close() }()

	// Read valid artifact
	content, err := pack.ReadFileUntrusted("artifacts/test.json")
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if string(content.UnsafeBytes()) != string(artifactContent) {
		t.Errorf("ReadFile() = %q, want %q", string(content.UnsafeBytes()), string(artifactContent))
	}

	// Read non-existent artifact
	_, err = pack.ReadFileUntrusted("artifacts/nonexistent.json")
	if err == nil {
		t.Fatal("ReadFile() expected error for non-existent artifact")
	}
	if errors.CodeOf(err) != errors.MissingEntry {
		t.Errorf("error code = %q, want %q", errors.CodeOf(err), errors.MissingEntry)
	}
}

func TestPack_OpenFile(t *testing.T) {
	h := newTestHelper(t)

	artifact := validArtifact("artifacts/test.json")
	artifactContent := []byte(`{"data": "streaming test content"}`)
	files := map[string][]byte{
		"manifest.json":       validManifest(artifact),
		"artifacts/test.json": artifactContent,
	}

	path := h.createZip(files)
	pack, err := Open(path)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer func() { _ = pack.Close() }()

	// Open valid artifact
	reader, err := pack.OpenFileUntrusted("artifacts/test.json")
	if err != nil {
		t.Fatalf("OpenFile() error = %v", err)
	}

	content, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("ReadAll() error = %v", err)
	}
	_ = reader.Close()

	if string(content) != string(artifactContent) {
		t.Errorf("OpenFile content = %q, want %q", string(content), string(artifactContent))
	}

	// Open non-existent artifact
	_, err = pack.OpenFileUntrusted("artifacts/nonexistent.json")
	if err == nil {
		t.Fatal("OpenFile() expected error for non-existent artifact")
	}
	if errors.CodeOf(err) != errors.MissingEntry {
		t.Errorf("error code = %q, want %q", errors.CodeOf(err), errors.MissingEntry)
	}
}

func TestPack_Close(t *testing.T) {
	h := newTestHelper(t)

	artifact := validArtifact("artifacts/test.json")
	files := map[string][]byte{
		"manifest.json":       validManifest(artifact),
		"artifacts/test.json": []byte(`{}`),
	}

	path := h.createZip(files)
	pack, err := Open(path)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}

	// Close should succeed
	if err := pack.Close(); err != nil {
		t.Errorf("Close() error = %v", err)
	}

	// Double close should also succeed (no-op)
	if err := pack.Close(); err != nil {
		t.Errorf("Close() second call error = %v", err)
	}
}

// Integration test with a real pack structure
func TestOpen_IntegrationValidPack(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "pack-integration-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	zipPath := filepath.Join(tmpDir, "test.pack")
	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatalf("failed to create zip file: %v", err)
	}

	w := zip.NewWriter(f)

	// Add manifest
	size := json.Number("42")
	manifest := Manifest{
		SpecVersion: "1.0",
		Stream:      "integration-test",
		GeneratedAt: "2024-01-15T10:30:00Z",
		PackDigest:  "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
		Sources:     []Source{{Name: "test", Version: "1.0.0"}},
		Artifacts: []Artifact{
			{
				Type:   "embedded",
				Path:   "artifacts/data.json",
				Digest: "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
				Size:   &size,
			},
		},
	}
	manifestData, _ := json.Marshal(manifest)
	fw, _ := w.Create("manifest.json")
	_, _ = fw.Write(manifestData)

	// Add artifact
	fw, _ = w.Create("artifacts/data.json")
	_, _ = fw.Write([]byte(`{"integration": "test"}`))

	// Add attestation
	fw, _ = w.Create("attestations/main.sigstore.json")
	_, _ = fw.Write([]byte(`{"type": "attestation"}`))

	_ = w.Close()
	_ = f.Close()

	// Test opening
	pack, err := Open(zipPath)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer func() { _ = pack.reader.Close() }()

	if pack.manifest.Stream != "integration-test" {
		t.Errorf("manifest.Stream = %q, want %q", pack.manifest.Stream, "integration-test")
	}
	if len(pack.manifest.Artifacts) != 1 {
		t.Errorf("len(manifest.Artifacts) = %d, want 1", len(pack.manifest.Artifacts))
	}
}

func TestPack_ListAttestations(t *testing.T) {
	tests := []struct {
		name         string
		attestations []string
		want         []string
	}{
		{
			name:         "no attestations",
			attestations: nil,
			want:         nil,
		},
		{
			name:         "single attestation",
			attestations: []string{"attestations/main.sigstore.json"},
			want:         []string{"attestations/main.sigstore.json"},
		},
		{
			name: "multiple attestations sorted",
			attestations: []string{
				"attestations/zebra.sigstore.json",
				"attestations/alpha.sigstore.json",
				"attestations/beta.sigstore.json",
			},
			want: []string{
				"attestations/alpha.sigstore.json",
				"attestations/beta.sigstore.json",
				"attestations/zebra.sigstore.json",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newTestHelper(t)

			artifact := validArtifact("artifacts/test.json")
			files := map[string][]byte{
				"manifest.json":       validManifest(artifact),
				"artifacts/test.json": []byte(`{}`),
			}

			// Add attestations
			for _, att := range tt.attestations {
				files[att] = []byte(`{"attestation": "data"}`)
			}

			path := h.createZip(files)
			pack, err := Open(path)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			defer func() { _ = pack.Close() }()

			got := pack.ListAttestations()

			if len(got) != len(tt.want) {
				t.Fatalf("ListAttestations() returned %d items, want %d", len(got), len(tt.want))
			}

			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("ListAttestations()[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestPack_Manifest(t *testing.T) {
	h := newTestHelper(t)

	artifact := validArtifact("artifacts/test.json")
	files := map[string][]byte{
		"manifest.json":       validManifest(artifact),
		"artifacts/test.json": []byte(`{}`),
	}

	path := h.createZip(files)
	pack, err := Open(path)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer func() { _ = pack.Close() }()

	manifest := pack.Manifest()
	if manifest.Stream != "test-stream" {
		t.Errorf("Manifest().Stream = %q, want %q", manifest.Stream, "test-stream")
	}
	if manifest.SpecVersion != "1.0" {
		t.Errorf("Manifest().SpecVersion = %q, want %q", manifest.SpecVersion, "1.0")
	}
	if len(manifest.Artifacts) != 1 {
		t.Errorf("len(Manifest().Artifacts) = %d, want 1", len(manifest.Artifacts))
	}
}

func TestPack_HasFile(t *testing.T) {
	h := newTestHelper(t)

	artifact := validArtifact("artifacts/test.json")
	files := map[string][]byte{
		"manifest.json":                   validManifest(artifact),
		"artifacts/test.json":             []byte(`{}`),
		"attestations/main.sigstore.json": []byte(`{}`),
	}

	path := h.createZip(files)
	pack, err := Open(path)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer func() { _ = pack.Close() }()

	tests := []struct {
		path string
		want bool
	}{
		{"manifest.json", true},
		{"artifacts/test.json", true},
		{"attestations/main.sigstore.json", true},
		{"nonexistent.json", false},
		{"artifacts/missing.json", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := pack.HasFile(tt.path)
			if got != tt.want {
				t.Errorf("HasFile(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestOpen_TooManyZipEntries(t *testing.T) {
	// Create a zip with more entries than maxZipEntries (15000)
	// To avoid creating a huge file, we'll test the boundary condition
	// by temporarily lowering the limit via the test.

	// Create zip with exactly maxZipEntries+1 entries
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)

	// Add manifest
	fw, _ := w.Create("manifest.json")
	m := Manifest{
		SpecVersion: "1.0",
		Stream:      "test-stream",
		GeneratedAt: "2024-01-15T10:30:00Z",
		PackDigest:  "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
		Sources:     []Source{{Name: "test-source", Version: "1.0.0"}},
		Artifacts:   []Artifact{},
	}
	manifestData, _ := json.Marshal(m)
	_, _ = fw.Write(manifestData)

	// Add artifacts directory
	fw, _ = w.Create("artifacts/")
	_, _ = fw.Write(nil)

	// Add 15000 more entries (empty attestation files that would be rejected later,
	// but the entry count check should catch it first)
	for i := 0; i < 15000; i++ {
		name := fmt.Sprintf("attestations/test%d.sigstore.json", i)
		fw, _ = w.Create(name)
		_, _ = fw.Write([]byte(`{}`))
	}

	_ = w.Close()

	dir := t.TempDir()
	path := filepath.Join(dir, "too-many-entries.zip")
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatalf("failed to write zip file: %v", err)
	}

	_, err := Open(path)
	if err == nil {
		t.Fatal("Open() expected error for too many zip entries")
	}
	if errors.CodeOf(err) != errors.TooManyArtifacts {
		t.Errorf("error code = %q, want %q", errors.CodeOf(err), errors.TooManyArtifacts)
	}
}

// limitedReader tests

func TestLimitedReader_ArtifactSizeLimit(t *testing.T) {
	h := newTestHelper(t)

	// Create artifact exactly at limit
	smallContent := bytes.Repeat([]byte("x"), 100)
	artifact := validArtifact("artifacts/test.json")
	files := map[string][]byte{
		"manifest.json":       validManifest(artifact),
		"artifacts/test.json": smallContent,
	}

	path := h.createZip(files)
	pack, err := Open(path)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer func() { _ = pack.Close() }()

	// Test that reading succeeds within limit
	reader, err := pack.OpenFileUntrusted("artifacts/test.json")
	if err != nil {
		t.Fatalf("OpenFileUntrusted() error = %v", err)
	}

	content, err := io.ReadAll(reader)
	_ = reader.Close()
	if err != nil {
		t.Fatalf("ReadAll() error = %v", err)
	}
	if len(content) != len(smallContent) {
		t.Errorf("content length = %d, want %d", len(content), len(smallContent))
	}
}

func TestLimitedReader_ExactSizeAtLimit(t *testing.T) {
	// Test the edge case where file size exactly equals the limit
	// This exercises the "peek 1 byte" logic in limitedReader.Read

	// Create a reader manually with a very small limit
	data := []byte("hello")
	underlying := io.NopCloser(bytes.NewReader(data))

	lr := &limitedReader{
		reader:           underlying,
		path:             "test.txt",
		maxArtifactBytes: 5,   // Exactly the size of "hello"
		budget:           nil, // No budget tracking for this test
	}

	content, err := io.ReadAll(lr)
	if err != nil {
		t.Fatalf("ReadAll() error = %v", err)
	}
	if string(content) != "hello" {
		t.Errorf("content = %q, want %q", string(content), "hello")
	}
}

func TestLimitedReader_ExceedsArtifactLimit(t *testing.T) {
	// Create a reader with content larger than limit
	data := []byte("hello world") // 11 bytes
	underlying := io.NopCloser(bytes.NewReader(data))

	lr := &limitedReader{
		reader:           underlying,
		path:             "test.txt",
		maxArtifactBytes: 5, // Limit to 5 bytes
		budget:           nil,
	}

	_, err := io.ReadAll(lr)
	if err == nil {
		t.Fatal("ReadAll() expected error for exceeding artifact limit")
	}
	if errors.CodeOf(err) != errors.ArtifactTooLarge {
		t.Errorf("error code = %q, want %q", errors.CodeOf(err), errors.ArtifactTooLarge)
	}
}

func TestLimitedReader_BudgetTracking(t *testing.T) {
	// Test that operation budget is properly tracked
	budget := NewReadBudgetWithLimit(100)

	data := []byte("hello")
	underlying := io.NopCloser(bytes.NewReader(data))

	lr := &limitedReader{
		reader:           underlying,
		path:             "test.txt",
		maxArtifactBytes: 100,
		budget:           budget,
	}

	_, err := io.ReadAll(lr)
	if err != nil {
		t.Fatalf("ReadAll() error = %v", err)
	}

	// Budget should reflect bytes read
	if budget.BytesRead() != 5 {
		t.Errorf("budget.BytesRead() = %d, want 5", budget.BytesRead())
	}
}

func TestLimitedReader_BudgetExhaustion(t *testing.T) {
	// Test that operation budget is enforced
	budget := NewReadBudgetWithLimit(100)
	budget.bytesRead.Store(95) // Pre-consume most of the budget

	data := []byte("hello world") // 11 bytes - would exceed budget
	underlying := io.NopCloser(bytes.NewReader(data))

	lr := &limitedReader{
		reader:           underlying,
		path:             "test.txt",
		maxArtifactBytes: 100,
		budget:           budget, // Only 5 bytes remaining
	}

	_, err := io.ReadAll(lr)
	if err == nil {
		t.Fatal("ReadAll() expected error for exceeding budget")
	}
	if errors.CodeOf(err) != errors.ZipBomb {
		t.Errorf("error code = %q, want %q", errors.CodeOf(err), errors.ZipBomb)
	}
}

func TestLimitedReader_TryReserveBudgetBytes(t *testing.T) {
	budget := NewReadBudgetWithLimit(100)

	lr := &limitedReader{
		budget: budget,
	}

	// Should succeed when under limit
	if !lr.tryReserveBudgetBytes(50) {
		t.Error("tryReserveBudgetBytes(50) should succeed")
	}
	if budget.BytesRead() != 50 {
		t.Errorf("budget.BytesRead() = %d, want 50", budget.BytesRead())
	}

	// Should succeed again
	if !lr.tryReserveBudgetBytes(50) {
		t.Error("tryReserveBudgetBytes(50) should succeed")
	}
	if budget.BytesRead() != 100 {
		t.Errorf("budget.BytesRead() = %d, want 100", budget.BytesRead())
	}

	// Should fail when at limit
	if lr.tryReserveBudgetBytes(1) {
		t.Error("tryReserveBudgetBytes(1) should fail when at limit")
	}
}

func TestLimitedReader_ReserveBudgetBytes(t *testing.T) {
	budget := NewReadBudgetWithLimit(100)

	lr := &limitedReader{
		budget: budget,
	}

	// Reserve 60 bytes
	reserved := lr.reserveBudgetBytes(60)
	if reserved != 60 {
		t.Errorf("reserveBudgetBytes(60) = %d, want 60", reserved)
	}

	// Reserve 60 more - should only get 40 (remaining)
	reserved = lr.reserveBudgetBytes(60)
	if reserved != 40 {
		t.Errorf("reserveBudgetBytes(60) = %d, want 40", reserved)
	}

	// No more budget
	reserved = lr.reserveBudgetBytes(10)
	if reserved != 0 {
		t.Errorf("reserveBudgetBytes(10) = %d, want 0", reserved)
	}
}

func TestLimitedReader_ReservationRelease(t *testing.T) {
	// Test that unused reservations are properly released
	budget := NewReadBudgetWithLimit(100)

	// Create a reader that returns fewer bytes than requested
	smallData := []byte("hi")
	underlying := io.NopCloser(bytes.NewReader(smallData))

	lr := &limitedReader{
		reader:           underlying,
		path:             "test.txt",
		maxArtifactBytes: 100,
		budget:           budget,
	}

	// Read with large buffer - should only consume 2 bytes
	buf := make([]byte, 1000)
	n, err := lr.Read(buf)
	if err != nil && err != io.EOF {
		t.Fatalf("Read() error = %v", err)
	}
	if n != 2 {
		t.Errorf("Read() = %d, want 2", n)
	}

	// Budget should reflect actual bytes read, not reserved
	if budget.BytesRead() != 2 {
		t.Errorf("budget.BytesRead() = %d, want 2", budget.BytesRead())
	}
}

func TestLimitedReader_EmptyRead(t *testing.T) {
	// Test reading empty content
	budget := NewReadBudgetWithLimit(100)

	underlying := io.NopCloser(bytes.NewReader([]byte{}))

	lr := &limitedReader{
		reader:           underlying,
		path:             "empty.txt",
		maxArtifactBytes: 100,
		budget:           budget,
	}

	content, err := io.ReadAll(lr)
	if err != nil {
		t.Fatalf("ReadAll() error = %v", err)
	}
	if len(content) != 0 {
		t.Errorf("content length = %d, want 0", len(content))
	}
	if budget.BytesRead() != 0 {
		t.Errorf("budget.BytesRead() = %d, want 0", budget.BytesRead())
	}
}

func TestLimitedReader_Close(t *testing.T) {
	// Test that Close() properly closes underlying reader
	var closed bool
	underlying := &mockReadCloser{
		Reader: bytes.NewReader([]byte("test")),
		onClose: func() error {
			closed = true
			return nil
		},
	}

	lr := &limitedReader{
		reader:           underlying,
		path:             "test.txt",
		maxArtifactBytes: 100,
		budget:           nil,
	}

	if err := lr.Close(); err != nil {
		t.Errorf("Close() error = %v", err)
	}
	if !closed {
		t.Error("underlying reader not closed")
	}
}

type mockReadCloser struct {
	*bytes.Reader
	onClose func() error
}

func (m *mockReadCloser) Close() error {
	if m.onClose != nil {
		return m.onClose()
	}
	return nil
}

func TestLimitedReader_NilBudget(t *testing.T) {
	// Test behavior when budget is nil (no operation-wide tracking)
	data := []byte("hello world")
	underlying := io.NopCloser(bytes.NewReader(data))

	lr := &limitedReader{
		reader:           underlying,
		path:             "test.txt",
		maxArtifactBytes: 100,
		budget:           nil, // No tracking
	}

	content, err := io.ReadAll(lr)
	if err != nil {
		t.Fatalf("ReadAll() error = %v", err)
	}
	if string(content) != "hello world" {
		t.Errorf("content = %q, want %q", string(content), "hello world")
	}
}

func TestLimitedReader_SmallBufferReads(t *testing.T) {
	// Test reading with very small buffer (1 byte at a time)
	budget := NewReadBudgetWithLimit(100)

	data := []byte("hello")
	underlying := io.NopCloser(bytes.NewReader(data))

	lr := &limitedReader{
		reader:           underlying,
		path:             "test.txt",
		maxArtifactBytes: 100,
		budget:           budget,
	}

	// Read 1 byte at a time
	var result []byte
	buf := make([]byte, 1)
	for {
		n, err := lr.Read(buf)
		if n > 0 {
			result = append(result, buf[:n]...)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("Read() error = %v", err)
		}
	}

	if string(result) != "hello" {
		t.Errorf("content = %q, want %q", string(result), "hello")
	}
	if budget.BytesRead() != 5 {
		t.Errorf("budget.BytesRead() = %d, want 5", budget.BytesRead())
	}
}

// TestReadBudget_PerOperationSemantics verifies that each operation gets its own budget.
func TestReadBudget_PerOperationSemantics(t *testing.T) {
	// First operation's budget
	budget1 := NewReadBudget()
	budget1.bytesRead.Store(1000000) // Simulate prior reads

	// Second operation gets a fresh budget
	budget2 := NewReadBudget()

	// budget2 should have full capacity despite budget1 being depleted
	if budget2.Remaining() <= 0 {
		t.Error("new budget should have full capacity")
	}
	if budget2.BytesRead() != 0 {
		t.Errorf("new budget.BytesRead() = %d, want 0", budget2.BytesRead())
	}
}

// TestReadBudget_ConcurrentAccess verifies thread-safety of budget tracking.
func TestReadBudget_ConcurrentAccess(t *testing.T) {
	budget := NewReadBudgetWithLimit(10000)

	// Spawn multiple goroutines that try to reserve bytes
	done := make(chan bool, 100)
	for i := 0; i < 100; i++ {
		go func() {
			lr := &limitedReader{budget: budget}
			lr.reserveBudgetBytes(100)
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 100; i++ {
		<-done
	}

	// Budget should reflect total reservations (100 goroutines * 100 bytes = 10000)
	if budget.BytesRead() != 10000 {
		t.Errorf("budget.BytesRead() = %d, want 10000", budget.BytesRead())
	}
}
