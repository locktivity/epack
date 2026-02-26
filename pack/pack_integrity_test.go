package pack

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/locktivity/epack/errors"
)

// createTestPack creates a test pack with proper digests.
func createTestPack(t *testing.T, artifactContent []byte) string {
	t.Helper()

	// Compute actual digest of artifact
	artifactDigest := computeSHA256(artifactContent)
	artifactPath := "artifacts/test.json"
	size := json.Number(strconv.Itoa(len(artifactContent)))

	// Build manifest with correct digests
	artifact := Artifact{
		Type:   "embedded",
		Path:   artifactPath,
		Digest: artifactDigest,
		Size:   &size,
	}

	// Build canonical list and compute pack_digest
	tmpManifest := &Manifest{Artifacts: []Artifact{artifact}}
	canonical := BuildCanonicalArtifactList(tmpManifest)
	packDigest := HashCanonicalList(canonical)

	manifest := Manifest{
		SpecVersion: "1.0",
		Stream:      "test-stream",
		GeneratedAt: "2024-01-15T10:30:00Z",
		PackDigest:  packDigest,
		Sources:     []Source{{Name: "test-source", Version: "1.0.0"}},
		Artifacts:   []Artifact{artifact},
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

	fw, _ = w.Create(artifactPath)
	_, _ = fw.Write(artifactContent)

	_ = w.Close()

	dir := t.TempDir()
	path := filepath.Join(dir, "integrity-test.zip")
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatalf("failed to write zip file: %v", err)
	}

	return path
}

// createTamperedPack creates a pack where the artifact content doesn't match the manifest digest.
func createTamperedPack(t *testing.T, manifestDigest string, actualContent []byte) string {
	t.Helper()

	artifactPath := "artifacts/test.json"
	size := json.Number("100") // Size mismatch too

	artifact := Artifact{
		Type:   "embedded",
		Path:   artifactPath,
		Digest: manifestDigest, // Fake digest
		Size:   &size,
	}

	// Compute pack_digest from manifest (internally consistent but artifact is fake)
	tmpManifest := &Manifest{Artifacts: []Artifact{artifact}}
	canonical := BuildCanonicalArtifactList(tmpManifest)
	packDigest := HashCanonicalList(canonical)

	manifest := Manifest{
		SpecVersion: "1.0",
		Stream:      "test-stream",
		GeneratedAt: "2024-01-15T10:30:00Z",
		PackDigest:  packDigest,
		Sources:     []Source{{Name: "test-source", Version: "1.0.0"}},
		Artifacts:   []Artifact{artifact},
	}

	manifestData, _ := json.Marshal(manifest)

	var buf bytes.Buffer
	w := zip.NewWriter(&buf)

	fw, _ := w.Create("manifest.json")
	_, _ = fw.Write(manifestData)

	fw, _ = w.Create(artifactPath)
	_, _ = fw.Write(actualContent)

	_ = w.Close()

	dir := t.TempDir()
	path := filepath.Join(dir, "tampered-test.zip")
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatalf("failed to write zip file: %v", err)
	}

	return path
}

func TestReadArtifact_ValidDigest(t *testing.T) {
	content := []byte(`{"valid": "content"}`)
	packPath := createTestPack(t, content)

	pack, err := Open(packPath)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer func() { _ = pack.Close() }()

	data, err := pack.ReadArtifact("artifacts/test.json")
	if err != nil {
		t.Fatalf("ReadArtifact() error = %v", err)
	}

	if !bytes.Equal(data.Bytes(), content) {
		t.Errorf("ReadArtifact() = %q, want %q", data, content)
	}
}

func TestReadArtifact_DigestMismatch(t *testing.T) {
	// Create pack with fake digest but real malicious content
	fakeDigest := "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	maliciousContent := []byte(`MALICIOUS`)

	packPath := createTamperedPack(t, fakeDigest, maliciousContent)

	pack, err := Open(packPath)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer func() { _ = pack.Close() }()

	// ReadArtifact should detect the mismatch (size or digest - size is checked first)
	_, err = pack.ReadArtifact("artifacts/test.json")
	if err == nil {
		t.Fatal("ReadArtifact() expected error for tampered content")
	}

	code := errors.CodeOf(err)
	if code != errors.DigestMismatch && code != errors.SizeMismatch {
		t.Errorf("error code = %q, want digest_mismatch or size_mismatch", code)
	}
}

func TestReadArtifact_SizeMismatch(t *testing.T) {
	content := []byte(`{"test": "data"}`)
	artifactDigest := computeSHA256(content)
	artifactPath := "artifacts/test.json"
	wrongSize := json.Number("999") // Wrong size

	artifact := Artifact{
		Type:   "embedded",
		Path:   artifactPath,
		Digest: artifactDigest, // Correct digest
		Size:   &wrongSize,     // Wrong size
	}

	tmpManifest := &Manifest{Artifacts: []Artifact{artifact}}
	canonical := BuildCanonicalArtifactList(tmpManifest)
	packDigest := HashCanonicalList(canonical)

	manifest := Manifest{
		SpecVersion: "1.0",
		Stream:      "test-stream",
		GeneratedAt: "2024-01-15T10:30:00Z",
		PackDigest:  packDigest,
		Sources:     []Source{{Name: "test-source", Version: "1.0.0"}},
		Artifacts:   []Artifact{artifact},
	}

	manifestData, _ := json.Marshal(manifest)

	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	fw, _ := w.Create("manifest.json")
	_, _ = fw.Write(manifestData)
	fw, _ = w.Create(artifactPath)
	_, _ = fw.Write(content)
	_ = w.Close()

	dir := t.TempDir()
	path := filepath.Join(dir, "size-mismatch.zip")
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatalf("failed to write zip file: %v", err)
	}

	pack, err := Open(path)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer func() { _ = pack.Close() }()

	_, err = pack.ReadArtifact("artifacts/test.json")
	if err == nil {
		t.Fatal("ReadArtifact() expected error for size mismatch")
	}

	if errors.CodeOf(err) != errors.SizeMismatch {
		t.Errorf("error code = %q, want %q", errors.CodeOf(err), errors.SizeMismatch)
	}
}

func TestReadArtifact_NotInManifest(t *testing.T) {
	content := []byte(`{"test": "data"}`)
	packPath := createTestPack(t, content)

	pack, err := Open(packPath)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer func() { _ = pack.Close() }()

	_, err = pack.ReadArtifact("artifacts/nonexistent.json")
	if err == nil {
		t.Fatal("ReadArtifact() expected error for artifact not in manifest")
	}

	if errors.CodeOf(err) != errors.MissingEntry {
		t.Errorf("error code = %q, want %q", errors.CodeOf(err), errors.MissingEntry)
	}
}

func TestVerifyPackDigest_Valid(t *testing.T) {
	content := []byte(`{"test": "data"}`)
	packPath := createTestPack(t, content)

	pack, err := Open(packPath)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer func() { _ = pack.Close() }()

	err = pack.VerifyPackDigest()
	if err != nil {
		t.Errorf("VerifyPackDigest() error = %v", err)
	}
}

func TestVerifyPackDigest_Invalid(t *testing.T) {
	content := []byte(`{"test": "data"}`)
	artifactDigest := computeSHA256(content)
	artifactPath := "artifacts/test.json"
	size := json.Number("15")

	artifact := Artifact{
		Type:   "embedded",
		Path:   artifactPath,
		Digest: artifactDigest,
		Size:   &size,
	}

	// Use wrong pack_digest
	manifest := Manifest{
		SpecVersion: "1.0",
		Stream:      "test-stream",
		GeneratedAt: "2024-01-15T10:30:00Z",
		PackDigest:  "sha256:0000000000000000000000000000000000000000000000000000000000000000", // Wrong!
		Sources:     []Source{{Name: "test-source", Version: "1.0.0"}},
		Artifacts:   []Artifact{artifact},
	}

	manifestData, _ := json.Marshal(manifest)

	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	fw, _ := w.Create("manifest.json")
	_, _ = fw.Write(manifestData)
	fw, _ = w.Create(artifactPath)
	_, _ = fw.Write(content)
	_ = w.Close()

	dir := t.TempDir()
	path := filepath.Join(dir, "bad-pack-digest.zip")
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatalf("failed to write zip file: %v", err)
	}

	pack, err := Open(path)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer func() { _ = pack.Close() }()

	err = pack.VerifyPackDigest()
	if err == nil {
		t.Fatal("VerifyPackDigest() expected error for invalid pack_digest")
	}

	if errors.CodeOf(err) != errors.DigestMismatch {
		t.Errorf("error code = %q, want %q", errors.CodeOf(err), errors.DigestMismatch)
	}
}

func TestVerifyAllArtifacts_Valid(t *testing.T) {
	content := []byte(`{"test": "data"}`)
	packPath := createTestPack(t, content)

	pack, err := Open(packPath)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer func() { _ = pack.Close() }()

	err = pack.VerifyAllArtifacts()
	if err != nil {
		t.Errorf("VerifyAllArtifacts() error = %v", err)
	}
}

func TestVerifyAllArtifacts_Invalid(t *testing.T) {
	fakeDigest := "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	maliciousContent := []byte(`MALICIOUS`)

	packPath := createTamperedPack(t, fakeDigest, maliciousContent)

	pack, err := Open(packPath)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer func() { _ = pack.Close() }()

	err = pack.VerifyAllArtifacts()
	if err == nil {
		t.Fatal("VerifyAllArtifacts() expected error for tampered artifact")
	}

	if errors.CodeOf(err) != errors.DigestMismatch && errors.CodeOf(err) != errors.SizeMismatch {
		t.Errorf("error code = %q, want digest_mismatch or size_mismatch", errors.CodeOf(err))
	}
}

func TestVerifyIntegrity_Valid(t *testing.T) {
	content := []byte(`{"test": "data"}`)
	packPath := createTestPack(t, content)

	pack, err := Open(packPath)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer func() { _ = pack.Close() }()

	err = pack.VerifyIntegrity()
	if err != nil {
		t.Errorf("VerifyIntegrity() error = %v", err)
	}
}

func TestVerifyIntegrity_TamperedArtifact(t *testing.T) {
	fakeDigest := "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	maliciousContent := []byte(`MALICIOUS`)

	packPath := createTamperedPack(t, fakeDigest, maliciousContent)

	pack, err := Open(packPath)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer func() { _ = pack.Close() }()

	err = pack.VerifyIntegrity()
	if err == nil {
		t.Fatal("VerifyIntegrity() expected error for tampered artifact")
	}
}

// TestIntegrityBypass_PoC reproduces the exact attack scenario from the security report.
func TestIntegrityBypass_PoC(t *testing.T) {
	// Attack: manifest claims benign digest, pack contains malicious bytes
	benignDigest := "sha256:b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c" // sha256("foo")
	maliciousContent := []byte("MALICIOUS")

	packPath := createTamperedPack(t, benignDigest, maliciousContent)

	// Open succeeds (format is valid)
	pack, err := Open(packPath)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer func() { _ = pack.Close() }()

	// ReadFileUntrusted returns malicious content WITHOUT verification
	data, err := pack.ReadFileUntrusted("artifacts/test.json")
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if string(data.UnsafeBytes()) != "MALICIOUS" {
		t.Fatalf("ReadFile() = %q, expected MALICIOUS", data)
	}

	// But ReadArtifact MUST fail with digest_mismatch
	_, err = pack.ReadArtifact("artifacts/test.json")
	if err == nil {
		t.Fatal("ReadArtifact() MUST fail for tampered content - integrity bypass!")
	}
	if errors.CodeOf(err) != errors.DigestMismatch && errors.CodeOf(err) != errors.SizeMismatch {
		t.Errorf("error code = %q, want digest_mismatch or size_mismatch", errors.CodeOf(err))
	}

	// VerifyIntegrity MUST also fail
	err = pack.VerifyIntegrity()
	if err == nil {
		t.Fatal("VerifyIntegrity() MUST fail for tampered content - integrity bypass!")
	}
}

// TestManifest_ReturnsCopy verifies that Manifest() returns a copy,
// not a reference to internal state. Mutations should not affect the pack.
func TestManifest_ReturnsCopy(t *testing.T) {
	content := []byte(`{"test": "data"}`)
	packPath := createTestPack(t, content)

	pack, err := Open(packPath)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer func() { _ = pack.Close() }()

	// Get manifest copy
	m1 := pack.Manifest()
	originalDigest := m1.PackDigest
	originalStream := m1.Stream

	// Mutate the copy
	m1.PackDigest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	m1.Stream = "attacker-controlled"
	if len(m1.Artifacts) > 0 {
		m1.Artifacts[0].Digest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	}

	// Get another copy - should have original values
	m2 := pack.Manifest()
	if m2.PackDigest != originalDigest {
		t.Errorf("PackDigest was mutated: got %q, want %q", m2.PackDigest, originalDigest)
	}
	if m2.Stream != originalStream {
		t.Errorf("Stream was mutated: got %q, want %q", m2.Stream, originalStream)
	}
}

// TestVerifyIntegrity_UnaffectedByExternalMutation verifies that integrity
// checks use the original manifest, not any mutated copies.
func TestVerifyIntegrity_UnaffectedByExternalMutation(t *testing.T) {
	content := []byte(`{"test": "data"}`)
	packPath := createTestPack(t, content)

	pack, err := Open(packPath)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer func() { _ = pack.Close() }()

	// First verify integrity passes
	if err := pack.VerifyIntegrity(); err != nil {
		t.Fatalf("Initial VerifyIntegrity() error = %v", err)
	}

	// Get manifest copy and mutate it
	m := pack.Manifest()
	m.PackDigest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	if len(m.Artifacts) > 0 {
		m.Artifacts[0].Digest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	}

	// Integrity check should still pass (uses original internal state)
	if err := pack.VerifyIntegrity(); err != nil {
		t.Errorf("VerifyIntegrity() after external mutation error = %v", err)
	}
}

// TestRepeatedReads_DoNotExhaustBudget verifies that reading the same artifact
// multiple times does not exhaust any lifetime budget and cause spurious errors.
func TestRepeatedReads_DoNotExhaustBudget(t *testing.T) {
	content := []byte(`{"test": "data"}`)
	packPath := createTestPack(t, content)

	pack, err := Open(packPath)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer func() { _ = pack.Close() }()

	// Read the same artifact 100 times - should not fail
	for i := 0; i < 100; i++ {
		_, err := pack.ReadArtifact("artifacts/test.json")
		if err != nil {
			t.Fatalf("ReadArtifact() failed on iteration %d: %v", i, err)
		}
	}

	// Also test ReadFileUntrusted
	for i := 0; i < 100; i++ {
		_, err := pack.ReadFileUntrusted("artifacts/test.json")
		if err != nil {
			t.Fatalf("ReadFileUntrusted() failed on iteration %d: %v", i, err)
		}
	}
}
