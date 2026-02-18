package pack

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"

	"github.com/locktivity/epack/errors"
)

// =============================================================================
// Contract Tests: ReadArtifact MUST verify before returning content
// =============================================================================

// TestReadArtifact_NeverReturnsUnverifiedContent is a contract test ensuring
// ReadArtifact ALWAYS returns an error for tampered content. This is the
// primary security invariant - no refactor should break this.
func TestReadArtifact_NeverReturnsUnverifiedContent(t *testing.T) {
	t.Parallel()

	// Tamper patterns to test - each represents a different attack vector
	tamperPatterns := []struct {
		name        string
		tamperFunc  func(content []byte, digest string) ([]byte, string)
		expectCode  errors.Code
		description string
	}{
		{
			name: "content_replaced",
			tamperFunc: func(content []byte, digest string) ([]byte, string) {
				return []byte("MALICIOUS REPLACEMENT"), digest // Keep claimed digest, change content
			},
			expectCode:  errors.DigestMismatch,
			description: "attacker replaces content but keeps manifest digest",
		},
		{
			name: "content_appended",
			tamperFunc: func(content []byte, digest string) ([]byte, string) {
				return append(content, []byte("APPENDED")...), digest
			},
			expectCode:  errors.SizeMismatch,
			description: "attacker appends to content",
		},
		{
			name: "content_truncated",
			tamperFunc: func(content []byte, digest string) ([]byte, string) {
				if len(content) > 1 {
					return content[:len(content)/2], digest
				}
				return []byte{}, digest
			},
			expectCode:  errors.SizeMismatch,
			description: "attacker truncates content",
		},
		{
			name: "single_byte_flip",
			tamperFunc: func(content []byte, digest string) ([]byte, string) {
				modified := make([]byte, len(content))
				copy(modified, content)
				if len(modified) > 0 {
					modified[0] ^= 0xFF // Flip all bits of first byte
				}
				return modified, digest
			},
			expectCode:  errors.DigestMismatch,
			description: "attacker flips single byte",
		},
		{
			name: "digest_zeroed",
			tamperFunc: func(content []byte, digest string) ([]byte, string) {
				return content, "sha256:0000000000000000000000000000000000000000000000000000000000000000"
			},
			expectCode:  errors.DigestMismatch,
			description: "attacker sets digest to zeros",
		},
		{
			name: "digest_of_other_file",
			tamperFunc: func(content []byte, digest string) ([]byte, string) {
				// Digest of "foo" - a well-known value
				return content, "sha256:b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c"
			},
			expectCode:  errors.DigestMismatch,
			description: "attacker uses digest of different content",
		},
	}

	// Test content variations
	testContents := []struct {
		name    string
		content []byte
	}{
		{"json_object", []byte(`{"key": "value", "nested": {"a": 1}}`)},
		{"empty", []byte{}},
		{"single_byte", []byte{0x42}},
		{"binary_data", []byte{0x00, 0x01, 0xFF, 0xFE, 0x7F}},
		{"large_json", bytes.Repeat([]byte(`{"data": "x"}`), 100)},
	}

	for _, tc := range testContents {
		for _, tp := range tamperPatterns {
			t.Run(fmt.Sprintf("%s/%s", tc.name, tp.name), func(t *testing.T) {
				t.Parallel()

				// Compute correct digest
				h := sha256.Sum256(tc.content)
				correctDigest := "sha256:" + hex.EncodeToString(h[:])

				// Apply tamper
				tamperedContent, claimedDigest := tp.tamperFunc(tc.content, correctDigest)

				// Skip if tamper produced no change (e.g., truncating empty content)
				if bytes.Equal(tamperedContent, tc.content) && claimedDigest == correctDigest {
					t.Skip("tamper pattern produced no change for this content")
				}

				// Create tampered pack
				packPath := createTamperedPackForContract(t, claimedDigest, tamperedContent, tc.content)

				pack, err := Open(packPath)
				if err != nil {
					t.Fatalf("Open() error = %v", err)
				}
				defer func() { _ = pack.Close() }()

				// THE CONTRACT: ReadArtifact MUST return an error
				data, err := pack.ReadArtifact("artifacts/test.json")

				if err == nil {
					t.Fatalf("SECURITY VIOLATION: ReadArtifact returned tampered content without error!\n"+
						"  Tamper: %s\n"+
						"  Description: %s\n"+
						"  Returned data: %q\n"+
						"  Expected error code: %s",
						tp.name, tp.description, data, tp.expectCode)
				}

				code := errors.CodeOf(err)
				if code != errors.DigestMismatch && code != errors.SizeMismatch {
					t.Errorf("ReadArtifact error code = %q, want digest_mismatch or size_mismatch", code)
				}
			})
		}
	}
}

// createTamperedPackForContract creates a pack where manifest claims one digest
// but actual content differs.
func createTamperedPackForContract(t *testing.T, claimedDigest string, actualContent, originalContent []byte) string {
	t.Helper()

	artifactPath := "artifacts/test.json"
	claimedSize := json.Number(strconv.Itoa(len(originalContent)))

	artifact := Artifact{
		Type:   "embedded",
		Path:   artifactPath,
		Digest: claimedDigest,
		Size:   &claimedSize,
	}

	// Build internally-consistent pack_digest
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

	var buf bytes.Buffer
	w := zip.NewWriter(&buf)

	fw, _ := w.Create("manifest.json")
	_, _ = fw.Write(manifestData)

	fw, _ = w.Create(artifactPath)
	_, _ = fw.Write(actualContent)

	_ = w.Close()

	dir := t.TempDir()
	path := filepath.Join(dir, "contract-test.zip")
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatalf("failed to write zip file: %v", err)
	}

	return path
}

// =============================================================================
// Concurrency Safety Tests
// =============================================================================

// TestConcurrentPackAccess verifies that Pack is safe for concurrent read operations.
// This catches race conditions that could appear during refactoring.
func TestConcurrentPackAccess(t *testing.T) {
	t.Parallel()

	content := []byte(`{"concurrent": "test", "id": 12345}`)
	packPath := createTestPack(t, content)

	pack, err := Open(packPath)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer func() { _ = pack.Close() }()

	const numGoroutines = 50
	const opsPerGoroutine = 20

	var wg sync.WaitGroup
	errChan := make(chan error, numGoroutines*opsPerGoroutine)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < opsPerGoroutine; j++ {
				// Mix of operations
				switch j % 4 {
				case 0:
					// ReadArtifact
					data, err := pack.ReadArtifact("artifacts/test.json")
					if err != nil {
						errChan <- fmt.Errorf("goroutine %d op %d: ReadArtifact: %w", id, j, err)
						return
					}
					if !bytes.Equal(data, content) {
						errChan <- fmt.Errorf("goroutine %d op %d: content mismatch", id, j)
						return
					}
				case 1:
					// VerifyIntegrity
					if err := pack.VerifyIntegrity(); err != nil {
						errChan <- fmt.Errorf("goroutine %d op %d: VerifyIntegrity: %w", id, j, err)
						return
					}
				case 2:
					// Manifest (should return copy)
					m := pack.Manifest()
					if m.Stream != "test-stream" {
						errChan <- fmt.Errorf("goroutine %d op %d: wrong stream", id, j)
						return
					}
				case 3:
					// ReadFileUntrusted
					data, err := pack.ReadFileUntrusted("artifacts/test.json")
					if err != nil {
						errChan <- fmt.Errorf("goroutine %d op %d: ReadFileUntrusted: %w", id, j, err)
						return
					}
					if !bytes.Equal(data, content) {
						errChan <- fmt.Errorf("goroutine %d op %d: ReadFileUntrusted content mismatch", id, j)
						return
					}
				}
			}
		}(i)
	}

	wg.Wait()
	close(errChan)

	var errs []error
	for err := range errChan {
		errs = append(errs, err)
	}
	if len(errs) > 0 {
		t.Fatalf("Concurrent access errors (%d total):\n%v", len(errs), errs[0])
	}
}

// TestConcurrentBudgetAccess verifies that ReadBudget is safe for concurrent use.
func TestConcurrentBudgetAccess(t *testing.T) {
	t.Parallel()

	content := []byte(`{"test": "budget concurrency"}`)
	packPath := createTestPack(t, content)

	pack, err := Open(packPath)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer func() { _ = pack.Close() }()

	// Shared budget across goroutines
	budget := NewReadBudget()

	const numGoroutines = 20
	const readsPerGoroutine = 10

	var wg sync.WaitGroup
	errChan := make(chan error, numGoroutines*readsPerGoroutine)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < readsPerGoroutine; j++ {
				data, err := pack.ReadArtifactWithBudget("artifacts/test.json", budget)
				if err != nil {
					errChan <- fmt.Errorf("goroutine %d read %d: %w", id, j, err)
					return
				}
				if !bytes.Equal(data, content) {
					errChan <- fmt.Errorf("goroutine %d read %d: content mismatch", id, j)
					return
				}
			}
		}(i)
	}

	wg.Wait()
	close(errChan)

	for err := range errChan {
		t.Errorf("Budget concurrency error: %v", err)
	}

	// Verify budget tracked all reads
	expectedBytes := int64(numGoroutines * readsPerGoroutine * len(content))
	actualBytes := budget.BytesRead()
	if actualBytes != expectedBytes {
		t.Errorf("Budget bytes = %d, want %d", actualBytes, expectedBytes)
	}
}

// =============================================================================
// Manifest Immutability Contract
// =============================================================================

// TestManifestImmutabilityContract verifies that external mutations cannot
// affect internal pack state. This is critical for security - if an attacker
// could mutate the manifest after Open(), they could bypass integrity checks.
func TestManifestImmutabilityContract(t *testing.T) {
	t.Parallel()

	content := []byte(`{"test": "immutability"}`)
	packPath := createTestPack(t, content)

	pack, err := Open(packPath)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer func() { _ = pack.Close() }()

	// Get original values
	original := pack.Manifest()
	originalDigest := original.PackDigest
	originalStream := original.Stream
	originalArtifactDigest := ""
	if len(original.Artifacts) > 0 {
		originalArtifactDigest = original.Artifacts[0].Digest
	}

	// Attempt to mutate the returned manifest
	mutations := []func(m *Manifest){
		func(m *Manifest) { m.PackDigest = "sha256:ATTACKER_CONTROLLED" },
		func(m *Manifest) { m.Stream = "attacker/controlled" },
		func(m *Manifest) {
			if len(m.Artifacts) > 0 {
				m.Artifacts[0].Digest = "sha256:FAKE"
			}
		},
		func(m *Manifest) {
			m.Artifacts = append(m.Artifacts, Artifact{
				Type: "embedded",
				Path: "artifacts/injected.json",
			})
		},
	}

	for i, mutate := range mutations {
		copy := pack.Manifest()
		mutate(&copy)

		// Get a fresh copy - should have original values
		fresh := pack.Manifest()
		if fresh.PackDigest != originalDigest {
			t.Errorf("mutation %d: PackDigest was affected", i)
		}
		if fresh.Stream != originalStream {
			t.Errorf("mutation %d: Stream was affected", i)
		}
		if len(fresh.Artifacts) > 0 && fresh.Artifacts[0].Digest != originalArtifactDigest {
			t.Errorf("mutation %d: Artifact digest was affected", i)
		}
	}

	// Verify integrity checks still work after attempted mutations
	if err := pack.VerifyIntegrity(); err != nil {
		t.Errorf("VerifyIntegrity failed after mutation attempts: %v", err)
	}
}

// =============================================================================
// Deterministic Build Contract
// =============================================================================

// TestBuilder_Idempotency verifies that building the same pack twice produces
// identical pack_digest values. This is critical for reproducible builds.
func TestBuilder_Idempotency(t *testing.T) {
	t.Parallel()

	// Fixed inputs for deterministic testing
	artifacts := map[string][]byte{
		"artifacts/config.json":  []byte(`{"setting": "value"}`),
		"artifacts/data.json":    []byte(`{"items": [1, 2, 3]}`),
		"artifacts/nested/a.txt": []byte("nested content"),
	}

	// Build pack multiple times
	var digests []string
	for i := 0; i < 5; i++ {
		packPath := buildTestPackWithArtifacts(t, "test/idempotent", artifacts)

		pack, err := Open(packPath)
		if err != nil {
			t.Fatalf("iteration %d: Open() error = %v", i, err)
		}

		digests = append(digests, pack.Manifest().PackDigest)
		_ = pack.Close()
	}

	// All digests should be identical
	for i := 1; i < len(digests); i++ {
		if digests[i] != digests[0] {
			t.Errorf("Non-deterministic build: digest[%d]=%s, digest[0]=%s", i, digests[i], digests[0])
		}
	}
}

// buildTestPackWithArtifacts creates a pack with specific artifacts for testing.
func buildTestPackWithArtifacts(t *testing.T, stream string, artifacts map[string][]byte) string {
	t.Helper()

	// Build manifest with sorted artifacts for determinism
	var manifestArtifacts []Artifact
	for path, data := range artifacts {
		h := sha256.Sum256(data)
		digest := "sha256:" + hex.EncodeToString(h[:])
		size := json.Number(strconv.Itoa(len(data)))

		manifestArtifacts = append(manifestArtifacts, Artifact{
			Type:   "embedded",
			Path:   path,
			Digest: digest,
			Size:   &size,
		})
	}

	// Sort for determinism
	for i := 0; i < len(manifestArtifacts)-1; i++ {
		for j := i + 1; j < len(manifestArtifacts); j++ {
			if manifestArtifacts[i].Path > manifestArtifacts[j].Path {
				manifestArtifacts[i], manifestArtifacts[j] = manifestArtifacts[j], manifestArtifacts[i]
			}
		}
	}

	tmpManifest := &Manifest{Artifacts: manifestArtifacts}
	canonical := BuildCanonicalArtifactList(tmpManifest)
	packDigest := HashCanonicalList(canonical)

	manifest := Manifest{
		SpecVersion: "1.0",
		Stream:      stream,
		GeneratedAt: "2024-01-15T10:30:00Z", // Fixed timestamp for determinism
		PackDigest:  packDigest,
		Sources:     []Source{},
		Artifacts:   manifestArtifacts,
	}

	manifestData, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("failed to marshal manifest: %v", err)
	}

	var buf bytes.Buffer
	w := zip.NewWriter(&buf)

	fw, _ := w.Create("manifest.json")
	_, _ = fw.Write(manifestData)

	// Write artifacts in sorted order
	for _, a := range manifestArtifacts {
		fw, _ := w.Create(a.Path)
		_, _ = fw.Write(artifacts[a.Path])
	}

	_ = w.Close()

	dir := t.TempDir()
	path := filepath.Join(dir, "idempotent-test.zip")
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatalf("failed to write zip file: %v", err)
	}

	return path
}

// =============================================================================
// Error Code Stability Tests
// =============================================================================

// TestErrorCodeStability ensures error codes remain stable across refactors.
// Error codes are part of the API contract for test vectors and integrations.
func TestErrorCodeStability(t *testing.T) {
	t.Parallel()

	// These mappings document the expected error codes for specific scenarios.
	// If a refactor changes these, it's a breaking change that must be intentional.
	scenarios := []struct {
		name       string
		setup      func(t *testing.T) (*Pack, string)
		operation  func(p *Pack, path string) error
		expectCode errors.Code
	}{
		{
			name: "artifact_not_in_manifest",
			setup: func(t *testing.T) (*Pack, string) {
				content := []byte(`{}`)
				packPath := createTestPack(t, content)
				p, _ := Open(packPath)
				return p, "artifacts/nonexistent.json"
			},
			operation: func(p *Pack, path string) error {
				_, err := p.ReadArtifact(path)
				return err
			},
			expectCode: errors.MissingEntry,
		},
		{
			name: "digest_mismatch",
			setup: func(t *testing.T) (*Pack, string) {
				fakeDigest := "sha256:0000000000000000000000000000000000000000000000000000000000000000"
				packPath := createTamperedPack(t, fakeDigest, []byte("wrong"))
				p, _ := Open(packPath)
				return p, "artifacts/test.json"
			},
			operation: func(p *Pack, path string) error {
				_, err := p.ReadArtifact(path)
				return err
			},
			expectCode: errors.SizeMismatch, // Size checked before digest
		},
		{
			name: "file_not_found_untrusted",
			setup: func(t *testing.T) (*Pack, string) {
				content := []byte(`{}`)
				packPath := createTestPack(t, content)
				p, _ := Open(packPath)
				return p, "nonexistent.txt"
			},
			operation: func(p *Pack, path string) error {
				_, err := p.ReadFileUntrusted(path)
				return err
			},
			expectCode: errors.MissingEntry,
		},
	}

	for _, sc := range scenarios {
		t.Run(sc.name, func(t *testing.T) {
			t.Parallel()

			pack, path := sc.setup(t)
			defer func() { _ = pack.Close() }()

			err := sc.operation(pack, path)
			if err == nil {
				t.Fatalf("expected error with code %s, got nil", sc.expectCode)
			}

			code := errors.CodeOf(err)
			if code != sc.expectCode {
				t.Errorf("error code = %q, want %q\n  error: %v", code, sc.expectCode, err)
			}
		})
	}
}

// =============================================================================
// Verification Completeness Tests
// =============================================================================

// TestVerifyIntegrity_ChecksBothPackAndArtifactDigests ensures VerifyIntegrity
// validates both pack_digest and individual artifact digests.
func TestVerifyIntegrity_ChecksBothPackAndArtifactDigests(t *testing.T) {
	t.Parallel()

	t.Run("detects_tampered_artifact", func(t *testing.T) {
		fakeDigest := "sha256:0000000000000000000000000000000000000000000000000000000000000000"
		packPath := createTamperedPack(t, fakeDigest, []byte("TAMPERED"))

		pack, err := Open(packPath)
		if err != nil {
			t.Fatalf("Open() error = %v", err)
		}
		defer func() { _ = pack.Close() }()

		err = pack.VerifyIntegrity()
		if err == nil {
			t.Fatal("VerifyIntegrity should fail for tampered artifact")
		}
	})

	t.Run("detects_wrong_pack_digest", func(t *testing.T) {
		content := []byte(`{"test": "data"}`)
		packPath := createPackWithWrongPackDigest(t, content)

		pack, err := Open(packPath)
		if err != nil {
			t.Fatalf("Open() error = %v", err)
		}
		defer func() { _ = pack.Close() }()

		err = pack.VerifyPackDigest()
		if err == nil {
			t.Fatal("VerifyPackDigest should fail for wrong pack_digest")
		}
		if errors.CodeOf(err) != errors.DigestMismatch {
			t.Errorf("error code = %q, want %q", errors.CodeOf(err), errors.DigestMismatch)
		}
	})
}

// createPackWithWrongPackDigest creates a pack with a valid artifact digest
// but an incorrect pack_digest.
func createPackWithWrongPackDigest(t *testing.T, content []byte) string {
	t.Helper()

	artifactDigest := computeSHA256(content)
	artifactPath := "artifacts/test.json"
	size := json.Number(strconv.Itoa(len(content)))

	artifact := Artifact{
		Type:   "embedded",
		Path:   artifactPath,
		Digest: artifactDigest,
		Size:   &size,
	}

	// Use wrong pack_digest (valid format but wrong value)
	manifest := Manifest{
		SpecVersion: "1.0",
		Stream:      "test-stream",
		GeneratedAt: "2024-01-15T10:30:00Z",
		PackDigest:  "sha256:0000000000000000000000000000000000000000000000000000000000000000", // Valid format, wrong value
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
	path := filepath.Join(dir, "wrong-pack-digest.zip")
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatalf("failed to write zip file: %v", err)
	}

	return path
}
