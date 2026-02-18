package pack

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/locktivity/epack/errors"
	"github.com/locktivity/epack/pack/verify"
)

// nilVerifier always returns nil, nil - simulating a broken verifier implementation.
type nilVerifier struct{}

func (v *nilVerifier) Verify(ctx context.Context, attestation []byte) (*verify.Result, error) {
	return nil, nil // Bug: returns nil result without error
}

func TestVerifyAttestation_NilVerifier(t *testing.T) {
	content := []byte(`{"test": "data"}`)
	packPath := createTestPack(t, content)

	pack, err := Open(packPath)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer func() { _ = pack.Close() }()

	// Passing nil verifier should return an error, not panic
	_, err = pack.VerifyAttestation(context.Background(), "attestations/test.json", nil)
	if err == nil {
		t.Fatal("VerifyAttestation() expected error for nil verifier")
	}

	if errors.CodeOf(err) != errors.InvalidInput {
		t.Errorf("error code = %q, want %q", errors.CodeOf(err), errors.InvalidInput)
	}
}

func TestVerifyAttestation_NilResult(t *testing.T) {
	// Create a pack with an attestation to test
	content := []byte(`{"test": "data"}`)
	packPath := createTestPackWithAttestation(t, content)

	pack, err := Open(packPath)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer func() { _ = pack.Close() }()

	// Use a verifier that returns nil result without error
	v := &nilVerifier{}

	_, err = pack.VerifyAttestation(context.Background(), "attestations/test.sigstore.json", v)
	if err == nil {
		t.Fatal("VerifyAttestation() expected error when verifier returns nil result")
	}

	if errors.CodeOf(err) != errors.SignatureInvalid {
		t.Errorf("error code = %q, want %q", errors.CodeOf(err), errors.SignatureInvalid)
	}
}

func TestVerifyAllAttestations_NilVerifier(t *testing.T) {
	content := []byte(`{"test": "data"}`)
	packPath := createTestPack(t, content)

	pack, err := Open(packPath)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer func() { _ = pack.Close() }()

	// Passing nil verifier should return an error, not panic
	_, err = pack.VerifyAllAttestations(context.Background(), nil)
	if err == nil {
		t.Fatal("VerifyAllAttestations() expected error for nil verifier")
	}

	if errors.CodeOf(err) != errors.InvalidInput {
		t.Errorf("error code = %q, want %q", errors.CodeOf(err), errors.InvalidInput)
	}
}

func TestVerifyAllAttestations_NilResult(t *testing.T) {
	content := []byte(`{"test": "data"}`)
	packPath := createTestPackWithAttestation(t, content)

	pack, err := Open(packPath)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer func() { _ = pack.Close() }()

	v := &nilVerifier{}

	_, err = pack.VerifyAllAttestations(context.Background(), v)
	if err == nil {
		t.Fatal("VerifyAllAttestations() expected error when verifier returns nil result")
	}

	if errors.CodeOf(err) != errors.SignatureInvalid {
		t.Errorf("error code = %q, want %q", errors.CodeOf(err), errors.SignatureInvalid)
	}
}

// createTestPackWithAttestation creates a test pack with an attestation file.
func createTestPackWithAttestation(t *testing.T, artifactContent []byte) string {
	t.Helper()

	return createTestPackWithFiles(t, artifactContent, map[string][]byte{
		"attestations/test.sigstore.json": []byte(`{"payloadType": "application/vnd.in-toto+json", "payload": "e30=", "signatures": []}`),
	})
}

// mockVerifier is a test verifier that returns configurable results.
type mockVerifier struct {
	result *verify.Result
	err    error
}

func (v *mockVerifier) Verify(ctx context.Context, attestation []byte) (*verify.Result, error) {
	return v.result, v.err
}

func TestVerifyEmbeddedAttestations_NilVerifier(t *testing.T) {
	content := []byte(`{"test": "data"}`)
	packPath := createTestPack(t, content)

	pack, err := Open(packPath)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer func() { _ = pack.Close() }()

	// Passing nil verifier should return an error
	_, err = pack.VerifyEmbeddedAttestations(context.Background(), nil)
	if err == nil {
		t.Fatal("VerifyEmbeddedAttestations() expected error for nil verifier")
	}

	if errors.CodeOf(err) != errors.InvalidInput {
		t.Errorf("error code = %q, want %q", errors.CodeOf(err), errors.InvalidInput)
	}
}

func TestVerifyEmbeddedAttestations_NonMergedPack(t *testing.T) {
	content := []byte(`{"test": "data"}`)
	packPath := createTestPack(t, content)

	pack, err := Open(packPath)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer func() { _ = pack.Close() }()

	v := &mockVerifier{result: &verify.Result{Verified: true}}

	// Non-merged pack should return nil with no error
	results, err := pack.VerifyEmbeddedAttestations(context.Background(), v)
	if err != nil {
		t.Fatalf("VerifyEmbeddedAttestations() error = %v", err)
	}
	if results != nil {
		t.Errorf("VerifyEmbeddedAttestations() = %v, want nil for non-merged pack", results)
	}
}

func TestVerifyEmbeddedAttestations_MergedPackNoEmbedded(t *testing.T) {
	// Create a merged pack without embedded attestations
	packPath := createTestMergedPackWithoutEmbedded(t)

	pack, err := Open(packPath)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer func() { _ = pack.Close() }()

	v := &mockVerifier{result: &verify.Result{Verified: true}}

	results, err := pack.VerifyEmbeddedAttestations(context.Background(), v)
	if err != nil {
		t.Fatalf("VerifyEmbeddedAttestations() error = %v", err)
	}
	if len(results) != 0 {
		t.Errorf("VerifyEmbeddedAttestations() returned %d results, want 0", len(results))
	}
}

// statementVerifier is a test verifier that returns a result with a configurable pack digest.
type statementVerifier struct {
	packDigest string
}

func (v *statementVerifier) Verify(ctx context.Context, attestation []byte) (*verify.Result, error) {
	// Build the predicate JSON with pack_digest
	predicateJSON, _ := json.Marshal(map[string]string{
		"pack_digest": v.packDigest,
	})

	return &verify.Result{
		Verified: true,
		Statement: &verify.Statement{
			Type:          "https://in-toto.io/Statement/v1",
			PredicateType: "https://evidencepack.org/attestation/v1",
			Predicate:     predicateJSON,
			Subjects: []verify.Subject{
				{
					Digest: map[string]string{"sha256": v.packDigest[7:]}, // strip "sha256:" prefix
				},
			},
		},
	}, nil
}

func TestVerifyEmbeddedAttestations_MergedPackWithEmbedded(t *testing.T) {
	// Create a merged pack with one embedded attestation
	packPath := createTestMergedPackWithEmbedded(t)

	pack, err := Open(packPath)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer func() { _ = pack.Close() }()

	// Create a verifier that returns a result with matching subject digest
	v := &statementVerifier{
		packDigest: "sha256:abc123def456abc123def456abc123def456abc123def456abc123def456abcd",
	}

	results, err := pack.VerifyEmbeddedAttestations(context.Background(), v)
	if err != nil {
		t.Fatalf("VerifyEmbeddedAttestations() error = %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("VerifyEmbeddedAttestations() returned %d results, want 1", len(results))
	}

	result := results[0]
	if result.SourcePackIndex != 0 {
		t.Errorf("SourcePackIndex = %d, want 0", result.SourcePackIndex)
	}
	if result.AttestationIndex != 0 {
		t.Errorf("AttestationIndex = %d, want 0", result.AttestationIndex)
	}
	if result.Stream != "test/source" {
		t.Errorf("Stream = %q, want %q", result.Stream, "test/source")
	}
	if result.Result == nil {
		t.Error("Result should not be nil")
	}
	if !result.Result.Verified {
		t.Error("Result.Verified should be true")
	}
}

func TestVerifyEmbeddedAttestations_MergedPackWithMultipleEmbedded(t *testing.T) {
	// Create a merged pack with multiple embedded attestations
	packPath := createTestMergedPackWithMultipleEmbedded(t)

	pack, err := Open(packPath)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer func() { _ = pack.Close() }()

	// Create a verifier that handles both source pack digests
	v := &multiDigestVerifier{
		packDigests: map[int]string{
			0: "sha256:abc123def456abc123def456abc123def456abc123def456abc123def456abcd",
			1: "sha256:def456abc123def456abc123def456abc123def456abc123def456abc123def4",
		},
	}

	results, err := pack.VerifyEmbeddedAttestations(context.Background(), v)
	if err != nil {
		t.Fatalf("VerifyEmbeddedAttestations() error = %v", err)
	}

	if len(results) != 2 {
		t.Fatalf("VerifyEmbeddedAttestations() returned %d results, want 2", len(results))
	}

	// Verify first result
	if results[0].SourcePackIndex != 0 {
		t.Errorf("results[0].SourcePackIndex = %d, want 0", results[0].SourcePackIndex)
	}
	if results[0].Stream != "test/source1" {
		t.Errorf("results[0].Stream = %q, want %q", results[0].Stream, "test/source1")
	}

	// Verify second result
	if results[1].SourcePackIndex != 1 {
		t.Errorf("results[1].SourcePackIndex = %d, want 1", results[1].SourcePackIndex)
	}
	if results[1].Stream != "test/source2" {
		t.Errorf("results[1].Stream = %q, want %q", results[1].Stream, "test/source2")
	}
}

// multiDigestVerifier returns statements with digests based on call index.
type multiDigestVerifier struct {
	packDigests map[int]string // full pack digests like "sha256:abc..."
	calls       int
}

func (v *multiDigestVerifier) Verify(ctx context.Context, attestation []byte) (*verify.Result, error) {
	packDigest := v.packDigests[v.calls]
	v.calls++

	// Build the predicate JSON with pack_digest
	predicateJSON, _ := json.Marshal(map[string]string{
		"pack_digest": packDigest,
	})

	// Extract the hash part after "sha256:"
	hashPart := packDigest
	if len(packDigest) > 7 && packDigest[:7] == "sha256:" {
		hashPart = packDigest[7:]
	}

	return &verify.Result{
		Verified: true,
		Statement: &verify.Statement{
			Type:          "https://in-toto.io/Statement/v1",
			PredicateType: "https://evidencepack.org/attestation/v1",
			Predicate:     predicateJSON,
			Subjects: []verify.Subject{
				{
					Digest: map[string]string{"sha256": hashPart},
				},
			},
		},
	}, nil
}

func TestVerifyEmbeddedAttestations_VerificationFailure(t *testing.T) {
	packPath := createTestMergedPackWithEmbedded(t)

	pack, err := Open(packPath)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer func() { _ = pack.Close() }()

	// Create a verifier that returns an error
	v := &mockVerifier{
		result: nil,
		err:    errors.E(errors.SignatureInvalid, "verification failed", nil),
	}

	_, err = pack.VerifyEmbeddedAttestations(context.Background(), v)
	if err == nil {
		t.Fatal("VerifyEmbeddedAttestations() expected error when verification fails")
	}
}

func TestVerifyEmbeddedAttestations_SubjectMismatch(t *testing.T) {
	packPath := createTestMergedPackWithEmbedded(t)

	pack, err := Open(packPath)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer func() { _ = pack.Close() }()

	// Create a verifier that returns a result with a non-matching subject digest
	v := &statementVerifier{
		packDigest: "sha256:wrong_digest_that_does_not_match_source_pack",
	}

	_, err = pack.VerifyEmbeddedAttestations(context.Background(), v)
	if err == nil {
		t.Fatal("VerifyEmbeddedAttestations() expected error when subject doesn't match pack digest")
	}
}

// createTestMergedPackWithEmbedded creates a merged pack with embedded attestations.
func createTestMergedPackWithEmbedded(t *testing.T) string {
	t.Helper()

	artifactContent := []byte(`{"test": "data"}`)
	artifactDigest := computeSHA256(artifactContent)
	artifactPath := "artifacts/source/test.json"
	size := json.Number(strconv.Itoa(len(artifactContent)))

	artifact := Artifact{
		Type:   "embedded",
		Path:   artifactPath,
		Digest: artifactDigest,
		Size:   &size,
	}

	tmpManifest := &Manifest{Artifacts: []Artifact{artifact}}
	canonical := BuildCanonicalArtifactList(tmpManifest)
	packDigest := HashCanonicalList(canonical)

	// Create a mock embedded attestation with required fields
	embeddedAttestation := EmbeddedAttestation{
		MediaType:            SigstoreBundleMediaType,
		VerificationMaterial: json.RawMessage(`{"certificate": {"rawBytes": "dGVzdA=="}}`),
		DSSEEnvelope:         json.RawMessage(`{"payloadType": "application/vnd.in-toto+json", "payload": "eyJ0ZXN0IjogdHJ1ZX0="}`),
	}

	manifest := Manifest{
		SpecVersion: "1.0",
		Stream:      "test/merged",
		GeneratedAt: "2024-01-15T10:30:00Z",
		PackDigest:  packDigest,
		Sources:     []Source{{Name: "test-source", Version: "1.0.0"}},
		Artifacts:   []Artifact{artifact},
		Provenance: &Provenance{
			Type:     "merged",
			MergedAt: "2024-01-15T10:30:00Z",
			MergedBy: "test",
			SourcePacks: []SourcePack{
				{
					Stream:               "test/source",
					PackDigest:           "sha256:abc123def456abc123def456abc123def456abc123def456abc123def456abcd",
					Artifacts:            json.Number("1"),
					EmbeddedAttestations: []EmbeddedAttestation{embeddedAttestation},
				},
			},
		},
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
	_, _ = fw.Write(artifactContent)

	_ = w.Close()

	dir := t.TempDir()
	path := filepath.Join(dir, "verify-embedded-test.zip")
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatalf("failed to write zip file: %v", err)
	}

	return path
}

// createTestMergedPackWithMultipleEmbedded creates a merged pack with multiple embedded attestations.
func createTestMergedPackWithMultipleEmbedded(t *testing.T) string {
	t.Helper()

	artifactContent := []byte(`{"test": "data"}`)
	artifactDigest := computeSHA256(artifactContent)
	artifactPath := "artifacts/source/test.json"
	size := json.Number(strconv.Itoa(len(artifactContent)))

	artifact := Artifact{
		Type:   "embedded",
		Path:   artifactPath,
		Digest: artifactDigest,
		Size:   &size,
	}

	tmpManifest := &Manifest{Artifacts: []Artifact{artifact}}
	canonical := BuildCanonicalArtifactList(tmpManifest)
	packDigest := HashCanonicalList(canonical)

	embeddedAttestation1 := EmbeddedAttestation{
		MediaType:            SigstoreBundleMediaType,
		VerificationMaterial: json.RawMessage(`{"certificate": {"rawBytes": "dGVzdDE="}}`),
		DSSEEnvelope:         json.RawMessage(`{"payloadType": "application/vnd.in-toto+json", "payload": "eyJ0ZXN0IjogMX0="}`),
	}
	embeddedAttestation2 := EmbeddedAttestation{
		MediaType:            SigstoreBundleMediaType,
		VerificationMaterial: json.RawMessage(`{"certificate": {"rawBytes": "dGVzdDI="}}`),
		DSSEEnvelope:         json.RawMessage(`{"payloadType": "application/vnd.in-toto+json", "payload": "eyJ0ZXN0IjogMn0="}`),
	}

	manifest := Manifest{
		SpecVersion: "1.0",
		Stream:      "test/merged-multi",
		GeneratedAt: "2024-01-15T10:30:00Z",
		PackDigest:  packDigest,
		Sources:     []Source{{Name: "test-source", Version: "1.0.0"}},
		Artifacts:   []Artifact{artifact},
		Provenance: &Provenance{
			Type:     "merged",
			MergedAt: "2024-01-15T10:30:00Z",
			MergedBy: "test",
			SourcePacks: []SourcePack{
				{
					Stream:               "test/source1",
					PackDigest:           "sha256:abc123def456abc123def456abc123def456abc123def456abc123def456abcd",
					Artifacts:            json.Number("1"),
					EmbeddedAttestations: []EmbeddedAttestation{embeddedAttestation1},
				},
				{
					Stream:               "test/source2",
					PackDigest:           "sha256:def456abc123def456abc123def456abc123def456abc123def456abc123def4",
					Artifacts:            json.Number("1"),
					EmbeddedAttestations: []EmbeddedAttestation{embeddedAttestation2},
				},
			},
		},
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
	_, _ = fw.Write(artifactContent)

	_ = w.Close()

	dir := t.TempDir()
	path := filepath.Join(dir, "verify-embedded-multi-test.zip")
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatalf("failed to write zip file: %v", err)
	}

	return path
}

// createTestMergedPackWithoutEmbedded creates a merged pack without embedded attestations.
func createTestMergedPackWithoutEmbedded(t *testing.T) string {
	t.Helper()

	artifactContent := []byte(`{"test": "data"}`)
	artifactDigest := computeSHA256(artifactContent)
	artifactPath := "artifacts/source/test.json"
	size := json.Number(strconv.Itoa(len(artifactContent)))

	artifact := Artifact{
		Type:   "embedded",
		Path:   artifactPath,
		Digest: artifactDigest,
		Size:   &size,
	}

	tmpManifest := &Manifest{Artifacts: []Artifact{artifact}}
	canonical := BuildCanonicalArtifactList(tmpManifest)
	packDigest := HashCanonicalList(canonical)

	manifest := Manifest{
		SpecVersion: "1.0",
		Stream:      "test/merged",
		GeneratedAt: "2024-01-15T10:30:00Z",
		PackDigest:  packDigest,
		Sources:     []Source{{Name: "test-source", Version: "1.0.0"}},
		Artifacts:   []Artifact{artifact},
		Provenance: &Provenance{
			Type:     "merged",
			MergedAt: "2024-01-15T10:30:00Z",
			MergedBy: "test",
			SourcePacks: []SourcePack{
				{
					Stream:     "test/source",
					PackDigest: "sha256:abc123def456abc123def456abc123def456abc123def456abc123def456abcd",
					Artifacts:  json.Number("1"),
					// No EmbeddedAttestation
				},
			},
		},
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
	_, _ = fw.Write(artifactContent)

	_ = w.Close()

	dir := t.TempDir()
	path := filepath.Join(dir, "verify-embedded-test.zip")
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatalf("failed to write zip file: %v", err)
	}

	return path
}

// createTestPackWithFiles creates a test pack with custom additional files.
func createTestPackWithFiles(t *testing.T, artifactContent []byte, extraFiles map[string][]byte) string {
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

	// Add extra files
	for path, content := range extraFiles {
		fw, _ = w.Create(path)
		_, _ = fw.Write(content)
	}

	_ = w.Close()

	dir := t.TempDir()
	path := filepath.Join(dir, "verify-test.zip")
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatalf("failed to write zip file: %v", err)
	}

	return path
}
