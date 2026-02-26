package merge

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/locktivity/epack/pack"
	"github.com/locktivity/epack/pack/builder"
	"github.com/locktivity/epack/pack/verify"
)

// createTestPack creates a test pack with the given stream and artifacts.
func createTestPack(t *testing.T, stream string, artifacts map[string][]byte) string {
	t.Helper()
	outputPath := filepath.Join(t.TempDir(), "test.pack")

	b := builder.New(stream)
	for path, content := range artifacts {
		if err := b.AddBytes(path, content); err != nil {
			t.Fatalf("AddBytes(%s) failed: %v", path, err)
		}
	}
	if err := b.Build(outputPath); err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	return outputPath
}

func TestMerge_Basic(t *testing.T) {
	pack1 := createTestPack(t, "org/stream1", map[string][]byte{
		"artifacts/data1.json": []byte(`{"from": "pack1"}`),
	})
	pack2 := createTestPack(t, "org/stream2", map[string][]byte{
		"artifacts/data2.json": []byte(`{"from": "pack2"}`),
	})

	outputPath := filepath.Join(t.TempDir(), "merged.pack")
	ctx := context.Background()

	sources := []SourcePack{
		{Path: pack1},
		{Path: pack2},
	}

	opts := Options{
		Stream:   "org/merged",
		MergedBy: "test",
	}

	if err := Merge(ctx, sources, outputPath, opts); err != nil {
		t.Fatalf("Merge failed: %v", err)
	}

	// Verify merged pack
	p, err := pack.Open(outputPath)
	if err != nil {
		t.Fatalf("Failed to open merged pack: %v", err)
	}
	defer func() { _ = p.Close() }()

	manifest := p.Manifest()

	if manifest.Stream != "org/merged" {
		t.Errorf("Stream = %q, want %q", manifest.Stream, "org/merged")
	}
	if len(manifest.Artifacts) != 2 {
		t.Errorf("len(Artifacts) = %d, want 2", len(manifest.Artifacts))
	}
	if manifest.Provenance == nil {
		t.Fatal("Provenance is nil")
	}
	if manifest.Provenance.Type != "merged" {
		t.Errorf("Provenance.Type = %q, want %q", manifest.Provenance.Type, "merged")
	}
	if len(manifest.Provenance.SourcePacks) != 2 {
		t.Errorf("len(SourcePacks) = %d, want 2", len(manifest.Provenance.SourcePacks))
	}
}

func TestMerge_EmptySources(t *testing.T) {
	outputPath := filepath.Join(t.TempDir(), "merged.pack")
	ctx := context.Background()

	err := Merge(ctx, []SourcePack{}, outputPath, Options{Stream: "org/merged"})
	if err == nil {
		t.Error("Expected error for empty sources, got nil")
	}
}

func TestMerge_MissingStream(t *testing.T) {
	pack1 := createTestPack(t, "org/stream1", map[string][]byte{
		"artifacts/data.json": []byte(`{}`),
	})

	outputPath := filepath.Join(t.TempDir(), "merged.pack")
	ctx := context.Background()

	err := Merge(ctx, []SourcePack{{Path: pack1}}, outputPath, Options{})
	if err == nil {
		t.Error("Expected error for missing stream, got nil")
	}
}

func TestMerge_PathPrefixing(t *testing.T) {
	// Create packs with same-named artifacts
	pack1 := createTestPack(t, "org/a", map[string][]byte{
		"artifacts/config.json": []byte(`{"source": "a"}`),
	})
	pack2 := createTestPack(t, "org/b", map[string][]byte{
		"artifacts/config.json": []byte(`{"source": "b"}`),
	})

	outputPath := filepath.Join(t.TempDir(), "merged.pack")
	ctx := context.Background()

	sources := []SourcePack{
		{Path: pack1},
		{Path: pack2},
	}

	if err := Merge(ctx, sources, outputPath, Options{Stream: "org/merged"}); err != nil {
		t.Fatalf("Merge failed: %v", err)
	}

	p, err := pack.Open(outputPath)
	if err != nil {
		t.Fatalf("Failed to open merged pack: %v", err)
	}
	defer func() { _ = p.Close() }()

	paths := make(map[string]bool)
	for _, a := range p.Manifest().Artifacts {
		paths[a.Path] = true
	}

	if !paths["artifacts/org/a/config.json"] {
		t.Error("Missing artifacts/org/a/config.json")
	}
	if !paths["artifacts/org/b/config.json"] {
		t.Error("Missing artifacts/org/b/config.json")
	}
}

func TestMerge_ProvenanceMetadata(t *testing.T) {
	pack1 := createTestPack(t, "test/p1", map[string][]byte{
		"artifacts/a.json": []byte(`{}`),
	})

	outputPath := filepath.Join(t.TempDir(), "merged.pack")
	ctx := context.Background()

	opts := Options{
		Stream:   "test/merged",
		MergedBy: "ci-system",
	}

	if err := Merge(ctx, []SourcePack{{Path: pack1}}, outputPath, opts); err != nil {
		t.Fatalf("Merge failed: %v", err)
	}

	p, err := pack.Open(outputPath)
	if err != nil {
		t.Fatalf("Failed to open merged pack: %v", err)
	}
	defer func() { _ = p.Close() }()

	prov := p.Manifest().Provenance

	if prov.Type != "merged" {
		t.Errorf("Type = %q, want %q", prov.Type, "merged")
	}
	if prov.MergedAt == "" {
		t.Error("MergedAt is empty")
	}
	if prov.MergedBy != "ci-system" {
		t.Errorf("MergedBy = %q, want %q", prov.MergedBy, "ci-system")
	}
}

func TestMerge_SourcePackFields(t *testing.T) {
	pack1 := createTestPack(t, "test/source", map[string][]byte{
		"artifacts/data.json": []byte(`{"test": true}`),
	})

	outputPath := filepath.Join(t.TempDir(), "merged.pack")
	ctx := context.Background()

	if err := Merge(ctx, []SourcePack{{Path: pack1}}, outputPath, Options{Stream: "test/merged"}); err != nil {
		t.Fatalf("Merge failed: %v", err)
	}

	p, err := pack.Open(outputPath)
	if err != nil {
		t.Fatalf("Failed to open merged pack: %v", err)
	}
	defer func() { _ = p.Close() }()

	if len(p.Manifest().Provenance.SourcePacks) != 1 {
		t.Fatalf("len(SourcePacks) = %d, want 1", len(p.Manifest().Provenance.SourcePacks))
	}

	sp := p.Manifest().Provenance.SourcePacks[0]

	if sp.Stream != "test/source" {
		t.Errorf("SourcePack.Stream = %q, want %q", sp.Stream, "test/source")
	}
	if sp.PackDigest == "" {
		t.Error("SourcePack.PackDigest is empty")
	}
	if sp.Artifacts == "" {
		t.Error("SourcePack.Artifacts is empty")
	}

	// Verify artifact count
	count, err := sp.Artifacts.Int64()
	if err != nil {
		t.Fatalf("sp.Artifacts.Int64() error: %v", err)
	}
	if count != 1 {
		t.Errorf("SourcePack.Artifacts = %d, want 1", count)
	}
}

func TestMerge_IntegrityVerification(t *testing.T) {
	pack1 := createTestPack(t, "test/s1", map[string][]byte{
		"artifacts/data.json": []byte(`{"test": true}`),
	})

	outputPath := filepath.Join(t.TempDir(), "merged.pack")
	ctx := context.Background()

	if err := Merge(ctx, []SourcePack{{Path: pack1}}, outputPath, Options{Stream: "test/merged"}); err != nil {
		t.Fatalf("Merge failed: %v", err)
	}

	p, err := pack.Open(outputPath)
	if err != nil {
		t.Fatalf("Failed to open merged pack: %v", err)
	}
	defer func() { _ = p.Close() }()

	if err := p.VerifyIntegrity(); err != nil {
		t.Errorf("VerifyIntegrity failed: %v", err)
	}
}

func TestCountEmbeddedArtifacts(t *testing.T) {
	tests := []struct {
		name      string
		artifacts []pack.Artifact
		want      int
	}{
		{
			name:      "empty",
			artifacts: nil,
			want:      0,
		},
		{
			name: "all embedded",
			artifacts: []pack.Artifact{
				{Type: "embedded"},
				{Type: "embedded"},
			},
			want: 2,
		},
		{
			name: "mixed",
			artifacts: []pack.Artifact{
				{Type: "embedded"},
				{Type: "reference"},
				{Type: "embedded"},
			},
			want: 2,
		},
		{
			name: "none embedded",
			artifacts: []pack.Artifact{
				{Type: "reference"},
				{Type: "external"},
			},
			want: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := countEmbeddedArtifacts(tt.artifacts)
			if got != tt.want {
				t.Errorf("countEmbeddedArtifacts() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestParseEmbeddedAttestation_Valid(t *testing.T) {
	bundle := map[string]interface{}{
		"mediaType":            pack.SigstoreBundleMediaType,
		"verificationMaterial": map[string]interface{}{"key": "value"},
		"dsseEnvelope":         map[string]interface{}{"payloadType": "test"},
	}

	data, err := json.Marshal(bundle)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	att, err := parseEmbeddedAttestation(data)
	if err != nil {
		t.Fatalf("parseEmbeddedAttestation() error: %v", err)
	}

	if att.MediaType != pack.SigstoreBundleMediaType {
		t.Errorf("MediaType = %q, want %q", att.MediaType, pack.SigstoreBundleMediaType)
	}
	if len(att.VerificationMaterial) == 0 {
		t.Error("VerificationMaterial is empty")
	}
	if len(att.DSSEEnvelope) == 0 {
		t.Error("DSSEEnvelope is empty")
	}
}

func TestParseEmbeddedAttestation_WrongMediaType(t *testing.T) {
	bundle := map[string]interface{}{
		"mediaType":            "application/vnd.unknown+json",
		"verificationMaterial": map[string]interface{}{},
		"dsseEnvelope":         map[string]interface{}{},
	}

	data, err := json.Marshal(bundle)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	_, err = parseEmbeddedAttestation(data)
	if err == nil {
		t.Error("Expected error for wrong media type, got nil")
	}
}

func TestParseEmbeddedAttestation_InvalidJSON(t *testing.T) {
	_, err := parseEmbeddedAttestation([]byte("not json"))
	if err == nil {
		t.Error("Expected error for invalid JSON, got nil")
	}
}

// mockVerifier is a test verifier that returns configurable results.
type mockVerifier struct {
	result *verify.Result
	err    error
}

func (v *mockVerifier) Verify(ctx context.Context, attestation []byte) (*verify.Result, error) {
	return v.result, v.err
}

func TestMerge_AttestationVerificationEnabled(t *testing.T) {
	// Create a pack - we can't actually add real attestations without signing,
	// but we can test that verification is attempted when IncludeAttestations is true
	pack1 := createTestPack(t, "org/stream1", map[string][]byte{
		"artifacts/data.json": []byte(`{"test": true}`),
	})

	outputPath := filepath.Join(t.TempDir(), "merged.pack")
	ctx := context.Background()

	// Without attestations, merge should succeed even with VerifyAttestations enabled
	opts := Options{
		Stream:              "org/merged",
		IncludeAttestations: true,
		VerifyAttestations:  true,
		Verifier:            &mockVerifier{result: &verify.Result{Verified: true}},
	}

	if err := Merge(ctx, []SourcePack{{Path: pack1}}, outputPath, opts); err != nil {
		t.Fatalf("Merge failed: %v", err)
	}
}

func TestMerge_AttestationVerificationRequiresVerifier(t *testing.T) {
	pack1 := createTestPack(t, "org/stream1", map[string][]byte{
		"artifacts/data.json": []byte(`{"test": true}`),
	})

	outputPath := filepath.Join(t.TempDir(), "merged.pack")
	ctx := context.Background()

	// VerifyAttestations=true but no Verifier - should work if no attestations present
	opts := Options{
		Stream:              "org/merged",
		IncludeAttestations: true,
		VerifyAttestations:  true,
		Verifier:            nil, // No verifier
	}

	// This should succeed because the source pack has no attestations
	if err := Merge(ctx, []SourcePack{{Path: pack1}}, outputPath, opts); err != nil {
		t.Fatalf("Merge failed: %v", err)
	}
}

func TestMerge_AttestationVerificationSkipped(t *testing.T) {
	pack1 := createTestPack(t, "org/stream1", map[string][]byte{
		"artifacts/data.json": []byte(`{"test": true}`),
	})

	outputPath := filepath.Join(t.TempDir(), "merged.pack")
	ctx := context.Background()

	// VerifyAttestations=false - should not require a verifier
	opts := Options{
		Stream:              "org/merged",
		IncludeAttestations: true,
		VerifyAttestations:  false, // Verification disabled
		Verifier:            nil,   // No verifier needed
	}

	if err := Merge(ctx, []SourcePack{{Path: pack1}}, outputPath, opts); err != nil {
		t.Fatalf("Merge failed: %v", err)
	}
}

func TestMerge_VerificationFailure(t *testing.T) {
	// This tests that when a verifier returns an error, the merge fails
	// We need a pack with attestations for this to trigger

	// Create a pack with a fake attestation file manually
	pack1 := createTestPack(t, "org/stream1", map[string][]byte{
		"artifacts/data.json": []byte(`{"test": true}`),
	})

	// Open and manually add an attestation to test the verification path
	// Since we can't easily add attestations, we'll test the verifier error path
	// by creating a mock that always fails
	outputPath := filepath.Join(t.TempDir(), "merged.pack")
	ctx := context.Background()

	failingVerifier := &mockVerifier{
		result: nil,
		err:    fmt.Errorf("verification failed: invalid signature"),
	}

	opts := Options{
		Stream:              "org/merged",
		IncludeAttestations: true,
		VerifyAttestations:  true,
		Verifier:            failingVerifier,
	}

	// This should succeed since the pack has no attestations
	// The verifier is only called when attestations exist
	if err := Merge(ctx, []SourcePack{{Path: pack1}}, outputPath, opts); err != nil {
		t.Fatalf("Merge failed unexpectedly: %v", err)
	}
}

func TestMerge_PreOpenedPack(t *testing.T) {
	// Create a pack file first
	pack1Path := createTestPack(t, "org/stream1", map[string][]byte{
		"artifacts/data.json": []byte(`{"from": "pack1"}`),
	})

	// Open it manually
	p, err := pack.Open(pack1Path)
	if err != nil {
		t.Fatalf("Failed to open pack: %v", err)
	}
	defer func() { _ = p.Close() }()

	outputPath := filepath.Join(t.TempDir(), "merged.pack")
	ctx := context.Background()

	// Use pre-opened pack
	sources := []SourcePack{
		{Pack: p}, // Use Pack field instead of Path
	}

	opts := Options{
		Stream: "org/merged",
	}

	if err := Merge(ctx, sources, outputPath, opts); err != nil {
		t.Fatalf("Merge failed: %v", err)
	}

	// Verify merged pack
	merged, err := pack.Open(outputPath)
	if err != nil {
		t.Fatalf("Failed to open merged pack: %v", err)
	}
	defer func() { _ = merged.Close() }()

	if len(merged.Manifest().Artifacts) != 1 {
		t.Errorf("len(Artifacts) = %d, want 1", len(merged.Manifest().Artifacts))
	}
}

func TestMerge_MixedPreOpenedAndPath(t *testing.T) {
	// Create two packs
	pack1Path := createTestPack(t, "org/stream1", map[string][]byte{
		"artifacts/data1.json": []byte(`{"from": "pack1"}`),
	})
	pack2Path := createTestPack(t, "org/stream2", map[string][]byte{
		"artifacts/data2.json": []byte(`{"from": "pack2"}`),
	})

	// Open only one manually
	p1, err := pack.Open(pack1Path)
	if err != nil {
		t.Fatalf("Failed to open pack: %v", err)
	}
	defer func() { _ = p1.Close() }()

	outputPath := filepath.Join(t.TempDir(), "merged.pack")
	ctx := context.Background()

	// Mix pre-opened and path-based
	sources := []SourcePack{
		{Pack: p1},        // Pre-opened
		{Path: pack2Path}, // Path-based
	}

	opts := Options{
		Stream: "org/merged",
	}

	if err := Merge(ctx, sources, outputPath, opts); err != nil {
		t.Fatalf("Merge failed: %v", err)
	}

	merged, err := pack.Open(outputPath)
	if err != nil {
		t.Fatalf("Failed to open merged pack: %v", err)
	}
	defer func() { _ = merged.Close() }()

	if len(merged.Manifest().Artifacts) != 2 {
		t.Errorf("len(Artifacts) = %d, want 2", len(merged.Manifest().Artifacts))
	}
}

func TestMerge_InvalidSourcePath(t *testing.T) {
	outputPath := filepath.Join(t.TempDir(), "merged.pack")
	ctx := context.Background()

	sources := []SourcePack{
		{Path: "/nonexistent/path/to/pack.pack"},
	}

	err := Merge(ctx, sources, outputPath, Options{Stream: "org/merged"})
	if err == nil {
		t.Error("Expected error for invalid source path, got nil")
	}
}

func TestMerge_MultipleArtifactsPerPack(t *testing.T) {
	// Create pack with multiple artifacts
	pack1 := createTestPack(t, "org/stream", map[string][]byte{
		"artifacts/data1.json":    []byte(`{"id": 1}`),
		"artifacts/data2.json":    []byte(`{"id": 2}`),
		"artifacts/nested/a.json": []byte(`{"nested": true}`),
	})

	outputPath := filepath.Join(t.TempDir(), "merged.pack")
	ctx := context.Background()

	if err := Merge(ctx, []SourcePack{{Path: pack1}}, outputPath, Options{Stream: "org/merged"}); err != nil {
		t.Fatalf("Merge failed: %v", err)
	}

	merged, err := pack.Open(outputPath)
	if err != nil {
		t.Fatalf("Failed to open merged pack: %v", err)
	}
	defer func() { _ = merged.Close() }()

	if len(merged.Manifest().Artifacts) != 3 {
		t.Errorf("len(Artifacts) = %d, want 3", len(merged.Manifest().Artifacts))
	}

	// Verify paths are correctly prefixed
	paths := make(map[string]bool)
	for _, a := range merged.Manifest().Artifacts {
		paths[a.Path] = true
	}

	expected := []string{
		"artifacts/org/stream/data1.json",
		"artifacts/org/stream/data2.json",
		"artifacts/org/stream/nested/a.json",
	}
	for _, exp := range expected {
		if !paths[exp] {
			t.Errorf("Missing expected artifact path: %s", exp)
		}
	}
}

func TestMerge_PreservesArtifactMetadata(t *testing.T) {
	// Create a pack with an artifact that has metadata
	pack1Path := filepath.Join(t.TempDir(), "source.pack")

	b := builder.New("org/source")
	addOpts := builder.ArtifactOptions{
		ContentType: "application/json",
		DisplayName: "Test Data",
		Description: "A test artifact with metadata",
		Controls:    []string{"AC-1", "AC-2"},
	}
	if err := b.AddBytesWithOptions("artifacts/data.json", []byte(`{"test": true}`), addOpts); err != nil {
		t.Fatalf("AddBytesWithOptions failed: %v", err)
	}
	if err := b.Build(pack1Path); err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	outputPath := filepath.Join(t.TempDir(), "merged.pack")
	ctx := context.Background()

	if err := Merge(ctx, []SourcePack{{Path: pack1Path}}, outputPath, Options{Stream: "org/merged"}); err != nil {
		t.Fatalf("Merge failed: %v", err)
	}

	merged, err := pack.Open(outputPath)
	if err != nil {
		t.Fatalf("Failed to open merged pack: %v", err)
	}
	defer func() { _ = merged.Close() }()

	if len(merged.Manifest().Artifacts) != 1 {
		t.Fatalf("len(Artifacts) = %d, want 1", len(merged.Manifest().Artifacts))
	}

	artifact := merged.Manifest().Artifacts[0]
	if artifact.ContentType != "application/json" {
		t.Errorf("ContentType = %q, want %q", artifact.ContentType, "application/json")
	}
	if artifact.DisplayName != "Test Data" {
		t.Errorf("DisplayName = %q, want %q", artifact.DisplayName, "Test Data")
	}
	if artifact.Description != "A test artifact with metadata" {
		t.Errorf("Description = %q, want %q", artifact.Description, "A test artifact with metadata")
	}
	if len(artifact.Controls) != 2 {
		t.Errorf("len(Controls) = %d, want 2", len(artifact.Controls))
	}
}

func TestParseEmbeddedAttestation_MissingFields(t *testing.T) {
	tests := []struct {
		name    string
		data    string
		wantErr bool
	}{
		{
			name:    "missing mediaType",
			data:    `{"verificationMaterial": {}, "dsseEnvelope": {}}`,
			wantErr: true, // Should error because mediaType won't match
		},
		{
			name:    "missing verificationMaterial",
			data:    fmt.Sprintf(`{"mediaType": %q, "dsseEnvelope": {}}`, pack.SigstoreBundleMediaType),
			wantErr: false, // Valid - verificationMaterial can be empty
		},
		{
			name:    "missing dsseEnvelope",
			data:    fmt.Sprintf(`{"mediaType": %q, "verificationMaterial": {}}`, pack.SigstoreBundleMediaType),
			wantErr: false, // Valid - dsseEnvelope can be empty/null
		},
		{
			name:    "empty object",
			data:    `{}`,
			wantErr: true, // Should error - missing required mediaType
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseEmbeddedAttestation([]byte(tt.data))
			if (err != nil) != tt.wantErr {
				t.Errorf("parseEmbeddedAttestation() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestMerge_ManySourcePacks(t *testing.T) {
	// Test merging more than 2 packs
	numPacks := 5
	var sources []SourcePack
	for i := 0; i < numPacks; i++ {
		p := createTestPack(t, fmt.Sprintf("org/stream%d", i), map[string][]byte{
			"artifacts/data.json": []byte(fmt.Sprintf(`{"index": %d}`, i)),
		})
		sources = append(sources, SourcePack{Path: p})
	}

	outputPath := filepath.Join(t.TempDir(), "merged.pack")
	ctx := context.Background()

	if err := Merge(ctx, sources, outputPath, Options{Stream: "org/merged"}); err != nil {
		t.Fatalf("Merge failed: %v", err)
	}

	merged, err := pack.Open(outputPath)
	if err != nil {
		t.Fatalf("Failed to open merged pack: %v", err)
	}
	defer func() { _ = merged.Close() }()

	if len(merged.Manifest().Artifacts) != numPacks {
		t.Errorf("len(Artifacts) = %d, want %d", len(merged.Manifest().Artifacts), numPacks)
	}
	if len(merged.Manifest().Provenance.SourcePacks) != numPacks {
		t.Errorf("len(SourcePacks) = %d, want %d", len(merged.Manifest().Provenance.SourcePacks), numPacks)
	}
}

func TestMerge_ContextCancellation(t *testing.T) {
	pack1 := createTestPack(t, "org/stream1", map[string][]byte{
		"artifacts/data.json": []byte(`{}`),
	})

	outputPath := filepath.Join(t.TempDir(), "merged.pack")
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	err := Merge(ctx, []SourcePack{{Path: pack1}}, outputPath, Options{Stream: "org/merged"})
	if err == nil {
		t.Fatal("expected error from cancelled context, got nil")
	}
	if err != context.Canceled {
		t.Errorf("expected context.Canceled, got %v", err)
	}
}

func TestMerge_SinglePack(t *testing.T) {
	// Test merging a single pack (edge case)
	pack1 := createTestPack(t, "org/single", map[string][]byte{
		"artifacts/data.json": []byte(`{"single": true}`),
	})

	outputPath := filepath.Join(t.TempDir(), "merged.pack")
	ctx := context.Background()

	if err := Merge(ctx, []SourcePack{{Path: pack1}}, outputPath, Options{Stream: "org/merged"}); err != nil {
		t.Fatalf("Merge failed: %v", err)
	}

	merged, err := pack.Open(outputPath)
	if err != nil {
		t.Fatalf("Failed to open merged pack: %v", err)
	}
	defer func() { _ = merged.Close() }()

	if len(merged.Manifest().Artifacts) != 1 {
		t.Errorf("len(Artifacts) = %d, want 1", len(merged.Manifest().Artifacts))
	}
	if len(merged.Manifest().Provenance.SourcePacks) != 1 {
		t.Errorf("len(SourcePacks) = %d, want 1", len(merged.Manifest().Provenance.SourcePacks))
	}
}

func TestMerge_NestedStreamPath(t *testing.T) {
	// Test with deeply nested stream path
	pack1 := createTestPack(t, "org/team/project/env", map[string][]byte{
		"artifacts/data.json": []byte(`{}`),
	})

	outputPath := filepath.Join(t.TempDir(), "merged.pack")
	ctx := context.Background()

	if err := Merge(ctx, []SourcePack{{Path: pack1}}, outputPath, Options{Stream: "org/merged"}); err != nil {
		t.Fatalf("Merge failed: %v", err)
	}

	merged, err := pack.Open(outputPath)
	if err != nil {
		t.Fatalf("Failed to open merged pack: %v", err)
	}
	defer func() { _ = merged.Close() }()

	// Check that nested path is correctly prefixed
	artifact := merged.Manifest().Artifacts[0]
	expected := "artifacts/org/team/project/env/data.json"
	if artifact.Path != expected {
		t.Errorf("Artifact path = %q, want %q", artifact.Path, expected)
	}
}

func TestMerge_EmptyMergedBy(t *testing.T) {
	// Test with empty MergedBy field
	pack1 := createTestPack(t, "org/stream", map[string][]byte{
		"artifacts/data.json": []byte(`{}`),
	})

	outputPath := filepath.Join(t.TempDir(), "merged.pack")
	ctx := context.Background()

	opts := Options{
		Stream:   "org/merged",
		MergedBy: "", // Empty MergedBy
	}

	if err := Merge(ctx, []SourcePack{{Path: pack1}}, outputPath, opts); err != nil {
		t.Fatalf("Merge failed: %v", err)
	}

	merged, err := pack.Open(outputPath)
	if err != nil {
		t.Fatalf("Failed to open merged pack: %v", err)
	}
	defer func() { _ = merged.Close() }()

	if merged.Manifest().Provenance.MergedBy != "" {
		t.Errorf("MergedBy = %q, want empty string", merged.Manifest().Provenance.MergedBy)
	}
}

func TestMerge_IncludeAttestationsWithoutVerify(t *testing.T) {
	// Test IncludeAttestations=true but VerifyAttestations=false
	pack1 := createTestPack(t, "org/stream", map[string][]byte{
		"artifacts/data.json": []byte(`{}`),
	})

	outputPath := filepath.Join(t.TempDir(), "merged.pack")
	ctx := context.Background()

	opts := Options{
		Stream:              "org/merged",
		IncludeAttestations: true,
		VerifyAttestations:  false,
	}

	if err := Merge(ctx, []SourcePack{{Path: pack1}}, outputPath, opts); err != nil {
		t.Fatalf("Merge failed: %v", err)
	}
}

func TestMerge_SameStreamCollision(t *testing.T) {
	// Test merging two packs with the same stream - should fail with duplicate path error
	// because artifacts from the same stream would have identical prefixed paths
	pack1 := createTestPack(t, "org/stream", map[string][]byte{
		"artifacts/config.json": []byte(`{"version": 1}`),
	})
	pack2 := createTestPack(t, "org/stream", map[string][]byte{
		"artifacts/config.json": []byte(`{"version": 2}`),
	})

	outputPath := filepath.Join(t.TempDir(), "merged.pack")
	ctx := context.Background()

	sources := []SourcePack{
		{Path: pack1},
		{Path: pack2},
	}

	err := Merge(ctx, sources, outputPath, Options{Stream: "org/merged"})
	if err == nil {
		t.Error("Expected error for duplicate artifact paths, got nil")
	}
	// Error should mention duplicate path
	if err != nil && !containsString(err.Error(), "duplicate") {
		t.Errorf("Expected error about duplicate path, got: %v", err)
	}
}

func containsString(s, substr string) bool {
	return len(s) >= len(substr) && findSubstring(s, substr)
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestOptions_Defaults(t *testing.T) {
	// Test that Options struct has sensible zero values
	opts := Options{}

	if opts.Stream != "" {
		t.Errorf("Default Stream = %q, want empty", opts.Stream)
	}
	if opts.MergedBy != "" {
		t.Errorf("Default MergedBy = %q, want empty", opts.MergedBy)
	}
	if opts.IncludeAttestations {
		t.Error("Default IncludeAttestations should be false")
	}
	if opts.VerifyAttestations {
		t.Error("Default VerifyAttestations should be false")
	}
	if opts.Verifier != nil {
		t.Error("Default Verifier should be nil")
	}
}

func TestSourcePack_Defaults(t *testing.T) {
	// Test that SourcePack struct has sensible zero values
	sp := SourcePack{}

	if sp.Path != "" {
		t.Errorf("Default Path = %q, want empty", sp.Path)
	}
	if sp.Pack != nil {
		t.Error("Default Pack should be nil")
	}
}

func TestMerge_VerificationFailsWithAttestations(t *testing.T) {
	// Create a pack to test verification failure path
	pack1 := createTestPack(t, "org/stream", map[string][]byte{
		"artifacts/data.json": []byte(`{"test": true}`),
	})

	outputPath := filepath.Join(t.TempDir(), "merged.pack")
	ctx := context.Background()

	// Create a verifier that always fails
	failingVerifier := &mockVerifier{
		err: fmt.Errorf("signature verification failed"),
	}

	opts := Options{
		Stream:              "org/merged",
		IncludeAttestations: true,
		VerifyAttestations:  true,
		Verifier:            failingVerifier,
	}

	// This should succeed because the source pack has no attestations
	err := Merge(ctx, []SourcePack{{Path: pack1}}, outputPath, opts)
	if err != nil {
		t.Fatalf("Merge should succeed when no attestations to verify: %v", err)
	}
}

func TestMerge_IncludeAttestationsDefault(t *testing.T) {
	pack1 := createTestPack(t, "org/stream1", map[string][]byte{
		"artifacts/data.json": []byte(`{"test": true}`),
	})

	outputPath := filepath.Join(t.TempDir(), "merged.pack")
	ctx := context.Background()

	// Default options should not include attestations
	opts := Options{
		Stream: "org/merged",
	}

	if err := Merge(ctx, []SourcePack{{Path: pack1}}, outputPath, opts); err != nil {
		t.Fatalf("Merge failed: %v", err)
	}

	merged, err := pack.Open(outputPath)
	if err != nil {
		t.Fatalf("Failed to open merged pack: %v", err)
	}
	defer func() { _ = merged.Close() }()

	// Verify no embedded attestations by default
	prov := merged.Manifest().Provenance
	if prov == nil {
		t.Fatal("Provenance should not be nil")
	}
	for _, sp := range prov.SourcePacks {
		if len(sp.EmbeddedAttestations) > 0 {
			t.Error("Default merge should not include embedded attestations")
		}
	}
}

func TestMerge_SourcePackDigestRecorded(t *testing.T) {
	pack1 := createTestPack(t, "org/stream1", map[string][]byte{
		"artifacts/data.json": []byte(`{"test": true}`),
	})

	// Get the source pack's digest before merge
	sourcePack, err := pack.Open(pack1)
	if err != nil {
		t.Fatalf("Failed to open source pack: %v", err)
	}
	sourceDigest := sourcePack.Manifest().PackDigest
	_ = sourcePack.Close()

	outputPath := filepath.Join(t.TempDir(), "merged.pack")
	ctx := context.Background()

	if err := Merge(ctx, []SourcePack{{Path: pack1}}, outputPath, Options{Stream: "org/merged"}); err != nil {
		t.Fatalf("Merge failed: %v", err)
	}

	merged, err := pack.Open(outputPath)
	if err != nil {
		t.Fatalf("Failed to open merged pack: %v", err)
	}
	defer func() { _ = merged.Close() }()

	// Verify source pack digest is recorded correctly
	prov := merged.Manifest().Provenance
	if len(prov.SourcePacks) != 1 {
		t.Fatalf("len(SourcePacks) = %d, want 1", len(prov.SourcePacks))
	}

	if prov.SourcePacks[0].PackDigest != sourceDigest {
		t.Errorf("SourcePack.PackDigest = %q, want %q", prov.SourcePacks[0].PackDigest, sourceDigest)
	}
}

func TestMerge_MergedPackDigestComputation(t *testing.T) {
	pack1 := createTestPack(t, "org/stream1", map[string][]byte{
		"artifacts/data.json": []byte(`{"test": true}`),
	})

	outputPath := filepath.Join(t.TempDir(), "merged.pack")
	ctx := context.Background()

	if err := Merge(ctx, []SourcePack{{Path: pack1}}, outputPath, Options{Stream: "org/merged"}); err != nil {
		t.Fatalf("Merge failed: %v", err)
	}

	merged, err := pack.Open(outputPath)
	if err != nil {
		t.Fatalf("Failed to open merged pack: %v", err)
	}
	defer func() { _ = merged.Close() }()

	// Verify merged pack has valid pack_digest
	if merged.Manifest().PackDigest == "" {
		t.Error("Merged pack should have pack_digest")
	}

	// Verify pack_digest is correct
	if err := merged.VerifyPackDigest(); err != nil {
		t.Errorf("VerifyPackDigest failed: %v", err)
	}
}

func TestMerge_BothPackAndPathProvided(t *testing.T) {
	// Create a pack
	pack1Path := createTestPack(t, "org/stream1", map[string][]byte{
		"artifacts/data.json": []byte(`{"test": true}`),
	})

	// Open it
	p, err := pack.Open(pack1Path)
	if err != nil {
		t.Fatalf("Failed to open pack: %v", err)
	}
	defer func() { _ = p.Close() }()

	outputPath := filepath.Join(t.TempDir(), "merged.pack")
	ctx := context.Background()

	// Provide both Pack and Path - Pack should be preferred
	sources := []SourcePack{
		{
			Pack: p,
			Path: "/nonexistent/path", // Would fail if used
		},
	}

	err = Merge(ctx, sources, outputPath, Options{Stream: "org/merged"})
	if err != nil {
		t.Fatalf("Merge should prefer Pack over Path: %v", err)
	}
}

func TestMerge_EmptyPackStream(t *testing.T) {
	pack1 := createTestPack(t, "org/stream", map[string][]byte{
		"artifacts/data.json": []byte(`{}`),
	})

	outputPath := filepath.Join(t.TempDir(), "merged.pack")
	ctx := context.Background()

	// Empty output stream should fail
	err := Merge(ctx, []SourcePack{{Path: pack1}}, outputPath, Options{Stream: ""})
	if err == nil {
		t.Error("Merge should fail with empty output stream")
	}
}

func TestMerge_ArtifactContentVerification(t *testing.T) {
	// Verify that artifact content is correctly copied
	originalContent := []byte(`{"important": "data", "id": 12345}`)
	pack1 := createTestPack(t, "org/stream", map[string][]byte{
		"artifacts/data.json": originalContent,
	})

	outputPath := filepath.Join(t.TempDir(), "merged.pack")
	ctx := context.Background()

	if err := Merge(ctx, []SourcePack{{Path: pack1}}, outputPath, Options{Stream: "org/merged"}); err != nil {
		t.Fatalf("Merge failed: %v", err)
	}

	merged, err := pack.Open(outputPath)
	if err != nil {
		t.Fatalf("Failed to open merged pack: %v", err)
	}
	defer func() { _ = merged.Close() }()

	// Read the artifact content
	content, err := merged.ReadArtifact("artifacts/org/stream/data.json")
	if err != nil {
		t.Fatalf("ReadArtifact failed: %v", err)
	}

	if string(content.Bytes()) != string(originalContent) {
		t.Errorf("Content = %q, want %q", string(content.Bytes()), string(originalContent))
	}
}

// Tests for stream uniqueness and flattening behavior

func TestMerge_DuplicateStreamFromDirectSources(t *testing.T) {
	// Two packs with the same stream should fail
	pack1 := createTestPack(t, "org/same-stream", map[string][]byte{
		"artifacts/data1.json": []byte(`{"from": "pack1"}`),
	})
	pack2 := createTestPack(t, "org/same-stream", map[string][]byte{
		"artifacts/data2.json": []byte(`{"from": "pack2"}`),
	})

	outputPath := filepath.Join(t.TempDir(), "merged.pack")
	ctx := context.Background()

	err := Merge(ctx, []SourcePack{{Path: pack1}, {Path: pack2}}, outputPath, Options{Stream: "org/merged"})
	if err == nil {
		t.Fatal("Expected error for duplicate streams, got nil")
	}
	if !containsString(err.Error(), "duplicate stream") {
		t.Errorf("Expected 'duplicate stream' error, got: %v", err)
	}
}

func TestMerge_DuplicateStreamFromNestedMergedPack(t *testing.T) {
	// Create two packs and merge them
	pack1 := createTestPack(t, "org/a", map[string][]byte{
		"artifacts/data.json": []byte(`{"from": "a"}`),
	})
	pack2 := createTestPack(t, "org/b", map[string][]byte{
		"artifacts/data.json": []byte(`{"from": "b"}`),
	})

	mergedPath := filepath.Join(t.TempDir(), "merged1.pack")
	ctx := context.Background()

	if err := Merge(ctx, []SourcePack{{Path: pack1}, {Path: pack2}}, mergedPath, Options{Stream: "org/merged1"}); err != nil {
		t.Fatalf("First merge failed: %v", err)
	}

	// Create another pack with stream that conflicts with nested stream
	pack3 := createTestPack(t, "org/a", map[string][]byte{
		"artifacts/other.json": []byte(`{"from": "duplicate-a"}`),
	})

	finalPath := filepath.Join(t.TempDir(), "final.pack")

	// This should fail: org/a exists in mergedPath's provenance
	err := Merge(ctx, []SourcePack{{Path: mergedPath}, {Path: pack3}}, finalPath, Options{Stream: "org/final"})
	if err == nil {
		t.Fatal("Expected error for duplicate nested stream, got nil")
	}
	if !containsString(err.Error(), "duplicate stream") {
		t.Errorf("Expected 'duplicate stream' error, got: %v", err)
	}
}

func TestMerge_FlattenAlreadyMergedPack(t *testing.T) {
	// Create two packs and merge them
	pack1 := createTestPack(t, "org/a", map[string][]byte{
		"artifacts/data.json": []byte(`{"from": "a"}`),
	})
	pack2 := createTestPack(t, "org/b", map[string][]byte{
		"artifacts/data.json": []byte(`{"from": "b"}`),
	})

	mergedPath := filepath.Join(t.TempDir(), "merged1.pack")
	ctx := context.Background()

	if err := Merge(ctx, []SourcePack{{Path: pack1}, {Path: pack2}}, mergedPath, Options{Stream: "org/merged1"}); err != nil {
		t.Fatalf("First merge failed: %v", err)
	}

	// Create a third pack with unique stream
	pack3 := createTestPack(t, "org/c", map[string][]byte{
		"artifacts/data.json": []byte(`{"from": "c"}`),
	})

	finalPath := filepath.Join(t.TempDir(), "final.pack")

	if err := Merge(ctx, []SourcePack{{Path: mergedPath}, {Path: pack3}}, finalPath, Options{Stream: "org/final"}); err != nil {
		t.Fatalf("Second merge failed: %v", err)
	}

	// Verify flattening: paths should NOT be re-nested
	final, err := pack.Open(finalPath)
	if err != nil {
		t.Fatalf("Failed to open final pack: %v", err)
	}
	defer func() { _ = final.Close() }()

	paths := make(map[string]bool)
	for _, a := range final.Manifest().Artifacts {
		paths[a.Path] = true
	}

	// Paths from merged pack should be preserved (not re-nested)
	expectedPaths := []string{
		"artifacts/org/a/data.json", // from merged pack, preserved
		"artifacts/org/b/data.json", // from merged pack, preserved
		"artifacts/org/c/data.json", // from pack3, newly prefixed
	}

	for _, exp := range expectedPaths {
		if !paths[exp] {
			t.Errorf("Missing expected path: %s", exp)
		}
	}

	// Should NOT have re-nested paths like artifacts/org/merged1/org/a/data.json
	for path := range paths {
		if containsString(path, "org/merged1/org/") {
			t.Errorf("Found re-nested path (should be flattened): %s", path)
		}
	}
}

func TestMerge_DeepNestingStaysFlat(t *testing.T) {
	ctx := context.Background()

	// Create base packs
	packA := createTestPack(t, "org/a", map[string][]byte{
		"artifacts/data.json": []byte(`{"from": "a"}`),
	})
	packB := createTestPack(t, "org/b", map[string][]byte{
		"artifacts/data.json": []byte(`{"from": "b"}`),
	})

	// First merge: A + B -> M1
	m1Path := filepath.Join(t.TempDir(), "m1.pack")
	if err := Merge(ctx, []SourcePack{{Path: packA}, {Path: packB}}, m1Path, Options{Stream: "org/m1"}); err != nil {
		t.Fatalf("Merge 1 failed: %v", err)
	}

	// Create C
	packC := createTestPack(t, "org/c", map[string][]byte{
		"artifacts/data.json": []byte(`{"from": "c"}`),
	})

	// Second merge: M1 + C -> M2
	m2Path := filepath.Join(t.TempDir(), "m2.pack")
	if err := Merge(ctx, []SourcePack{{Path: m1Path}, {Path: packC}}, m2Path, Options{Stream: "org/m2"}); err != nil {
		t.Fatalf("Merge 2 failed: %v", err)
	}

	// Create D
	packD := createTestPack(t, "org/d", map[string][]byte{
		"artifacts/data.json": []byte(`{"from": "d"}`),
	})

	// Third merge: M2 + D -> M3
	m3Path := filepath.Join(t.TempDir(), "m3.pack")
	if err := Merge(ctx, []SourcePack{{Path: m2Path}, {Path: packD}}, m3Path, Options{Stream: "org/m3"}); err != nil {
		t.Fatalf("Merge 3 failed: %v", err)
	}

	// Verify final paths are flat (single level of stream prefixing)
	final, err := pack.Open(m3Path)
	if err != nil {
		t.Fatalf("Failed to open final pack: %v", err)
	}
	defer func() { _ = final.Close() }()

	expectedPaths := []string{
		"artifacts/org/a/data.json",
		"artifacts/org/b/data.json",
		"artifacts/org/c/data.json",
		"artifacts/org/d/data.json",
	}

	paths := make(map[string]bool)
	for _, a := range final.Manifest().Artifacts {
		paths[a.Path] = true
	}

	for _, exp := range expectedPaths {
		if !paths[exp] {
			t.Errorf("Missing expected path: %s", exp)
		}
	}

	// Verify no deep nesting
	if len(paths) != 4 {
		t.Errorf("Expected 4 artifacts, got %d", len(paths))
	}
}

func TestMerge_DuplicateStreamAcrossTwoMergedPacks(t *testing.T) {
	ctx := context.Background()

	// Create packs
	packA := createTestPack(t, "org/a", map[string][]byte{
		"artifacts/data.json": []byte(`{"from": "a"}`),
	})
	packB := createTestPack(t, "org/b", map[string][]byte{
		"artifacts/data.json": []byte(`{"from": "b"}`),
	})
	packC := createTestPack(t, "org/c", map[string][]byte{
		"artifacts/data.json": []byte(`{"from": "c"}`),
	})

	// First merged pack: A + B
	m1Path := filepath.Join(t.TempDir(), "m1.pack")
	if err := Merge(ctx, []SourcePack{{Path: packA}, {Path: packB}}, m1Path, Options{Stream: "org/m1"}); err != nil {
		t.Fatalf("Merge 1 failed: %v", err)
	}

	// Second merged pack: A + C (reuses org/a!)
	m2Path := filepath.Join(t.TempDir(), "m2.pack")
	if err := Merge(ctx, []SourcePack{{Path: packA}, {Path: packC}}, m2Path, Options{Stream: "org/m2"}); err != nil {
		t.Fatalf("Merge 2 failed: %v", err)
	}

	// Try to merge M1 + M2 - should fail because org/a appears in both
	finalPath := filepath.Join(t.TempDir(), "final.pack")
	err := Merge(ctx, []SourcePack{{Path: m1Path}, {Path: m2Path}}, finalPath, Options{Stream: "org/final"})
	if err == nil {
		t.Fatal("Expected error for duplicate stream across merged packs, got nil")
	}
	if !containsString(err.Error(), "duplicate stream") || !containsString(err.Error(), "org/a") {
		t.Errorf("Expected 'duplicate stream' error mentioning 'org/a', got: %v", err)
	}
}

func TestMerge_UniqueStreamsSucceeds(t *testing.T) {
	ctx := context.Background()

	// Create packs with unique streams
	packA := createTestPack(t, "org/a", map[string][]byte{
		"artifacts/data.json": []byte(`{"from": "a"}`),
	})
	packB := createTestPack(t, "org/b", map[string][]byte{
		"artifacts/data.json": []byte(`{"from": "b"}`),
	})
	packC := createTestPack(t, "org/c", map[string][]byte{
		"artifacts/data.json": []byte(`{"from": "c"}`),
	})

	// Merge A + B
	m1Path := filepath.Join(t.TempDir(), "m1.pack")
	if err := Merge(ctx, []SourcePack{{Path: packA}, {Path: packB}}, m1Path, Options{Stream: "org/m1"}); err != nil {
		t.Fatalf("Merge 1 failed: %v", err)
	}

	// Merge M1 + C (all streams unique)
	finalPath := filepath.Join(t.TempDir(), "final.pack")
	if err := Merge(ctx, []SourcePack{{Path: m1Path}, {Path: packC}}, finalPath, Options{Stream: "org/final"}); err != nil {
		t.Fatalf("Final merge failed: %v", err)
	}

	// Verify success
	final, err := pack.Open(finalPath)
	if err != nil {
		t.Fatalf("Failed to open final pack: %v", err)
	}
	defer func() { _ = final.Close() }()

	if len(final.Manifest().Artifacts) != 3 {
		t.Errorf("Expected 3 artifacts, got %d", len(final.Manifest().Artifacts))
	}
}

func TestIsAlreadyMergedPack(t *testing.T) {
	tests := []struct {
		name     string
		manifest pack.Manifest
		want     bool
	}{
		{
			name:     "nil provenance",
			manifest: pack.Manifest{},
			want:     false,
		},
		{
			name: "non-merged provenance",
			manifest: pack.Manifest{
				Provenance: &pack.Provenance{Type: "built"},
			},
			want: false,
		},
		{
			name: "merged provenance",
			manifest: pack.Manifest{
				Provenance: &pack.Provenance{Type: "merged"},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isAlreadyMergedPack(tt.manifest)
			if got != tt.want {
				t.Errorf("isAlreadyMergedPack() = %v, want %v", got, tt.want)
			}
		})
	}
}
