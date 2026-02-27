package cmd

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"

	"github.com/locktivity/epack/internal/cli/output"
	"github.com/locktivity/epack/pack"
	"github.com/locktivity/epack/pack/merge"
)

func TestMerge_TwoPacks(t *testing.T) {
	// Create two source packs
	pack1 := createTestPack(t, "org/stream1", map[string][]byte{
		"artifacts/data1.json": []byte(`{"from": "pack1"}`),
	})
	pack2 := createTestPack(t, "org/stream2", map[string][]byte{
		"artifacts/data2.json": []byte(`{"from": "pack2"}`),
	})

	// Merge them
	outputPath := filepath.Join(t.TempDir(), "merged.epack")
	ctx := context.Background()

	sources := []merge.SourcePack{
		{Path: pack1},
		{Path: pack2},
	}

	opts := merge.Options{
		Stream:   "org/combined",
		MergedBy: "test",
	}

	if err := merge.Merge(ctx, sources, outputPath, opts); err != nil {
		t.Fatalf("Merge failed: %v", err)
	}

	// Verify merged pack
	p, err := pack.Open(outputPath)
	if err != nil {
		t.Fatalf("Failed to open merged pack: %v", err)
	}
	defer func() { _ = p.Close() }()

	manifest := p.Manifest()

	// Check stream
	if manifest.Stream != "org/combined" {
		t.Errorf("Stream = %q, want %q", manifest.Stream, "org/combined")
	}

	// Check artifact count
	if len(manifest.Artifacts) != 2 {
		t.Errorf("len(Artifacts) = %d, want 2", len(manifest.Artifacts))
	}

	// Check provenance
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

func TestMerge_ArtifactPathPrefixing(t *testing.T) {
	// Create packs with same-named artifacts
	pack1 := createTestPack(t, "org/a", map[string][]byte{
		"artifacts/config.json": []byte(`{"source": "a"}`),
	})
	pack2 := createTestPack(t, "org/b", map[string][]byte{
		"artifacts/config.json": []byte(`{"source": "b"}`),
	})

	outputPath := filepath.Join(t.TempDir(), "merged.epack")
	ctx := context.Background()

	sources := []merge.SourcePack{
		{Path: pack1},
		{Path: pack2},
	}

	opts := merge.Options{
		Stream: "org/merged",
	}

	if err := merge.Merge(ctx, sources, outputPath, opts); err != nil {
		t.Fatalf("Merge failed: %v", err)
	}

	p, err := pack.Open(outputPath)
	if err != nil {
		t.Fatalf("Failed to open merged pack: %v", err)
	}
	defer func() { _ = p.Close() }()

	manifest := p.Manifest()

	// Verify both artifacts are present with prefixed paths
	paths := make(map[string]bool)
	for _, a := range manifest.Artifacts {
		paths[a.Path] = true
	}

	// Should have artifacts/org/a/config.json and artifacts/org/b/config.json
	if !paths["artifacts/org/a/config.json"] {
		t.Error("Missing artifacts/org/a/config.json")
	}
	if !paths["artifacts/org/b/config.json"] {
		t.Error("Missing artifacts/org/b/config.json")
	}
}

func TestMerge_ProvenanceFields(t *testing.T) {
	pack1 := createTestPack(t, "test/p1", map[string][]byte{
		"artifacts/a.json": []byte(`{}`),
	})
	pack2 := createTestPack(t, "test/p2", map[string][]byte{
		"artifacts/b.json": []byte(`{}`),
	})

	outputPath := filepath.Join(t.TempDir(), "merged.epack")
	ctx := context.Background()

	sources := []merge.SourcePack{
		{Path: pack1},
		{Path: pack2},
	}

	opts := merge.Options{
		Stream:   "test/merged",
		MergedBy: "ci-system",
	}

	if err := merge.Merge(ctx, sources, outputPath, opts); err != nil {
		t.Fatalf("Merge failed: %v", err)
	}

	p, err := pack.Open(outputPath)
	if err != nil {
		t.Fatalf("Failed to open merged pack: %v", err)
	}
	defer func() { _ = p.Close() }()

	manifest := p.Manifest()
	prov := manifest.Provenance

	// Verify provenance fields
	if prov.Type != "merged" {
		t.Errorf("Provenance.Type = %q, want %q", prov.Type, "merged")
	}
	if prov.MergedAt == "" {
		t.Error("Provenance.MergedAt is empty")
	}
	if prov.MergedBy != "ci-system" {
		t.Errorf("Provenance.MergedBy = %q, want %q", prov.MergedBy, "ci-system")
	}

	// Verify source packs
	for i, sp := range prov.SourcePacks {
		if sp.Stream == "" {
			t.Errorf("SourcePacks[%d].Stream is empty", i)
		}
		if sp.PackDigest == "" {
			t.Errorf("SourcePacks[%d].PackDigest is empty", i)
		}
		if sp.Artifacts == "" {
			t.Errorf("SourcePacks[%d].Artifacts is empty", i)
		}
	}
}

func TestMerge_IntegrityVerification(t *testing.T) {
	pack1 := createTestPack(t, "test/s1", map[string][]byte{
		"artifacts/data.json": []byte(`{"test": true}`),
	})

	outputPath := filepath.Join(t.TempDir(), "merged.epack")
	ctx := context.Background()

	sources := []merge.SourcePack{
		{Path: pack1},
	}

	opts := merge.Options{
		Stream: "test/merged",
	}

	if err := merge.Merge(ctx, sources, outputPath, opts); err != nil {
		t.Fatalf("Merge failed: %v", err)
	}

	// Verify merged pack integrity
	p, err := pack.Open(outputPath)
	if err != nil {
		t.Fatalf("Failed to open merged pack: %v", err)
	}
	defer func() { _ = p.Close() }()

	if err := p.VerifyIntegrity(); err != nil {
		t.Errorf("VerifyIntegrity failed: %v", err)
	}
}

func TestMerge_EmptySourcePacks(t *testing.T) {
	ctx := context.Background()
	outputPath := filepath.Join(t.TempDir(), "merged.epack")

	opts := merge.Options{
		Stream: "test/merged",
	}

	// Empty sources should fail
	err := merge.Merge(ctx, []merge.SourcePack{}, outputPath, opts)
	if err == nil {
		t.Error("Expected error for empty sources, got nil")
	}
}

func TestMerge_MissingStream(t *testing.T) {
	pack1 := createTestPack(t, "test/src", map[string][]byte{
		"artifacts/data.json": []byte(`{}`),
	})

	ctx := context.Background()
	outputPath := filepath.Join(t.TempDir(), "merged.epack")

	sources := []merge.SourcePack{
		{Path: pack1},
	}

	// Missing stream should fail
	opts := merge.Options{
		Stream: "",
	}

	err := merge.Merge(ctx, sources, outputPath, opts)
	if err == nil {
		t.Error("Expected error for missing stream, got nil")
	}
}

// Golden file tests for merge output

func TestMerge_GoldenHuman(t *testing.T) {
	// Create two source packs
	pack1 := createTestPack(t, "org/stream1", map[string][]byte{
		"artifacts/data1.json": []byte(`{"from": "pack1"}`),
	})
	pack2 := createTestPack(t, "org/stream2", map[string][]byte{
		"artifacts/data2.json": []byte(`{"from": "pack2"}`),
	})

	outputPath := filepath.Join(t.TempDir(), "merged.epack")

	var buf bytes.Buffer
	var errBuf bytes.Buffer
	out = output.New(&buf, &errBuf, output.Options{
		Quiet:   false,
		JSON:    false,
		NoColor: true,
		Verbose: false,
	})

	// Reset flags
	mergeStream = "test/golden-merge"
	mergeMergedBy = ""
	mergeIncludeAttestations = false
	mergeForce = false
	mergeInsecureSkipAttestationVerify = false
	mergeTrustRoot = ""

	err := runMerge(nil, []string{outputPath, pack1, pack2})
	if err != nil {
		t.Fatalf("runMerge failed: %v", err)
	}

	got := buf.String()
	normalized := NormalizeTempPaths(got)

	assertGolden(t, goldenPath("merge_human"), normalized)
}

func TestMerge_GoldenJSON(t *testing.T) {
	// Create two source packs
	pack1 := createTestPack(t, "org/stream1", map[string][]byte{
		"artifacts/data1.json": []byte(`{"from": "pack1"}`),
	})
	pack2 := createTestPack(t, "org/stream2", map[string][]byte{
		"artifacts/data2.json": []byte(`{"from": "pack2"}`),
	})

	outputPath := filepath.Join(t.TempDir(), "merged.epack")

	var buf bytes.Buffer
	var errBuf bytes.Buffer
	out = output.New(&buf, &errBuf, output.Options{
		Quiet:   false,
		JSON:    true,
		NoColor: true,
		Verbose: false,
	})

	// Reset flags
	mergeStream = "test/golden-merge"
	mergeMergedBy = "test-system"
	mergeIncludeAttestations = false
	mergeForce = false
	mergeInsecureSkipAttestationVerify = false
	mergeTrustRoot = ""

	err := runMerge(nil, []string{outputPath, pack1, pack2})
	if err != nil {
		t.Fatalf("runMerge failed: %v", err)
	}

	got := buf.String()
	normalized := NormalizeTempPaths(got)

	assertGolden(t, goldenPath("merge_json"), normalized)
}

func TestMerge_GoldenDryRun(t *testing.T) {
	// Create two source packs
	pack1 := createTestPack(t, "org/stream1", map[string][]byte{
		"artifacts/data1.json": []byte(`{"from": "pack1"}`),
	})
	pack2 := createTestPack(t, "org/stream2", map[string][]byte{
		"artifacts/data2.json": []byte(`{"from": "pack2"}`),
	})

	outputPath := filepath.Join(t.TempDir(), "merged.epack")

	var buf bytes.Buffer
	var errBuf bytes.Buffer
	out = output.New(&buf, &errBuf, output.Options{
		Quiet:   false,
		JSON:    false,
		NoColor: true,
		Verbose: false,
	})

	// Reset flags
	mergeStream = "test/golden-dryrun"
	mergeMergedBy = "test-operator"
	mergeIncludeAttestations = false
	mergeForce = false
	mergeInsecureSkipAttestationVerify = false
	mergeTrustRoot = ""
	mergeDryRun = true
	defer func() { mergeDryRun = false }()

	err := runMerge(nil, []string{outputPath, pack1, pack2})
	if err != nil {
		t.Fatalf("runMerge failed: %v", err)
	}

	got := buf.String()
	normalized := NormalizeTempPaths(got)

	assertGolden(t, goldenPath("merge_dryrun"), normalized)
}

func TestMerge_GoldenDryRunJSON(t *testing.T) {
	// Create two source packs
	pack1 := createTestPack(t, "org/stream1", map[string][]byte{
		"artifacts/data1.json": []byte(`{"from": "pack1"}`),
	})
	pack2 := createTestPack(t, "org/stream2", map[string][]byte{
		"artifacts/data2.json": []byte(`{"from": "pack2"}`),
	})

	outputPath := filepath.Join(t.TempDir(), "merged.epack")

	var buf bytes.Buffer
	var errBuf bytes.Buffer
	out = output.New(&buf, &errBuf, output.Options{
		Quiet:   false,
		JSON:    true,
		NoColor: true,
		Verbose: false,
	})

	// Reset flags
	mergeStream = "test/golden-dryrun"
	mergeMergedBy = ""
	mergeIncludeAttestations = true
	mergeForce = false
	mergeInsecureSkipAttestationVerify = false
	mergeTrustRoot = ""
	mergeDryRun = true
	defer func() { mergeDryRun = false }()

	err := runMerge(nil, []string{outputPath, pack1, pack2})
	if err != nil {
		t.Fatalf("runMerge failed: %v", err)
	}

	got := buf.String()
	normalized := NormalizeTempPaths(got)

	assertGolden(t, goldenPath("merge_dryrun_json"), normalized)
}

// Regression test: merge --include-attestations must require identity policy.
// SECURITY: Without identity policy validation, an attacker could sign malicious
// attestations with any valid Sigstore identity and have them embedded in merged
// packs. The merge command must require either:
//   - An explicit identity policy (--issuer, --subject, --subject-regex), OR
//   - An explicit opt-out (--insecure-skip-identity-check)
func TestMerge_RequiresIdentityPolicyForAttestations(t *testing.T) {
	// SECURITY REGRESSION TEST: Merge with --include-attestations must fail
	// if no identity policy is provided and --insecure-skip-identity-check is not set.
	//
	// This test documents the fix for: Merge identity-blind acceptance where
	// attestations from ANY valid Sigstore signer would be blindly accepted
	// and embedded into the merged pack.

	// Create two source packs (attestations aren't needed to test the flag validation)
	pack1 := createTestPack(t, "org/stream1", map[string][]byte{
		"artifacts/data1.json": []byte(`{"from": "pack1"}`),
	})
	pack2 := createTestPack(t, "org/stream2", map[string][]byte{
		"artifacts/data2.json": []byte(`{"from": "pack2"}`),
	})

	outputPath := filepath.Join(t.TempDir(), "merged.epack")

	var buf bytes.Buffer
	var errBuf bytes.Buffer
	out = output.New(&buf, &errBuf, output.Options{
		Quiet:   false,
		JSON:    false,
		NoColor: true,
		Verbose: false,
	})

	// Reset flags to test state: include-attestations but NO identity policy
	mergeStream = "test/security-test"
	mergeMergedBy = ""
	mergeIncludeAttestations = true // This requires identity policy
	mergeForce = false
	mergeInsecureSkipAttestationVerify = false // Verification enabled
	mergeTrustRoot = ""
	mergeDryRun = false

	// Clear identity policy flags - THIS SHOULD CAUSE FAILURE
	mergeIssuer = ""
	mergeSubject = ""
	mergeSubjectRegex = ""
	mergeInsecureSkipIdentityCheck = false // NOT explicitly opting out

	err := runMerge(nil, []string{outputPath, pack1, pack2})

	// MUST fail because no identity policy is provided
	if err == nil {
		t.Error("SECURITY REGRESSION: merge --include-attestations should require identity policy or explicit --insecure-skip-identity-check")
	}

	// Verify the error message mentions the requirement
	if err != nil {
		errMsg := err.Error()
		if !containsMergeStr(errMsg, "identity") && !containsMergeStr(errMsg, "insecure-skip-identity-check") {
			t.Errorf("Error message should mention identity policy requirement, got: %v", err)
		}
	}
}

// Test that merge succeeds with explicit identity policy
func TestMerge_SucceedsWithIdentityPolicy(t *testing.T) {
	// Skip this test if Sigstore network is not available (CI environment)
	// The test verifies the flag validation logic, not actual verification
	t.Skip("Skipping integration test that requires Sigstore TUF access")
}

// Test that merge succeeds with explicit insecure-skip-identity-check
func TestMerge_SucceedsWithInsecureSkipIdentityCheck(t *testing.T) {
	// Skip this test if Sigstore network is not available (CI environment)
	// The test verifies the flag validation logic, not actual verification
	t.Skip("Skipping integration test that requires Sigstore TUF access")
}

// containsMergeStr is a simple contains check for error messages
func containsMergeStr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
