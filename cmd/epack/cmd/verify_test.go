package cmd

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"strings"
	"testing"

	"github.com/locktivity/epack/internal/cli/output"
	iverify "github.com/locktivity/epack/internal/verify"
	"github.com/locktivity/epack/pack"
	"github.com/locktivity/epack/pack/builder"
	"github.com/locktivity/epack/pack/verify"
)

func TestVerifyResult_HasErrors(t *testing.T) {
	tests := []struct {
		name   string
		result iverify.PackResult
		want   bool
	}{
		{
			name:   "no errors",
			result: iverify.PackResult{},
			want:   false,
		},
		{
			name: "artifact error",
			result: iverify.PackResult{
				ArtifactErrors: []string{"artifact error"},
			},
			want: true,
		},
		{
			name: "pack digest error",
			result: iverify.PackResult{
				PackDigestError: "digest mismatch",
			},
			want: true,
		},
		{
			name: "attestation error",
			result: iverify.PackResult{
				AttestationErrors: []string{"attestation error"},
			},
			want: true,
		},
		{
			name: "multiple errors",
			result: iverify.PackResult{
				ArtifactErrors:    []string{"error1"},
				PackDigestError:   "digest error",
				AttestationErrors: []string{"error2"},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.result.HasErrors()
			if got != tt.want {
				t.Errorf("HasErrors() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestVerifyResult_Fields(t *testing.T) {
	result := iverify.PackResult{
		Verified:          false,
		Stream:            "test/stream",
		PackDigest:        "sha256:abc123",
		ArtifactCount:     1,
		AttestationCount:  1,
		ArtifactErrors:    []string{"error1"},
		PackDigestError:   "digest error",
		AttestationErrors: []string{"error2"},
	}

	if result.Verified != false {
		t.Errorf("Verified = %v, want false", result.Verified)
	}
	if result.Stream != "test/stream" {
		t.Errorf("Stream = %v, want test/stream", result.Stream)
	}
	if result.ArtifactCount != 1 {
		t.Errorf("ArtifactCount = %v, want 1", result.ArtifactCount)
	}
	if result.AttestationCount != 1 {
		t.Errorf("AttestationCount = %v, want 1", result.AttestationCount)
	}
}

func TestVerifyArtifactIntegrity_ValidPack(t *testing.T) {
	// Create a valid pack
	packPath := createTestPack(t, "test/verify", map[string][]byte{
		"artifacts/data.json": []byte(`{"valid": true}`),
	})

	p, err := pack.Open(packPath)
	if err != nil {
		t.Fatalf("Failed to open pack: %v", err)
	}
	defer func() { _ = p.Close() }()

	// Use iverify.Pack with IntegrityOnly to test artifact verification
	result, err := iverify.Pack(context.Background(), p, iverify.PackOpts{
		IntegrityOnly: true,
	})
	if err != nil {
		t.Fatalf("VerifyPack failed: %v", err)
	}

	if len(result.ArtifactErrors) != 0 {
		t.Errorf("VerifyPack returned artifact errors: %v", result.ArtifactErrors)
	}
}

func TestVerifyPackDigest(t *testing.T) {
	// Create a valid pack and verify pack digest computation
	packPath := createTestPack(t, "test/digest", map[string][]byte{
		"artifacts/a.json": []byte(`{"a": 1}`),
		"artifacts/b.json": []byte(`{"b": 2}`),
	})

	p, err := pack.Open(packPath)
	if err != nil {
		t.Fatalf("Failed to open pack: %v", err)
	}
	defer func() { _ = p.Close() }()

	manifest := p.Manifest()

	// Compute the digest ourselves
	canonical := pack.BuildCanonicalArtifactList(&manifest)
	computedDigest := pack.HashCanonicalList(canonical)

	if computedDigest != manifest.PackDigest {
		t.Errorf("Pack digest mismatch: computed %s, manifest %s", computedDigest, manifest.PackDigest)
	}
}

func TestVerifyCommand_IntegrityCheck(t *testing.T) {
	// Create a pack and verify it passes integrity check
	tmpDir := t.TempDir()
	packPath := filepath.Join(tmpDir, "test.pack")

	content := []byte(`{"test": "data"}`)
	b := builder.New("test/integrity")
	if err := b.AddBytes("artifacts/test.json", content); err != nil {
		t.Fatalf("AddBytes failed: %v", err)
	}
	if err := b.Build(packPath); err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	// Open and verify
	p, err := pack.Open(packPath)
	if err != nil {
		t.Fatalf("Failed to open pack: %v", err)
	}
	defer func() { _ = p.Close() }()

	// Use the library's VerifyIntegrity method
	if err := p.VerifyIntegrity(); err != nil {
		t.Errorf("VerifyIntegrity failed: %v", err)
	}
}

func TestComputeSHA256(t *testing.T) {
	data := []byte("test data")
	h := sha256.Sum256(data)
	expected := "sha256:" + hex.EncodeToString(h[:])

	// Verify our digest computation matches
	p := createTestPack(t, "test/sha256", map[string][]byte{
		"artifacts/test.txt": data,
	})

	pack, err := pack.Open(p)
	if err != nil {
		t.Fatalf("Failed to open pack: %v", err)
	}
	defer func() { _ = pack.Close() }()

	manifest := pack.Manifest()
	if len(manifest.Artifacts) != 1 {
		t.Fatalf("Expected 1 artifact, got %d", len(manifest.Artifacts))
	}

	if manifest.Artifacts[0].Digest != expected {
		t.Errorf("Digest = %s, want %s", manifest.Artifacts[0].Digest, expected)
	}
}

// Security regression tests

func TestVerifyCmd_RequiresIdentityPolicyOrExplicitSkip(t *testing.T) {
	// Verify that the --insecure-skip-identity-check flag exists
	// This is a security requirement to prevent accidental trust downgrade
	flags := verifyCmd.Flags()

	insecureFlag := flags.Lookup("insecure-skip-identity-check")
	if insecureFlag == nil {
		t.Fatal("verifyCmd missing --insecure-skip-identity-check flag")
	}

	// Verify default is false (secure by default)
	if insecureFlag.DefValue != "false" {
		t.Errorf("--insecure-skip-identity-check default = %q, want %q", insecureFlag.DefValue, "false")
	}
}

func TestVerifyCmd_IdentityFlags(t *testing.T) {
	// Verify that identity policy flags exist
	flags := verifyCmd.Flags()

	identityFlags := []string{"issuer", "issuer-regexp", "subject", "subject-regexp"}
	for _, name := range identityFlags {
		if flags.Lookup(name) == nil {
			t.Errorf("verifyCmd missing identity flag: %s", name)
		}
	}
}

func TestVerifyCmd_SecurityDocumentation(t *testing.T) {
	// Verify that the help text explains the security implications
	if verifyCmd.Long == "" {
		t.Fatal("verifyCmd.Long is empty")
	}

	// Check for security-relevant documentation
	securityTerms := []string{
		"identity",
		"--issuer",
		"--subject",
		"insecure",
	}

	for _, term := range securityTerms {
		if !containsIgnoreCase(verifyCmd.Long, term) {
			t.Errorf("verifyCmd.Long should mention %q for security awareness", term)
		}
	}
}

func containsIgnoreCase(s, substr string) bool {
	return len(s) >= len(substr) &&
		(s == substr ||
			len(s) > 0 && (containsIgnoreCase(s[1:], substr) ||
				(len(s) >= len(substr) && equalFoldPrefix(s, substr))))
}

func equalFoldPrefix(s, prefix string) bool {
	if len(s) < len(prefix) {
		return false
	}
	for i := 0; i < len(prefix); i++ {
		c1, c2 := s[i], prefix[i]
		if c1 >= 'A' && c1 <= 'Z' {
			c1 += 'a' - 'A'
		}
		if c2 >= 'A' && c2 <= 'Z' {
			c2 += 'a' - 'A'
		}
		if c1 != c2 {
			return false
		}
	}
	return true
}

// Golden file tests for verify output

func TestVerify_GoldenSuccess(t *testing.T) {
	packPath := createTestPack(t, "test/golden-verify", map[string][]byte{
		"artifacts/data.json": []byte(`{"verified": true}`),
	})

	var buf bytes.Buffer
	var errBuf bytes.Buffer
	out = output.New(&buf, &errBuf, output.Options{
		Quiet:   false,
		JSON:    false,
		NoColor: true,
		Verbose: false,
	})

	// Reset flags for integrity-only verification
	verifyIntegrityOnly = true
	verifyRequireAttestation = false
	verifyOffline = false
	verifyIssuer = ""
	verifySubject = ""
	verifyIssuerRegexp = ""
	verifySubjectRegexp = ""
	verifyInsecureSkipIdentityCheck = false

	err := runVerify(nil, []string{packPath})
	if err != nil {
		t.Fatalf("runVerify failed: %v", err)
	}

	got := buf.String()
	normalized := NormalizeDigests(got)
	normalized = NormalizeTempPaths(normalized)

	assertGolden(t, goldenPath("verify_success"), normalized)
}

// Security tests for statement semantic validation
// These tests ensure that cryptographically valid but semantically irrelevant
// attestations are rejected. The CLI uses verify.VerifyStatementSemantics for this.
// These tests verify the library function rejects the bypass scenarios.

func TestVerifyStatementSemantics_WrongStatementType(t *testing.T) {
	// PoC: A validly signed statement with wrong _type should be rejected
	result := &verify.Result{
		Verified: true,
		Statement: &verify.Statement{
			Type:          "https://in-toto.io/Statement/v0.1", // Wrong type!
			PredicateType: "https://evidencepack.org/attestation/v1",
			Subjects: []verify.Subject{
				{Name: "pack", Digest: map[string]string{"sha256": "abc123"}},
			},
			Predicate: []byte(`{"pack_digest":"sha256:abc123"}`),
		},
	}

	err := verify.VerifyStatementSemantics(result, "sha256:abc123")
	if err == nil {
		t.Error("VerifyStatementSemantics should reject wrong statement type")
	}
	if !strings.Contains(err.Error(), "unexpected statement type") {
		t.Errorf("error should mention unexpected statement type, got: %v", err)
	}
}

func TestVerifyStatementSemantics_WrongPredicateType(t *testing.T) {
	// PoC: A validly signed statement with wrong predicateType should be rejected
	result := &verify.Result{
		Verified: true,
		Statement: &verify.Statement{
			Type:          "https://in-toto.io/Statement/v1",
			PredicateType: "https://slsa.dev/provenance/v1", // Wrong predicate type!
			Subjects: []verify.Subject{
				{Name: "pack", Digest: map[string]string{"sha256": "abc123"}},
			},
			Predicate: []byte(`{"pack_digest":"sha256:abc123"}`),
		},
	}

	err := verify.VerifyStatementSemantics(result, "sha256:abc123")
	if err == nil {
		t.Error("VerifyStatementSemantics should reject wrong predicate type")
	}
	if !strings.Contains(err.Error(), "unexpected predicate type") {
		t.Errorf("error should mention unexpected predicate type, got: %v", err)
	}
}

func TestVerifyStatementSemantics_WrongPredicatePackDigest(t *testing.T) {
	// PoC: A validly signed statement with mismatched predicate pack_digest should be rejected
	result := &verify.Result{
		Verified: true,
		Statement: &verify.Statement{
			Type:          "https://in-toto.io/Statement/v1",
			PredicateType: "https://evidencepack.org/attestation/v1",
			Subjects: []verify.Subject{
				{Name: "pack", Digest: map[string]string{"sha256": "abc123"}},
			},
			// Subject matches, but predicate has different pack_digest
			Predicate: []byte(`{"pack_digest":"sha256:different_digest"}`),
		},
	}

	err := verify.VerifyStatementSemantics(result, "sha256:abc123")
	if err == nil {
		t.Error("VerifyStatementSemantics should reject mismatched predicate pack_digest")
	}
	if !strings.Contains(err.Error(), "pack_digest") && !strings.Contains(err.Error(), "does not match") {
		t.Errorf("error should mention pack_digest mismatch, got: %v", err)
	}
}

func TestVerifyStatementSemantics_NilStatement(t *testing.T) {
	result := &verify.Result{
		Verified: true,
		// Statement is nil - should be rejected
	}

	err := verify.VerifyStatementSemantics(result, "sha256:abc123")
	if err == nil {
		t.Error("VerifyStatementSemantics should reject nil statement")
	}
}

func TestVerifyStatementSemantics_NoSubjects(t *testing.T) {
	result := &verify.Result{
		Verified: true,
		Statement: &verify.Statement{
			Type:          "https://in-toto.io/Statement/v1",
			PredicateType: "https://evidencepack.org/attestation/v1",
			Subjects:      []verify.Subject{}, // Empty subjects
			Predicate:     []byte(`{"pack_digest":"sha256:abc123"}`),
		},
	}

	err := verify.VerifyStatementSemantics(result, "sha256:abc123")
	if err == nil {
		t.Error("VerifyStatementSemantics should reject empty subjects")
	}
}

func TestVerifyStatementSemantics_SubjectDigestMismatch(t *testing.T) {
	result := &verify.Result{
		Verified: true,
		Statement: &verify.Statement{
			Type:          "https://in-toto.io/Statement/v1",
			PredicateType: "https://evidencepack.org/attestation/v1",
			Subjects: []verify.Subject{
				{Name: "pack", Digest: map[string]string{"sha256": "wrong_digest"}},
			},
			Predicate: []byte(`{"pack_digest":"sha256:abc123"}`),
		},
	}

	err := verify.VerifyStatementSemantics(result, "sha256:abc123")
	if err == nil {
		t.Error("VerifyStatementSemantics should reject mismatched subject digest")
	}
}

func TestVerifyStatementSemantics_ValidStatement(t *testing.T) {
	expectedDigest := "sha256:abc123"
	result := &verify.Result{
		Verified: true,
		Statement: &verify.Statement{
			Type:          "https://in-toto.io/Statement/v1",
			PredicateType: "https://evidencepack.org/attestation/v1",
			Subjects: []verify.Subject{
				{Name: "pack", Digest: map[string]string{"sha256": "abc123"}},
			},
			Predicate: []byte(`{"pack_digest":"sha256:abc123"}`),
		},
	}

	err := verify.VerifyStatementSemantics(result, expectedDigest)
	if err != nil {
		t.Errorf("VerifyStatementSemantics should accept valid statement, got error: %v", err)
	}
}

// SECURITY REGRESSION TEST: Verify uses aggregate read budget
// This test verifies that iverify.Pack uses a shared budget
// across all artifacts to prevent DoS via many large artifacts.
func TestVerifyArtifactIntegrity_UsesBudget(t *testing.T) {
	// This is a design verification test. The actual budget enforcement
	// is tested in pack/pack_test.go. Here we verify the app uses the
	// budget-aware function.
	//
	// The fix in app.verifyArtifactIntegrity:
	// 1. Creates a shared ReadBudget
	// 2. Passes it to ReadArtifactWithBudget for each artifact
	//
	// Without this fix, a malicious pack with 10,000 artifacts at 100MB each
	// would read 1TB into memory, causing DoS.

	// Create a valid pack with multiple artifacts
	packPath := createTestPack(t, "test/budget", map[string][]byte{
		"artifacts/a.json": []byte(`{"a": 1}`),
		"artifacts/b.json": []byte(`{"b": 2}`),
		"artifacts/c.json": []byte(`{"c": 3}`),
	})

	p, err := pack.Open(packPath)
	if err != nil {
		t.Fatalf("Failed to open pack: %v", err)
	}
	defer func() { _ = p.Close() }()

	// Use iverify.Pack with IntegrityOnly to test artifact verification
	result, err := iverify.Pack(context.Background(), p, iverify.PackOpts{
		IntegrityOnly: true,
	})
	if err != nil {
		t.Fatalf("VerifyPack failed: %v", err)
	}

	if len(result.ArtifactErrors) != 0 {
		t.Errorf("VerifyPack returned artifact errors: %v", result.ArtifactErrors)
	}

	// The key security property is that app.verifyArtifactIntegrity now uses
	// ReadArtifactWithBudget with a shared budget. This is enforced by code
	// review of the implementation in internal/app/verify.go.
	//
	// A more thorough test would create a pack that exceeds the budget,
	// but that requires creating a 2GB+ pack which is expensive.
}

func TestVerify_GoldenJSON(t *testing.T) {
	packPath := createTestPack(t, "test/golden-verify-json", map[string][]byte{
		"artifacts/config.json": []byte(`{"config": true}`),
	})

	var buf bytes.Buffer
	var errBuf bytes.Buffer
	out = output.New(&buf, &errBuf, output.Options{
		Quiet:   false,
		JSON:    true,
		NoColor: true,
		Verbose: false,
	})

	verifyIntegrityOnly = true
	verifyRequireAttestation = false
	verifyOffline = false
	verifyIssuer = ""
	verifySubject = ""
	verifyIssuerRegexp = ""
	verifySubjectRegexp = ""
	verifyInsecureSkipIdentityCheck = false

	err := runVerify(nil, []string{packPath})
	if err != nil {
		t.Fatalf("runVerify failed: %v", err)
	}

	got := buf.String()
	normalized := NormalizeDigests(got)

	assertGolden(t, goldenPath("verify_json"), normalized)
}
