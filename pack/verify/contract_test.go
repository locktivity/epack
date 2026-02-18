package verify

import (
	"context"
	"encoding/json"
	"testing"
)

// =============================================================================
// Verifier Interface Contract Tests
// =============================================================================
// These tests define the contract that all Verifier implementations must satisfy.
// Run these against any new Verifier implementation to ensure compliance.

// TestVerifierContract_NilAttestationReturnsError verifies that all Verifier
// implementations return an error when given nil attestation data.
func TestVerifierContract_NilAttestationReturnsError(t *testing.T) {
	t.Parallel()

	// Create verifier with skip identity check (we're testing input validation)
	verifier, err := NewSigstoreVerifier(WithInsecureSkipIdentityCheck())
	if err != nil {
		t.Fatalf("failed to create verifier: %v", err)
	}

	ctx := context.Background()

	_, err = verifier.Verify(ctx, nil)
	if err == nil {
		t.Error("Verify(nil) should return error")
	}
}

// TestVerifierContract_EmptyAttestationReturnsError verifies that empty
// attestation data returns an error.
func TestVerifierContract_EmptyAttestationReturnsError(t *testing.T) {
	t.Parallel()

	verifier, err := NewSigstoreVerifier(WithInsecureSkipIdentityCheck())
	if err != nil {
		t.Fatalf("failed to create verifier: %v", err)
	}

	ctx := context.Background()

	_, err = verifier.Verify(ctx, []byte{})
	if err == nil {
		t.Error("Verify(empty) should return error")
	}
}

// TestVerifierContract_InvalidJSONReturnsError verifies that malformed JSON
// returns an error.
func TestVerifierContract_InvalidJSONReturnsError(t *testing.T) {
	t.Parallel()

	verifier, err := NewSigstoreVerifier(WithInsecureSkipIdentityCheck())
	if err != nil {
		t.Fatalf("failed to create verifier: %v", err)
	}

	ctx := context.Background()

	invalidInputs := [][]byte{
		[]byte("not json"),
		[]byte("{invalid}"),
		[]byte(`{"unclosed": `),
		[]byte(`[1, 2, 3]`), // Valid JSON but wrong type
	}

	for _, input := range invalidInputs {
		_, err := verifier.Verify(ctx, input)
		if err == nil {
			t.Errorf("Verify(%q) should return error", input)
		}
	}
}

// TestVerifierContract_WrongMediaTypeReturnsError verifies that bundles with
// incorrect media type are rejected.
func TestVerifierContract_WrongMediaTypeReturnsError(t *testing.T) {
	t.Parallel()

	verifier, err := NewSigstoreVerifier(WithInsecureSkipIdentityCheck())
	if err != nil {
		t.Fatalf("failed to create verifier: %v", err)
	}

	ctx := context.Background()

	// Bundle with wrong media type
	wrongTypeBundle := map[string]interface{}{
		"mediaType":            "application/vnd.wrong+json",
		"verificationMaterial": map[string]interface{}{},
		"dsseEnvelope":         map[string]interface{}{},
	}

	data, _ := json.Marshal(wrongTypeBundle)
	_, err = verifier.Verify(ctx, data)
	if err == nil {
		t.Error("Verify with wrong media type should return error")
	}
}

// TestVerifierContract_MissingFieldsReturnsError verifies that incomplete
// bundles are rejected.
func TestVerifierContract_MissingFieldsReturnsError(t *testing.T) {
	t.Parallel()

	verifier, err := NewSigstoreVerifier(WithInsecureSkipIdentityCheck())
	if err != nil {
		t.Fatalf("failed to create verifier: %v", err)
	}

	ctx := context.Background()

	// Empty bundle
	emptyBundle := map[string]interface{}{}

	data, _ := json.Marshal(emptyBundle)
	_, err = verifier.Verify(ctx, data)
	if err == nil {
		t.Error("Verify with empty bundle should return error")
	}
}

// TestVerifierContract_ContextCancellation verifies that verification respects
// context cancellation (where applicable).
func TestVerifierContract_ContextCancellation(t *testing.T) {
	t.Parallel()

	verifier, err := NewSigstoreVerifier(
		WithInsecureSkipIdentityCheck(),
		WithOffline(), // Don't need network for this test
	)
	if err != nil {
		t.Fatalf("failed to create verifier: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	// Note: The current sigstore-go implementation doesn't check context during
	// verification, so this test documents the current behavior rather than
	// asserting cancellation. A future implementation may honor cancellation.
	_, _ = verifier.Verify(ctx, []byte(`{}`))
	// We just verify it doesn't panic with cancelled context
}

// TestVerifierContract_RequiresIdentityPolicyOrExplicitSkip verifies that
// creating a verifier without identity policy and without explicit skip fails.
func TestVerifierContract_RequiresIdentityPolicyOrExplicitSkip(t *testing.T) {
	t.Parallel()

	// Create verifier WITHOUT any identity options
	verifier, err := NewSigstoreVerifier(WithOffline())
	if err != nil {
		t.Fatalf("failed to create verifier: %v", err)
	}

	ctx := context.Background()

	// Create a minimal but structurally valid bundle
	bundle := createMinimalBundle(t)
	data, _ := json.Marshal(bundle)

	_, err = verifier.Verify(ctx, data)
	if err == nil {
		t.Error("Verify without identity policy should return error")
	}

	// Error should mention identity policy requirement
	if err != nil && !containsAny(err.Error(), []string{"identity", "issuer", "subject"}) {
		t.Errorf("Error should mention identity policy, got: %v", err)
	}
}

// TestVerifierContract_ResultFieldsOnSuccess verifies that successful
// verification populates required result fields.
func TestVerifierContract_ResultFieldsOnSuccess(t *testing.T) {
	// This test would require a valid signed bundle, which needs network access
	// or a test fixture. Skipping for now but documenting the expected contract.
	t.Skip("Requires valid signed bundle fixture")

	// When verification succeeds:
	// - Result.Verified MUST be true
	// - Result.Identity SHOULD be non-nil (may be nil with InsecureSkipIdentityCheck)
	// - Result.Statement SHOULD be non-nil for DSSE envelopes
	// - Result.Timestamps SHOULD have at least one entry (when using tlog)
}

// TestVerifierContract_VerifiedFalseNotReturned verifies that a Result with
// Verified=false is never returned without an accompanying error.
// If verification fails, an error MUST be returned.
func TestVerifierContract_VerifiedFalseNotReturned(t *testing.T) {
	t.Parallel()

	// This is a design contract: we never return (Result{Verified: false}, nil)
	// Either we return (Result{Verified: true}, nil) on success
	// Or we return (nil, error) on failure

	// Test with various invalid inputs
	verifier, err := NewSigstoreVerifier(WithInsecureSkipIdentityCheck())
	if err != nil {
		t.Fatalf("failed to create verifier: %v", err)
	}

	ctx := context.Background()

	testCases := [][]byte{
		nil,
		{},
		[]byte("invalid"),
		[]byte(`{}`),
		[]byte(`{"mediaType": "wrong"}`),
	}

	for _, tc := range testCases {
		result, err := verifier.Verify(ctx, tc)
		if err == nil && result != nil && !result.Verified {
			t.Errorf("Got (Result{Verified: false}, nil) for input %q - should return error instead", tc)
		}
	}
}

// =============================================================================
// Helper Functions
// =============================================================================

// createMinimalBundle creates a structurally valid but cryptographically invalid bundle.
func createMinimalBundle(t *testing.T) map[string]interface{} {
	t.Helper()
	return map[string]interface{}{
		"mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.1",
		"verificationMaterial": map[string]interface{}{
			"publicKey": map[string]interface{}{
				"hint": "test",
			},
		},
		"dsseEnvelope": map[string]interface{}{
			"payloadType": "application/vnd.in-toto+json",
			"payload":     "", // Base64-encoded payload
			"signatures":  []interface{}{},
		},
	}
}

// containsAny checks if s contains any of the substrings.
func containsAny(s string, substrs []string) bool {
	for _, sub := range substrs {
		if len(s) >= len(sub) {
			for i := 0; i <= len(s)-len(sub); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
		}
	}
	return false
}

// =============================================================================
// Option Contract Tests
// =============================================================================

// TestWithOfflineOption verifies the WithOffline option behavior.
func TestWithOfflineOption(t *testing.T) {
	t.Parallel()

	// Should succeed - offline mode doesn't require network
	verifier, err := NewSigstoreVerifier(
		WithOffline(),
		WithInsecureSkipIdentityCheck(),
	)
	if err != nil {
		t.Fatalf("NewSigstoreVerifier with WithOffline failed: %v", err)
	}
	if verifier == nil {
		t.Error("verifier should not be nil")
	}
}

// TestWithIssuerOption verifies the WithIssuer option configures identity policy.
func TestWithIssuerOption(t *testing.T) {
	t.Parallel()

	// Should succeed - issuer provides identity policy
	verifier, err := NewSigstoreVerifier(
		WithIssuer("https://accounts.google.com"),
		WithOffline(),
	)
	if err != nil {
		t.Fatalf("NewSigstoreVerifier with WithIssuer failed: %v", err)
	}
	if verifier == nil {
		t.Error("verifier should not be nil")
	}
}

// TestWithSubjectOption verifies the WithSubject option configures identity policy.
func TestWithSubjectOption(t *testing.T) {
	t.Parallel()

	// Should succeed - subject provides identity policy
	verifier, err := NewSigstoreVerifier(
		WithSubject("test@example.com"),
		WithOffline(),
	)
	if err != nil {
		t.Fatalf("NewSigstoreVerifier with WithSubject failed: %v", err)
	}
	if verifier == nil {
		t.Error("verifier should not be nil")
	}
}

// TestCombinedOptions verifies multiple options can be combined.
func TestCombinedOptions(t *testing.T) {
	t.Parallel()

	verifier, err := NewSigstoreVerifier(
		WithIssuer("https://accounts.google.com"),
		WithSubject("test@example.com"),
		WithOffline(),
		WithTransparencyLogThreshold(0),
	)
	if err != nil {
		t.Fatalf("NewSigstoreVerifier with combined options failed: %v", err)
	}
	if verifier == nil {
		t.Error("verifier should not be nil")
	}
}
