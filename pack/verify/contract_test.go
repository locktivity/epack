package verify

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
)

// =============================================================================
// Verifier Interface Contract Tests
// =============================================================================
// These tests define the contract that all Verifier implementations must satisfy.
// They use MockVerifier to test interface behavior without network dependencies.

// TestVerifierContract_VerifiedFalseNeverReturnedWithNilError verifies that a Result
// with Verified=false is never returned without an accompanying error.
// If verification fails, an error MUST be returned.
func TestVerifierContract_VerifiedFalseNeverReturnedWithNilError(t *testing.T) {
	t.Parallel()

	// This is a design contract: we never return (Result{Verified: false}, nil)
	// Either we return (Result{Verified: true}, nil) on success
	// Or we return (nil, error) on failure

	// A well-behaved Verifier should never do this:
	badVerifier := &MockVerifier{
		VerifyFunc: func(ctx context.Context, attestation []byte) (*Result, error) {
			return &Result{Verified: false}, nil // BAD: Verified=false with nil error
		},
	}

	result, err := badVerifier.Verify(context.Background(), []byte("test"))
	if err == nil && result != nil && !result.Verified {
		// This documents the contract violation - implementations MUST NOT do this
		t.Log("Contract violation detected: (Result{Verified: false}, nil) returned")
		t.Log("Implementations should return (nil, error) when verification fails")
	}

	// A well-behaved Verifier returns error on failure:
	goodVerifier := NewFailingVerifier(errors.New("verification failed"))
	result, err = goodVerifier.Verify(context.Background(), []byte("test"))
	if err == nil {
		t.Error("Failing verifier should return error")
	}
	if result != nil && !result.Verified {
		t.Error("Failing verifier should not return Result{Verified: false}")
	}
}

// TestVerifierContract_SuccessReturnsVerifiedTrue verifies that successful
// verification always sets Verified=true.
func TestVerifierContract_SuccessReturnsVerifiedTrue(t *testing.T) {
	t.Parallel()

	verifier := NewSuccessVerifier()
	result, err := verifier.Verify(context.Background(), []byte("test"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("result should not be nil on success")
	}
	if !result.Verified {
		t.Error("Result.Verified should be true on success")
	}
}

// TestVerifierContract_ContextPassedToVerify verifies that context is passed through.
func TestVerifierContract_ContextPassedToVerify(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	var receivedCtx context.Context
	verifier := &MockVerifier{
		VerifyFunc: func(ctx context.Context, attestation []byte) (*Result, error) {
			receivedCtx = ctx
			return &Result{Verified: true}, nil
		},
	}

	_, _ = verifier.Verify(ctx, []byte("test"))

	if receivedCtx == nil {
		t.Error("context should be passed to VerifyFunc")
	}
	if receivedCtx.Err() == nil {
		t.Error("context should be cancelled")
	}
}

// TestVerifierContract_CallsRecorded verifies that MockVerifier records calls.
func TestVerifierContract_CallsRecorded(t *testing.T) {
	t.Parallel()

	verifier := NewSuccessVerifier()

	input1 := []byte("input1")
	input2 := []byte("input2")

	_, _ = verifier.Verify(context.Background(), input1)
	_, _ = verifier.Verify(context.Background(), input2)

	if len(verifier.VerifyCalls) != 2 {
		t.Errorf("expected 2 calls, got %d", len(verifier.VerifyCalls))
	}
	if string(verifier.VerifyCalls[0]) != "input1" {
		t.Errorf("first call should be 'input1', got %q", verifier.VerifyCalls[0])
	}
	if string(verifier.VerifyCalls[1]) != "input2" {
		t.Errorf("second call should be 'input2', got %q", verifier.VerifyCalls[1])
	}
}

// =============================================================================
// SigstoreVerifier Implementation Tests
// =============================================================================
// These tests verify the SigstoreVerifier-specific behavior.
// They require network access for TUF root fetch - tests skip if unavailable.

// mustCreateSigstoreVerifier creates a SigstoreVerifier for testing.
// Skips the test if network is unavailable (TUF fetch fails).
func mustCreateSigstoreVerifier(t *testing.T, opts ...Option) *SigstoreVerifier {
	t.Helper()
	cfg := applyOptions(opts)
	if cfg.offline && cfg.trustedRoot == nil {
		opts = append(opts, WithTrustedRoot(mustLoadTestTrustedRoot(t)))
	}
	verifier, err := NewSigstoreVerifier(opts...)
	if err != nil {
		t.Skipf("skipping test, cannot create verifier (network may be unavailable): %v", err)
	}
	return verifier
}

// TestSigstoreVerifier_NilAttestationReturnsError verifies that nil attestation
// returns an error.
func TestSigstoreVerifier_NilAttestationReturnsError(t *testing.T) {
	t.Parallel()

	verifier := mustCreateSigstoreVerifier(t, WithInsecureSkipIdentityCheck())

	_, err := verifier.Verify(context.Background(), nil)
	if err == nil {
		t.Error("Verify(nil) should return error")
	}
}

// TestSigstoreVerifier_EmptyAttestationReturnsError verifies that empty
// attestation data returns an error.
func TestSigstoreVerifier_EmptyAttestationReturnsError(t *testing.T) {
	t.Parallel()

	verifier := mustCreateSigstoreVerifier(t, WithInsecureSkipIdentityCheck())

	_, err := verifier.Verify(context.Background(), []byte{})
	if err == nil {
		t.Error("Verify(empty) should return error")
	}
}

// TestSigstoreVerifier_InvalidJSONReturnsError verifies that malformed JSON
// returns an error.
func TestSigstoreVerifier_InvalidJSONReturnsError(t *testing.T) {
	t.Parallel()

	verifier := mustCreateSigstoreVerifier(t, WithInsecureSkipIdentityCheck())

	invalidInputs := [][]byte{
		[]byte("not json"),
		[]byte("{invalid}"),
		[]byte(`{"unclosed": `),
		[]byte(`[1, 2, 3]`), // Valid JSON but wrong type
	}

	for _, input := range invalidInputs {
		_, err := verifier.Verify(context.Background(), input)
		if err == nil {
			t.Errorf("Verify(%q) should return error", input)
		}
	}
}

// TestSigstoreVerifier_WrongMediaTypeReturnsError verifies that bundles with
// incorrect media type are rejected.
func TestSigstoreVerifier_WrongMediaTypeReturnsError(t *testing.T) {
	t.Parallel()

	verifier := mustCreateSigstoreVerifier(t, WithInsecureSkipIdentityCheck())

	// Bundle with wrong media type
	wrongTypeBundle := map[string]interface{}{
		"mediaType":            "application/vnd.wrong+json",
		"verificationMaterial": map[string]interface{}{},
		"dsseEnvelope":         map[string]interface{}{},
	}

	data, _ := json.Marshal(wrongTypeBundle)
	_, err := verifier.Verify(context.Background(), data)
	if err == nil {
		t.Error("Verify with wrong media type should return error")
	}
}

// TestSigstoreVerifier_MissingFieldsReturnsError verifies that incomplete
// bundles are rejected.
func TestSigstoreVerifier_MissingFieldsReturnsError(t *testing.T) {
	t.Parallel()

	verifier := mustCreateSigstoreVerifier(t, WithInsecureSkipIdentityCheck())

	// Empty bundle
	emptyBundle := map[string]interface{}{}

	data, _ := json.Marshal(emptyBundle)
	_, err := verifier.Verify(context.Background(), data)
	if err == nil {
		t.Error("Verify with empty bundle should return error")
	}
}

// TestSigstoreVerifier_ContextCancellation verifies that verification respects
// context cancellation (where applicable).
func TestSigstoreVerifier_ContextCancellation(t *testing.T) {
	t.Parallel()

	verifier := mustCreateSigstoreVerifier(t,
		WithInsecureSkipIdentityCheck(),
		WithOffline(),
	)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	// Note: The current sigstore-go implementation doesn't check context during
	// verification, so this test documents the current behavior rather than
	// asserting cancellation. A future implementation may honor cancellation.
	_, _ = verifier.Verify(ctx, []byte(`{}`))
	// We just verify it doesn't panic with cancelled context
}

// TestSigstoreVerifier_RequiresIdentityPolicyOrExplicitSkip verifies that
// creating a verifier without identity policy and without explicit skip fails.
func TestSigstoreVerifier_RequiresIdentityPolicyOrExplicitSkip(t *testing.T) {
	t.Parallel()

	// Create verifier WITHOUT any identity options
	verifier := mustCreateSigstoreVerifier(t, WithOffline())

	// Create a minimal but structurally valid bundle
	bundle := createMinimalBundle(t)
	data, _ := json.Marshal(bundle)

	_, err := verifier.Verify(context.Background(), data)
	if err == nil {
		t.Error("Verify without identity policy should return error")
	}

	// Error should mention identity policy requirement
	if err != nil && !containsAny(err.Error(), []string{"identity", "issuer", "subject"}) {
		t.Errorf("Error should mention identity policy, got: %v", err)
	}
}

// TestSigstoreVerifier_VerifiedFalseNotReturned verifies that a Result with
// Verified=false is never returned without an accompanying error.
func TestSigstoreVerifier_VerifiedFalseNotReturned(t *testing.T) {
	t.Parallel()

	verifier := mustCreateSigstoreVerifier(t, WithInsecureSkipIdentityCheck())

	testCases := [][]byte{
		nil,
		{},
		[]byte("invalid"),
		[]byte(`{}`),
		[]byte(`{"mediaType": "wrong"}`),
	}

	for _, tc := range testCases {
		result, err := verifier.Verify(context.Background(), tc)
		if err == nil && result != nil && !result.Verified {
			t.Errorf("Got (Result{Verified: false}, nil) for input %q - should return error instead", tc)
		}
	}
}

// =============================================================================
// Option Tests
// =============================================================================

// TestWithOfflineOption verifies the WithOffline option behavior.
func TestWithOfflineOption(t *testing.T) {
	t.Parallel()

	verifier := mustCreateSigstoreVerifier(t,
		WithOffline(),
		WithInsecureSkipIdentityCheck(),
	)
	if verifier == nil {
		t.Error("verifier should not be nil")
	}
}

// TestWithIssuerOption verifies the WithIssuer option configures identity policy.
func TestWithIssuerOption(t *testing.T) {
	t.Parallel()

	// Should succeed - issuer provides identity policy
	verifier := mustCreateSigstoreVerifier(t,
		WithIssuer("https://accounts.google.com"),
		WithOffline(),
	)
	if verifier == nil {
		t.Error("verifier should not be nil")
	}
}

// TestWithSubjectOption verifies the WithSubject option configures identity policy.
func TestWithSubjectOption(t *testing.T) {
	t.Parallel()

	// Should succeed - subject provides identity policy
	verifier := mustCreateSigstoreVerifier(t,
		WithSubject("test@example.com"),
		WithOffline(),
	)
	if verifier == nil {
		t.Error("verifier should not be nil")
	}
}

// TestCombinedOptions verifies multiple options can be combined.
func TestCombinedOptions(t *testing.T) {
	t.Parallel()

	verifier := mustCreateSigstoreVerifier(t,
		WithIssuer("https://accounts.google.com"),
		WithSubject("test@example.com"),
		WithOffline(),
		WithTransparencyLogThreshold(0),
	)
	if verifier == nil {
		t.Error("verifier should not be nil")
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
