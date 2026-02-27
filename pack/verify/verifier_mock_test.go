package verify

import (
	"context"
	"errors"
)

// MockVerifier is a test verifier that returns configurable results.
// Use this for unit testing code that depends on the Verifier interface.
type MockVerifier struct {
	// VerifyFunc is called when Verify is invoked.
	// If nil, returns ErrMockNotConfigured.
	VerifyFunc func(ctx context.Context, attestation []byte) (*Result, error)

	// VerifyCalls records all calls to Verify for assertion.
	VerifyCalls [][]byte
}

// ErrMockNotConfigured is returned when MockVerifier.VerifyFunc is nil.
var ErrMockNotConfigured = errors.New("mock verifier not configured")

// Verify implements the Verifier interface.
func (m *MockVerifier) Verify(ctx context.Context, attestation []byte) (*Result, error) {
	m.VerifyCalls = append(m.VerifyCalls, attestation)
	if m.VerifyFunc != nil {
		return m.VerifyFunc(ctx, attestation)
	}
	return nil, ErrMockNotConfigured
}

// Ensure MockVerifier implements Verifier.
var _ Verifier = (*MockVerifier)(nil)

// NewMockVerifier creates a MockVerifier that always returns the given result.
func NewMockVerifier(result *Result, err error) *MockVerifier {
	return &MockVerifier{
		VerifyFunc: func(ctx context.Context, attestation []byte) (*Result, error) {
			return result, err
		},
	}
}

// NewSuccessVerifier creates a MockVerifier that always succeeds with a basic result.
func NewSuccessVerifier() *MockVerifier {
	return NewMockVerifier(&Result{Verified: true}, nil)
}

// NewFailingVerifier creates a MockVerifier that always returns the given error.
func NewFailingVerifier(err error) *MockVerifier {
	return NewMockVerifier(nil, err)
}
