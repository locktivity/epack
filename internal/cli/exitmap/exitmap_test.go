package exitmap

import (
	"fmt"
	"testing"

	"github.com/locktivity/epack/errors"
	"github.com/locktivity/epack/internal/exitcode"
	"github.com/locktivity/epack/internal/redact"
)

func TestToExit_Nil(t *testing.T) {
	msg, code := ToExit(nil)
	if code != exitcode.Success {
		t.Errorf("ToExit(nil) code = %d, want %d", code, exitcode.Success)
	}
	if msg != "" {
		t.Errorf("ToExit(nil) msg = %q, want empty", msg)
	}
}

func TestToExit_ErrorsError(t *testing.T) {
	// Test with explicit Exit code
	err := &errors.Error{Code: errors.InvalidInput, Exit: 42, Message: "custom error"}
	msg, code := ToExit(err)
	if code != 42 {
		t.Errorf("ToExit(errors.Error) code = %d, want 42", code)
	}
	if msg != "custom error" {
		t.Errorf("ToExit(errors.Error) msg = %q, want %q", msg, "custom error")
	}
}

func TestToExit_TypedErrors(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		wantCode int
	}{
		{
			name:     "LockfileInvalid",
			err:      errors.E(errors.LockfileInvalid, "lockfile error", nil),
			wantCode: exitcode.LockInvalid,
		},
		{
			name:     "DigestMismatch",
			err:      errors.E(errors.DigestMismatch, "digest error", nil),
			wantCode: exitcode.DigestMismatch,
		},
		{
			name:     "PackDigestMismatch",
			err:      errors.E(errors.PackDigestMismatch, "pack digest error", nil),
			wantCode: exitcode.DigestMismatch,
		},
		{
			name:     "SizeMismatch",
			err:      errors.E(errors.SizeMismatch, "size error", nil),
			wantCode: exitcode.DigestMismatch,
		},
		{
			name:     "SignatureInvalid",
			err:      errors.E(errors.SignatureInvalid, "signature error", nil),
			wantCode: exitcode.SignatureMismatch,
		},
		{
			name:     "IdentityMismatch",
			err:      errors.E(errors.IdentityMismatch, "identity error", nil),
			wantCode: exitcode.SignatureMismatch,
		},
		{
			name:     "BinaryNotFound",
			err:      errors.E(errors.BinaryNotFound, "binary error", nil),
			wantCode: exitcode.MissingBinary,
		},
		{
			name:     "NetworkError",
			err:      errors.E(errors.NetworkError, "network error", nil),
			wantCode: exitcode.Network,
		},
		{
			name:     "Timeout",
			err:      errors.E(errors.Timeout, "operation timed out", nil),
			wantCode: exitcode.Timeout,
		},
		{
			name:     "ValidationError (general)",
			err:      errors.E(errors.InvalidInput, "validation error", nil),
			wantCode: exitcode.General,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, code := ToExit(tt.err)
			if code != tt.wantCode {
				t.Errorf("ToExit(%s) code = %d, want %d", tt.name, code, tt.wantCode)
			}
		})
	}
}

func TestToExit_WrappedError(t *testing.T) {
	// Test that wrapped errors are unwrapped to find the code
	inner := errors.E(errors.DigestMismatch, "digest error", nil)
	wrapped := fmt.Errorf("outer context: %w", inner)

	_, code := ToExit(wrapped)
	if code != exitcode.DigestMismatch {
		t.Errorf("ToExit(wrapped) code = %d, want %d", code, exitcode.DigestMismatch)
	}
}

func TestToExit_PlainError(t *testing.T) {
	err := fmt.Errorf("plain error")
	msg, code := ToExit(err)
	if code != exitcode.General {
		t.Errorf("ToExit(plain) code = %d, want %d", code, exitcode.General)
	}
	if msg != "plain error" {
		t.Errorf("ToExit(plain) msg = %q, want %q", msg, "plain error")
	}
}

func TestToExit_RedactsSecrets(t *testing.T) {
	// Enable redaction for this test
	redact.Enable()
	defer redact.Disable()

	// Error containing a JWT token
	err := fmt.Errorf("auth failed: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.signature")
	msg, _ := ToExit(err)

	// Should be redacted
	if msg == err.Error() {
		t.Errorf("ToExit did not redact secret, got %q", msg)
	}
	// Should contain [REDACTED]
	if msg != "auth failed: Bearer [REDACTED]" {
		t.Errorf("ToExit redaction unexpected: %q", msg)
	}
}

func TestToExitResult(t *testing.T) {
	err := errors.E(errors.NetworkError, "connection failed", nil)
	result := ToExitResult(err)

	if result.Code != exitcode.Network {
		t.Errorf("ToExitResult code = %d, want %d", result.Code, exitcode.Network)
	}
	if result.Message != "connection failed" {
		t.Errorf("ToExitResult msg = %q, want %q", result.Message, "connection failed")
	}
}
