package errors

import (
	stderrors "errors"
	"fmt"
	"testing"
)

func TestE(t *testing.T) {
	err := E(InvalidJSON, "test message", nil)

	if err == nil {
		t.Fatal("E() returned nil")
	}

	e, ok := err.(*Error)
	if !ok {
		t.Fatalf("E() returned %T, want *Error", err)
	}

	if e.Code != InvalidJSON {
		t.Errorf("Code = %s, want %s", e.Code, InvalidJSON)
	}
	if e.Message != "test message" {
		t.Errorf("Message = %s, want %s", e.Message, "test message")
	}
	if e.Cause != nil {
		t.Errorf("Cause = %v, want nil", e.Cause)
	}
}

func TestError_Error(t *testing.T) {
	tests := []struct {
		name    string
		err     *Error
		wantMsg string
	}{
		{
			name:    "without cause",
			err:     &Error{Code: InvalidJSON, Message: "invalid JSON"},
			wantMsg: "invalid JSON",
		},
		{
			name:    "with cause",
			err:     &Error{Code: InvalidJSON, Message: "invalid JSON", Cause: fmt.Errorf("unexpected EOF")},
			wantMsg: "invalid JSON: unexpected EOF",
		},
		{
			name:    "with nested cause",
			err:     &Error{Code: InvalidManifest, Message: "bad manifest", Cause: &Error{Code: InvalidJSON, Message: "parse error"}},
			wantMsg: "bad manifest: parse error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.wantMsg {
				t.Errorf("Error() = %q, want %q", got, tt.wantMsg)
			}
		})
	}
}

func TestError_Unwrap(t *testing.T) {
	cause := fmt.Errorf("root cause")
	err := &Error{Code: InvalidJSON, Message: "wrapper", Cause: cause}

	if got := err.Unwrap(); got != cause {
		t.Errorf("Unwrap() = %v, want %v", got, cause)
	}

	errNoCause := &Error{Code: InvalidJSON, Message: "no cause"}
	if got := errNoCause.Unwrap(); got != nil {
		t.Errorf("Unwrap() = %v, want nil", got)
	}
}

func TestCodeOf(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		wantCode Code
	}{
		{
			name:     "direct Error",
			err:      E(DuplicateKeys, "dupe", nil),
			wantCode: DuplicateKeys,
		},
		{
			name:     "wrapped Error",
			err:      fmt.Errorf("wrapped: %w", E(InvalidTimestamp, "bad time", nil)),
			wantCode: InvalidTimestamp,
		},
		{
			name:     "deeply wrapped Error",
			err:      fmt.Errorf("outer: %w", fmt.Errorf("middle: %w", E(MissingRequiredField, "missing", nil))),
			wantCode: MissingRequiredField,
		},
		{
			name:     "non-Error",
			err:      fmt.Errorf("plain error"),
			wantCode: "",
		},
		{
			name:     "nil error",
			err:      nil,
			wantCode: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := CodeOf(tt.err); got != tt.wantCode {
				t.Errorf("CodeOf() = %q, want %q", got, tt.wantCode)
			}
		})
	}
}

func TestErrorCodes(t *testing.T) {
	// Verify error codes have expected stable values
	codes := map[Code]string{
		DuplicateKeys:          "duplicate_keys",
		InvalidJSON:            "invalid_json",
		MissingRequiredField:   "missing_required_field",
		InvalidManifest:        "invalid_manifest",
		InvalidTimestamp:       "invalid_timestamp",
		UnsupportedSpecVersion: "unsupported_spec_version",
	}

	for code, want := range codes {
		if string(code) != want {
			t.Errorf("Code %v = %q, want %q", code, string(code), want)
		}
	}
}

func TestAllErrorCodes(t *testing.T) {
	// Verify all error codes are defined and have expected string values
	allCodes := []struct {
		code Code
		want string
	}{
		// JSON parsing errors
		{DuplicateKeys, "duplicate_keys"},
		{InvalidJSON, "invalid_json"},
		{MissingRequiredField, "missing_required_field"},

		// Manifest validation errors
		{InvalidManifest, "invalid_manifest"},
		{InvalidTimestamp, "invalid_timestamp"},
		{UnsupportedSpecVersion, "unsupported_spec_version"},

		// Zip/pack validation errors
		{ZipBomb, "zip_bomb"},
		{TooManyArtifacts, "too_many_artifacts"},
		{DuplicatePath, "duplicate_path"},
		{ArtifactTooLarge, "artifact_too_large"},
		{InvalidPath, "invalid_path"},
		{MissingEntry, "missing_entry"},

		// Attestation validation errors
		{InvalidAttestation, "invalid_attestation"},
		{AttestationTooLarge, "attestation_too_large"},

		// Signature verification errors
		{SignatureInvalid, "signature_invalid"},
		{IdentityMismatch, "identity_mismatch"},

		// Integrity verification errors
		{DigestMismatch, "digest_mismatch"},
		{SizeMismatch, "size_mismatch"},
		{PackDigestMismatch, "pack_digest_mismatch"},

		// Input validation errors
		{InvalidInput, "invalid_input"},

		// Filesystem errors
		{SymlinkNotAllowed, "symlink_not_allowed"},
		{PathTraversal, "path_traversal"},
		{PermissionDenied, "permission_denied"},

		// Operation errors
		{Timeout, "timeout"},
		{NetworkError, "network_error"},

		// Collector errors
		{LockfileInvalid, "lockfile_invalid"},
		{BinaryNotFound, "binary_not_found"},
		{InsecureInstall, "insecure_install"},
	}

	for _, tc := range allCodes {
		t.Run(tc.want, func(t *testing.T) {
			if string(tc.code) != tc.want {
				t.Errorf("Code = %q, want %q", string(tc.code), tc.want)
			}

			// Verify the code can be used to create an error
			err := E(tc.code, "test message", nil)
			if CodeOf(err) != tc.code {
				t.Errorf("CodeOf(E(%s, ...)) = %q, want %q", tc.code, CodeOf(err), tc.code)
			}
		})
	}
}

func TestE_WithCause(t *testing.T) {
	cause := fmt.Errorf("underlying error")
	err := E(InvalidJSON, "parse failed", cause)

	e, ok := err.(*Error)
	if !ok {
		t.Fatalf("E() returned %T, want *Error", err)
	}

	if e.Cause != cause {
		t.Errorf("Cause = %v, want %v", e.Cause, cause)
	}
}

func TestError_ErrorsIs(t *testing.T) {
	// Test that stderrors.Is works with wrapped errors
	cause := fmt.Errorf("root cause")
	err := E(InvalidJSON, "wrapper", cause)

	// stderrors.Is should find the cause
	if !stderrors.Is(err, cause) {
		t.Error("stderrors.Is should find the cause")
	}

	// stderrors.Is should not find an unrelated error
	unrelated := fmt.Errorf("unrelated")
	if stderrors.Is(err, unrelated) {
		t.Error("stderrors.Is should not find unrelated error")
	}
}

func TestError_ErrorsAs(t *testing.T) {
	// Test that stderrors.As works with *Error
	cause := fmt.Errorf("root cause")
	inner := E(InvalidJSON, "inner", cause)
	outer := fmt.Errorf("outer: %w", inner)

	var target *Error
	if !stderrors.As(outer, &target) {
		t.Fatal("stderrors.As should find *Error")
	}

	if target.Code != InvalidJSON {
		t.Errorf("Code = %s, want %s", target.Code, InvalidJSON)
	}
	if target.Message != "inner" {
		t.Errorf("Message = %s, want %s", target.Message, "inner")
	}
}

func TestError_NestedErrors(t *testing.T) {
	// Test nested *Error chain
	innermost := E(InvalidJSON, "json parse error", nil)
	middle := E(InvalidManifest, "manifest validation failed", innermost)
	outer := E(MissingRequiredField, "field check failed", middle)

	// CodeOf should return the outermost code
	if got := CodeOf(outer); got != MissingRequiredField {
		t.Errorf("CodeOf(outer) = %s, want %s", got, MissingRequiredField)
	}

	// stderrors.As should find each level
	var target *Error

	if !stderrors.As(outer, &target) {
		t.Fatal("stderrors.As should find outer *Error")
	}
	if target.Code != MissingRequiredField {
		t.Errorf("First target.Code = %s, want %s", target.Code, MissingRequiredField)
	}

	// Unwrap and check middle
	if target.Cause == nil {
		t.Fatal("outer.Cause should not be nil")
	}

	var middleTarget *Error
	if !stderrors.As(target.Cause, &middleTarget) {
		t.Fatal("stderrors.As should find middle *Error")
	}
	if middleTarget.Code != InvalidManifest {
		t.Errorf("Middle target.Code = %s, want %s", middleTarget.Code, InvalidManifest)
	}
}

func TestCodeOf_ReturnsFirstError(t *testing.T) {
	// When there are multiple *Error in chain, CodeOf returns the first one
	inner := E(InvalidJSON, "inner", nil)
	outer := E(InvalidManifest, "outer", inner)

	// Should return outer code, not inner
	if got := CodeOf(outer); got != InvalidManifest {
		t.Errorf("CodeOf() = %s, want %s", got, InvalidManifest)
	}
}

func TestError_EmptyMessage(t *testing.T) {
	err := E(InvalidJSON, "", nil)

	e, ok := err.(*Error)
	if !ok {
		t.Fatalf("E() returned %T, want *Error", err)
	}

	if e.Message != "" {
		t.Errorf("Message = %q, want empty string", e.Message)
	}

	// Error() should return empty string for empty message
	if e.Error() != "" {
		t.Errorf("Error() = %q, want empty string", e.Error())
	}
}

func TestError_EmptyMessageWithCause(t *testing.T) {
	cause := fmt.Errorf("cause message")
	err := E(InvalidJSON, "", cause)

	e := err.(*Error)

	// Error() should return ": cause message" when message is empty
	if e.Error() != ": cause message" {
		t.Errorf("Error() = %q, want %q", e.Error(), ": cause message")
	}
}

func TestCode_String(t *testing.T) {
	// Code is a string type, so it should be directly usable as a string
	code := InvalidJSON
	s := string(code)

	if s != "invalid_json" {
		t.Errorf("string(InvalidJSON) = %q, want %q", s, "invalid_json")
	}
}

func TestE_WithNestedCause(t *testing.T) {
	// Test creating error with a nested *Error cause
	innerCause := E(ZipBomb, "compression ratio exceeded", nil)
	outerErr := E(InvalidManifest, "pack validation failed", innerCause)

	// The error message should include the full chain
	wantMsg := "pack validation failed: compression ratio exceeded"
	if outerErr.Error() != wantMsg {
		t.Errorf("Error() = %q, want %q", outerErr.Error(), wantMsg)
	}

	// Both codes should be accessible via stderrors.As
	var target *Error
	if stderrors.As(outerErr, &target) {
		if target.Code != InvalidManifest {
			t.Errorf("First error Code = %s, want %s", target.Code, InvalidManifest)
		}
	}
}

// =============================================================================
// ERROR CHAIN PRESERVATION TESTS
// =============================================================================
// These tests verify that error codes are preserved when errors are wrapped
// in various ways. This is critical for CLI error handling and programmatic
// error code extraction.

func TestErrorChain_CodePreservedThroughFmtErrorf(t *testing.T) {
	// CRITICAL: Error codes must be preserved when wrapped with fmt.Errorf("%w", ...)
	// This is the most common wrapping pattern in Go code.

	tests := []struct {
		name         string
		wrapLevels   int
		originalCode Code
	}{
		{"single wrap", 1, DigestMismatch},
		{"double wrap", 2, SizeMismatch},
		{"triple wrap", 3, PackDigestMismatch},
		{"deep wrap", 5, SignatureInvalid},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create original error
			err := E(tt.originalCode, "original message", nil)

			// Wrap it N times with fmt.Errorf
			wrapped := error(err)
			for i := 0; i < tt.wrapLevels; i++ {
				wrapped = fmt.Errorf("wrap level %d: %w", i+1, wrapped)
			}

			// CodeOf must still return the original code
			gotCode := CodeOf(wrapped)
			if gotCode != tt.originalCode {
				t.Errorf("CodeOf() after %d wraps = %q, want %q",
					tt.wrapLevels, gotCode, tt.originalCode)
			}

			// errors.As must still find the *Error
			var target *Error
			if !stderrors.As(wrapped, &target) {
				t.Errorf("errors.As failed to find *Error after %d wraps", tt.wrapLevels)
			}
			if target != nil && target.Code != tt.originalCode {
				t.Errorf("target.Code after errors.As = %q, want %q",
					target.Code, tt.originalCode)
			}
		})
	}
}

func TestErrorChain_CodePreservedThroughMixedWrapping(t *testing.T) {
	// Test mixed wrapping: *Error wrapping *Error wrapping fmt.Errorf wrapping *Error
	innermost := E(InvalidJSON, "json parse error", nil)
	stdErr := fmt.Errorf("standard library wrapper: %w", innermost)
	middle := E(InvalidManifest, "manifest failed", stdErr)
	outer := fmt.Errorf("outer wrapper: %w", middle)

	// CodeOf should return the first *Error code in the chain
	if got := CodeOf(outer); got != InvalidManifest {
		t.Errorf("CodeOf(mixed chain) = %q, want %q", got, InvalidManifest)
	}

	// errors.Is should find the innermost cause
	if !stderrors.Is(outer, innermost) {
		t.Error("errors.Is should find innermost *Error through mixed chain")
	}
}

func TestErrorChain_UnwrapReturnsActualCause(t *testing.T) {
	// SECURITY: Unwrap() must return the actual cause, not create a new error.
	// This test catches the bug found in collector/errors.go where Unwrap()
	// was creating new errors instead of returning the stored cause.

	cause := fmt.Errorf("root cause")
	err := E(InvalidJSON, "wrapper", cause)

	// Unwrap should return the exact same error object
	unwrapped := err.(*Error).Unwrap()
	if unwrapped != cause {
		t.Errorf("Unwrap() returned different error instance")
	}

	// Verify identity with pointer comparison
	if fmt.Sprintf("%p", unwrapped) != fmt.Sprintf("%p", cause) {
		t.Errorf("Unwrap() should return same pointer: got %p, want %p", unwrapped, cause)
	}
}

func TestErrorChain_UnwrapChainIntegrity(t *testing.T) {
	// Test that the full unwrap chain is intact
	level1 := fmt.Errorf("level 1")
	level2 := E(InvalidJSON, "level 2", level1)
	level3 := fmt.Errorf("level 3: %w", level2)
	level4 := E(InvalidManifest, "level 4", level3)

	// Walk the chain manually
	current := error(level4)

	// Level 4 -> Level 3 (should be level3 error)
	if u, ok := current.(interface{ Unwrap() error }); ok {
		current = u.Unwrap()
	} else {
		t.Fatal("level4 should implement Unwrap")
	}
	if current.Error() != "level 3: level 2: level 1" {
		t.Errorf("after unwrap 4->3, got %q", current.Error())
	}

	// Level 3 -> Level 2 (should be *Error with InvalidJSON)
	if u, ok := current.(interface{ Unwrap() error }); ok {
		current = u.Unwrap()
	} else {
		t.Fatal("level3 should implement Unwrap")
	}
	if e, ok := current.(*Error); !ok || e.Code != InvalidJSON {
		t.Errorf("after unwrap 3->2, expected *Error with InvalidJSON, got %T %v", current, current)
	}

	// Level 2 -> Level 1 (should be the original fmt.Errorf)
	if u, ok := current.(interface{ Unwrap() error }); ok {
		current = u.Unwrap()
	} else {
		t.Fatal("level2 should implement Unwrap")
	}
	if current != level1 {
		t.Errorf("after unwrap 2->1, expected level1, got %v", current)
	}
}

func TestErrorChain_AllCodesAccessibleViaTraversal(t *testing.T) {
	// When multiple *Error exist in a chain, all codes should be accessible
	// by walking the chain (useful for logging/debugging)

	inner := E(DigestMismatch, "digest error", nil)
	middle := E(InvalidManifest, "manifest error", inner)
	outer := E(SignatureInvalid, "signature error", middle)

	// Collect all codes in the chain
	var codes []Code
	current := error(outer)
	for current != nil {
		if e, ok := current.(*Error); ok {
			codes = append(codes, e.Code)
		}
		// Try to unwrap
		if u, ok := current.(interface{ Unwrap() error }); ok {
			current = u.Unwrap()
		} else {
			break
		}
	}

	// Should have all three codes
	expectedCodes := []Code{SignatureInvalid, InvalidManifest, DigestMismatch}
	if len(codes) != len(expectedCodes) {
		t.Errorf("found %d codes, want %d", len(codes), len(expectedCodes))
	}
	for i, code := range codes {
		if i < len(expectedCodes) && code != expectedCodes[i] {
			t.Errorf("codes[%d] = %q, want %q", i, code, expectedCodes[i])
		}
	}
}

func TestErrorChain_NilCauseHandling(t *testing.T) {
	// Errors with nil cause should have Unwrap() return nil
	err := E(InvalidJSON, "no cause", nil)

	unwrapped := err.(*Error).Unwrap()
	if unwrapped != nil {
		t.Errorf("Unwrap() of error with nil cause = %v, want nil", unwrapped)
	}

	// CodeOf should still work
	if got := CodeOf(err); got != InvalidJSON {
		t.Errorf("CodeOf(error with nil cause) = %q, want %q", got, InvalidJSON)
	}
}

func TestErrorChain_ErrorMessageIncludesFullChain(t *testing.T) {
	// Error messages should include the full cause chain for debugging

	level1 := fmt.Errorf("file not found")
	level2 := E(InvalidJSON, "failed to parse config", level1)
	level3 := E(InvalidManifest, "manifest validation failed", level2)

	expectedMsg := "manifest validation failed: failed to parse config: file not found"
	if got := level3.Error(); got != expectedMsg {
		t.Errorf("Error() = %q, want %q", got, expectedMsg)
	}
}

func TestCodeOf_ReturnsEmptyForNonError(t *testing.T) {
	// CodeOf should return empty string for errors that aren't *Error
	// even when deeply wrapped

	plainErr := fmt.Errorf("plain error")
	wrapped := fmt.Errorf("wrap1: %w", fmt.Errorf("wrap2: %w", plainErr))

	if got := CodeOf(wrapped); got != "" {
		t.Errorf("CodeOf(non-Error chain) = %q, want empty string", got)
	}
}

func TestErrorChain_CodeOfFindsFirstError(t *testing.T) {
	// When there are multiple *Error in the chain, CodeOf returns the first one
	// (outermost), which is the most specific error

	inner := E(InvalidJSON, "inner json error", nil)
	outer := E(InvalidManifest, "outer manifest error", inner)

	// Should get outer code
	if got := CodeOf(outer); got != InvalidManifest {
		t.Errorf("CodeOf(outer) = %q, want %q", got, InvalidManifest)
	}

	// When wrapped in fmt.Errorf, should still get outer code
	wrapped := fmt.Errorf("wrapper: %w", outer)
	if got := CodeOf(wrapped); got != InvalidManifest {
		t.Errorf("CodeOf(wrapped outer) = %q, want %q", got, InvalidManifest)
	}
}
