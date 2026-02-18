// Package exitmap provides centralized error-to-exit-code mapping for the CLI.
//
// All CLI commands should use ToExit() to convert internal errors to exit codes.
// This ensures consistent exit codes across the codebase and prevents exit code
// logic from being scattered across multiple packages.
//
// Security: All error messages are passed through redact.Error() before being
// returned to sanitize any sensitive information (tokens, secrets, etc.).
package exitmap

import (
	"errors"

	epackerrors "github.com/locktivity/epack/errors"
	"github.com/locktivity/epack/internal/exitcode"
	"github.com/locktivity/epack/internal/redact"
)

// ToExit converts an error to an exit code and sanitized message.
// It extracts the exit code from errors.Error (which implements ExitCode()).
// Falls back to general error (exit code 1) for non-typed errors.
//
// The returned message is always sanitized via redact.Error().
func ToExit(err error) (msg string, code int) {
	if err == nil {
		return "", exitcode.Success
	}

	// Check for *errors.Error which has ExitCode() method
	var e *epackerrors.Error
	if errors.As(err, &e) {
		return redact.Error(err.Error()), e.ExitCode()
	}

	return redact.Error(err.Error()), exitcode.General
}

// Result holds the exit code and message from ToExit.
// This is a convenience type for commands that need to return both.
type Result struct {
	Code    int
	Message string
}

// ToExitResult is like ToExit but returns a Result struct.
func ToExitResult(err error) Result {
	msg, code := ToExit(err)
	return Result{Code: code, Message: msg}
}
