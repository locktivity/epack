//go:build components

package utilitycmd

import (
	"testing"

	"github.com/locktivity/epack/internal/componenttypes"
)

func TestExitError(t *testing.T) {
	tests := []struct {
		name     string
		exitCode int
		message  string
	}{
		{
			name:     "component not found",
			exitCode: componenttypes.ExitComponentNotFound,
			message:  "utility not installed",
		},
		{
			name:     "verification failed",
			exitCode: componenttypes.ExitVerifyFailed,
			message:  "digest mismatch",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := &exitError{
				Exit:    tt.exitCode,
				Message: tt.message,
			}

			if err.ExitCode() != tt.exitCode {
				t.Errorf("ExitCode() = %d, want %d", err.ExitCode(), tt.exitCode)
			}

			if err.Error() != tt.message {
				t.Errorf("Error() = %q, want %q", err.Error(), tt.message)
			}
		})
	}
}

func TestExitCodes_InWrapperRange(t *testing.T) {
	// Exit codes 10-19 are reserved for wrapper errors
	// Verify component exit codes are in this range
	codes := []struct {
		name string
		code int
	}{
		{"ExitComponentNotFound", componenttypes.ExitComponentNotFound},
		{"ExitVerifyFailed", componenttypes.ExitVerifyFailed},
		{"ExitPackVerifyFailed", componenttypes.ExitPackVerifyFailed},
		{"ExitLockfileMissing", componenttypes.ExitLockfileMissing},
		{"ExitRunDirFailed", componenttypes.ExitRunDirFailed},
		{"ExitConfigFailed", componenttypes.ExitConfigFailed},
		{"ExitPackRequired", componenttypes.ExitPackRequired},
		{"ExitDependencyMissing", componenttypes.ExitDependencyMissing},
	}

	for _, c := range codes {
		t.Run(c.name, func(t *testing.T) {
			if c.code < 10 || c.code > 19 {
				t.Errorf("%s = %d, want value in range 10-19", c.name, c.code)
			}
		})
	}
}
