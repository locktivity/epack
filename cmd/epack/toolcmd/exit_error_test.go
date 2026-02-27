//go:build components

package toolcmd

import "testing"

func TestExitErrorError_UsesMessageWhenPresent(t *testing.T) {
	err := &exitError{code: 16, message: "pack required but not provided"}
	if got := err.Error(); got != "pack required but not provided" {
		t.Fatalf("Error() = %q, want %q", got, "pack required but not provided")
	}
}

func TestExitErrorError_FallsBackToCode(t *testing.T) {
	err := &exitError{code: 16}
	if got := err.Error(); got != "exit code 16" {
		t.Fatalf("Error() = %q, want %q", got, "exit code 16")
	}
}
