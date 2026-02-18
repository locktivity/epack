package exitcode

import "testing"

func TestIsToolExitCode(t *testing.T) {
	tests := []struct {
		code   int
		expect bool
	}{
		{0, false},
		{1, false},
		{9, false},
		{10, true},
		{15, true},
		{19, true},
		{20, false},
	}

	for _, tc := range tests {
		got := IsToolExitCode(tc.code)
		if got != tc.expect {
			t.Errorf("IsToolExitCode(%d) = %v, want %v", tc.code, got, tc.expect)
		}
	}
}

func TestExitCodeConstants(t *testing.T) {
	// Verify exit code constants are in expected ranges
	if Success != 0 {
		t.Errorf("Success = %d, want 0", Success)
	}
	if General != 1 {
		t.Errorf("General = %d, want 1", General)
	}

	// Component exit codes should be 10-19
	componentCodes := []int{LockInvalid, DigestMismatch, SignatureMismatch, MissingBinary, Network}
	for _, code := range componentCodes {
		if code < 10 || code > 19 {
			t.Errorf("component exit code %d not in range 10-19", code)
		}
	}

	// Tool wrapper codes should be 10-19
	toolCodes := []int{ToolNotFound, ToolVerifyFailed, PackVerifyFailed, LockfileMissing, RunDirFailed, ConfigFileFailed, PackRequired}
	for _, code := range toolCodes {
		if code < 10 || code > 19 {
			t.Errorf("tool exit code %d not in range 10-19", code)
		}
	}
}
