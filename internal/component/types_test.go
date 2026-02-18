package component

import (
	"testing"

	"github.com/locktivity/epack/internal/exitcode"
	"github.com/locktivity/epack/internal/platform"
)

func TestPlatformKey(t *testing.T) {
	tests := []struct {
		goos   string
		goarch string
		want   string
	}{
		{"linux", "amd64", "linux/amd64"},
		{"darwin", "arm64", "darwin/arm64"},
		{"windows", "amd64", "windows/amd64"},
		{"linux", "arm64", "linux/arm64"},
		{"freebsd", "386", "freebsd/386"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := platform.Key(tt.goos, tt.goarch)
			if got != tt.want {
				t.Errorf("PlatformKey(%q, %q) = %q, want %q", tt.goos, tt.goarch, got, tt.want)
			}
		})
	}
}

func TestExitCodes(t *testing.T) {
	// Verify exit codes are distinct and match documentation
	codes := map[int]string{
		exitcode.General:           "General",
		exitcode.LockInvalid:       "LockInvalid",
		exitcode.DigestMismatch:    "DigestMismatch",
		exitcode.SignatureMismatch: "SignatureMismatch",
		exitcode.MissingBinary:     "MissingBinary",
		exitcode.Network:           "Network",
	}

	// Check we have 6 distinct codes
	if len(codes) != 6 {
		t.Errorf("expected 6 distinct exit codes, got %d", len(codes))
	}

	// Check specific values match plan
	if exitcode.General != 1 {
		t.Errorf("General = %d, want 1", exitcode.General)
	}
	if exitcode.LockInvalid != 10 {
		t.Errorf("LockInvalid = %d, want 10", exitcode.LockInvalid)
	}
	if exitcode.DigestMismatch != 11 {
		t.Errorf("DigestMismatch = %d, want 11", exitcode.DigestMismatch)
	}
	if exitcode.SignatureMismatch != 12 {
		t.Errorf("SignatureMismatch = %d, want 12", exitcode.SignatureMismatch)
	}
	if exitcode.MissingBinary != 14 {
		t.Errorf("MissingBinary = %d, want 14", exitcode.MissingBinary)
	}
	if exitcode.Network != 15 {
		t.Errorf("Network = %d, want 15", exitcode.Network)
	}
}
