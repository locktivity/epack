package verify

import (
	"errors"
	"strings"
	"testing"
)

type verifyTestNetError struct {
	msg string
}

func (e verifyTestNetError) Error() string   { return e.msg }
func (e verifyTestNetError) Timeout() bool   { return true }
func (e verifyTestNetError) Temporary() bool { return false }

func TestWrapTrustedRootError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		contains []string
	}{
		{
			name: "dns lookup failure",
			err:  errors.New("lookup tuf.sigstore.dev: no such host"),
			contains: []string{
				"DNS lookup failed",
				"--trust-root",
				"--integrity-only",
			},
		},
		{
			name: "network timeout",
			err:  verifyTestNetError{msg: "connection timed out"},
			contains: []string{
				"network error",
				"Check Sigstore status",
				"--trust-root",
			},
		},
		{
			name: "fallback",
			err:  errors.New("boom"),
			contains: []string{
				"failed to get Sigstore trusted root",
				"boom",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := wrapTrustedRootError(tt.err).Error()
			for _, want := range tt.contains {
				if !strings.Contains(got, want) {
					t.Fatalf("wrapTrustedRootError() missing %q in %q", want, got)
				}
			}
		})
	}
}
