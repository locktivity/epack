package sigstore

import (
	"errors"
	"strings"
	"testing"
)

type testNetError struct {
	msg string
}

func (e testNetError) Error() string   { return e.msg }
func (e testNetError) Timeout() bool   { return true }
func (e testNetError) Temporary() bool { return false }

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
				"status.sigstore.dev",
				"--insecure-skip-verify",
			},
		},
		{
			name: "network timeout",
			err:  testNetError{msg: "i/o timeout"},
			contains: []string{
				"network error",
				"Check Sigstore status",
				"Check your network connection",
			},
		},
		{
			name: "fallback",
			err:  errors.New("boom"),
			contains: []string{
				"failed to fetch Sigstore trusted root",
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
