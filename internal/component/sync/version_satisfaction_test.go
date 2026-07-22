package sync

import (
	stderrors "errors"
	"testing"

	epackerrors "github.com/locktivity/epack/errors"
)

func TestValidateVersionSatisfaction(t *testing.T) {
	tests := []struct {
		name             string
		configuredSource string
		lockedVersion    string
		wantCode         epackerrors.Code
	}{
		{
			name:             "exact constraint satisfied",
			configuredSource: "locktivity/epack-collector-aws@v0.3.1",
			lockedVersion:    "v0.3.1",
		},
		{
			name:             "exact constraint violated",
			configuredSource: "locktivity/epack-collector-aws@v0.3.1",
			lockedVersion:    "v0.3.0",
			wantCode:         epackerrors.LockConfigMismatch,
		},
		{
			name:             "caret constraint satisfied",
			configuredSource: "locktivity/epack-collector-aws@^0.3.0",
			lockedVersion:    "v0.3.4",
		},
		{
			name:             "caret constraint violated by bumped range",
			configuredSource: "locktivity/epack-collector-aws@^0.3.0",
			lockedVersion:    "v0.2.9",
			wantCode:         epackerrors.LockConfigMismatch,
		},
		{
			name:             "tilde constraint violated",
			configuredSource: "locktivity/epack-collector-aws@~0.3.1",
			lockedVersion:    "v0.4.0",
			wantCode:         epackerrors.LockConfigMismatch,
		},
		{
			name:             "no constraint declared",
			configuredSource: "locktivity/epack-collector-aws",
			lockedVersion:    "v0.1.0",
		},
		{
			name:             "empty locked version skipped",
			configuredSource: "locktivity/epack-collector-aws@^0.3.0",
			lockedVersion:    "",
		},
		{
			name:             "unparseable locked version",
			configuredSource: "locktivity/epack-collector-aws@^0.3.0",
			lockedVersion:    "not-a-version",
			wantCode:         epackerrors.LockfileInvalid,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateVersionSatisfaction("collector", "aws", tt.configuredSource, tt.lockedVersion, "epack collector lock")
			if tt.wantCode == "" {
				if err != nil {
					t.Fatalf("ValidateVersionSatisfaction() = %v, want nil", err)
				}
				return
			}
			var e *epackerrors.Error
			if !stderrors.As(err, &e) {
				t.Fatalf("ValidateVersionSatisfaction() = %v, want *errors.Error", err)
			}
			if e.Code != tt.wantCode {
				t.Fatalf("code = %q, want %q", e.Code, tt.wantCode)
			}
		})
	}
}
