package securitypolicy

import (
	"os"
	"testing"
)

func TestExecutionPolicyEnforce(t *testing.T) {
	tests := []struct {
		name                  string
		frozen                bool
		insecureAllowUnpinned bool
		wantErr               bool
	}{
		{
			name:                  "default mode allows pinned execution",
			frozen:                false,
			insecureAllowUnpinned: false,
			wantErr:               false,
		},
		{
			name:                  "frozen mode allows pinned execution",
			frozen:                true,
			insecureAllowUnpinned: false,
			wantErr:               false,
		},
		{
			name:                  "non-frozen mode allows insecure unpinned",
			frozen:                false,
			insecureAllowUnpinned: true,
			wantErr:               false,
		},
		{
			name:                  "frozen mode rejects insecure unpinned",
			frozen:                true,
			insecureAllowUnpinned: true,
			wantErr:               true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ExecutionPolicy{
				Frozen:        tt.frozen,
				AllowUnpinned: tt.insecureAllowUnpinned,
			}.Enforce()
			if tt.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("expected no error, got %v", err)
			}
		})
	}
}

func TestValidateRemoteExecutionCompatibility(t *testing.T) {
	if err := ValidateRemoteExecution(true, true); err == nil {
		t.Fatal("expected error from compatibility wrapper")
	}
}

func TestEnforceStrictProduction(t *testing.T) {
	orig := os.Getenv(StrictProductionEnvVar)
	t.Cleanup(func() {
		_ = os.Setenv(StrictProductionEnvVar, orig)
	})

	_ = os.Setenv(StrictProductionEnvVar, "1")
	if err := EnforceStrictProduction("collector", true); err == nil {
		t.Fatal("expected strict production enforcement error")
	}
	if err := EnforceStrictProduction("collector", false); err != nil {
		t.Fatalf("unexpected error with no unsafe overrides: %v", err)
	}
}
