package security

import (
	"testing"
)

func TestExecutionPolicy_String(t *testing.T) {
	tests := []struct {
		policy ExecutionPolicy
		want   string
	}{
		{PolicyStrict, "strict"},
		{PolicyTrustOnFirstUse, "trust-on-first-use"},
		{PolicyPermissive, "permissive"},
		{ExecutionPolicy(99), "unknown(99)"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.policy.String(); got != tt.want {
				t.Errorf("ExecutionPolicy.String() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestExecutionPolicy_IsInsecure(t *testing.T) {
	tests := []struct {
		policy   ExecutionPolicy
		insecure bool
	}{
		{PolicyStrict, false},
		{PolicyTrustOnFirstUse, true},
		{PolicyPermissive, true},
	}

	for _, tt := range tests {
		t.Run(tt.policy.String(), func(t *testing.T) {
			if got := tt.policy.IsInsecure(); got != tt.insecure {
				t.Errorf("ExecutionPolicy.IsInsecure() = %v, want %v", got, tt.insecure)
			}
		})
	}
}

func TestExecutionPolicy_RequiresSigstore(t *testing.T) {
	tests := []struct {
		policy   ExecutionPolicy
		requires bool
	}{
		{PolicyStrict, true},
		{PolicyTrustOnFirstUse, false},
		{PolicyPermissive, false},
	}

	for _, tt := range tests {
		t.Run(tt.policy.String(), func(t *testing.T) {
			if got := tt.policy.RequiresSigstore(); got != tt.requires {
				t.Errorf("ExecutionPolicy.RequiresSigstore() = %v, want %v", got, tt.requires)
			}
		})
	}
}

func TestExecutionPolicy_RequiresDigest(t *testing.T) {
	tests := []struct {
		policy   ExecutionPolicy
		requires bool
	}{
		{PolicyStrict, true},
		{PolicyTrustOnFirstUse, true},
		{PolicyPermissive, false},
	}

	for _, tt := range tests {
		t.Run(tt.policy.String(), func(t *testing.T) {
			if got := tt.policy.RequiresDigest(); got != tt.requires {
				t.Errorf("ExecutionPolicy.RequiresDigest() = %v, want %v", got, tt.requires)
			}
		})
	}
}

func TestParsePolicy(t *testing.T) {
	tests := []struct {
		input   string
		want    ExecutionPolicy
		wantErr bool
	}{
		{"strict", PolicyStrict, false},
		{"", PolicyStrict, false}, // empty defaults to strict
		{"trust-on-first-use", PolicyTrustOnFirstUse, false},
		{"tofu", PolicyTrustOnFirstUse, false},
		{"permissive", PolicyPermissive, false},
		{"invalid", PolicyStrict, true},
		{"STRICT", PolicyStrict, true}, // case-sensitive
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := ParsePolicy(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParsePolicy(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("ParsePolicy(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestInsecureOptions(t *testing.T) {
	// Test with no options
	opts := NewInsecureOptions()

	// Initially no options enabled
	if opts.HasAny() {
		t.Error("new InsecureOptions should have no options enabled")
	}
	if opts.SkipVerify {
		t.Error("SkipVerify should not be enabled initially")
	}
	if opts.String() != "(none)" {
		t.Errorf("String() = %q, want %q", opts.String(), "(none)")
	}

	// Create options with some enabled
	opts = NewInsecureOptions(DangerouslySkipVerify(), DangerouslySkipIdentityCheck())

	if !opts.HasAny() {
		t.Error("HasAny() should return true after enabling options")
	}
	if !opts.SkipVerify {
		t.Error("SkipVerify should be enabled")
	}
	if !opts.SkipIdentityCheck {
		t.Error("SkipIdentityCheck should be enabled")
	}
	if opts.AllowHTTP {
		t.Error("AllowHTTP should not be enabled")
	}
}
