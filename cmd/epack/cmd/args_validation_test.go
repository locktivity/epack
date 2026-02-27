package cmd

import (
	"strings"
	"testing"
)

// Tests for custom argument validation error messages.
// These ensure commands provide helpful feedback when arguments are missing or invalid.

func TestExtractCmd_ArgsValidation(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		wantErr     bool
		errContains string
	}{
		{
			name:        "missing pack file",
			args:        []string{},
			wantErr:     true,
			errContains: "missing pack file argument",
		},
		{
			name:        "missing pack file shows usage",
			args:        []string{},
			wantErr:     true,
			errContains: "Usage: epack extract",
		},
		{
			name:    "valid single arg",
			args:    []string{"test.epack"},
			wantErr: false,
		},
		{
			name:    "valid with artifact paths",
			args:    []string{"test.epack", "artifacts/a.json", "artifacts/b.json"},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := extractCmd.Args(extractCmd, tt.args)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error but got nil")
				}
				if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("error %q should contain %q", err.Error(), tt.errContains)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestVerifyCmd_ArgsValidation(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		wantErr     bool
		errContains string
	}{
		{
			name:        "missing pack file",
			args:        []string{},
			wantErr:     true,
			errContains: "missing pack file argument",
		},
		{
			name:        "missing pack file shows usage",
			args:        []string{},
			wantErr:     true,
			errContains: "Usage: epack verify",
		},
		{
			name:    "valid single arg",
			args:    []string{"test.epack"},
			wantErr: false,
		},
		{
			name:        "too many args",
			args:        []string{"test.epack", "extra"},
			wantErr:     true,
			errContains: "too many arguments",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := verifyCmd.Args(verifyCmd, tt.args)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error but got nil")
				}
				if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("error %q should contain %q", err.Error(), tt.errContains)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestInspectCmd_ArgsValidation(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		wantErr     bool
		errContains string
	}{
		{
			name:        "missing pack file",
			args:        []string{},
			wantErr:     true,
			errContains: "missing pack file argument",
		},
		{
			name:        "missing pack file shows usage",
			args:        []string{},
			wantErr:     true,
			errContains: "Usage: epack inspect",
		},
		{
			name:    "valid single arg",
			args:    []string{"test.epack"},
			wantErr: false,
		},
		{
			name:        "too many args",
			args:        []string{"test.epack", "extra"},
			wantErr:     true,
			errContains: "too many arguments",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := inspectCmd.Args(inspectCmd, tt.args)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error but got nil")
				}
				if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("error %q should contain %q", err.Error(), tt.errContains)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestSignCmd_ArgsValidation(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		wantErr     bool
		errContains string
	}{
		{
			name:        "missing pack file",
			args:        []string{},
			wantErr:     true,
			errContains: "missing pack file argument",
		},
		{
			name:        "missing pack file shows usage",
			args:        []string{},
			wantErr:     true,
			errContains: "Usage: epack sign",
		},
		{
			name:    "valid single arg",
			args:    []string{"test.epack"},
			wantErr: false,
		},
		{
			name:        "too many args",
			args:        []string{"test.epack", "extra"},
			wantErr:     true,
			errContains: "too many arguments",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := signCmd.Args(signCmd, tt.args)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error but got nil")
				}
				if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("error %q should contain %q", err.Error(), tt.errContains)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestMergeCmd_ArgsValidation(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		wantErr     bool
		errContains string
	}{
		{
			name:        "missing all args",
			args:        []string{},
			wantErr:     true,
			errContains: "missing arguments",
		},
		{
			name:        "missing all args shows usage",
			args:        []string{},
			wantErr:     true,
			errContains: "Usage: epack merge",
		},
		{
			name:        "only output, no inputs",
			args:        []string{"out.epack"},
			wantErr:     true,
			errContains: "missing arguments",
		},
		{
			name:    "valid with output and inputs",
			args:    []string{"out.epack", "a.epack", "b.epack"},
			wantErr: false,
		},
		{
			name:    "valid with output and single input",
			args:    []string{"out.epack", "a.epack"},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := mergeCmd.Args(mergeCmd, tt.args)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error but got nil")
				}
				if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("error %q should contain %q", err.Error(), tt.errContains)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			}
		})
	}
}

// Test that error messages provide helpful examples
func TestArgsValidation_IncludesExamples(t *testing.T) {
	tests := []struct {
		name    string
		argsErr error
	}{
		{"extract", extractCmd.Args(extractCmd, []string{})},
		{"verify", verifyCmd.Args(verifyCmd, []string{})},
		{"inspect", inspectCmd.Args(inspectCmd, []string{})},
		{"sign", signCmd.Args(signCmd, []string{})},
		{"merge", mergeCmd.Args(mergeCmd, []string{})},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.argsErr == nil {
				t.Skip("command accepts empty args")
			}

			errStr := tt.argsErr.Error()
			if !strings.Contains(errStr, "Example") && !strings.Contains(errStr, "epack "+tt.name) {
				t.Errorf("error message should include examples or usage with 'epack %s', got: %s", tt.name, errStr)
			}
		})
	}
}
