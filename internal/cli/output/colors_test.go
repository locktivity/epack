package output

import (
	"strings"
	"testing"
)

func TestNewPalette(t *testing.T) {
	enabled := NewPalette(true)
	disabled := NewPalette(false)

	if enabled == nil || disabled == nil {
		t.Fatal("NewPalette returned nil")
	}
}

func TestPalette_Enabled(t *testing.T) {
	p := NewPalette(true)

	tests := []struct {
		name   string
		fn     func(string) string
		input  string
		hasESC bool
	}{
		{"Bold", p.Bold, "text", true},
		{"Dim", p.Dim, "text", true},
		{"Red", p.Red, "text", true},
		{"Green", p.Green, "text", true},
		{"Yellow", p.Yellow, "text", true},
		{"Blue", p.Blue, "text", true},
		{"Magenta", p.Magenta, "text", true},
		{"Cyan", p.Cyan, "text", true},
		{"BoldRed", p.BoldRed, "text", true},
		{"BoldGreen", p.BoldGreen, "text", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.fn(tt.input)
			hasESC := strings.Contains(got, "\033[")
			if hasESC != tt.hasESC {
				t.Errorf("%s(%q) has escape codes = %v, want %v", tt.name, tt.input, hasESC, tt.hasESC)
			}
			if !strings.Contains(got, tt.input) {
				t.Errorf("%s(%q) = %q, missing input text", tt.name, tt.input, got)
			}
			// Check reset code
			if tt.hasESC && !strings.HasSuffix(got, reset) {
				t.Errorf("%s(%q) = %q, missing reset code", tt.name, tt.input, got)
			}
		})
	}
}

func TestPalette_Disabled(t *testing.T) {
	p := NewPalette(false)

	tests := []struct {
		name  string
		fn    func(string) string
		input string
	}{
		{"Bold", p.Bold, "text"},
		{"Dim", p.Dim, "text"},
		{"Red", p.Red, "text"},
		{"Green", p.Green, "text"},
		{"Yellow", p.Yellow, "text"},
		{"Blue", p.Blue, "text"},
		{"Magenta", p.Magenta, "text"},
		{"Cyan", p.Cyan, "text"},
		{"BoldRed", p.BoldRed, "text"},
		{"BoldGreen", p.BoldGreen, "text"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.fn(tt.input)
			if got != tt.input {
				t.Errorf("%s(%q) = %q, want %q (no formatting when disabled)", tt.name, tt.input, got, tt.input)
			}
		})
	}
}

func TestPalette_EmptyString(t *testing.T) {
	enabled := NewPalette(true)
	disabled := NewPalette(false)

	// Empty strings should remain empty regardless of enabled state
	if got := enabled.Bold(""); got != "" {
		t.Errorf("Bold(\"\") with enabled = %q, want empty", got)
	}
	if got := disabled.Bold(""); got != "" {
		t.Errorf("Bold(\"\") with disabled = %q, want empty", got)
	}
}

func TestPalette_Success(t *testing.T) {
	t.Run("enabled", func(t *testing.T) {
		p := NewPalette(true)
		got := p.Success("operation done")
		if !strings.Contains(got, "✓") {
			t.Errorf("Success() = %q, missing checkmark", got)
		}
		if !strings.Contains(got, "operation done") {
			t.Errorf("Success() = %q, missing message", got)
		}
	})

	t.Run("disabled", func(t *testing.T) {
		p := NewPalette(false)
		got := p.Success("operation done")
		if !strings.Contains(got, "[OK]") {
			t.Errorf("Success() = %q, missing [OK] prefix", got)
		}
		if !strings.Contains(got, "operation done") {
			t.Errorf("Success() = %q, missing message", got)
		}
		if strings.Contains(got, "✓") {
			t.Errorf("Success() = %q, should not have checkmark when disabled", got)
		}
	})
}

func TestPalette_Failure(t *testing.T) {
	t.Run("enabled", func(t *testing.T) {
		p := NewPalette(true)
		got := p.Failure("operation failed")
		if !strings.Contains(got, "✗") {
			t.Errorf("Failure() = %q, missing cross mark", got)
		}
		if !strings.Contains(got, "operation failed") {
			t.Errorf("Failure() = %q, missing message", got)
		}
	})

	t.Run("disabled", func(t *testing.T) {
		p := NewPalette(false)
		got := p.Failure("operation failed")
		if !strings.Contains(got, "[FAIL]") {
			t.Errorf("Failure() = %q, missing [FAIL] prefix", got)
		}
		if !strings.Contains(got, "operation failed") {
			t.Errorf("Failure() = %q, missing message", got)
		}
		if strings.Contains(got, "✗") {
			t.Errorf("Failure() = %q, should not have cross mark when disabled", got)
		}
	})
}

func TestPalette_ANSICodes(t *testing.T) {
	p := NewPalette(true)

	// Verify specific ANSI codes
	tests := []struct {
		name string
		fn   func(string) string
		code string
	}{
		{"Bold", p.Bold, "\033[1m"},
		{"Dim", p.Dim, "\033[2m"},
		{"Red", p.Red, "\033[31m"},
		{"Green", p.Green, "\033[32m"},
		{"Yellow", p.Yellow, "\033[33m"},
		{"Blue", p.Blue, "\033[34m"},
		{"Magenta", p.Magenta, "\033[35m"},
		{"Cyan", p.Cyan, "\033[36m"},
		{"BoldRed", p.BoldRed, "\033[1;31m"},
		{"BoldGreen", p.BoldGreen, "\033[1;32m"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.fn("x")
			if !strings.HasPrefix(got, tt.code) {
				t.Errorf("%s(\"x\") = %q, should start with %q", tt.name, got, tt.code)
			}
		})
	}
}
