package dispatch

import (
	"bytes"
	"strings"
	"testing"

	epackerrors "github.com/locktivity/epack/errors"
	"github.com/locktivity/epack/internal/componenttypes"
)

type validateInputsOutput struct {
	buf bytes.Buffer
}

func (o *validateInputsOutput) Stderr() interface{ Write([]byte) (int, error) } {
	return &o.buf
}

func TestValidateToolInputs_PackRequiredIncludesUsage(t *testing.T) {
	out := &validateInputsOutput{}

	err := validateToolInputs(out, "scan", "run-1", "", "", "", "v1.2.3", true, nil)
	if err == nil {
		t.Fatal("validateToolInputs() expected error, got nil")
	}

	exitErr, ok := err.(*epackerrors.Error)
	if !ok {
		t.Fatalf("validateToolInputs() error type = %T, want *errors.Error", err)
	}
	if exitErr.ExitCode() != componenttypes.ExitPackRequired {
		t.Fatalf("ExitCode = %d, want %d", exitErr.ExitCode(), componenttypes.ExitPackRequired)
	}

	msg := exitErr.Error()
	wantParts := []string{
		"pack required but not provided",
		"Usage: epack tool scan <file.epack> [tool args...]",
		"Example: epack tool scan evidence.epack",
	}
	for _, want := range wantParts {
		if !strings.Contains(msg, want) {
			t.Fatalf("error message missing %q in %q", want, msg)
		}
	}
}
