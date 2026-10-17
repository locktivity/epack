package exitmap

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/locktivity/epack/errors"
	"github.com/locktivity/epack/internal/exitcode"
	"github.com/locktivity/epack/internal/redact"
)

func TestToExit_Nil(t *testing.T) {
	msg, code := ToExit(nil)
	if code != exitcode.Success {
		t.Errorf("ToExit(nil) code = %d, want %d", code, exitcode.Success)
	}
	if msg != "" {
		t.Errorf("ToExit(nil) msg = %q, want empty", msg)
	}
}

func TestToExit_ErrorsError(t *testing.T) {
	// Test with explicit Exit code
	err := &errors.Error{Code: errors.InvalidInput, Exit: 42, Message: "custom error"}
	msg, code := ToExit(err)
	if code != 42 {
		t.Errorf("ToExit(errors.Error) code = %d, want 42", code)
	}
	if msg != "custom error" {
		t.Errorf("ToExit(errors.Error) msg = %q, want %q", msg, "custom error")
	}
}

func TestToExit_TypedErrors(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		wantCode int
	}{
		{
			name:     "LockfileInvalid",
			err:      errors.E(errors.LockfileInvalid, "lockfile error", nil),
			wantCode: exitcode.LockInvalid,
		},
		{
			name:     "DigestMismatch",
			err:      errors.E(errors.DigestMismatch, "digest error", nil),
			wantCode: exitcode.DigestMismatch,
		},
		{
			name:     "PackDigestMismatch",
			err:      errors.E(errors.PackDigestMismatch, "pack digest error", nil),
			wantCode: exitcode.DigestMismatch,
		},
		{
			name:     "SizeMismatch",
			err:      errors.E(errors.SizeMismatch, "size error", nil),
			wantCode: exitcode.DigestMismatch,
		},
		{
			name:     "SignatureInvalid",
			err:      errors.E(errors.SignatureInvalid, "signature error", nil),
			wantCode: exitcode.SignatureMismatch,
		},
		{
			name:     "IdentityMismatch",
			err:      errors.E(errors.IdentityMismatch, "identity error", nil),
			wantCode: exitcode.SignatureMismatch,
		},
		{
			name:     "BinaryNotFound",
			err:      errors.E(errors.BinaryNotFound, "binary error", nil),
			wantCode: exitcode.MissingBinary,
		},
		{
			name:     "NetworkError",
			err:      errors.E(errors.NetworkError, "network error", nil),
			wantCode: exitcode.Network,
		},
		{
			name:     "Timeout",
			err:      errors.E(errors.Timeout, "operation timed out", nil),
			wantCode: exitcode.Timeout,
		},
		{
			name:     "ValidationError (general)",
			err:      errors.E(errors.InvalidInput, "validation error", nil),
			wantCode: exitcode.General,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, code := ToExit(tt.err)
			if code != tt.wantCode {
				t.Errorf("ToExit(%s) code = %d, want %d", tt.name, code, tt.wantCode)
			}
		})
	}
}

func TestToExit_WrappedError(t *testing.T) {
	// Test that wrapped errors are unwrapped to find the code
	inner := errors.E(errors.DigestMismatch, "digest error", nil)
	wrapped := fmt.Errorf("outer context: %w", inner)

	_, code := ToExit(wrapped)
	if code != exitcode.DigestMismatch {
		t.Errorf("ToExit(wrapped) code = %d, want %d", code, exitcode.DigestMismatch)
	}
}

func TestToExit_PlainError(t *testing.T) {
	err := fmt.Errorf("plain error")
	msg, code := ToExit(err)
	if code != exitcode.General {
		t.Errorf("ToExit(plain) code = %d, want %d", code, exitcode.General)
	}
	if msg != "plain error" {
		t.Errorf("ToExit(plain) msg = %q, want %q", msg, "plain error")
	}
}

func TestToExit_RedactsSecrets(t *testing.T) {
	// Enable redaction for this test
	redact.Enable()
	defer redact.Disable()

	// Error containing a JWT token
	err := fmt.Errorf("auth failed: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.signature")
	msg, _ := ToExit(err)

	// Should be redacted
	if msg == err.Error() {
		t.Errorf("ToExit did not redact secret, got %q", msg)
	}
	// Should contain [REDACTED]
	if msg != "auth failed: Bearer [REDACTED]" {
		t.Errorf("ToExit redaction unexpected: %q", msg)
	}
}

func TestToExitResult(t *testing.T) {
	err := errors.E(errors.NetworkError, "connection failed", nil)
	result := ToExitResult(err)

	if result.Code != exitcode.Network {
		t.Errorf("ToExitResult code = %d, want %d", result.Code, exitcode.Network)
	}
	if result.Message != "connection failed" {
		t.Errorf("ToExitResult msg = %q, want %q", result.Message, "connection failed")
	}
}

func TestWriteErrorFile_TypedError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "error.txt")
	err := errors.WithHint(errors.LockConfigMismatch, exitcode.LockInvalid,
		"locked version v0.2.3 does not satisfy configured constraint", "Run 'epack lock'", nil)

	if werr := WriteErrorFile(path, err); werr != nil {
		t.Fatalf("WriteErrorFile() = %v", werr)
	}

	data, rerr := os.ReadFile(path)
	if rerr != nil {
		t.Fatalf("reading error file: %v", rerr)
	}
	got := string(data)
	want := fmt.Sprintf("code=lock_config_mismatch\nexit=%d\nsummary=locked version v0.2.3 does not satisfy configured constraint\n", exitcode.LockInvalid)
	if got != want {
		t.Fatalf("error file = %q, want %q", got, want)
	}
}

func TestWriteErrorFile_PlainErrorAppends(t *testing.T) {
	path := filepath.Join(t.TempDir(), "error.txt")

	if werr := WriteErrorFile(path, fmt.Errorf("first")); werr != nil {
		t.Fatalf("WriteErrorFile() = %v", werr)
	}
	if werr := WriteErrorFile(path, fmt.Errorf("second\nwith detail")); werr != nil {
		t.Fatalf("WriteErrorFile() = %v", werr)
	}

	data, rerr := os.ReadFile(path)
	if rerr != nil {
		t.Fatalf("reading error file: %v", rerr)
	}
	got := string(data)
	want := "code=error\nexit=1\nsummary=first\ncode=error\nexit=1\nsummary=second\n"
	if got != want {
		t.Fatalf("error file = %q, want %q", got, want)
	}
}

// failedRun stands in for collector.FailedError, which the collector package
// tests against WriteErrorFile end to end.
type failedRun struct{ summary *errors.Error }

func (f failedRun) Error() string { return f.summary.Message }
func (f failedRun) Unwrap() error { return f.summary }

func (failedRun) EachCollectorFailure(fn func(collector string, code errors.Code, exit int, codeSource string)) {
	fn("okta", "auth_failed", 3, "exit_code")
	fn("sentry", errors.Timeout, exitcode.Timeout, "runner")
}

func TestWriteErrorFile_ListsEachFailedCollector(t *testing.T) {
	path := filepath.Join(t.TempDir(), "error.txt")
	err := fmt.Errorf("collect failed: %w", failedRun{&errors.Error{Code: "collect_failed", Exit: exitcode.General, Message: "2 collectors failed: okta, sentry"}})

	if werr := WriteErrorFile(path, err); werr != nil {
		t.Fatalf("WriteErrorFile() = %v", werr)
	}

	data, rerr := os.ReadFile(path)
	if rerr != nil {
		t.Fatalf("reading error file: %v", rerr)
	}
	got := string(data)
	want := "code=collect_failed\nexit=1\nsummary=collect failed: 2 collectors failed: okta, sentry\n" +
		"collector=okta code=auth_failed exit=3 code_source=exit_code\n" +
		fmt.Sprintf("collector=sentry code=timeout exit=%d code_source=runner\n", exitcode.Timeout)
	if got != want {
		t.Fatalf("error file = %q, want %q", got, want)
	}
}

func TestReadCollectorFailures_ReadsWhatWriteErrorFileWrote(t *testing.T) {
	path := filepath.Join(t.TempDir(), "error.txt")
	err := failedRun{&errors.Error{Code: "collect_failed", Exit: exitcode.General, Message: "2 collectors failed: okta, sentry"}}
	if werr := WriteErrorFile(path, err); werr != nil {
		t.Fatalf("WriteErrorFile() = %v", werr)
	}

	got := ReadCollectorFailures(path, "collect_failed")
	want := []CollectorFailure{{Collector: "okta", Code: "auth_failed", Exit: 3, CodeSource: "exit_code"}, {Collector: "sentry", Code: "timeout", Exit: exitcode.Timeout, CodeSource: "runner"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ReadCollectorFailures() = %+v, want %+v", got, want)
	}
}

func TestReadCollectorFailures_OnlyTheLastErrorWithTheReportedCode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "error.txt")
	earlier := "code=collect_failed\nexit=1\nsummary=2 collectors failed: okta, sentry\n" +
		"collector=okta code=auth_failed exit=3\ncollector=sentry code=timeout exit=13\n"
	last := "code=collect_failed\nexit=3\nsummary=okta: exited with code 3: 401 Unauthorized\n" +
		"collector=okta code=auth_failed exit=3\ncollector=tls code=collector_error exit=three\n"
	if err := os.WriteFile(path, []byte(earlier+last), 0600); err != nil {
		t.Fatal(err)
	}

	got := ReadCollectorFailures(path, "collect_failed")
	want := []CollectorFailure{{Collector: "okta", Code: "auth_failed", Exit: 3}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ReadCollectorFailures() = %+v, want %+v", got, want)
	}
	if got := ReadCollectorFailures(path, "workflow_failed"); got != nil {
		t.Errorf("another code = %+v, want none", got)
	}

	hook := "code=hook_failed\nexit=1\nsummary=post-collect hook exited 1\n"
	if err := os.WriteFile(path, []byte(earlier+hook), 0600); err != nil {
		t.Fatal(err)
	}
	if got := ReadCollectorFailures(path, "collect_failed"); got != nil {
		t.Errorf("collect failure before a later error = %+v, want none", got)
	}
	if got := ReadCollectorFailures(path, "hook_failed"); got != nil {
		t.Errorf("later error without collectors = %+v, want none", got)
	}
}

func TestReadCollectorFailures_NoFileListsNone(t *testing.T) {
	if got := ReadCollectorFailures("", "collect_failed"); got != nil {
		t.Errorf("no path = %+v, want none", got)
	}
	if got := ReadCollectorFailures(filepath.Join(t.TempDir(), "missing.txt"), "collect_failed"); got != nil {
		t.Errorf("missing file = %+v, want none", got)
	}
}
