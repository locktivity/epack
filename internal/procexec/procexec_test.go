package procexec

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		return
	}

	switch os.Getenv("HELPER_MODE") {
	case "print":
		_, _ = os.Stdout.WriteString(os.Getenv("HELPER_STDOUT"))
		_, _ = os.Stderr.WriteString(os.Getenv("HELPER_STDERR"))
	case "sleep":
		ms, _ := strconv.Atoi(os.Getenv("HELPER_SLEEP_MS"))
		time.Sleep(time.Duration(ms) * time.Millisecond)
	default:
		_, _ = os.Stderr.WriteString("unknown helper mode")
		os.Exit(2)
	}

	exitCode, _ := strconv.Atoi(os.Getenv("HELPER_EXIT"))
	os.Exit(exitCode)
}

func helperSpec() Spec {
	return Spec{
		Path: os.Args[0],
		Args: []string{"-test.run=TestHelperProcess"},
		Env: []string{
			"GO_WANT_HELPER_PROCESS=1",
			"HELPER_MODE=print",
			"HELPER_STDOUT=token=abc",
			"HELPER_STDERR=secret=xyz",
			"HELPER_EXIT=0",
		},
		EnforceEnvAllowlist: true,
		AllowedEnv: []string{
			"GO_WANT_HELPER_PROCESS",
			"HELPER_MODE",
			"HELPER_STDOUT",
			"HELPER_STDERR",
			"HELPER_EXIT",
		},
	}
}

func TestRunCaptureRedaction(t *testing.T) {
	spec := helperSpec()
	spec.RedactStdout = func(b []byte) []byte { return bytes.ReplaceAll(b, []byte("abc"), []byte("REDACTED")) }
	spec.RedactStderr = func(b []byte) []byte { return bytes.ReplaceAll(b, []byte("xyz"), []byte("REDACTED")) }

	result, err := RunCapture(context.Background(), spec)
	if err != nil {
		t.Fatalf("RunCapture() error: %v", err)
	}
	if got := string(result.Stdout); got != "token=REDACTED" {
		t.Fatalf("stdout = %q, want %q", got, "token=REDACTED")
	}
	if got := string(result.Stderr); got != "secret=REDACTED" {
		t.Fatalf("stderr = %q, want %q", got, "secret=REDACTED")
	}
}

func TestRunRejectsDisallowedEnv(t *testing.T) {
	spec := helperSpec()
	spec.Env = append(spec.Env, "NOT_ALLOWED=1")

	err := Run(context.Background(), spec)
	if err == nil {
		t.Fatal("expected env policy error, got nil")
	}
	if !strings.Contains(err.Error(), "not permitted by policy") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunRejectsDirOutsideAllowedRoots(t *testing.T) {
	spec := helperSpec()
	spec.EnforceDirPolicy = true
	spec.Dir = t.TempDir()
	spec.AllowedDirRoots = []string{filepath.Join(spec.Dir, "..", "other")}

	err := Run(context.Background(), spec)
	if err == nil {
		t.Fatal("expected dir policy error, got nil")
	}
	if !strings.Contains(err.Error(), "outside allowed roots") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunWithTimeout(t *testing.T) {
	spec := Spec{
		Path: os.Args[0],
		Args: []string{"-test.run=TestHelperProcess"},
		Env: []string{
			"GO_WANT_HELPER_PROCESS=1",
			"HELPER_MODE=sleep",
			"HELPER_SLEEP_MS=500",
			"HELPER_EXIT=0",
		},
		EnforceEnvAllowlist: true,
		AllowedEnv: []string{
			"GO_WANT_HELPER_PROCESS",
			"HELPER_MODE",
			"HELPER_SLEEP_MS",
			"HELPER_EXIT",
		},
		Timeout: 50 * time.Millisecond,
	}

	start := time.Now()
	err := Run(context.Background(), spec)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
	if elapsed > 2*time.Second {
		t.Fatalf("timeout not enforced, elapsed=%s", elapsed)
	}
}
