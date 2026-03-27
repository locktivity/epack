package hooks

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRunnerRunExecutesHookViaSh(t *testing.T) {
	t.Parallel()

	workDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(workDir, "epack.yaml"), []byte("collectors:\n  test:\n    binary: /bin/true\n"), 0644); err != nil {
		t.Fatalf("WriteFile(epack.yaml) error = %v", err)
	}
	hooksDir := filepath.Join(workDir, ".epack", "hooks")
	if err := os.MkdirAll(hooksDir, 0755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	outputPath := filepath.Join(workDir, "hook-output.txt")
	if err := os.WriteFile(filepath.Join(hooksDir, "pre-collect.sh"), []byte("echo hook-ran > "+outputPath+"\n"), 0644); err != nil {
		t.Fatalf("WriteFile(pre-collect.sh) error = %v", err)
	}

	runner := Runner{WorkDir: workDir}
	if err := runner.Run(context.Background(), "pre-collect"); err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("ReadFile(hook-output.txt) error = %v", err)
	}
	if string(data) != "hook-ran\n" {
		t.Fatalf("hook output = %q, want %q", string(data), "hook-ran\n")
	}
}

func TestRunnerRunReturnsSuccessForMissingHook(t *testing.T) {
	t.Parallel()

	workDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(workDir, "epack.yaml"), []byte("collectors:\n  test:\n    binary: /bin/true\n"), 0644); err != nil {
		t.Fatalf("WriteFile(epack.yaml) error = %v", err)
	}

	runner := Runner{WorkDir: workDir}
	if err := runner.Run(context.Background(), "pre-collect"); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
}

func TestRunnerRunReturnsSuccessForEmptyHook(t *testing.T) {
	t.Parallel()

	workDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(workDir, "epack.yaml"), []byte("collectors:\n  test:\n    binary: /bin/true\n"), 0644); err != nil {
		t.Fatalf("WriteFile(epack.yaml) error = %v", err)
	}
	hooksDir := filepath.Join(workDir, ".epack", "hooks")
	if err := os.MkdirAll(hooksDir, 0755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(hooksDir, "pre-collect.sh"), nil, 0644); err != nil {
		t.Fatalf("WriteFile(pre-collect.sh) error = %v", err)
	}

	runner := Runner{WorkDir: workDir}
	if err := runner.Run(context.Background(), "pre-collect"); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
}

func TestRunnerRunRejectsHookNamesWithTrailingHyphen(t *testing.T) {
	t.Parallel()

	runner := Runner{WorkDir: t.TempDir()}
	err := runner.Run(context.Background(), "pre-collect-")
	if err == nil {
		t.Fatal("Run() expected error for invalid hook name, got nil")
	}
	if !strings.Contains(err.Error(), "invalid hook name") {
		t.Fatalf("Run() error = %v, want invalid hook name", err)
	}
}

func TestRunnerRunTimesOutLongRunningHook(t *testing.T) {
	t.Parallel()

	workDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(workDir, "epack.yaml"), []byte("collectors:\n  test:\n    binary: /bin/true\n"), 0644); err != nil {
		t.Fatalf("WriteFile(epack.yaml) error = %v", err)
	}
	hooksDir := filepath.Join(workDir, ".epack", "hooks")
	if err := os.MkdirAll(hooksDir, 0755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(hooksDir, "pre-collect.sh"), []byte("sleep 1\n"), 0644); err != nil {
		t.Fatalf("WriteFile(pre-collect.sh) error = %v", err)
	}

	runner := Runner{WorkDir: workDir, Timeout: 50 * time.Millisecond}
	err := runner.Run(context.Background(), "pre-collect")
	if err == nil {
		t.Fatal("Run() expected timeout error, got nil")
	}
	if !strings.Contains(err.Error(), "timed out after 50ms") {
		t.Fatalf("Run() error = %v, want timeout message", err)
	}
}
