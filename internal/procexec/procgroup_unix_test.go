//go:build unix

package procexec

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestIsolatedProcessGroupKillsGrandchildrenOnCancel(t *testing.T) {
	dir := t.TempDir()
	pidFile := filepath.Join(dir, "pid")
	script := filepath.Join(dir, "linger.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nsleep 30 &\necho $! > "+pidFile+"\nsleep 30\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var stdout bytes.Buffer
	cmd := Command(ctx, Spec{Path: script, Stdout: &stdout, IsolateProcessGroup: true})
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	pid := waitForPID(t, pidFile)

	cancel()
	started := time.Now()
	_ = cmd.Wait()
	if elapsed := time.Since(started); elapsed > WaitDelay {
		t.Fatalf("Wait took %v; the group kill should free the output pipe at once", elapsed)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if err := syscall.Kill(pid, 0); err != nil {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("grandchild %d is still running after the group kill", pid)
}

func waitForPID(t *testing.T, path string) int {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if raw, err := os.ReadFile(path); err == nil && strings.TrimSpace(string(raw)) != "" {
			pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
			if err != nil {
				t.Fatal(err)
			}
			return pid
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("the script never wrote its grandchild's pid")
	return 0
}
