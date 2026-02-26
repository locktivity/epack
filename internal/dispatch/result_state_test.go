package dispatch

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/locktivity/epack/internal/componenttypes"
	"github.com/locktivity/epack/internal/securityaudit"
	"github.com/locktivity/epack/internal/toolprotocol"
)

type testOutput struct {
	stderr bytes.Buffer
}

func (o *testOutput) Stderr() interface{ Write([]byte) (int, error) } {
	return &o.stderr
}

func TestProcessToolResult_ExecFailedStateWritesTerminalResult(t *testing.T) {
	runDir := t.TempDir()
	out := &testOutput{}
	startedAt := time.Now().UTC().Add(-time.Second)
	completedAt := time.Now().UTC()

	exitCode, result := processToolResult(out, "demo", "run-1", runDir, "", startedAt, completedAt, 0, "v1.2.3", errors.New("exec boom"))

	if exitCode != componenttypes.ExitRunDirFailed {
		t.Fatalf("exit code = %d, want %d", exitCode, componenttypes.ExitRunDirFailed)
	}
	if result == nil {
		t.Fatal("result is nil")
	}
	if result.Status != toolprotocol.StatusFailure {
		t.Fatalf("status = %q, want %q", result.Status, toolprotocol.StatusFailure)
	}
	if len(result.Errors) != 1 || result.Errors[0].Code != componenttypes.ErrCodeComponentFailed {
		t.Fatalf("errors = %+v, expected component failed entry", result.Errors)
	}

	parsed, err := toolprotocol.ReadResult(filepath.Join(runDir, "result.json"))
	if err != nil {
		t.Fatalf("reading result.json: %v", err)
	}
	if parsed.Status != toolprotocol.StatusFailure {
		t.Fatalf("persisted status = %q, want %q", parsed.Status, toolprotocol.StatusFailure)
	}
}

func TestProcessToolResult_BackfilledStateOnMissingResult(t *testing.T) {
	runDir := t.TempDir()
	out := &testOutput{}
	startedAt := time.Now().UTC().Add(-time.Second)
	completedAt := time.Now().UTC()

	exitCode, result := processToolResult(out, "demo", "run-2", runDir, "", startedAt, completedAt, 0, "v1.2.3", nil)

	if exitCode != 0 {
		t.Fatalf("exit code = %d, want 0", exitCode)
	}
	if result == nil {
		t.Fatal("result is nil")
	}
	if result.Status != toolprotocol.StatusPartial {
		t.Fatalf("status = %q, want %q", result.Status, toolprotocol.StatusPartial)
	}
	if len(result.Warnings) == 0 || result.Warnings[0].Code != componenttypes.ErrCodeResultMissing {
		t.Fatalf("warnings = %+v, expected missing result warning", result.Warnings)
	}

	if _, err := os.Stat(filepath.Join(runDir, "result.json")); err != nil {
		t.Fatalf("result.json not written: %v", err)
	}
}

func TestProcessToolResult_ValidResultPreservesToolFile(t *testing.T) {
	runDir := t.TempDir()
	out := &testOutput{}
	startedAt := time.Now().UTC().Add(-time.Second)
	completedAt := time.Now().UTC()

	toolResult := createWrapperResult("demo", "run-3", runDir, "", startedAt, completedAt, "v1.2.3", nil, 0)
	toolResult.Status = toolprotocol.StatusSuccess
	data, err := json.Marshal(toolResult)
	if err != nil {
		t.Fatalf("marshal tool result: %v", err)
	}

	resultPath := filepath.Join(runDir, "result.json")
	if err := os.WriteFile(resultPath, data, 0600); err != nil {
		t.Fatalf("writing tool result: %v", err)
	}

	exitCode, result := processToolResult(out, "demo", "run-3", runDir, "", startedAt, completedAt, 0, "v1.2.3", nil)
	if exitCode != 0 {
		t.Fatalf("exit code = %d, want 0", exitCode)
	}
	if result == nil || result.Status != toolprotocol.StatusSuccess {
		t.Fatalf("unexpected result: %+v", result)
	}

	after, err := os.ReadFile(resultPath)
	if err != nil {
		t.Fatalf("reading result file: %v", err)
	}
	if !bytes.Equal(data, after) {
		t.Fatal("expected tool-written result.json to remain unchanged for valid terminal state")
	}
}

type captureAuditSink struct {
	events []securityaudit.Event
}

func (c *captureAuditSink) HandleSecurityEvent(evt securityaudit.Event) {
	c.events = append(c.events, evt)
}

func TestProcessToolResult_MissingResultEmitsBackfillAuditEvent(t *testing.T) {
	runDir := t.TempDir()
	out := &testOutput{}
	startedAt := time.Now().UTC().Add(-time.Second)
	completedAt := time.Now().UTC()

	sink := &captureAuditSink{}
	securityaudit.SetSink(sink)
	t.Cleanup(func() { securityaudit.SetSink(nil) })

	_, result := processToolResult(out, "demo", "run-audit", runDir, "", startedAt, completedAt, 0, "v1.2.3", nil)
	if result == nil {
		t.Fatal("result is nil")
	}
	if len(sink.events) == 0 {
		t.Fatal("expected at least one security audit event")
	}

	found := false
	for _, evt := range sink.events {
		if evt.Type != securityaudit.EventResultBackfilled {
			continue
		}
		if evt.Attrs["reason"] != "missing_result" {
			t.Fatalf("reason = %q, want %q", evt.Attrs["reason"], "missing_result")
		}
		found = true
	}
	if !found {
		t.Fatal("expected EventResultBackfilled event")
	}
}
