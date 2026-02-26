package dispatch

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/locktivity/epack/errors"
	"github.com/locktivity/epack/internal/boundedio"
	"github.com/locktivity/epack/internal/componenttypes"
	"github.com/locktivity/epack/internal/jsonutil"
	"github.com/locktivity/epack/internal/limits"
	"github.com/locktivity/epack/internal/redact"
	"github.com/locktivity/epack/internal/safefile"
	"github.com/locktivity/epack/internal/securityaudit"
	"github.com/locktivity/epack/internal/toolprotocol"
	"github.com/locktivity/epack/internal/version"
)

// wrapperVersion returns the current wrapper version for result.json.
func wrapperVersion() string {
	return version.Version
}

// processToolResult validates the tool's result.json or creates a wrapper backfill.
// Returns the wrapper exit code and the final result (for summary output).
func processToolResult(out Output, toolName, runID, runDir, packPath string, startedAt, completedAt time.Time, toolExitCode int, toolVersion string, execErr error) (int, *toolprotocol.Result) {
	resultPath := filepath.Join(runDir, "result.json")

	// Compute wrapper exit code from tool exit code
	wrapperExitCode, toolExitCodePtr := toolprotocol.NormalizeExitCode(toolExitCode)
	state := toolprotocol.RunStateCreated
	var result *toolprotocol.Result
	transition := func(next toolprotocol.RunState) error {
		var err error
		state, err = toolprotocol.TransitionRunState(state, next)
		return err
	}
	finalize := func() (int, *toolprotocol.Result) {
		return wrapperExitCode, finalizeResultState(out, runDir, state, result, wrapperExitCode)
	}

	if execErr != nil {
		result = createWrapperResult(toolName, runID, runDir, packPath, startedAt, completedAt, toolVersion, nil, componenttypes.ExitRunDirFailed)
		result.Errors = append(result.Errors, toolprotocol.ErrorEntry{
			Code:    componenttypes.ErrCodeComponentFailed,
			Message: fmt.Sprintf("tool failed to execute: %s", redact.Error(execErr.Error())),
		})
		result.Status = toolprotocol.StatusFailure
		if err := transition(toolprotocol.RunStateExecFailed); err != nil {
			return handleRunStateTransitionFailure(out, runDir, result, wrapperExitCode, err)
		}
		wrapperExitCode = componenttypes.ExitRunDirFailed
		return finalize()
	}

	resultData, err := boundedio.ReadFileWithLimit(resultPath, limits.ToolResult)
	if err != nil {
		backfillReason := "read_error"
		switch {
		case os.IsNotExist(err):
			backfillReason = "missing_result"
			result = createBackfilledResult(toolName, runID, runDir, packPath, startedAt, completedAt, toolVersion, toolExitCodePtr, wrapperExitCode,
				componenttypes.ErrCodeResultMissing, "result.json not written by tool; wrapper backfill applied")
		case boundedio.IsBoundedReadError(err):
			backfillReason = "result_too_large"
			_, _ = fmt.Fprintf(out.Stderr(), "Warning: result.json exceeds maximum size (%d bytes)\n", limits.ToolResult.Bytes())
			result = createBackfilledResult(toolName, runID, runDir, packPath, startedAt, completedAt, toolVersion, toolExitCodePtr, wrapperExitCode,
				componenttypes.ErrCodeResultInvalid, fmt.Sprintf("result.json exceeds maximum size (%d bytes); wrapper backfill applied", limits.ToolResult.Bytes()))
		default:
			_, _ = fmt.Fprintf(out.Stderr(), "Warning: failed to read result.json: %s\n", redact.Error(err.Error()))
			result = createBackfilledResult(toolName, runID, runDir, packPath, startedAt, completedAt, toolVersion, toolExitCodePtr, wrapperExitCode,
				componenttypes.ErrCodeResultInvalid, fmt.Sprintf("failed to read result.json: %s; wrapper backfill applied", redact.Error(err.Error())))
		}
		emitResultBackfillEvent(toolName, runID, backfillReason, result.Warnings)
		if err := transition(toolprotocol.RunStateBackfilled); err != nil {
			return handleRunStateTransitionFailure(out, runDir, result, wrapperExitCode, err)
		}
		return finalize()
	}

	parsed, parseErr := parseToolResultData(resultData, resultPath)
	if parseErr != nil {
		result = createBackfilledResult(toolName, runID, runDir, packPath, startedAt, completedAt, toolVersion, toolExitCodePtr, wrapperExitCode,
			componenttypes.ErrCodeResultInvalid, parseErr.Error())
		emitResultBackfillEvent(toolName, runID, "invalid_result", result.Warnings)
		if err := transition(toolprotocol.RunStateBackfilled); err != nil {
			return handleRunStateTransitionFailure(out, runDir, result, wrapperExitCode, err)
		}
		return finalize()
	}

	result = parsed
	if err := transition(toolprotocol.RunStateToolResultValid); err != nil {
		return handleRunStateTransitionFailure(out, runDir, result, wrapperExitCode, err)
	}
	return finalize()
}

func parseToolResultData(resultData []byte, resultPath string) (*toolprotocol.Result, error) {
	if err := jsonutil.ValidateNoDuplicateKeys(resultData); err != nil {
		backupPath := preserveToolResult(resultPath)
		return nil, fmt.Errorf("result.json contains duplicate keys (preserved as %s); wrapper backfill applied", filepath.Base(backupPath))
	}

	var result toolprotocol.Result
	if err := json.Unmarshal(resultData, &result); err != nil {
		backupPath := preserveToolResult(resultPath)
		return nil, fmt.Errorf("invalid result.json (preserved as %s); wrapper backfill applied", filepath.Base(backupPath))
	}

	if err := toolprotocol.ValidateResult(&result); err != nil {
		backupPath := preserveToolResult(resultPath)
		return nil, fmt.Errorf("result.json schema invalid: %v (preserved as %s); wrapper backfill applied", err, filepath.Base(backupPath))
	}

	return &result, nil
}

func preserveToolResult(resultPath string) string {
	backupPath := resultPath + ".tool"
	runDir := filepath.Dir(resultPath)
	_ = safefile.Rename(runDir, resultPath, backupPath)
	return backupPath
}

func createBackfilledResult(toolName, runID, runDir, packPath string, startedAt, completedAt time.Time, toolVersion string, toolExitCodePtr *int, wrapperExitCode int, code, message string) *toolprotocol.Result {
	result := createWrapperResult(toolName, runID, runDir, packPath, startedAt, completedAt, toolVersion, toolExitCodePtr, wrapperExitCode)
	result.Warnings = append(result.Warnings, toolprotocol.ErrorEntry{
		Code:    code,
		Message: message,
	})
	return result
}

func finalizeResultState(out Output, runDir string, state toolprotocol.RunState, result *toolprotocol.Result, wrapperExitCode int) *toolprotocol.Result {
	if result == nil {
		return nil
	}
	if !toolprotocol.IsTerminalRunState(state) {
		result.Warnings = append(result.Warnings, toolprotocol.ErrorEntry{
			Code:    componenttypes.ErrCodeResultInvalid,
			Message: fmt.Sprintf("internal wrapper state error: non-terminal state %q", state),
		})
		state = toolprotocol.RunStateBackfilled
	}

	changed := sanitizeResultForTerminalState(runDir, result, wrapperExitCode)
	shouldWrite := state != toolprotocol.RunStateToolResultValid || changed
	if shouldWrite {
		writeResultWithWarning(out, runDir, result)
	}
	return result
}

func handleRunStateTransitionFailure(out Output, runDir string, result *toolprotocol.Result, wrapperExitCode int, transitionErr error) (int, *toolprotocol.Result) {
	if result == nil {
		result = &toolprotocol.Result{}
	}
	result.Warnings = append(result.Warnings, toolprotocol.ErrorEntry{
		Code:    componenttypes.ErrCodeResultInvalid,
		Message: fmt.Sprintf("internal wrapper state transition failure: %v", transitionErr),
	})
	return wrapperExitCode, finalizeResultState(out, runDir, toolprotocol.RunStateBackfilled, result, wrapperExitCode)
}

func emitResultBackfillEvent(toolName, runID, reason string, warnings []toolprotocol.ErrorEntry) {
	attrs := map[string]string{
		"reason": reason,
	}
	if runID != "" {
		attrs["run_id"] = runID
	}
	if len(warnings) > 0 {
		attrs["warning_code"] = warnings[0].Code
	}

	securityaudit.Emit(securityaudit.Event{
		Type:        securityaudit.EventResultBackfilled,
		Component:   "dispatch",
		Name:        toolName,
		Description: "wrapper backfilled tool result",
		Attrs:       attrs,
	})
}

func sanitizeResultForTerminalState(runDir string, result *toolprotocol.Result, wrapperExitCode int) bool {
	changed := false
	validOutputs := make([]toolprotocol.OutputEntry, 0, len(result.Outputs))
	for _, output := range result.Outputs {
		if err := toolprotocol.ValidateOutputPath(runDir, output.Path); err != nil {
			changed = true
			result.Warnings = append(result.Warnings, toolprotocol.ErrorEntry{
				Code:    componenttypes.ErrCodeInvalidOutput,
				Message: err.Error(),
				Path:    output.Path,
			})
			continue
		}
		validOutputs = append(validOutputs, output)
	}
	if len(validOutputs) != len(result.Outputs) {
		changed = true
	}
	result.Outputs = validOutputs
	result.Status = toolprotocol.ComputeStatus(result.Errors, result.Warnings, wrapperExitCode)
	return changed
}

func writeResultWithWarning(out Output, runDir string, result *toolprotocol.Result) {
	if err := toolprotocol.WriteResultAtomic(runDir, result); err != nil {
		_, _ = fmt.Fprintf(out.Stderr(), "Warning: failed to write result.json: %s\n", redact.Error(err.Error()))
	}
}

// printRunSummary prints a summary of the tool run for user feedback.
// Respects quiet mode - only prints if not in quiet mode.
func printRunSummary(out Output, result *toolprotocol.Result, runDir string, quiet bool) {
	if quiet || result == nil {
		return
	}

	w := out.Stderr()

	// Status indicator
	var statusIcon string
	switch result.Status {
	case toolprotocol.StatusSuccess:
		statusIcon = "✓"
	case toolprotocol.StatusPartial:
		statusIcon = "⚠"
	default:
		statusIcon = "✗"
	}

	// Format duration
	duration := formatDuration(result.DurationMs)

	// Print summary header
	_, _ = fmt.Fprintf(w, "\n%s %s completed in %s\n", statusIcon, result.Tool.Name, duration)

	// Print outputs
	if len(result.Outputs) > 0 {
		_, _ = fmt.Fprintf(w, "\nOutputs:\n")
		for _, output := range result.Outputs {
			_, _ = fmt.Fprintf(w, "  • %s\n", output.Path)
		}
	}

	// Print warnings (if any)
	if len(result.Warnings) > 0 {
		_, _ = fmt.Fprintf(w, "\nWarnings:\n")
		for _, warning := range result.Warnings {
			_, _ = fmt.Fprintf(w, "  ⚠ %s\n", warning.Message)
		}
	}

	// Print run directory
	_, _ = fmt.Fprintf(w, "\nRun directory: %s\n", runDir)
}

// formatDuration formats milliseconds into a human-readable duration.
func formatDuration(ms int64) string {
	if ms < 1000 {
		return fmt.Sprintf("%dms", ms)
	}
	secs := float64(ms) / 1000.0
	if secs < 60 {
		return fmt.Sprintf("%.1fs", secs)
	}
	mins := int(secs / 60)
	remainingSecs := secs - float64(mins*60)
	return fmt.Sprintf("%dm%.1fs", mins, remainingSecs)
}

// createWrapperResult creates a wrapper-generated result.json.
func createWrapperResult(toolName, runID, runDir, packPath string, startedAt, completedAt time.Time, toolVersion string, toolExitCode *int, wrapperExitCode int) *toolprotocol.Result {
	result := &toolprotocol.Result{
		SchemaVersion: toolprotocol.CurrentSchemaVersion,
		Wrapper:       toolprotocol.NewWrapperInfo(wrapperVersion()),
		Tool:          toolprotocol.NewToolInfo(toolName, toolVersion, toolprotocol.CurrentProtocolVersion),
		RunID:         runID,
		PackPath:      packPath,
		StartedAt:     toolprotocol.FormatTimestamp(startedAt),
		CompletedAt:   toolprotocol.FormatTimestamp(completedAt),
		DurationMs:    completedAt.Sub(startedAt).Milliseconds(),
		ExitCode:      wrapperExitCode,
		ToolExitCode:  toolExitCode,
		Inputs:        map[string]any{}, // Empty inputs for backfill
		Outputs:       []toolprotocol.OutputEntry{},
		Errors:        []toolprotocol.ErrorEntry{},
		Warnings:      []toolprotocol.ErrorEntry{},
	}

	// Compute status based on exit code
	result.Status = toolprotocol.ComputeStatus(result.Errors, result.Warnings, wrapperExitCode)

	return result
}

// writePreExecFailure writes a result.json for wrapper pre-execution failures.
// This ensures that even failures like "pack required" produce a run record per the spec.
func writePreExecFailure(out Output, toolName, runID, runDir, packPath, toolVersion string, exitCode int, errCode, errMsg string) error {
	startedAt := time.Now().UTC()
	completedAt := startedAt // Instant failure

	result := createWrapperResult(toolName, runID, runDir, packPath, startedAt, completedAt, toolVersion, nil, exitCode)
	result.Errors = append(result.Errors, toolprotocol.ErrorEntry{
		Code:    errCode,
		Message: errMsg,
	})
	result.Status = toolprotocol.StatusFailure

	if err := toolprotocol.WriteResultAtomic(runDir, result); err != nil {
		_, _ = fmt.Fprintf(out.Stderr(), "Warning: failed to write result.json: %s\n", redact.Error(err.Error()))
	}

	return &errors.Error{Code: errors.InvalidInput, Exit: exitCode, Message: errMsg}
}
