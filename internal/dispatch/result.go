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
	"github.com/locktivity/epack/internal/toolprotocol"
	"github.com/locktivity/epack/internal/version"
)

// wrapperVersion returns the current wrapper version for result.json.
func wrapperVersion() string {
	return version.Version
}

// processToolResult validates the tool's result.json or creates a wrapper backfill.
// Returns the wrapper exit code.
func processToolResult(out Output, toolName, runID, runDir, packPath string, startedAt, completedAt time.Time, toolExitCode int, toolVersion string, execErr error) int {
	resultPath := filepath.Join(runDir, "result.json")

	// Compute wrapper exit code from tool exit code
	wrapperExitCode, toolExitCodePtr := toolprotocol.NormalizeExitCode(toolExitCode)

	// Handle case where tool never ran
	if execErr != nil {
		// Tool failed to execute - create wrapper-generated result
		result := createWrapperResult(toolName, runID, runDir, packPath, startedAt, completedAt, toolVersion, nil, componenttypes.ExitRunDirFailed)
		result.Errors = append(result.Errors, toolprotocol.ErrorEntry{
			Code:    componenttypes.ErrCodeComponentFailed,
			Message: fmt.Sprintf("tool failed to execute: %s", redact.Error(execErr.Error())),
		})
		result.Status = toolprotocol.StatusFailure
		if err := toolprotocol.WriteResultAtomic(runDir, result); err != nil {
			_, _ = fmt.Fprintf(out.Stderr(), "Warning: failed to write result.json: %s\n", redact.Error(err.Error()))
		}
		return componenttypes.ExitRunDirFailed
	}

	// Check if result.json exists and read with size limit
	// SECURITY: Use boundedio for TOCTOU-safe size checking
	resultData, err := boundedio.ReadFileWithLimit(resultPath, limits.ToolResult)
	if os.IsNotExist(err) {
		// Tool didn't write result.json - create wrapper backfill
		result := createWrapperResult(toolName, runID, runDir, packPath, startedAt, completedAt, toolVersion, toolExitCodePtr, wrapperExitCode)
		result.Warnings = append(result.Warnings, toolprotocol.ErrorEntry{
			Code:    componenttypes.ErrCodeResultMissing,
			Message: "result.json not written by tool; wrapper backfill applied",
		})
		if err := toolprotocol.WriteResultAtomic(runDir, result); err != nil {
			_, _ = fmt.Fprintf(out.Stderr(), "Warning: failed to write result.json: %s\n", redact.Error(err.Error()))
		}
		return wrapperExitCode
	} else if boundedio.IsBoundedReadError(err) {
		_, _ = fmt.Fprintf(out.Stderr(), "Warning: result.json exceeds maximum size (%d bytes)\n", limits.ToolResult.Bytes())
		// Create wrapper backfill for oversized result
		result := createWrapperResult(toolName, runID, runDir, packPath, startedAt, completedAt, toolVersion, toolExitCodePtr, wrapperExitCode)
		result.Warnings = append(result.Warnings, toolprotocol.ErrorEntry{
			Code:    componenttypes.ErrCodeResultInvalid,
			Message: fmt.Sprintf("result.json exceeds maximum size (%d bytes); wrapper backfill applied", limits.ToolResult.Bytes()),
		})
		if err := toolprotocol.WriteResultAtomic(runDir, result); err != nil {
			_, _ = fmt.Fprintf(out.Stderr(), "Warning: failed to write result.json: %s\n", redact.Error(err.Error()))
		}
		return wrapperExitCode
	} else if err != nil {
		_, _ = fmt.Fprintf(out.Stderr(), "Warning: failed to read result.json: %s\n", redact.Error(err.Error()))
		return wrapperExitCode
	}

	// SECURITY: Validate no duplicate keys before unmarshaling.
	// json.Unmarshal silently keeps the last duplicate, which could allow
	// malicious tools to ambiguously override fields.
	if err := jsonutil.ValidateNoDuplicateKeys(resultData); err != nil {
		backupPath := resultPath + ".tool"
		_ = os.Rename(resultPath, backupPath)

		backfill := createWrapperResult(toolName, runID, runDir, packPath, startedAt, completedAt, toolVersion, toolExitCodePtr, wrapperExitCode)
		backfill.Warnings = append(backfill.Warnings, toolprotocol.ErrorEntry{
			Code:    componenttypes.ErrCodeResultInvalid,
			Message: fmt.Sprintf("result.json contains duplicate keys (preserved as %s); wrapper backfill applied", filepath.Base(backupPath)),
		})
		if err := toolprotocol.WriteResultAtomic(runDir, backfill); err != nil {
			_, _ = fmt.Fprintf(out.Stderr(), "Warning: failed to write result.json: %s\n", redact.Error(err.Error()))
		}
		return wrapperExitCode
	}

	// Parse and validate result.json
	var result toolprotocol.Result
	if err := json.Unmarshal(resultData, &result); err != nil {
		// Invalid JSON - preserve tool's malformed result and create wrapper backfill
		backupPath := resultPath + ".tool"
		_ = os.Rename(resultPath, backupPath)

		backfill := createWrapperResult(toolName, runID, runDir, packPath, startedAt, completedAt, toolVersion, toolExitCodePtr, wrapperExitCode)
		backfill.Warnings = append(backfill.Warnings, toolprotocol.ErrorEntry{
			Code:    componenttypes.ErrCodeResultInvalid,
			Message: fmt.Sprintf("invalid result.json (preserved as %s); wrapper backfill applied", filepath.Base(backupPath)),
		})
		if err := toolprotocol.WriteResultAtomic(runDir, backfill); err != nil {
			_, _ = fmt.Fprintf(out.Stderr(), "Warning: failed to write result.json: %s\n", redact.Error(err.Error()))
		}
		return wrapperExitCode
	}

	// SECURITY: Validate result schema - ensure required fields are present and valid.
	// This catches malformed tool outputs (missing required fields, invalid status, etc.)
	// that could break downstream consumers.
	if err := toolprotocol.ValidateResult(&result); err != nil {
		// Schema-invalid result - preserve and backfill
		backupPath := resultPath + ".tool"
		_ = os.Rename(resultPath, backupPath)

		backfill := createWrapperResult(toolName, runID, runDir, packPath, startedAt, completedAt, toolVersion, toolExitCodePtr, wrapperExitCode)
		backfill.Warnings = append(backfill.Warnings, toolprotocol.ErrorEntry{
			Code:    componenttypes.ErrCodeResultInvalid,
			Message: fmt.Sprintf("result.json schema invalid: %v (preserved as %s); wrapper backfill applied", err, filepath.Base(backupPath)),
		})
		if err := toolprotocol.WriteResultAtomic(runDir, backfill); err != nil {
			_, _ = fmt.Fprintf(out.Stderr(), "Warning: failed to write result.json: %s\n", redact.Error(err.Error()))
		}
		return wrapperExitCode
	}

	// Validate output paths - remove invalid ones and add warnings (non-fatal)
	var validOutputs []toolprotocol.OutputEntry
	for _, output := range result.Outputs {
		if err := toolprotocol.ValidateOutputPath(runDir, output.Path); err != nil {
			// Add warning for invalid output, remove from outputs list
			result.Warnings = append(result.Warnings, toolprotocol.ErrorEntry{
				Code:    componenttypes.ErrCodeInvalidOutput,
				Message: err.Error(),
				Path:    output.Path,
			})
		} else {
			validOutputs = append(validOutputs, output)
		}
	}

	// If we removed invalid outputs or added warnings, update result
	if len(validOutputs) != len(result.Outputs) || len(result.Warnings) > 0 {
		result.Outputs = validOutputs
		// Recompute status - partial if there were warnings but tool succeeded
		result.Status = toolprotocol.ComputeStatus(result.Errors, result.Warnings, wrapperExitCode)
		if err := toolprotocol.WriteResultAtomic(runDir, &result); err != nil {
			_, _ = fmt.Fprintf(out.Stderr(), "Warning: failed to update result.json: %s\n", redact.Error(err.Error()))
		}
	}

	return wrapperExitCode
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
