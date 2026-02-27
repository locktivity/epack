// Package toolprotocol implements the epack Tool Protocol v1.
// This package provides types and utilities for tool execution, result handling,
// and run directory management.
package toolprotocol

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	epackerrors "github.com/locktivity/epack/errors"
	"github.com/locktivity/epack/internal/boundedio"
	"github.com/locktivity/epack/internal/digest"
	"github.com/locktivity/epack/internal/jsonutil"
	"github.com/locktivity/epack/internal/limits"
	"github.com/locktivity/epack/internal/safefile"
	"github.com/locktivity/epack/internal/safefile/tx"
	"github.com/locktivity/epack/internal/timestamp"
)

// Result represents the result.json schema for tool runs.
// All fields marked as "Yes" in Required are always present.
type Result struct {
	SchemaVersion int           `json:"schema_version"`
	Wrapper       WrapperInfo   `json:"wrapper"`
	Tool          ToolInfo      `json:"tool"`
	RunID         string        `json:"run_id"`
	PackPath      string        `json:"pack_path,omitempty"`   // Omit for packless runs
	PackDigest    string        `json:"pack_digest,omitempty"` // Omit for packless runs
	StartedAt     string        `json:"started_at"`
	CompletedAt   string        `json:"completed_at"`
	DurationMs    int64         `json:"duration_ms"`
	ExitCode      int           `json:"exit_code"`
	ToolExitCode  *int          `json:"tool_exit_code"` // null if tool never ran
	Status        string        `json:"status"`         // success, failure, partial
	Inputs        any           `json:"inputs"`         // Tool inputs (may be empty {})
	Outputs       []OutputEntry `json:"outputs"`
	Errors        []ErrorEntry  `json:"errors"`
	Warnings      []ErrorEntry  `json:"warnings"`

	// Optional fields for run metadata and provenance.
	// These are populated by tools or orchestration systems that need to track
	// identity, CI context, or sync state. Tools may leave these empty.
	Sync       *SyncMetadata   `json:"sync,omitempty"`        // Sync/ledger state
	Identity   *IdentityInfo   `json:"identity,omitempty"`    // Actor identity for audit trails
	RunContext *RunContextInfo `json:"run_context,omitempty"` // CI/environment context
	RunDigest  string          `json:"run_digest,omitempty"`  // Cryptographic hash of run for deduplication

	// Supply chain provenance fields (populated by wrapper from lockfile).
	// These fields are always set when running a locked tool.
	Signing      *SigningIdentity  `json:"signing,omitempty"`       // Sigstore signing identity
	ResolvedFrom *ResolvedFromInfo `json:"resolved_from,omitempty"` // Resolution provenance
}

// WrapperInfo contains metadata about the wrapper that orchestrated the run.
type WrapperInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// ToolInfo contains metadata about the tool that was executed.
type ToolInfo struct {
	Name            string `json:"name"`
	Version         string `json:"version"`
	ProtocolVersion int    `json:"protocol_version"`
}

// OutputEntry describes a file produced by the tool.
type OutputEntry struct {
	Path      string `json:"path"`
	MediaType string `json:"media_type"`
	Digest    string `json:"digest,omitempty"`
	Bytes     int64  `json:"bytes,omitempty"`
}

// ErrorEntry is a structured error or warning.
type ErrorEntry struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Path    string `json:"path,omitempty"`
	Details any    `json:"details,omitempty"`
}

// SyncMetadata contains optional metadata for run synchronization.
// This enables tracking which runs have been synced to external systems.
type SyncMetadata struct {
	LedgerID  *string `json:"ledger_id"`           // External ledger/database ID after sync
	SyncedAt  *string `json:"synced_at"`           // Timestamp when run was synced
	Workspace string  `json:"workspace,omitempty"` // Workspace/org context
}

// IdentityInfo contains optional identity metadata for audit trails.
// This enables tracking who initiated a run and how they authenticated.
type IdentityInfo struct {
	Workspace string `json:"workspace,omitempty"`  // Workspace/org context
	Actor     string `json:"actor,omitempty"`      // User, service account, or CI identity
	ActorType string `json:"actor_type,omitempty"` // "user", "service", or "ci"
	AuthMode  string `json:"auth_mode,omitempty"`  // "interactive", "api_key", or "ci_token"
}

// RunContextInfo contains optional CI/environment metadata.
// This enables tracking the execution environment for provenance.
type RunContextInfo struct {
	CI         bool   `json:"ci,omitempty"`          // True if running in CI environment
	CIProvider string `json:"ci_provider,omitempty"` // e.g., "github-actions", "gitlab-ci"
	Repo       string `json:"repo,omitempty"`        // Source repository URL
	Commit     string `json:"commit,omitempty"`      // Git commit SHA
	Branch     string `json:"branch,omitempty"`      // Git branch or ref
	RunnerOS   string `json:"runner_os,omitempty"`   // e.g., "linux", "darwin"
	RunnerArch string `json:"runner_arch,omitempty"` // e.g., "amd64", "arm64"
}

// SigningIdentity contains cryptographic signing information from the lockfile.
// This provides supply chain provenance for the tool binary.
type SigningIdentity struct {
	Issuer              string `json:"issuer,omitempty"`                // OIDC issuer (e.g., "https://token.actions.githubusercontent.com")
	Subject             string `json:"subject,omitempty"`               // Certificate subject (e.g., workflow path)
	SourceRepositoryURI string `json:"source_repository_uri,omitempty"` // Source repo from Sigstore cert
	SourceRepositoryRef string `json:"source_repository_ref,omitempty"` // Source ref from Sigstore cert
}

// ResolvedFromInfo captures where the tool was resolved from.
// This provides traceability back to the registry/source.
type ResolvedFromInfo struct {
	Registry   string `json:"registry,omitempty"`   // Registry name (e.g., "github", "locktivity")
	Descriptor string `json:"descriptor,omitempty"` // Original descriptor (e.g., "owner/repo@^1.0.0")
}

// Capabilities represents the JSON returned by a tool's --capabilities flag.
type Capabilities struct {
	Name            string `json:"name"`
	Version         string `json:"version"`
	ProtocolVersion int    `json:"protocol_version"`
	Description     string `json:"description,omitempty"`
	RequiresPack    bool   `json:"requires_pack"`
	Network         bool   `json:"network,omitempty"`

	// Tool dependencies (wrapper may check these before invocation)
	RequiresTools   []string `json:"requires_tools,omitempty"`   // Tools that must run first (e.g., ["index"])
	RequiresOutputs []string `json:"requires_outputs,omitempty"` // Output files that must exist (e.g., ["index/outputs/embeddings.json"])

	// Optional fields for future registry integration
	Publisher       string   `json:"publisher,omitempty"`
	Repo            string   `json:"repo,omitempty"`
	SigningIdentity string   `json:"signing_identity,omitempty"`
	Commands        []string `json:"commands,omitempty"`
}

// CurrentSchemaVersion is the current result.json schema version.
const CurrentSchemaVersion = 1

// CurrentProtocolVersion is the current tool protocol version.
const CurrentProtocolVersion = 1

// Status values for result.json
const (
	StatusSuccess = "success"
	StatusFailure = "failure"
	StatusPartial = "partial"
)

// RunState models wrapper-side lifecycle states when processing a tool run.
// These states are used by wrapper orchestration to ensure one terminal write path.
type RunState string

const (
	RunStateCreated         RunState = "created"
	RunStateExecFailed      RunState = "exec_failed"
	RunStateToolResultValid RunState = "tool_result_valid"
	RunStateBackfilled      RunState = "backfilled"
)

// IsTerminalRunState returns true when the state is terminal.
func IsTerminalRunState(state RunState) bool {
	switch state {
	case RunStateExecFailed, RunStateToolResultValid, RunStateBackfilled:
		return true
	default:
		return false
	}
}

// CanTransitionRunState returns true if transitioning from current to next is valid.
// State transitions are intentionally strict:
//   - created -> exec_failed|tool_result_valid|backfilled
//   - terminal states are immutable (except idempotent self-transition)
func CanTransitionRunState(current, next RunState) bool {
	if current == next && IsTerminalRunState(current) {
		return true
	}
	if current != RunStateCreated {
		return false
	}
	return IsTerminalRunState(next)
}

// TransitionRunState validates and applies a state transition.
func TransitionRunState(current, next RunState) (RunState, error) {
	if !CanTransitionRunState(current, next) {
		return current, fmt.Errorf("invalid run state transition: %s -> %s", current, next)
	}
	return next, nil
}

// Exit codes and error codes are centralized in componenttypes package.
// Use componenttypes.ExitComponentNotFound, componenttypes.ErrCodeComponentNotFound, etc.

// FormatTimestamp formats a time in the normative protocol format.
// Uses internal/timestamp package for centralized format enforcement.
func FormatTimestamp(t time.Time) string {
	return timestamp.FromTime(t).String()
}

// ParseTimestamp parses a timestamp in the normative protocol format.
// Uses internal/timestamp package for strict format validation.
func ParseTimestamp(s string) (time.Time, error) {
	ts, err := timestamp.Parse(s)
	if err != nil {
		return time.Time{}, err
	}
	return ts.Time(), nil
}

// runIDCounter is a per-process monotonic counter for run ID generation.
var (
	runIDMu      sync.Mutex
	runIDCounter uint32
	lastRunIDTs  string
)

// GenerateRunID generates a unique run ID in the format:
// YYYY-MM-DDTHH-MM-SS-uuuuuuZ-NNNNNN
//
// The counter guarantees monotonicity within a single process.
// Cross-process uniqueness is handled by mkdir-retry in CreateRunDir.
func GenerateRunID() string {
	runIDMu.Lock()
	defer runIDMu.Unlock()

	now := time.Now().UTC()
	// Format: YYYY-MM-DDTHH-MM-SS-uuuuuuZ
	ts := fmt.Sprintf("%04d-%02d-%02dT%02d-%02d-%02d-%06dZ",
		now.Year(), now.Month(), now.Day(),
		now.Hour(), now.Minute(), now.Second(),
		now.Nanosecond()/1000) // microseconds

	if ts == lastRunIDTs {
		runIDCounter++
	} else {
		runIDCounter = 0
		lastRunIDTs = ts
	}

	return fmt.Sprintf("%s-%06d", ts, runIDCounter)
}

// CreateRunDir creates a run directory with collision handling.
// Returns the run ID used and the full path to the run directory.
//
// For pack-based runs: baseDir/<pack>.epack/tools/<tool>/<run-id>/
// For packless runs: baseDir/runs/<tool>/<run-id>/
//
// SECURITY: Uses safefile.MkdirAllPrivate to prevent symlink-based attacks where
// an attacker creates a symlink at .epack or runs/ pointing to an arbitrary
// directory. This ensures all directory creation stays within baseDir.
func CreateRunDir(baseDir, toolName string, withPack bool) (runID, runDir string, err error) {
	var parentDir string
	if withPack {
		parentDir = filepath.Join(baseDir, "tools", toolName)
	} else {
		parentDir = filepath.Join(baseDir, "runs", toolName)
	}

	// Ensure the baseDir exists before using safefile.MkdirAllPrivate.
	// For packless runs, baseDir is a user-controlled state directory (e.g., $XDG_STATE_HOME/epack)
	// that may not exist yet. We create it with os.MkdirAll since it's a trusted base path.
	// SECURITY NOTE: os.MkdirAll is acceptable here because baseDir is derived from
	// trusted sources (XDG_STATE_HOME, user home dir) - not from user input or pack paths.
	if err := os.MkdirAll(baseDir, 0700); err != nil {
		return "", "", fmt.Errorf("creating base dir: %w", err)
	}

	// SECURITY: Use safefile.MkdirAllPrivate to refuse symlinks in the path.
	// This prevents an attacker from redirecting run output outside the
	// intended tree by creating a symlink at any parent directory component.
	if err := safefile.MkdirAllPrivate(baseDir, parentDir); err != nil {
		return "", "", fmt.Errorf("creating parent dir: %w", err)
	}

	// Try to create run directory with collision retry
	// os.Mkdir is atomic - if a symlink exists at runDir, it will fail
	const maxRetries = 100
	for i := 0; i < maxRetries; i++ {
		runID = GenerateRunID()
		runDir = filepath.Join(parentDir, runID)

		err := os.Mkdir(runDir, 0700)
		if err == nil {
			return runID, runDir, nil
		}
		if !os.IsExist(err) {
			return "", "", fmt.Errorf("creating run dir: %w", err)
		}
		// Directory exists, retry with new run ID
	}

	return "", "", fmt.Errorf("failed to create unique run directory after %d attempts", maxRetries)
}

// ValidateDigest checks if a digest string matches the required format.
// Uses internal/digest package for centralized format validation.
func ValidateDigest(d string) error {
	if err := digest.Validate(d); err != nil {
		return epackerrors.E(epackerrors.InvalidInput, "invalid digest format: must be sha256:<64 lowercase hex chars>", err)
	}
	return nil
}

// ComputeFileDigest computes the SHA256 digest of a file in the protocol format.
// Uses internal/digest package for consistent formatting.
func ComputeFileDigest(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()

	d, err := digest.FromReader(f)
	if err != nil {
		return "", err
	}

	return d.String(), nil
}

// ValidateOutputPath validates an output path according to protocol rules.
// Returns nil if valid, or an error describing the problem.
//
// SECURITY: Uses safefile.ValidateRegularFile for symlink-aware validation.
// This ensures that:
//   - The path is relative and doesn't escape runDir
//   - No symlinks exist in the path from runDir to the file
//   - The final path is a regular file (not dir, symlink, device, etc.)
func ValidateOutputPath(runDir, outputPath string) error {
	cleanPath, err := validateOutputPathBasics(outputPath)
	if err != nil {
		return err
	}
	return validateOutputRegularFile(runDir, cleanPath, outputPath)
}

func validateOutputPathBasics(outputPath string) (string, error) {
	if filepath.IsAbs(outputPath) {
		return "", fmt.Errorf("output path must be relative: %s", outputPath)
	}
	if filepath.VolumeName(outputPath) != "" {
		return "", fmt.Errorf("output path must not have volume name: %s", outputPath)
	}
	cleanPath := filepath.Clean(outputPath)
	if cleanPath == "." || cleanPath == ".." || strings.HasPrefix(cleanPath, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("output path escapes run directory: %s", outputPath)
	}
	return cleanPath, nil
}

func validateOutputRegularFile(runDir, cleanPath, outputPath string) error {
	_, err := safefile.ValidateRegularFile(runDir, cleanPath)
	if err == nil {
		return nil
	}
	errMsg := err.Error()
	switch {
	case os.IsNotExist(err) || strings.Contains(errMsg, "does not exist"):
		return fmt.Errorf("output file does not exist: %s", outputPath)
	case strings.Contains(errMsg, "symlink"):
		return fmt.Errorf("output path contains symlink (not allowed): %s", outputPath)
	case strings.Contains(errMsg, "not a regular file"):
		return fmt.Errorf("output path is not a regular file: %s", outputPath)
	case strings.Contains(errMsg, "escapes") || strings.Contains(errMsg, "traversal"):
		return fmt.Errorf("output path escapes run directory: %s", outputPath)
	default:
		return fmt.Errorf("invalid output path %s: %w", outputPath, err)
	}
}

// ComputeStatus determines the status based on errors, warnings, and exit code.
// This implements the precedence rules from the protocol spec.
func ComputeStatus(errors []ErrorEntry, warnings []ErrorEntry, exitCode int) string {
	// 1. failure: If errors is non-empty OR exit_code ≠ 0
	if len(errors) > 0 || exitCode != 0 {
		return StatusFailure
	}
	// 2. partial: If warnings is non-empty (and errors empty and exit_code = 0)
	if len(warnings) > 0 {
		return StatusPartial
	}
	// 3. success: Otherwise
	return StatusSuccess
}

// NormalizeExitCode normalizes a tool exit code according to protocol rules.
// Returns (wrapper exit code, tool exit code pointer).
// Tool codes 0-9 pass through unchanged. Codes ≥10 are normalized to 1.
func NormalizeExitCode(toolExitCode int) (wrapperExitCode int, toolCode *int) {
	tc := toolExitCode
	toolCode = &tc

	if toolExitCode >= 0 && toolExitCode <= 9 {
		return toolExitCode, toolCode
	}
	// Normalize codes ≥10 to 1
	return 1, toolCode
}

// WriteResultAtomic writes a result.json atomically using tmp+rename.
//
// SECURITY: Uses internal/safefile/tx to perform an fsync+rename transaction
// with symlink refusal semantics.
//
// Note: We don't validate the entire runDir path for symlinks because:
// 1. CreateRunDir already uses safefile.MkdirAllPrivate which refuses symlinks
// 2. System symlinks (e.g., /var -> /private/var on macOS) are legitimate
// 3. tx.WriteAtomicPath enforces symlink protections for result writes
func WriteResultAtomic(runDir string, result *Result) error {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling result: %w", err)
	}

	finalPath := filepath.Join(runDir, "result.json")
	if err := tx.WriteAtomicPath(finalPath, data, limits.StandardFileMode); err != nil {
		return fmt.Errorf("writing result file atomically: %w", err)
	}

	// Best-effort directory fsync
	if dirHandle, err := os.Open(runDir); err == nil {
		_ = dirHandle.Sync()
		_ = dirHandle.Close()
	}

	return nil
}

// ReadResult reads and parses a result.json file.
// Unknown fields are preserved (forward compatibility).
// SECURITY:
//   - Enforces size limit to prevent memory exhaustion from malicious tool output.
//   - Validates no duplicate JSON keys to prevent ambiguous field overrides.
func ReadResult(path string) (*Result, error) {
	data, err := boundedio.ReadFileWithLimit(path, limits.ToolResult)
	if err != nil {
		return nil, err
	}

	// SECURITY: Use DecodeNoDup to validate no duplicate keys.
	// json.Unmarshal silently keeps the last duplicate, which could allow
	// malicious tools to ambiguously override fields.
	result, err := jsonutil.DecodeNoDup[Result](data)
	if err != nil {
		return nil, fmt.Errorf("parsing result.json: %w", err)
	}

	return &result, nil
}

// ValidateResult checks if a result has all required fields.
// Returns typed errors with MissingRequiredField code for programmatic handling.
func ValidateResult(r *Result) error {
	if err := validateResultRequiredFields(r); err != nil {
		return err
	}
	if err := validateResultTimestamps(r); err != nil {
		return err
	}
	if err := validateResultStatus(r); err != nil {
		return err
	}
	return validateResultCollections(r)
}

func validateResultRequiredFields(r *Result) error {
	if r.SchemaVersion == 0 {
		return epackerrors.E(epackerrors.MissingRequiredField, "result.json missing 'schema_version'", nil)
	}
	if r.Wrapper.Name == "" {
		return epackerrors.E(epackerrors.MissingRequiredField, "result.json missing 'wrapper.name'", nil)
	}
	if r.Tool.Name == "" {
		return epackerrors.E(epackerrors.MissingRequiredField, "result.json missing 'tool.name'", nil)
	}
	if r.RunID == "" {
		return epackerrors.E(epackerrors.MissingRequiredField, "result.json missing 'run_id'", nil)
	}
	if r.StartedAt == "" {
		return epackerrors.E(epackerrors.MissingRequiredField, "result.json missing 'started_at'", nil)
	}
	if r.CompletedAt == "" {
		return epackerrors.E(epackerrors.MissingRequiredField, "result.json missing 'completed_at'", nil)
	}
	if r.Status == "" {
		return epackerrors.E(epackerrors.MissingRequiredField, "result.json missing 'status'", nil)
	}
	return nil
}

func validateResultTimestamps(r *Result) error {
	if err := timestamp.Validate(r.StartedAt); err != nil {
		return epackerrors.E(epackerrors.InvalidTimestamp, "result.json invalid 'started_at'", err)
	}
	if err := timestamp.Validate(r.CompletedAt); err != nil {
		return epackerrors.E(epackerrors.InvalidTimestamp, "result.json invalid 'completed_at'", err)
	}
	return nil
}

func validateResultStatus(r *Result) error {
	if r.Status != StatusSuccess && r.Status != StatusFailure && r.Status != StatusPartial {
		return epackerrors.E(epackerrors.InvalidInput, fmt.Sprintf("result.json invalid 'status': %s", r.Status), nil)
	}
	return nil
}

func validateResultCollections(r *Result) error {
	if r.Inputs == nil {
		return epackerrors.E(epackerrors.MissingRequiredField, "result.json missing 'inputs'", nil)
	}
	if _, ok := r.Inputs.(map[string]interface{}); !ok {
		return epackerrors.E(epackerrors.InvalidInput, fmt.Sprintf("result.json 'inputs' must be a JSON object, got %T", r.Inputs), nil)
	}
	if r.Outputs == nil {
		return epackerrors.E(epackerrors.MissingRequiredField, "result.json missing 'outputs'", nil)
	}
	if r.Errors == nil {
		return epackerrors.E(epackerrors.MissingRequiredField, "result.json missing 'errors'", nil)
	}
	if r.Warnings == nil {
		return epackerrors.E(epackerrors.MissingRequiredField, "result.json missing 'warnings'", nil)
	}
	return nil
}

// NewWrapperInfo creates a WrapperInfo with the standard wrapper name.
func NewWrapperInfo(version string) WrapperInfo {
	return WrapperInfo{
		Name:    "epack",
		Version: version,
	}
}

// NewToolInfo creates a ToolInfo from capabilities or defaults.
func NewToolInfo(name, version string, protocolVersion int) ToolInfo {
	if protocolVersion == 0 {
		protocolVersion = CurrentProtocolVersion
	}
	return ToolInfo{
		Name:            name,
		Version:         version,
		ProtocolVersion: protocolVersion,
	}
}

// NewResult creates a Result with required fields and correct schema version.
// This is the recommended way to create Result structs to ensure invariants are met.
//
// The returned Result has:
//   - SchemaVersion set to CurrentSchemaVersion
//   - Wrapper info populated
//   - Tool info populated with protocol version
//   - RunID generated
//   - Timestamps set
//   - Empty but non-nil slices for Outputs, Errors, Warnings
//
// Callers should set additional fields like PackPath, ExitCode, etc.
func NewResult(toolName, toolVersion, wrapperVersion string) *Result {
	now := time.Now().UTC()
	return &Result{
		SchemaVersion: CurrentSchemaVersion,
		Wrapper:       NewWrapperInfo(wrapperVersion),
		Tool:          NewToolInfo(toolName, toolVersion, CurrentProtocolVersion),
		RunID:         GenerateRunID(),
		StartedAt:     FormatTimestamp(now),
		CompletedAt:   FormatTimestamp(now),
		DurationMs:    0,
		ExitCode:      0,
		Status:        StatusSuccess,
		Inputs:        map[string]any{},
		Outputs:       []OutputEntry{},
		Errors:        []ErrorEntry{},
		Warnings:      []ErrorEntry{},
	}
}
