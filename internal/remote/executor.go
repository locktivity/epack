package remote

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/locktivity/epack/internal/execsafe"
	"github.com/locktivity/epack/internal/limits"
	"github.com/locktivity/epack/internal/procexec"
	"github.com/locktivity/epack/internal/redact"
	"github.com/locktivity/epack/internal/safejson"
	"golang.org/x/time/rate"
)

// DefaultTimeout is the default timeout for adapter commands.
const DefaultTimeout = 5 * time.Minute

// Rate limiting constants for adapter invocations.
const (
	// DefaultAdapterRateLimit caps adapter invocations to prevent
	// overwhelming remote services or exhausting API quotas.
	DefaultAdapterRateLimit = 10 // requests per second

	// DefaultAdapterRateBurst permits short bursts for batch operations
	// while maintaining the average rate over time.
	DefaultAdapterRateBurst = 5
)

// globalAdapterRateLimiter enforces a process-wide rate limit across all
// Executor instances. Using a global limiter (vs per-executor) ensures that
// parallel operations don't collectively exceed safe thresholds.
var globalAdapterRateLimiter = rate.NewLimiter(rate.Limit(DefaultAdapterRateLimit), DefaultAdapterRateBurst)

// Executor runs remote adapter commands.
type Executor struct {
	// BinaryPath is the path to the adapter binary.
	// For verified execution, this is the path to the verified copy.
	BinaryPath string

	// AdapterName is the adapter name (for error messages).
	AdapterName string

	// Timeout is the command timeout (defaults to DefaultTimeout).
	Timeout time.Duration

	// Stderr is where adapter stderr output is written.
	// If nil, stderr is discarded.
	Stderr io.Writer

	// Secrets is a list of env var names to pass through to the adapter.
	// These are passed as-is (not renamed) to allow adapter-specific auth.
	Secrets []string

	// cleanup is called when the executor is closed to remove verified binary copies.
	cleanup func()
}

// NewExecutor creates an executor for the given adapter binary.
//
// SECURITY WARNING: This creates an unverified executor. For source-based adapters,
// use NewVerifiedExecutor instead to ensure TOCTOU-safe execution with digest
// verification. Unverified executors should only be used for:
//   - PATH-based adapters (no source configured)
//   - Development/testing scenarios
func NewExecutor(binaryPath, adapterName string) *Executor {
	return &Executor{
		BinaryPath:  binaryPath,
		AdapterName: adapterName,
		Timeout:     DefaultTimeout,
	}
}

// NewVerifiedExecutor creates a TOCTOU-safe executor that verifies the adapter
// binary against the expected digest before execution.
//
// SECURITY: This function provides the same security guarantees as collector/tool
// execution:
//   - Binary is verified against expected digest (TOCTOU-safe via copy-while-hash)
//   - A verified copy of the binary is executed (not the original)
//   - The verified copy is sealed (read-only directory) to prevent modification
//
// The caller MUST call Close() when done to clean up the verified binary copy.
//
// Example:
//
//	exec, err := NewVerifiedExecutor(binaryPath, expectedDigest, adapterName)
//	if err != nil {
//	    return err
//	}
//	defer exec.Close()
//	// ... use exec for adapter operations
func NewVerifiedExecutor(binaryPath, expectedDigest, adapterName string) (*Executor, error) {
	// TOCTOU-safe: verify digest and get safe exec path
	// This creates a verified copy that we execute instead of the original.
	execPath, cleanup, err := execsafe.VerifiedBinaryFD(binaryPath, expectedDigest)
	if err != nil {
		return nil, fmt.Errorf("verifying adapter binary: %w", err)
	}

	return &Executor{
		BinaryPath:  execPath,
		AdapterName: adapterName,
		Timeout:     DefaultTimeout,
		cleanup:     cleanup,
	}, nil
}

// Close releases resources associated with this executor.
// For verified executors, this removes the verified binary copy.
// Safe to call multiple times or on unverified executors.
func (e *Executor) Close() {
	if e != nil && e.cleanup != nil {
		e.cleanup()
		e.cleanup = nil
	}
}

// QueryCapabilities queries the adapter's capabilities without digest verification.
//
// SECURITY WARNING: This function does NOT verify the binary digest. It should only
// be used for PATH-based adapters or when verification is handled separately.
// For source-based adapters, use QueryCapabilitiesVerified instead.
func QueryCapabilities(ctx context.Context, binaryPath string) (*Capabilities, error) {
	return queryCapabilitiesInternal(ctx, binaryPath, nil)
}

// QueryCapabilitiesVerified queries capabilities using TOCTOU-safe execution.
//
// SECURITY: This function verifies the binary against the expected digest before
// executing it, preventing TOCTOU attacks where an attacker modifies the binary
// between resolution and execution.
//
// The verification creates a temporary copy of the binary, hashes it during copy,
// verifies the hash matches, then executes the verified copy.
func QueryCapabilitiesVerified(ctx context.Context, binaryPath, expectedDigest string) (*Capabilities, error) {
	// TOCTOU-safe: verify digest and get safe exec path
	execPath, cleanup, err := execsafe.VerifiedBinaryFD(binaryPath, expectedDigest)
	if err != nil {
		return nil, fmt.Errorf("verifying adapter binary: %w", err)
	}
	defer cleanup()

	return queryCapabilitiesInternal(ctx, execPath, nil)
}

// queryCapabilitiesInternal is the shared implementation for capabilities queries.
func queryCapabilitiesInternal(ctx context.Context, binaryPath string, cleanup func()) (*Capabilities, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	// SECURITY: Use restricted environment to prevent credential exfiltration.
	// Even for capability queries, use filtered environment for consistency.
	env := execsafe.BuildRestrictedEnvSafe(os.Environ(), true)
	env = append(env, "EPACK_REMOTE_PROTOCOL_VERSION=1")

	var stdout, stderr bytes.Buffer

	if err := procexec.Run(ctx, procexec.Spec{
		Path:   binaryPath,
		Args:   []string{CommandCapabilities},
		Env:    env,
		Stdout: &stdout,
		Stderr: &stderr,
	}); err != nil {
		// SECURITY: Redact stderr in error messages to prevent secret leakage
		return nil, fmt.Errorf("capabilities query failed: %w (stderr: %s)", err, redact.Sensitive(stderr.String()))
	}

	var caps Capabilities
	// SECURITY: Use safejson with size limits to prevent memory exhaustion
	// from malicious adapter output.
	if err := safejson.Unmarshal(stdout.Bytes(), limits.JSONResponse, &caps); err != nil {
		return nil, fmt.Errorf("parsing capabilities: %w", err)
	}

	return &caps, nil
}

// Prepare initiates a push operation and returns upload information.
func (e *Executor) Prepare(ctx context.Context, req *PrepareRequest) (*PrepareResponse, error) {
	req.Type = TypePushPrepare
	req.ProtocolVersion = ProtocolVersion
	if req.RequestID == "" {
		req.RequestID = uuid.New().String()
	}

	var resp PrepareResponse
	if err := e.execute(ctx, CommandPushPrepare, req, &resp); err != nil {
		return nil, err
	}

	if !resp.OK {
		return nil, fmt.Errorf("prepare failed: unexpected response")
	}

	return &resp, nil
}

// Finalize completes a push operation after upload.
func (e *Executor) Finalize(ctx context.Context, req *FinalizeRequest) (*FinalizeResponse, error) {
	req.Type = TypePushFinalize
	req.ProtocolVersion = ProtocolVersion
	if req.RequestID == "" {
		req.RequestID = uuid.New().String()
	}

	var resp FinalizeResponse
	if err := e.execute(ctx, CommandPushFinalize, req, &resp); err != nil {
		return nil, err
	}

	if !resp.OK {
		return nil, fmt.Errorf("finalize failed: unexpected response")
	}

	return &resp, nil
}

// PullPrepare initiates a pull operation and returns download information.
func (e *Executor) PullPrepare(ctx context.Context, req *PullPrepareRequest) (*PullPrepareResponse, error) {
	req.Type = TypePullPrepare
	req.ProtocolVersion = ProtocolVersion
	if req.RequestID == "" {
		req.RequestID = uuid.New().String()
	}

	var resp PullPrepareResponse
	if err := e.execute(ctx, CommandPullPrepare, req, &resp); err != nil {
		return nil, err
	}

	if !resp.OK {
		return nil, fmt.Errorf("pull prepare failed: unexpected response")
	}

	return &resp, nil
}

// PullFinalize completes a pull operation after download.
func (e *Executor) PullFinalize(ctx context.Context, req *PullFinalizeRequest) (*PullFinalizeResponse, error) {
	req.Type = TypePullFinalize
	req.ProtocolVersion = ProtocolVersion
	if req.RequestID == "" {
		req.RequestID = uuid.New().String()
	}

	var resp PullFinalizeResponse
	if err := e.execute(ctx, CommandPullFinalize, req, &resp); err != nil {
		return nil, err
	}

	if !resp.OK {
		return nil, fmt.Errorf("pull finalize failed: unexpected response")
	}

	return &resp, nil
}

// SyncRuns syncs run ledgers to the remote.
func (e *Executor) SyncRuns(ctx context.Context, req *RunsSyncRequest) (*RunsSyncResponse, error) {
	req.Type = TypeRunsSync
	req.ProtocolVersion = ProtocolVersion
	if req.RequestID == "" {
		req.RequestID = uuid.New().String()
	}

	var resp RunsSyncResponse
	if err := e.execute(ctx, CommandRunsSync, req, &resp); err != nil {
		return nil, err
	}

	if !resp.OK {
		return nil, fmt.Errorf("runs sync failed: unexpected response")
	}

	return &resp, nil
}

// AuthLogin initiates interactive authentication.
func (e *Executor) AuthLogin(ctx context.Context) (*AuthLoginResponse, error) {
	req := &AuthLoginRequest{
		Type:            TypeAuthLogin,
		ProtocolVersion: ProtocolVersion,
		RequestID:       uuid.New().String(),
	}

	var resp AuthLoginResponse
	if err := e.execute(ctx, CommandAuthLogin, req, &resp); err != nil {
		return nil, err
	}

	if !resp.OK {
		return nil, fmt.Errorf("auth login failed: unexpected response")
	}

	return &resp, nil
}

// AuthWhoami queries the current authentication state.
func (e *Executor) AuthWhoami(ctx context.Context) (*AuthWhoamiResponse, error) {
	req := &AuthWhoamiRequest{
		Type:            TypeAuthWhoami,
		ProtocolVersion: ProtocolVersion,
		RequestID:       uuid.New().String(),
	}

	var resp AuthWhoamiResponse
	if err := e.execute(ctx, CommandAuthWhoami, req, &resp); err != nil {
		return nil, err
	}

	if !resp.OK {
		return nil, fmt.Errorf("auth whoami failed: unexpected response")
	}

	return &resp, nil
}

// execute runs an adapter command with JSON stdin/stdout.
func (e *Executor) execute(ctx context.Context, command string, req any, resp any) error {
	ctx, cancel, reqJSON, err := prepareExecuteRequest(ctx, e, req)
	if err != nil {
		return err
	}
	defer cancel()
	stdout, stderr, runErr := runAdapterCommand(ctx, e, command, reqJSON)
	if runErr != nil {
		return handleAdapterExecutionError(e.AdapterName, command, stdout, stderr, runErr)
	}
	if err := safejson.Unmarshal(stdout.Bytes(), limits.JSONResponse, resp); err != nil {
		return fmt.Errorf("parsing adapter response: %w", err)
	}
	return parseAdapterErrorResponse(e.AdapterName, stdout.Bytes())
}

func prepareExecuteRequest(ctx context.Context, e *Executor, req any) (context.Context, context.CancelFunc, []byte, error) {
	if err := globalAdapterRateLimiter.Wait(ctx); err != nil {
		return nil, nil, nil, fmt.Errorf("rate limit wait cancelled: %w", err)
	}
	timeout := e.Timeout
	if timeout == 0 {
		timeout = DefaultTimeout
	}
	timeoutCtx, cancel := context.WithTimeout(ctx, timeout)
	reqJSON, err := json.Marshal(req)
	if err != nil {
		cancel()
		return nil, nil, nil, fmt.Errorf("marshaling request: %w", err)
	}
	return timeoutCtx, cancel, reqJSON, nil
}

func runAdapterCommand(ctx context.Context, e *Executor, command string, reqJSON []byte) (*bytes.Buffer, *bytes.Buffer, error) {
	var stdout, stderr bytes.Buffer
	env := execsafe.BuildRestrictedEnvSafe(os.Environ(), true)
	env = append(env, "EPACK_REMOTE_PROTOCOL_VERSION=1")
	env = execsafe.AppendAllowedSecrets(env, e.Secrets, os.Getenv)

	stderrWriter := io.Writer(&stderr)
	if e.Stderr != nil {
		stderrWriter = io.MultiWriter(&stderr, &redactingWriter{w: e.Stderr})
	}
	err := procexec.Run(ctx, procexec.Spec{
		Path:   e.BinaryPath,
		Args:   []string{command},
		Env:    env,
		Stdin:  bytes.NewReader(reqJSON),
		Stdout: &stdout,
		Stderr: stderrWriter,
	})
	return &stdout, &stderr, err
}

func handleAdapterExecutionError(adapterName, command string, stdout, stderr *bytes.Buffer, runErr error) error {
	if len(stdout.Bytes()) > 0 {
		var errResp ErrorResponse
		if err := safejson.Unmarshal(stdout.Bytes(), limits.JSONResponse, &errResp); err == nil && !errResp.OK {
			return &AdapterError{
				AdapterName: adapterName,
				Code:        errResp.Error.Code,
				Message:     errResp.Error.Message,
				Retryable:   errResp.Error.Retryable,
				Action:      errResp.Error.Action,
			}
		}
	}
	return fmt.Errorf("adapter %q command %q failed: %w (stderr: %s)",
		adapterName, command, runErr, redact.Sensitive(stderr.String()))
}

func parseAdapterErrorResponse(adapterName string, data []byte) error {
	var rawResp struct {
		OK    bool       `json:"ok"`
		Type  string     `json:"type"`
		Error *ErrorInfo `json:"error,omitempty"`
	}
	if err := safejson.Unmarshal(data, limits.JSONResponse, &rawResp); err != nil || rawResp.OK {
		return nil
	}
	if rawResp.Error == nil {
		return fmt.Errorf("adapter %q returned error response", adapterName)
	}
	return &AdapterError{
		AdapterName: adapterName,
		Code:        rawResp.Error.Code,
		Message:     rawResp.Error.Message,
		Retryable:   rawResp.Error.Retryable,
		Action:      rawResp.Error.Action,
	}
}

// AdapterError represents a structured error from a remote adapter.
// Check IsAuthRequired to determine if re-authentication is needed.
// Check IsRetryable to determine if the operation can be retried.
type AdapterError struct {
	AdapterName string      // Adapter that returned the error
	Code        string      // Machine-readable error code (e.g., "auth_required")
	Message     string      // Human-readable description
	Retryable   bool        // Whether the operation may succeed if retried
	Action      *ActionHint // Optional guidance for resolution (may be nil)
}

func (e *AdapterError) Error() string {
	return fmt.Sprintf("adapter %q: %s: %s", e.AdapterName, e.Code, e.Message)
}

// IsAuthRequired returns true if authentication is required.
func (e *AdapterError) IsAuthRequired() bool {
	return e.Code == ErrCodeAuthRequired
}

// IsRetryable returns true if the error is retryable.
func (e *AdapterError) IsRetryable() bool {
	return e.Retryable
}

// HasAction returns true if the error includes an action hint.
func (e *AdapterError) HasAction() bool {
	return e.Action != nil
}

// redactingWriter wraps an io.Writer and applies secret redaction to all writes.
// SECURITY: This prevents malicious or buggy adapters from leaking secrets
// via stderr output that gets displayed to users or written to logs.
type redactingWriter struct {
	w io.Writer
}

func (r *redactingWriter) Write(p []byte) (n int, err error) {
	// Apply redaction to the output before writing
	redacted := redact.Sensitive(string(p))
	_, err = r.w.Write([]byte(redacted))
	// Return original length to satisfy io.Writer contract
	// (caller expects len(p) bytes to be "consumed")
	return len(p), err
}
