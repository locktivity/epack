// Package exec provides process execution utilities for collectors.
// This package isolates subprocess management, environment handling,
// and output sanitization from collector workflow orchestration.
package exec

import (
	"bytes"
	"context"
	"encoding/json"
	stderrors "errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/locktivity/epack/errors"
	"github.com/locktivity/epack/internal/execsafe"
	"github.com/locktivity/epack/internal/exitcode"
	"github.com/locktivity/epack/internal/limits"
	"github.com/locktivity/epack/internal/procexec"
	"github.com/locktivity/epack/internal/redact"
	"github.com/locktivity/epack/internal/version"
)

// CollectorProtocolVersion is the current version of the collector protocol.
// This is passed to collectors via EPACK_PROTOCOL_VERSION env var.
const CollectorProtocolVersion = 1

// maxStderrLen is the maximum length of stderr to include in error messages.
const maxStderrLen = 500

// ProgressMessage represents a progress update from a component.
type ProgressMessage struct {
	Type            string `json:"type"`
	ProtocolVersion int    `json:"protocol_version"`
	Kind            string `json:"kind"`              // "status" or "progress"
	Message         string `json:"message"`
	Current         int64  `json:"current,omitempty"`
	Total           int64  `json:"total,omitempty"`
}

// RunOptions configures collector process execution.
type RunOptions struct {
	// Timeout for collector execution. 0 uses DefaultCollectorTimeout.
	Timeout time.Duration

	// InsecureInheritPath allows inheriting PATH from the environment.
	// When false (default), collectors run with a safe, deterministic PATH.
	InsecureInheritPath bool

	// OnProgress is called for each progress message parsed from stdout.
	// If nil, progress messages are silently discarded.
	OnProgress func(ProgressMessage)
}

// RunResult contains the result of executing a collector process.
type RunResult struct {
	Stdout []byte
	Stderr string
	Err    error
}

// streamingStdoutWriter intercepts stdout, parses progress messages, and collects
// the final result. Progress messages are forwarded via callback; the result
// message is accumulated in the result buffer.
type streamingStdoutWriter struct {
	callback   func(ProgressMessage)
	result     bytes.Buffer // Accumulates the final result (non-progress) output
	partial    bytes.Buffer // Partial line awaiting newline
	mu         sync.Mutex
}

func newStreamingStdoutWriter(callback func(ProgressMessage)) *streamingStdoutWriter {
	return &streamingStdoutWriter{callback: callback}
}

func (s *streamingStdoutWriter) Write(p []byte) (n int, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Process incoming bytes looking for complete lines
	s.partial.Write(p)

	for {
		line, err := s.partial.ReadBytes('\n')
		if err != nil {
			// No complete line yet - put the partial back
			s.partial.Reset()
			s.partial.Write(line)
			break
		}

		// Complete line - check if it's a progress message
		trimmed := bytes.TrimSpace(line)
		if msg, ok := parseProgressLine(trimmed); ok {
			// It's a progress message - forward to callback
			if s.callback != nil {
				s.callback(msg)
			}
		} else {
			// Not a progress message - accumulate as result
			s.result.Write(line)
		}
	}

	return len(p), nil
}

// Result returns the accumulated non-progress output.
func (s *streamingStdoutWriter) Result() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Include any remaining partial line in result
	if s.partial.Len() > 0 {
		s.result.Write(s.partial.Bytes())
		s.partial.Reset()
	}

	return s.result.Bytes()
}

// parseProgressLine attempts to parse a line as a progress message.
// Returns false if the line is not a valid progress JSON.
func parseProgressLine(line []byte) (ProgressMessage, bool) {
	// Quick check: must start with { to be JSON
	if len(line) == 0 || line[0] != '{' {
		return ProgressMessage{}, false
	}

	var msg ProgressMessage
	if err := json.Unmarshal(line, &msg); err != nil {
		return ProgressMessage{}, false
	}

	// Verify it's a progress message (not a result or other JSON)
	if msg.Type != "epack_progress" {
		return ProgressMessage{}, false
	}

	return msg, true
}

// Run executes a collector binary and returns its output.
//
// SECURITY: execPath must be a verified path from execsafe.VerifiedBinaryFD
// or an explicitly opted-in unverified path. This function does not perform
// verification - callers must verify before calling.
//
// The function:
//   - Writes config to a secure temp file
//   - Builds a restricted environment with protocol variables
//   - Executes with timeout and output limits
//   - Streams stdout to parse progress messages in real-time
//   - Sanitizes stderr before returning errors
func Run(ctx context.Context, name, execPath, configPath string, env []string, opts RunOptions) RunResult {
	// Apply timeout to prevent DoS from collectors that hang
	timeout := opts.Timeout
	if timeout == 0 {
		timeout = limits.DefaultCollectorTimeout
	}
	execCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Execute collector
	// Use streaming writer for stdout to parse progress messages in real-time
	streamingStdout := newStreamingStdoutWriter(opts.OnProgress)
	stdoutWriter := limits.NewLimitedWriter(streamingStdout, limits.CollectorOutput.Bytes())

	// Capture stderr with size limit to prevent memory exhaustion
	var stderr bytes.Buffer
	stderrWriter := limits.NewLimitedWriter(&stderr, limits.CollectorOutput.Bytes())

	err := procexec.Run(execCtx, procexec.Spec{
		Path:   execPath,
		Env:    env,
		Stdout: stdoutWriter,
		Stderr: stderrWriter,
	})
	if err != nil {
		// Check if this was a timeout
		if execCtx.Err() == context.DeadlineExceeded {
			return RunResult{
				Stderr: stderr.String(),
				Err: errors.WithHint(errors.Timeout, exitcode.Timeout,
					fmt.Sprintf("collector %q timed out after %s", name, timeout),
					"Increase timeout or check collector for hanging operations", nil),
			}
		}
		var exitErr interface{ ExitCode() int }
		if stderrors.As(err, &exitErr) {
			// SECURITY: Sanitize stderr before including in error messages.
			sanitized := SanitizeStderr(stderr.String())
			return RunResult{
				Stderr: stderr.String(),
				Err:    fmt.Errorf("collector exited with code %d: %s", exitErr.ExitCode(), sanitized),
			}
		}
		return RunResult{
			Stderr: stderr.String(),
			Err:    fmt.Errorf("executing collector: %w", err),
		}
	}

	return RunResult{
		Stdout: streamingStdout.Result(),
		Stderr: stderr.String(),
	}
}

// BuildEnv constructs the environment for collector execution.
//
// SECURITY: Uses BuildRestrictedEnvSafe to strip proxy credentials.
// Collectors are untrusted code and should not receive credentials
// embedded in proxy URLs.
func BuildEnv(baseEnv []string, name, configPath string, secrets []string, getenv func(string) string, insecureInheritPath bool) []string {
	env := execsafe.BuildRestrictedEnvSafe(baseEnv, insecureInheritPath)

	// Add protocol environment variables
	env = append(env,
		fmt.Sprintf("EPACK_COLLECTOR_NAME=%s", name),
		fmt.Sprintf("EPACK_PROTOCOL_VERSION=%d", CollectorProtocolVersion),
		"EPACK_WRAPPER_VERSION="+version.Version,
	)

	// Add config file path if config exists
	if configPath != "" {
		env = append(env, "EPACK_COLLECTOR_CONFIG="+configPath)
	}

	// Pass through EPACK_IDENTITY if set (for authenticated/CI contexts)
	if identity := getenv("EPACK_IDENTITY"); identity != "" {
		env = append(env, "EPACK_IDENTITY="+identity)
	}

	// Pass through secrets listed in epack.yaml.
	// Only explicitly configured secrets are passed to collectors.
	// Reserved prefixes (EPACK_, LD_, DYLD_, _) are blocked.
	env = execsafe.AppendAllowedSecrets(env, secrets, getenv)

	return env
}

// WriteConfig writes collector config to a temporary JSON file.
// Returns the file path and a cleanup function.
//
// SECURITY: Uses execsafe.WriteSecureConfigFile which creates the temp directory
// with umask 0077, eliminating the race condition between MkdirTemp and Chmod.
func WriteConfig(config map[string]interface{}) (string, func(), error) {
	return execsafe.WriteSecureConfigFile(config, "epack-collector-config-*")
}

// SanitizeStderr sanitizes collector stderr for safe inclusion in error messages.
//
// SECURITY: Collector stderr is untrusted input that could contain secrets or
// log injection attacks. This function:
//   - Truncates to a reasonable length (first 500 bytes)
//   - Escapes control characters (newlines, tabs, etc.)
//   - Redacts patterns that look like secrets (via redact.Sensitive)
func SanitizeStderr(stderr string) string {
	if stderr == "" {
		return "(no stderr)"
	}

	// Truncate to prevent massive error messages
	if len(stderr) > maxStderrLen {
		stderr = stderr[:maxStderrLen] + "... [truncated]"
	}

	// Escape control characters to prevent log injection
	var sanitized strings.Builder
	sanitized.Grow(len(stderr))
	for _, r := range stderr {
		switch {
		case r == '\n':
			sanitized.WriteString("\\n")
		case r == '\r':
			sanitized.WriteString("\\r")
		case r == '\t':
			sanitized.WriteString("\\t")
		case r < 32 || r == 127:
			// Escape other control characters as \xNN
			sanitized.WriteString(fmt.Sprintf("\\x%02x", r))
		default:
			sanitized.WriteRune(r)
		}
	}

	// SECURITY: Redact sensitive patterns (tokens, secrets, API keys) AFTER
	// escaping to ensure the redaction patterns can match the escaped output.
	return redact.Sensitive(sanitized.String())
}
