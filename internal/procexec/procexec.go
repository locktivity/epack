package procexec

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Spec describes a process invocation.
type Spec struct {
	Path   string
	Args   []string
	Dir    string
	Env    []string
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer

	// Timeout bounds process execution duration. Zero means no additional timeout.
	Timeout time.Duration

	// EnforceEnvAllowlist filters/validates the process environment against AllowedEnv
	// and AllowedEnvPrefixes. When true and Env is nil, os.Environ() is used as input.
	EnforceEnvAllowlist bool
	AllowedEnv          []string
	AllowedEnvPrefixes  []string

	// EnforceDirPolicy requires Dir to be under one of AllowedDirRoots.
	EnforceDirPolicy bool
	AllowedDirRoots  []string

	// Optional output redaction hooks used by RunCapture.
	RedactStdout func([]byte) []byte
	RedactStderr func([]byte) []byte
}

// Result contains captured process output and metadata from RunCapture.
type Result struct {
	Stdout   []byte
	Stderr   []byte
	ExitCode int
	TimedOut bool
}

// Command builds an exec.Cmd from the given spec.
// This is a low-level constructor and does not enforce Spec policy fields.
// Prefer Run/Output/RunCapture to enforce policies.
func Command(ctx context.Context, spec Spec) *exec.Cmd {
	var cmd *exec.Cmd
	if ctx == nil {
		cmd = exec.Command(spec.Path, spec.Args...)
	} else {
		cmd = exec.CommandContext(ctx, spec.Path, spec.Args...)
	}
	cmd.Dir = spec.Dir
	cmd.Env = spec.Env
	cmd.Stdin = spec.Stdin
	cmd.Stdout = spec.Stdout
	cmd.Stderr = spec.Stderr
	return cmd
}

// CommandChecked builds an exec.Cmd from spec after enforcing policy fields.
func CommandChecked(ctx context.Context, spec Spec) (*exec.Cmd, context.CancelFunc, error) {
	checked, err := enforceSpec(spec)
	if err != nil {
		return nil, nil, err
	}
	runCtx, cancel := withTimeout(ctx, checked.Timeout)
	return Command(runCtx, checked), cancel, nil
}

// Run executes the command and waits for completion.
func Run(ctx context.Context, spec Spec) error {
	cmd, cancel, err := CommandChecked(ctx, spec)
	if err != nil {
		return err
	}
	if cancel != nil {
		defer cancel()
	}
	return cmd.Run()
}

// Output executes the command and returns stdout bytes.
func Output(ctx context.Context, spec Spec) ([]byte, error) {
	cmd, cancel, err := CommandChecked(ctx, spec)
	if err != nil {
		return nil, err
	}
	if cancel != nil {
		defer cancel()
	}
	return cmd.Output()
}

// RunCapture executes a command and captures stdout/stderr with optional redaction hooks.
func RunCapture(ctx context.Context, spec Spec) (Result, error) {
	cmd, cancel, err := CommandChecked(ctx, spec)
	if err != nil {
		return Result{}, err
	}
	if cancel != nil {
		defer cancel()
	}

	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf

	runErr := cmd.Run()
	result := Result{
		Stdout: outBuf.Bytes(),
		Stderr: errBuf.Bytes(),
	}
	if spec.RedactStdout != nil {
		result.Stdout = spec.RedactStdout(result.Stdout)
	}
	if spec.RedactStderr != nil {
		result.Stderr = spec.RedactStderr(result.Stderr)
	}
	if cmd.ProcessState != nil {
		result.ExitCode = cmd.ProcessState.ExitCode()
	}
	if runErr != nil && cmd.ProcessState != nil {
		// Best-effort timeout signal: timeout kill typically exits with non-zero code.
		result.TimedOut = ctx != nil && ctx.Err() == context.DeadlineExceeded
	}
	return result, runErr
}

// LookPath searches for an executable named file in PATH.
func LookPath(file string) (string, error) {
	return exec.LookPath(file)
}

func withTimeout(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if ctx == nil {
		ctx = context.Background()
	}
	if timeout <= 0 {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, timeout)
}

func enforceSpec(spec Spec) (Spec, error) {
	if spec.Path == "" {
		return spec, fmt.Errorf("process path is required")
	}

	if spec.EnforceEnvAllowlist {
		env, err := enforceEnv(spec)
		if err != nil {
			return spec, err
		}
		spec.Env = env
	}

	if spec.EnforceDirPolicy {
		if err := enforceDir(spec.Dir, spec.AllowedDirRoots); err != nil {
			return spec, err
		}
	}

	return spec, nil
}

func enforceEnv(spec Spec) ([]string, error) {
	if len(spec.AllowedEnv) == 0 && len(spec.AllowedEnvPrefixes) == 0 {
		return nil, fmt.Errorf("env allowlist enforcement enabled but no allow rules provided")
	}
	src := spec.Env
	if src == nil {
		src = os.Environ()
	}

	allowedExact := make(map[string]struct{}, len(spec.AllowedEnv))
	for _, k := range spec.AllowedEnv {
		allowedExact[k] = struct{}{}
	}

	filtered := make([]string, 0, len(src))
	for _, kv := range src {
		eq := strings.IndexByte(kv, '=')
		if eq <= 0 {
			return nil, fmt.Errorf("invalid env entry: %q", kv)
		}
		key := kv[:eq]
		if _, ok := allowedExact[key]; ok || hasPrefixAllowed(key, spec.AllowedEnvPrefixes) {
			filtered = append(filtered, kv)
			continue
		}
		return nil, fmt.Errorf("environment variable %q not permitted by policy", key)
	}

	return filtered, nil
}

func hasPrefixAllowed(key string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(key, p) {
			return true
		}
	}
	return false
}

func enforceDir(dir string, roots []string) error {
	if dir == "" {
		return fmt.Errorf("working directory is required when dir policy enforcement is enabled")
	}
	if len(roots) == 0 {
		return fmt.Errorf("dir policy enforcement enabled but no allowed roots provided")
	}

	absDir, err := filepath.Abs(filepath.Clean(dir))
	if err != nil {
		return fmt.Errorf("resolving working directory: %w", err)
	}
	for _, root := range roots {
		absRoot, err := filepath.Abs(filepath.Clean(root))
		if err != nil {
			continue
		}
		rel, err := filepath.Rel(absRoot, absDir)
		if err != nil {
			continue
		}
		if rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))) {
			return nil
		}
	}
	return fmt.Errorf("working directory %q is outside allowed roots", absDir)
}
