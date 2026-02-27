package componentsdk

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// TestOptions configures conformance testing.
type TestOptions struct {
	// BinaryPath is the path to the component binary to test.
	BinaryPath string

	// Verbose enables detailed test output.
	Verbose bool

	// OnBuildStart is called when building starts (for directory mode).
	OnBuildStart func()

	// OnBuildSuccess is called when building succeeds.
	OnBuildSuccess func()

	// OnBuildFailed is called when building fails.
	OnBuildFailed func(err error)

	// OnTestStart is called when tests start running.
	OnTestStart func(caps *Capabilities)
}

// TestResult contains the result of conformance testing.
type TestResult struct {
	// Passed is true if all tests passed.
	Passed bool

	// ExitCode is the exit code from epack-conformance.
	ExitCode int
}

// Test runs conformance tests against a component binary.
// If binaryPath is a directory, it builds the Go project first.
func Test(ctx context.Context, opts TestOptions) (*TestResult, error) {
	binaryPath, err := resolveTestBinary(ctx, opts)
	if err != nil {
		return nil, err
	}

	// Get component capabilities to determine type
	caps, err := GetCapabilities(binaryPath)
	if err != nil {
		return nil, fmt.Errorf("not a valid epack component: %w", err)
	}

	if opts.OnTestStart != nil {
		opts.OnTestStart(caps)
	}

	conformanceCmd, err := buildConformanceCommand(ctx, caps.Kind, binaryPath, opts.Verbose)
	if err != nil {
		return nil, err
	}
	conformanceCmd.Stdout = os.Stdout
	conformanceCmd.Stderr = os.Stderr

	err = conformanceCmd.Run()
	result := &TestResult{Passed: err == nil, ExitCode: 0}

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			result.ExitCode = exitErr.ExitCode()
		} else {
			return nil, fmt.Errorf("running conformance tests: %w", err)
		}
	}

	return result, nil
}

func resolveTestBinary(ctx context.Context, opts TestOptions) (string, error) {
	info, err := os.Stat(opts.BinaryPath)
	if err != nil {
		return "", fmt.Errorf("checking path: %w", err)
	}
	if !info.IsDir() {
		if info.Mode()&0111 == 0 {
			return "", fmt.Errorf("binary is not executable: %s", opts.BinaryPath)
		}
		return opts.BinaryPath, nil
	}
	return buildProjectBinary(ctx, opts)
}

func buildProjectBinary(ctx context.Context, opts TestOptions) (string, error) {
	projectDir := opts.BinaryPath
	if !IsGoProject(projectDir) {
		return "", fmt.Errorf("directory mode requires a Go project (go.mod not found in %s)", projectDir)
	}
	binaryPath := filepath.Join(projectDir, filepath.Base(projectDir))
	if opts.OnBuildStart != nil {
		opts.OnBuildStart()
	}

	buildCmd := exec.CommandContext(ctx, "go", "build", "-o", binaryPath, ".")
	buildCmd.Dir = projectDir
	buildCmd.Stdout = os.Stdout
	buildCmd.Stderr = os.Stderr

	if err := buildCmd.Run(); err != nil {
		if opts.OnBuildFailed != nil {
			opts.OnBuildFailed(err)
		}
		return "", fmt.Errorf("build failed: %w", err)
	}
	if opts.OnBuildSuccess != nil {
		opts.OnBuildSuccess()
	}
	return binaryPath, nil
}

func buildConformanceCommand(ctx context.Context, kind, binaryPath string, verbose bool) (*exec.Cmd, error) {
	conformancePath, err := exec.LookPath("epack-conformance")
	if err != nil {
		return nil, fmt.Errorf("epack-conformance not found in PATH\n\nInstall with: go install -tags conformance github.com/locktivity/epack/cmd/epack-conformance@latest")
	}

	args := []string{kind, binaryPath}
	if verbose {
		args = append([]string{"-v"}, args...)
	}
	return exec.CommandContext(ctx, conformancePath, args...), nil
}
