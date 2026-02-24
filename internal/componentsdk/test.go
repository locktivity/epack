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
	binaryPath := opts.BinaryPath

	// Check if it's a directory (needs building)
	info, err := os.Stat(binaryPath)
	if err != nil {
		return nil, fmt.Errorf("checking path: %w", err)
	}

	if info.IsDir() {
		projectDir := binaryPath
		binaryPath = filepath.Join(projectDir, filepath.Base(projectDir))

		// Check for go.mod
		if !IsGoProject(projectDir) {
			return nil, fmt.Errorf("directory mode requires a Go project (go.mod not found in %s)", projectDir)
		}

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
			return nil, fmt.Errorf("build failed: %w", err)
		}

		if opts.OnBuildSuccess != nil {
			opts.OnBuildSuccess()
		}
	} else {
		// Check it's executable
		if info.Mode()&0111 == 0 {
			return nil, fmt.Errorf("binary is not executable: %s", binaryPath)
		}
	}

	// Get component capabilities to determine type
	caps, err := GetCapabilities(binaryPath)
	if err != nil {
		return nil, fmt.Errorf("not a valid epack component: %w", err)
	}

	if opts.OnTestStart != nil {
		opts.OnTestStart(caps)
	}

	// Check if epack-conformance is installed
	conformancePath, err := exec.LookPath("epack-conformance")
	if err != nil {
		return nil, fmt.Errorf("epack-conformance not found in PATH\n\nInstall with: go install -tags conformance github.com/locktivity/epack/cmd/epack-conformance@latest")
	}

	// Build conformance command args
	conformanceArgs := []string{caps.Kind, binaryPath}
	if opts.Verbose {
		conformanceArgs = append([]string{"-v"}, conformanceArgs...)
	}

	// Run conformance tests
	conformanceCmd := exec.CommandContext(ctx, conformancePath, conformanceArgs...)
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
