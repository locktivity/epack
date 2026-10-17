package componentsdk

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/locktivity/epack/internal/componenttypes"
	"github.com/locktivity/epack/internal/version"
)

// TestOptions configures conformance testing.
type TestOptions struct {
	// BinaryPath is the path to the component binary to test.
	BinaryPath string

	// Verbose enables detailed test output.
	Verbose bool

	// ConfigPath is a collector config to pass to the conformance harness.
	// Empty in directory mode uses the project's testdata/conformance.json
	// when it has one.
	ConfigPath string

	// Secrets name the variables a collector reads credentials from. The
	// harness sets each to a canary value and fails if any output contains it.
	Secrets []string

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

	configPath := opts.ConfigPath
	if configPath == "" && caps.Kind == string(componenttypes.KindCollector) {
		configPath = projectConformanceConfig(opts.BinaryPath)
	}

	conformanceCmd, err := buildConformanceCommand(ctx, caps.Kind, binaryPath, conformanceFlags{
		Verbose: opts.Verbose,
		Config:  configPath,
		Secrets: opts.Secrets,
	})
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
	projectDir, err := filepath.Abs(opts.BinaryPath)
	if err != nil {
		return "", fmt.Errorf("resolving path: %w", err)
	}
	if !IsGoProject(projectDir) {
		return "", fmt.Errorf("directory mode requires a Go project (go.mod not found in %s)", projectDir)
	}
	binaryPath := filepath.Join(projectDir, filepath.Base(projectDir))
	if opts.OnBuildStart != nil {
		opts.OnBuildStart()
	}

	buildCmd := exec.CommandContext(ctx, "go", "build", "-o", binaryPath, MainPackage(projectDir))
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

// projectConformanceConfig is the testdata/conformance.json of the project
// directory path names, or "" when path is a binary or the file is absent.
func projectConformanceConfig(path string) string {
	info, err := os.Stat(path)
	if err != nil || !info.IsDir() {
		return ""
	}
	config := filepath.Join(path, "testdata", "conformance.json")
	if _, err := os.Stat(config); err != nil {
		return ""
	}
	return config
}

// conformanceFlags are the epack-conformance flags epack sdk test passes.
type conformanceFlags struct {
	Verbose bool
	Config  string
	Secrets []string
}

func buildConformanceCommand(ctx context.Context, kind, binaryPath string, flags conformanceFlags) (*exec.Cmd, error) {
	conformancePath, err := exec.LookPath("epack-conformance")
	if err != nil {
		return nil, fmt.Errorf("epack-conformance not found in PATH\n\nInstall with: %s", ConformanceInstallCommand())
	}

	// epack-conformance reads the type and binary first, then its flags.
	args := []string{conformanceType(kind), binaryPath}
	if flags.Verbose {
		args = append(args, "--verbose")
	}
	if flags.Config != "" {
		args = append(args, "--config", flags.Config)
	}
	for _, name := range flags.Secrets {
		args = append(args, "--secret", name)
	}
	return exec.CommandContext(ctx, conformancePath, args...), nil
}

// ConformanceInstallCommand installs the conformance harness of this epack's
// release, or of main for a source build, so the harness matches the epack
// that runs it rather than whatever @latest resolves to.
func ConformanceInstallCommand() string {
	v := epackModuleVersion(version.Version)
	if v == "" {
		v = "main"
	}
	return "go install -tags conformance github.com/locktivity/epack/cmd/epack-conformance@" + v
}

func conformanceType(kind string) string {
	switch kind {
	case "remote_adapter":
		return "remote"
	default:
		return kind
	}
}
