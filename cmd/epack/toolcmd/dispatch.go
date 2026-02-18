//go:build components

package toolcmd

import (
	"fmt"

	"github.com/locktivity/epack/errors"
	"github.com/locktivity/epack/internal/dispatch"
	"github.com/locktivity/epack/internal/project"
	"github.com/spf13/cobra"
)

// cobraOutput adapts cobra.Command to dispatch.Output interface.
type cobraOutput struct {
	cmd *cobra.Command
}

func (o *cobraOutput) Stderr() interface{ Write([]byte) (int, error) } {
	return o.cmd.ErrOrStderr()
}

// exitError is a simple error type that carries an exit code.
type exitError struct {
	code int
}

func (e *exitError) Error() string {
	return fmt.Sprintf("exit code %d", e.code)
}

// dispatchTool parses wrapper flags in the CLI layer and delegates to dispatch.
// Flag parsing is done here (CLI layer) to keep dispatch focused on core logic.
func dispatchTool(cmd *cobra.Command, toolName string, args []string) error {
	// Parse wrapper flags in CLI layer
	cliFlags, toolArgs, err := ParseWrapperArgs(args)
	if err != nil {
		return err
	}

	// Convert CLI flags to dispatch flags
	flags := dispatch.WrapperFlags{
		PackPath:             cliFlags.PackPath,
		OutputDir:            cliFlags.OutputDir,
		JSONMode:             cliFlags.JSONMode,
		QuietMode:            cliFlags.QuietMode,
		HasSeparator:         cliFlags.HasSeparator,
		InsecureAllowUnpinned: cliFlags.InsecureAllowUnpinned,
	}

	// Delegate to dispatch with pre-parsed flags
	// Use cmd.Context() to enable cancellation (e.g., Ctrl+C)
	out := &cobraOutput{cmd: cmd}
	err = dispatch.ToolWithFlags(cmd.Context(), out, toolName, toolArgs, flags)

	// Convert errors.Error to our exitError for cobra handling
	if exitErr, ok := err.(*errors.Error); ok {
		return &exitError{code: exitErr.ExitCode()}
	}
	return err
}

// findProjectRoot searches upward from dir for epack.yaml.
// Returns the directory containing epack.yaml, or error if not found.
// This is used by list.go and info.go for discovering the project root.
func findProjectRoot(dir string) (string, error) {
	return project.FindRoot(dir)
}
