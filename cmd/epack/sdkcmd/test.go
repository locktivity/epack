//go:build components

package sdkcmd

import (
	"os"

	"github.com/locktivity/epack/internal/componentsdk"
	"github.com/spf13/cobra"
)

var testVerbose bool

func newTestCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "test <binary|directory>",
		Short: "Run conformance tests on a component",
		Long: `Run the epack conformance test suite against a component binary.

This command runs protocol conformance tests to verify your component
correctly implements the epack component protocol. It's a wrapper around
the 'epack-conformance' tool with automatic component type detection.

If you pass a directory, it will build the Go project first and then test
the resulting binary.

Examples:
  epack sdk test ./epack-utility-viewer
  epack sdk test .
  epack sdk test --verbose ./my-tool

The conformance tool must be installed:
  go install github.com/locktivity/epack/cmd/epack-conformance@latest`,
		Args: cobra.ExactArgs(1),
		RunE: runTest,
	}

	cmd.Flags().BoolVarP(&testVerbose, "verbose", "v", false, "show detailed test output")

	return cmd
}

func runTest(cmd *cobra.Command, args []string) error {
	out := getOutput(cmd)
	p := out.Palette()
	targetPath := args[0]

	result, err := componentsdk.Test(cmd.Context(), componentsdk.TestOptions{
		BinaryPath: targetPath,
		Verbose:    testVerbose,
		OnBuildStart: func() {
			out.Print("%s Building...\n", p.Cyan("→"))
		},
		OnBuildSuccess: func() {
			out.Print("%s Build succeeded\n\n", p.Green("✓"))
		},
		OnBuildFailed: func(err error) {
			out.Print("%s Build failed: %v\n", p.Red("✗"), err)
		},
		OnTestStart: func(caps *componentsdk.Capabilities) {
			out.Print("%s Running conformance tests for %s (%s)\n\n", p.Cyan("→"), caps.Name, caps.Kind)
		},
	})

	if err != nil {
		return err
	}

	if result.Passed {
		out.Print("\n%s All conformance tests passed\n", p.Green("✓"))
	} else {
		out.Print("\n%s Conformance tests failed\n", p.Red("✗"))
		os.Exit(result.ExitCode)
	}

	return nil
}
