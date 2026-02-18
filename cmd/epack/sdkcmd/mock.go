//go:build components

package sdkcmd

import (
	"fmt"
	"path/filepath"

	"github.com/locktivity/epack/internal/componentsdk"
	"github.com/spf13/cobra"
)

var mockOutputDir string

func newMockCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "mock <type>",
		Short: "Generate sample inputs for testing components",
		Long: `Generate sample input files for testing your components during development.

This creates realistic test fixtures that you can use to verify your component
works correctly before running conformance tests.

Supported types:
  tool       - Creates a minimal evidence pack for testing tools
  collector  - Creates a sample configuration and mock environment
  remote     - Creates sample registry responses (push/pull/list)
  utility    - Creates sample command-line invocation scripts

Examples:
  epack sdk mock tool              # Creates sample-evidence.pack
  epack sdk mock collector         # Creates sample-config.yaml and env vars
  epack sdk mock tool -o testdata  # Output to testdata/ directory`,
		Args:      cobra.ExactArgs(1),
		ValidArgs: []string{"tool", "collector", "remote", "utility"},
		RunE:      runMock,
	}

	cmd.Flags().StringVarP(&mockOutputDir, "output", "o", ".", "output directory for generated files")

	return cmd
}

func runMock(cmd *cobra.Command, args []string) error {
	out := getOutput(cmd)
	p := out.Palette()
	componentType := args[0]

	// Parse and validate component type
	kind, err := componentsdk.ParseKind(componentType)
	if err != nil {
		return err
	}

	// Resolve output directory
	outputDir, err := filepath.Abs(mockOutputDir)
	if err != nil {
		return fmt.Errorf("resolving output path: %w", err)
	}

	out.Print("%s Generating mock inputs for %s component\n\n", p.Cyan("→"), componentType)

	result, err := componentsdk.GenerateMocks(componentsdk.MockOptions{
		OutputDir: outputDir,
		Kind:      kind,
	})
	if err != nil {
		return err
	}

	out.Print("%s Generated files:\n", p.Green("✓"))
	for _, f := range result.FilesCreated {
		rel, _ := filepath.Rel(outputDir, f)
		if rel == "" {
			rel = f
		}
		out.Print("  %s\n", rel)
	}

	out.Print("\n%s\n", p.Dim("Use these files to test your component during development."))

	return nil
}
