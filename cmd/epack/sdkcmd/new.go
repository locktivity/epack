//go:build components

package sdkcmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/locktivity/epack/internal/componentsdk"
	"github.com/spf13/cobra"
)

var newForce bool

func newNewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "new <type> <name>",
		Short: "Create a new component project",
		Long: `Create a new component project using the Component SDK.

Supported component types:
  tool       - Processes evidence packs (e.g., analyzers, redactors)
  collector  - Gathers evidence from external systems
  remote     - Registry adapter for push/pull operations
  utility    - Helper commands and scripts

This scaffolds a complete Go project with:
  - main.go           SDK-based implementation template
  - go.mod            Module with SDK dependency
  - docs/             Registry documentation (overview, config, examples)
  - .goreleaser.yaml  Multi-platform release configuration
  - .github/workflows/release.yaml  Sigstore signing on tag

Examples:
  epack sdk new tool my-analyzer
  epack sdk new collector github-posture
  epack sdk new remote s3-registry
  epack sdk new utility pack-viewer`,
		Args: cobra.ExactArgs(2),
		RunE: runNew,
	}

	cmd.Flags().BoolVarP(&newForce, "force", "f", false, "overwrite existing directory")

	return cmd
}

func runNew(cmd *cobra.Command, args []string) error {
	out := getOutput(cmd)

	// Parse and validate component type
	kind, err := componentsdk.ParseKind(args[0])
	if err != nil {
		return err
	}

	// Validate component name
	componentName := args[1]
	if err := componentsdk.ValidateName(componentName); err != nil {
		return err
	}

	// Create directory name with prefix
	dirName := fmt.Sprintf("epack-%s-%s", kind, componentName)
	targetDir, err := filepath.Abs(dirName)
	if err != nil {
		return fmt.Errorf("failed to resolve path: %w", err)
	}

	// Check if directory exists
	if info, err := os.Stat(targetDir); err == nil {
		if !info.IsDir() {
			return fmt.Errorf("path exists but is not a directory: %s", targetDir)
		}
		if !newForce {
			return fmt.Errorf("directory %s already exists (use --force to overwrite)", dirName)
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("failed to check directory: %w", err)
	}

	// Create the directory
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// Scaffold the component
	result, err := componentsdk.Scaffold(componentsdk.ScaffoldOptions{
		TargetDir: targetDir,
		Name:      componentName,
		Kind:      kind,
	})
	if err != nil {
		return err
	}

	// Print success
	p := out.Palette()

	out.Print("%s Created %s\n\n", p.Green("✓"), dirName)

	// Print structure
	out.Print("  %s/\n", dirName)
	out.Print("  ├── main.go              %s\n", p.Dim("# SDK-based implementation"))
	out.Print("  ├── go.mod               %s\n", p.Dim("# Module configuration"))
	out.Print("  ├── docs/                %s\n", p.Dim("# Registry documentation"))
	out.Print("  │   ├── overview.md\n")
	out.Print("  │   ├── configuration.md\n")
	out.Print("  │   └── examples.md\n")
	out.Print("  ├── .goreleaser.yaml     %s\n", p.Dim("# Multi-platform builds"))
	out.Print("  ├── .github/workflows/\n")
	out.Print("  │   └── release.yaml     %s\n", p.Dim("# Sigstore signing"))
	out.Print("  ├── README.md            %s\n", p.Dim("# Development guide"))
	out.Print("  └── .gitignore\n")
	out.Print("\n")

	out.Print("%s\n", p.Bold("Next steps:"))
	out.Print("  cd %s\n", dirName)
	out.Print("  # Edit main.go to implement your %s\n", kind)
	out.Print("  # Update go.mod with your module path\n")
	out.Print("  # Edit docs/ for registry documentation\n")
	out.Print("\n")

	out.Print("%s\n", p.Bold("Build & test:"))
	out.Print("  go build -o %s .\n", result.BinaryName)
	out.Print("  ./%s --capabilities\n", result.BinaryName)
	out.Print("\n")

	out.Print("%s\n", p.Bold("Run conformance:"))
	out.Print("  epack sdk test .\n")

	return nil
}
