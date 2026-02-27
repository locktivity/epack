//go:build components

package componentcmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/locktivity/epack/internal/cli/output"
	"github.com/spf13/cobra"
)

var (
	initSkipSample bool
	initForce      bool
)

func newInitCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Initialize epack in the current directory",
		Long: `Initialize evidence pack configuration in the current directory.

This command is idempotent and can be run multiple times safely:
  - Creates epack.yaml with commented examples (skips if exists, unless --force)
  - Updates .gitignore managed block (always rewrites to current rules)
  - Creates packs/ directory with .gitkeep
  - Copies sample.epack for exploration (unless --skip-sample or exists)

Running 'epack init' twice will not fail or duplicate entries.

The stream name is automatically inferred from your git remote,
or uses a placeholder that you can edit in epack.yaml.

Use 'epack new <name>' to create a new project directory instead.

Examples:
  epack init              # Initialize current directory
  epack init --force      # Overwrite existing epack.yaml
  epack init --skip-sample # Don't include sample pack

After initialization:
  epack verify sample.epack   # Check cryptographic signature
  epack inspect sample.epack  # See metadata and sources
  vim epack.yaml             # Configure your collectors
  epack collect              # Run collection`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runInitInPlace(cmd, initSkipSample, initForce)
		},
	}

	cmd.Flags().BoolVar(&initSkipSample, "skip-sample", false, "don't include sample.epack")
	cmd.Flags().BoolVarP(&initForce, "force", "f", false, "overwrite existing epack.yaml")

	return cmd
}

// runInitInPlace initializes epack in the current directory.
// This is shared between 'epack init' and 'epack new .'.
//
// Idempotent behavior:
//   - If epack.yaml exists and --force is not set: leave it alone
//   - If --force is set: overwrite epack.yaml
//   - Always update the managed block in .gitignore (rewrite to current rules)
//   - Always ensure packs/.gitkeep exists
//   - Copy sample.epack only if it doesn't exist (and --skip-sample not set)
func runInitInPlace(cmd *cobra.Command, skipSample, force bool) error {
	out := getOutput(cmd)

	// Get current directory
	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get current directory: %w", err)
	}

	// Check if epack.yaml already exists
	configPath := filepath.Join(cwd, configFileName)
	configExists := false
	if _, err := os.Stat(configPath); err == nil {
		configExists = true
	}

	// Run scaffolding with idempotent options
	result, err := Scaffold(ScaffoldOptions{
		ProjectName:    filepath.Base(cwd),
		TargetDir:      cwd,
		SkipSample:     skipSample,
		SkipGit:        true, // init doesn't run git init (directory already exists)
		Force:          force,
		SkipConfig:     configExists && !force, // Skip config if exists and not forcing
		AlreadyInitted: configExists && !force, // Track for output message
	})
	if err != nil {
		return err
	}

	// Print success output
	printInitSuccess(out, result)

	return nil
}

// printInitSuccess prints the success message for init.
func printInitSuccess(out *output.Writer, result *ScaffoldResult) {
	p := out.Palette()

	if result.AlreadyInitted {
		out.Print("%s %s\n\n", p.Success("Already initialized"), p.Dim("(epack.yaml unchanged)"))
	} else {
		out.Print("%s\n\n", p.Success("Initialized epack"))
	}

	// Print files created/updated
	if len(result.FilesCreated) > 0 || result.AlreadyInitted {
		out.Print("  Files:\n")
		for _, f := range result.FilesCreated {
			switch f {
			case configFileName:
				out.Print("    %s      Configuration (edit to add collectors)\n", f)
			case samplePackFile:
				out.Print("    %s     Example pack to explore\n", f)
			case gitignoreFile:
				out.Print("    %s       Updated with epack entries\n", f)
			case filepath.Join(packsDir, gitkeepFile):
				out.Print("    %s/          Output directory\n", packsDir)
			}
		}
		if result.AlreadyInitted {
			out.Print("    %s      %s\n", configFileName, p.Dim("(unchanged)"))
		}
		out.Print("\n")
	}

	// Print stream info (only if newly created)
	if !result.AlreadyInitted {
		out.Print("  Stream: %s\n", result.Stream)
		if strings.HasPrefix(result.Stream, "example/") {
			out.Print("  %s\n", p.Dim("(This is just an identifier - safe to change in epack.yaml)"))
		}
		out.Print("\n")
	}

	// Check if sample pack was created
	hasSample := false
	for _, f := range result.FilesCreated {
		if f == samplePackFile {
			hasSample = true
			break
		}
	}

	// Print next steps
	out.Print("%s\n", p.Bold("Next steps:"))

	if hasSample {
		out.Print("  epack verify %s        %s\n", samplePackFile, p.Dim("# Check cryptographic signature"))
		out.Print("  epack inspect %s       %s\n", samplePackFile, p.Dim("# See metadata and sources"))
		out.Print("\n")
	}

	out.Print("%s\n", p.Bold("When ready:"))
	out.Print("  vim %s                  %s\n", configFileName, p.Dim("# Configure your collectors"))
	out.Print("  epack collect                   %s\n", p.Dim("# Run collection"))
	out.Print("  epack sign %s/*.epack         %s\n", packsDir, p.Dim("# Sign the output"))
}
