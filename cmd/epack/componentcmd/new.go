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
	newSkipSample bool
	newSkipGit    bool
	newForce      bool
)

func newNewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "new <project-name>",
		Short: "Create a new evidence pack project",
		Long: `Create a new directory with evidence pack configuration.

This command scaffolds a complete project structure with:
  - epack.yaml      Configuration with commented examples
  - sample.epack     Demo pack to explore (verify, inspect, list)
  - packs/          Output directory for generated packs
  - README.md       Quick reference
  - .gitignore      Ignores .epack/ and packs/*.pack

The stream name is automatically inferred from your git remote,
or uses a placeholder that you can edit in epack.yaml.

Special case: 'epack new .' initializes the current directory.

Examples:
  epack new my-pipeline         # Create new project directory
  epack new .                   # Initialize current directory
  epack new my-pipeline --force # Allow non-empty directory

After creation:
  cd my-pipeline
  epack verify sample.epack      # Check cryptographic signature
  epack inspect sample.epack     # See metadata and sources
  vim epack.yaml                # Configure your collectors
  epack collect                 # Run collection`,
		Args: cobra.ExactArgs(1),
		RunE: runNew,
	}

	cmd.Flags().BoolVar(&newSkipSample, "skip-sample", false, "don't include sample.epack")
	cmd.Flags().BoolVar(&newSkipGit, "skip-git", false, "don't initialize git repository")
	cmd.Flags().BoolVarP(&newForce, "force", "f", false, "allow writing into non-empty directory")

	return cmd
}

func runNew(cmd *cobra.Command, args []string) error {
	out := getOutput(cmd)
	projectName := args[0]

	// Special case: "epack new ." delegates to init
	if projectName == "." {
		return runInitInPlace(cmd, initSkipSample, initForce)
	}

	// Validate project name
	if err := ValidateProjectName(projectName); err != nil {
		return fmt.Errorf("invalid project name: %w", err)
	}

	// Determine target directory
	targetDir, err := filepath.Abs(projectName)
	if err != nil {
		return fmt.Errorf("invalid project path %q: %w", projectName, err)
	}

	// Check if directory exists
	info, err := os.Stat(targetDir)
	if err == nil {
		// Path exists
		if !info.IsDir() {
			return fmt.Errorf("path exists but is not a directory: %s", targetDir)
		}

		// Check if non-empty
		nonEmpty, err := IsDirNonEmpty(targetDir)
		if err != nil {
			return err
		}
		if nonEmpty && !newForce {
			return fmt.Errorf("directory %s is not empty (use --force to proceed)", projectName)
		}
	} else if os.IsNotExist(err) {
		// Create the directory
		if err := os.MkdirAll(targetDir, defaultDirPerm); err != nil {
			if os.IsPermission(err) {
				return fmt.Errorf("cannot create %s: permission denied", targetDir)
			}
			return fmt.Errorf("cannot create directory %s: %w", targetDir, err)
		}
	} else {
		if os.IsPermission(err) {
			return fmt.Errorf("cannot access %s: permission denied", targetDir)
		}
		return fmt.Errorf("cannot access directory %s: %w", targetDir, err)
	}

	// Run scaffolding
	result, err := Scaffold(ScaffoldOptions{
		ProjectName: projectName,
		TargetDir:   targetDir,
		SkipSample:  newSkipSample,
		SkipGit:     newSkipGit,
		Force:       newForce,
	})
	if err != nil {
		return err
	}

	// Print success output
	printNewSuccess(out, projectName, result)

	return nil
}

// printNewSuccess prints the success message with project structure.
func printNewSuccess(out *output.Writer, projectName string, result *ScaffoldResult) {
	p := out.Palette()

	out.Print("%s Created %s/\n\n", p.Success("✓"), projectName)

	// Print structure
	out.Print("  %s/\n", projectName)
	out.Print("  ├── %s      Configuration (edit to add collectors)\n", configFileName)

	// Check which files were created
	hasSample := false
	for _, f := range result.FilesCreated {
		if f == samplePackFile {
			hasSample = true
			break
		}
	}
	if hasSample {
		out.Print("  ├── %s     Example pack to explore\n", samplePackFile)
	}
	out.Print("  ├── %s/          Output directory\n", packsDir)
	out.Print("  └── %s       Quick reference\n", readmeFile)
	out.Print("\n")

	// Print stream info
	out.Print("  Stream: %s\n", result.Stream)
	if strings.HasPrefix(result.Stream, "example/") {
		out.Print("  %s\n", p.Dim("(This is just an identifier - safe to change in epack.yaml)"))
	}
	out.Print("\n")

	// Print next steps
	out.Print("%s\n", p.Bold("Next steps:"))
	out.Print("  cd %s\n", projectName)

	if hasSample {
		out.Print("  epack verify %s        %s\n", samplePackFile, p.Dim("# Check cryptographic signature"))
		out.Print("  epack inspect %s       %s\n", samplePackFile, p.Dim("# See metadata and sources"))
		out.Print("  epack list artifacts %s  %s\n", samplePackFile, p.Dim("# View collected evidence"))
		out.Print("\n")
	}

	out.Print("%s\n", p.Bold("When ready:"))
	out.Print("  vim %s                  %s\n", configFileName, p.Dim("# Configure your collectors"))
	out.Print("  epack collect                   %s\n", p.Dim("# Run collection"))
	out.Print("  epack sign %s/*.pack         %s\n", packsDir, p.Dim("# Sign the output"))
}
