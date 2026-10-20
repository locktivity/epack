//go:build components

package sdkcmd

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/locktivity/epack/internal/componentsdk"
	"github.com/locktivity/epack/internal/componenttypes"
	"github.com/spf13/cobra"
)

var (
	newForce  bool
	newModule string
)

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
  - .slsa-goreleaser/ Multi-platform release configuration
  - .github/workflows/ CI with conformance, and SLSA signing on tag

A collector gets the layout the epack collectors share: its entrypoint in
cmd/epack-collector-<name>/main.go, its handler and gap records in
internal/collector, an API client under internal/, its artifact's JSON
Schema in docs/schema, a collectortest suite that go test runs, a test that
records a scenario from a real account, and CI that calls epack's shared
collector workflow.

Examples:
  epack sdk new tool my-analyzer
  epack sdk new collector github-posture --module github.com/acme/epack-collector-github-posture
  epack sdk new remote s3-registry
  epack sdk new utility pack-viewer`,
		Args: cobra.ExactArgs(2),
		RunE: runNew,
	}

	cmd.Flags().BoolVarP(&newForce, "force", "f", false, "overwrite existing directory")
	cmd.Flags().StringVar(&newModule, "module", "", "Go module path (default github.com/OWNER/epack-<type>-<name>)")

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
		TargetDir:  targetDir,
		Name:       componentName,
		Kind:       kind,
		ModulePath: newModule,
	})
	if err != nil {
		return err
	}

	// Print success
	p := out.Palette()

	out.Print("%s Created %s\n\n", p.Green("✓"), dirName)
	files := append([]string(nil), result.FilesCreated...)
	sort.Strings(files)
	for _, file := range files {
		out.Print("  %s/%s\n", dirName, file)
	}
	out.Print("\n")

	out.Print("%s\n", p.Bold("Next steps:"))
	out.Print("  cd %s\n", dirName)
	if newModule == "" {
		out.Print("  # Replace github.com/OWNER in go.mod%s with your module path\n", importNote(kind))
	}
	if result.EpackVersion == "" {
		out.Print("  go get github.com/locktivity/epack@main  %s\n", p.Dim("# source build of epack: pick the SDK to build against"))
	}
	out.Print("  go mod tidy\n")
	out.Print("  # Edit %s to implement your %s\n", implementationFile(kind), kind)
	out.Print("  # Edit docs/ for registry documentation\n")
	out.Print("\n")

	out.Print("%s\n", p.Bold("Build & test:"))
	out.Print("  go build -o %s %s\n", result.BinaryName, result.MainPackage)
	out.Print("  ./%s --capabilities\n", result.BinaryName)
	if kind == componenttypes.KindCollector {
		out.Print("  go test ./...  %s\n", p.Dim("# runs the collectortest suite"))
		out.Print("  make trace-map  %s\n", p.Dim("# rewrites docs/schema/trace-map.json after a change to the code"))
	}
	out.Print("\n")

	out.Print("%s\n", p.Bold("Run conformance:"))
	out.Print("  epack sdk test .\n")

	return nil
}

func importNote(kind componenttypes.ComponentKind) string {
	if kind == componenttypes.KindCollector {
		return " and the imports"
	}
	return ""
}

func implementationFile(kind componenttypes.ComponentKind) string {
	if kind == componenttypes.KindCollector {
		return "internal/collector/collector.go and the API client under internal/"
	}
	return "main.go"
}
