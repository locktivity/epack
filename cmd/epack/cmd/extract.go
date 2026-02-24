package cmd

import (
	"path/filepath"

	"github.com/locktivity/epack/internal/cli/output"
	"github.com/locktivity/epack/pack"
	"github.com/spf13/cobra"
)

var (
	extractOutput string
	extractAll    bool
	extractFilter string
	extractForce  bool
	extractDryRun bool
)

func init() {
	rootCmd.AddCommand(extractCmd)

	extractCmd.Flags().StringVarP(&extractOutput, "output", "o", ".", "output directory")
	extractCmd.Flags().BoolVar(&extractAll, "all", false, "extract all artifacts")
	extractCmd.Flags().StringVar(&extractFilter, "filter", "", "filter by path pattern (glob)")
	extractCmd.Flags().BoolVar(&extractForce, "force", false, "overwrite existing files")
	extractCmd.Flags().BoolVar(&extractDryRun, "dry-run", false, "show what would be extracted without writing files")
}

var extractCmd = &cobra.Command{
	Use:        "extract <pack> [artifact-paths...]",
	Short:      "Extract artifacts from a pack",
	SuggestFor: []string{"unpack", "export"},
	Long: `Extract artifacts from an evidence pack to the filesystem.

By default, artifacts are extracted to the current directory, preserving
the artifacts/ subdirectory structure. Use --output to specify a different
destination.

Examples:
  # Extract specific artifacts
  epack extract evidence.pack artifacts/config.json

  # Extract all artifacts
  epack extract --all evidence.pack

  # Extract to specific directory
  epack extract --all -o ./extracted evidence.pack

  # Extract matching a pattern
  epack extract --filter "*.json" evidence.pack

  # Force overwrite existing files
  epack extract --all --force evidence.pack

  # Preview what would be extracted (dry-run)
  epack extract --all --dry-run evidence.pack`,
	Args: cobra.MinimumNArgs(1),
	RunE: runExtract,
}

func runExtract(cmd *cobra.Command, args []string) error {
	packPath := args[0]
	requestedPaths := args[1:]
	out := outputWriter()

	// Open the pack
	p, err := pack.Open(packPath)
	if err != nil {
		return packOpenError(packPath, err)
	}
	defer func() { _ = p.Close() }()

	// Dry-run mode: show what would be extracted without writing files
	if extractDryRun {
		return runExtractDryRun(p, requestedPaths, out)
	}

	// Extract artifacts
	result, err := p.Extract(pack.ExtractOptions{
		OutputDir: extractOutput,
		Paths:     requestedPaths,
		All:       extractAll,
		Filter:    extractFilter,
		Force:     extractForce,
	})
	if err != nil {
		return exitError("failed to extract artifacts: %v\n\nCheck that the output directory is writable: %s", err, extractOutput)
	}

	if len(result.Extracted) == 0 {
		out.Print("No artifacts to extract\n")
		return nil
	}

	// Output result
	if out.IsJSON() {
		return out.JSON(map[string]interface{}{
			"extracted": result.Extracted,
			"count":     len(result.Extracted),
			"output":    extractOutput,
		})
	}

	out.Success("Extracted %d artifact(s) to %s", len(result.Extracted), extractOutput)
	for _, path := range result.Extracted {
		// Show path relative to output dir if possible
		relPath, err := filepath.Rel(extractOutput, path)
		if err != nil {
			relPath = path
		}
		out.Print("  %s\n", relPath)
	}

	return nil
}

func runExtractDryRun(p *pack.Pack, requestedPaths []string, out *output.Writer) error {
	manifest := p.Manifest()

	// Filter artifacts based on options
	var toExtract []pack.Artifact
	for _, artifact := range manifest.Artifacts {
		if artifact.Type != "embedded" {
			continue
		}

		// Check if this artifact matches the extraction criteria
		if len(requestedPaths) > 0 {
			// Check if path is in requested list
			found := false
			for _, reqPath := range requestedPaths {
				if artifact.Path == reqPath {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		} else if extractFilter != "" {
			// Apply glob filter
			matched, err := filepath.Match(extractFilter, filepath.Base(artifact.Path))
			if err != nil || !matched {
				continue
			}
		} else if !extractAll {
			// If no paths, filter, or --all, nothing to extract
			continue
		}

		toExtract = append(toExtract, artifact)
	}

	if len(toExtract) == 0 {
		out.Print("No artifacts would be extracted\n")
		return nil
	}

	// Calculate total size
	var totalSize int64
	for _, artifact := range toExtract {
		if artifact.Size != nil {
			size, _ := artifact.Size.Int64()
			totalSize += size
		}
	}

	// Output result
	if out.IsJSON() {
		paths := make([]string, len(toExtract))
		for i, a := range toExtract {
			paths[i] = a.Path
		}
		return out.JSON(map[string]interface{}{
			"dry_run":       true,
			"would_extract": paths,
			"count":         len(toExtract),
			"total_size":    totalSize,
			"output":        extractOutput,
		})
	}

	out.Print("Would extract %d artifact(s) to %s (%s total)\n\n",
		len(toExtract), extractOutput, output.FormatBytes(totalSize))

	for _, artifact := range toExtract {
		size := "?"
		if artifact.Size != nil {
			s, _ := artifact.Size.Int64()
			size = output.FormatBytes(s)
		}
		out.Print("  %-50s %s\n", artifact.Path, out.Palette().Dim(size))
	}

	return nil
}
