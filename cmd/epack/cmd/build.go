package cmd

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/locktivity/epack/internal/limits"
	"github.com/locktivity/epack/pack/builder"
	"github.com/spf13/cobra"
)

var (
	buildStream      string
	buildSources     []string
	buildFiles       []string
	buildStdin       string
	buildContentType string
	buildOutput      string
	buildForce       bool
)

func init() {
	rootCmd.AddCommand(buildCmd)

	buildCmd.Flags().StringVarP(&buildStream, "stream", "s", "", "stream identifier (required)")
	buildCmd.Flags().StringArrayVar(&buildSources, "source", nil, "source collector (name:version, repeatable)")
	buildCmd.Flags().StringArrayVarP(&buildFiles, "file", "f", nil, "file mapping (src:dest or src)")
	buildCmd.Flags().StringVar(&buildStdin, "stdin", "", "read artifact from stdin with given path")
	buildCmd.Flags().StringVar(&buildContentType, "content-type", "", "default content type for artifacts")
	buildCmd.Flags().StringVarP(&buildOutput, "output", "o", "", "output path (alternative to positional)")
	buildCmd.Flags().BoolVar(&buildForce, "force", false, "overwrite existing file")

	// Note: --stream is required but we handle it interactively in runBuild
	// instead of using MarkFlagRequired, which just fails with an error
}

var buildCmd = &cobra.Command{
	Use:        "build [flags] <output.pack> [artifact...]",
	Short:      "Create an evidence pack from artifacts",
	SuggestFor: []string{"create", "new", "make", "pack"},
	Long: `Build creates an evidence pack containing the specified artifacts.

Artifacts can be specified as positional arguments or with --file flags.
Each artifact is stored under artifacts/ with its filename preserved.

Exit codes:
  0  Pack created successfully
  1  Build failed (missing files, invalid arguments, etc.)

Examples:
  # Build from files
  epack build evidence.pack ./reports/*.json --stream myorg/prod

  # Specify destination paths
  epack build evidence.pack --stream myorg/prod \
    --file ./local/config.json:artifacts/config.json \
    --file ./local/audit.json:artifacts/audit.json

  # Add source metadata
  epack build evidence.pack ./data.json --stream myorg/prod \
    --source "collector:1.0" --source "scanner:2.3"

  # Read from stdin
  echo '{"key":"value"}' | epack build evidence.pack --stream myorg/prod \
    --stdin artifacts/data.json --content-type application/json`,
	Args: cobra.MinimumNArgs(0),
	RunE: runBuild,
}

func runBuild(cmd *cobra.Command, args []string) error {
	out := outputWriter()

	// Determine output path
	outputPath := buildOutput
	artifacts := args
	if outputPath == "" {
		if len(args) < 1 {
			// Interactive prompt for output path if TTY
			if out.IsTTY() && !out.IsJSON() {
				path, err := out.PromptRequired("Output path: ")
				if err != nil {
					return exitError("output path required: specify as first argument or with --output")
				}
				outputPath = path
			} else {
				return exitError("output path required: specify as first argument or with --output")
			}
		} else {
			outputPath = args[0]
			artifacts = args[1:]
		}
	}

	// Interactive prompt for stream if not provided
	stream := buildStream
	if stream == "" {
		if out.IsTTY() && !out.IsJSON() {
			s, err := out.PromptRequired("Stream identifier (e.g., myorg/prod): ")
			if err != nil {
				return exitError("--stream is required")
			}
			stream = s
		} else {
			return exitError("--stream is required")
		}
	}

	// Check if output exists
	if !buildForce {
		if _, err := os.Stat(outputPath); err == nil {
			return exitError("output file %q already exists (use --force to overwrite)", outputPath)
		}
	}

	// Create builder
	b := builder.New(stream)

	// Add sources
	for _, src := range buildSources {
		name, version := parseSource(src)
		b.AddSource(name, version)
	}

	// Build artifact sources from CLI args and flags
	var sources []builder.ArtifactSource

	// Add artifacts from positional arguments (glob patterns)
	for _, path := range artifacts {
		matches, err := filepath.Glob(path)
		if err != nil {
			return exitError("invalid glob pattern %q: %v", path, err)
		}
		if len(matches) == 0 {
			return exitError("no files matching %q", path)
		}
		for _, match := range matches {
			sources = append(sources, builder.ArtifactSource{
				SourcePath:  match,
				DestPath:    "artifacts/" + filepath.Base(match),
				ContentType: buildContentType,
			})
			out.Verbose("Adding %s -> artifacts/%s\n", match, filepath.Base(match))
		}
	}

	// Add artifacts from --file flags
	for _, fileSpec := range buildFiles {
		src, dest := parseFileSpec(fileSpec)
		if dest == "" {
			dest = "artifacts/" + filepath.Base(src)
		}
		sources = append(sources, builder.ArtifactSource{
			SourcePath:  src,
			DestPath:    dest,
			ContentType: buildContentType,
		})
		out.Verbose("Adding %s -> %s\n", src, dest)
	}

	// Add artifact from stdin
	if buildStdin != "" {
		// SECURITY: Enforce artifact size limit on stdin to prevent memory exhaustion.
		// Without this limit, a malicious pipe could send unbounded data.
		data, err := limits.ReadAllWithLimit(os.Stdin, limits.Artifact.Bytes())
		if err != nil {
			if _, ok := err.(*limits.ErrSizeLimitExceeded); ok {
				return exitError("stdin exceeds maximum artifact size (%d bytes)", limits.Artifact.Bytes())
			}
			return exitError("failed to read stdin: %v", err)
		}
		destPath := buildStdin
		if !strings.HasPrefix(destPath, "artifacts/") {
			destPath = "artifacts/" + destPath
		}
		sources = append(sources, builder.ArtifactSource{
			Data:        data,
			DestPath:    destPath,
			ContentType: buildContentType,
		})
		out.Verbose("Adding stdin -> %s\n", destPath)
	}

	// Add artifacts to builder
	if err := b.AddArtifacts(sources); err != nil {
		return exitError("failed to add artifacts: %v", err)
	}

	// Build the pack
	buildSpinner := out.StartSpinner("Building pack...")
	if err := b.Build(outputPath); err != nil {
		buildSpinner.Fail("Build failed")
		return exitError("failed to build pack: %v", err)
	}
	buildSpinner.Success("Pack created")

	// Output result
	if out.IsJSON() {
		return out.JSON(map[string]interface{}{
			"path":   outputPath,
			"stream": stream,
		})
	}

	out.Success("Created %s", outputPath)
	out.Print("  Stream: %s\n", stream)
	out.Print("  Use 'epack inspect %s' to view contents\n", outputPath)

	return nil
}

// parseSource parses "name:version" or just "name"
func parseSource(s string) (name, version string) {
	parts := strings.SplitN(s, ":", 2)
	name = parts[0]
	if len(parts) == 2 {
		version = parts[1]
	}
	return
}

// parseFileSpec parses "src:dest" or just "src"
func parseFileSpec(s string) (src, dest string) {
	// Handle Windows paths like C:\path
	if len(s) >= 2 && s[1] == ':' {
		// Likely a Windows path - look for second colon
		idx := strings.Index(s[2:], ":")
		if idx >= 0 {
			return s[:idx+2], s[idx+3:]
		}
		return s, ""
	}
	parts := strings.SplitN(s, ":", 2)
	src = parts[0]
	if len(parts) == 2 {
		dest = parts[1]
	}
	return
}
