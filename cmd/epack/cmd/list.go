package cmd

import (
	"path/filepath"
	"strings"

	"github.com/locktivity/epack/internal/cli/output"
	"github.com/locktivity/epack/pack"
	"github.com/spf13/cobra"
)

var (
	listLong   bool
	listFilter string
)

func init() {
	rootCmd.AddCommand(listCmd)
	listCmd.AddCommand(listArtifactsCmd)
	listCmd.AddCommand(listAttestationsCmd)
	listCmd.AddCommand(listSourcesCmd)

	// Add flags to all subcommands
	for _, cmd := range []*cobra.Command{listArtifactsCmd, listAttestationsCmd, listSourcesCmd} {
		cmd.Flags().BoolVarP(&listLong, "long", "l", false, "detailed information")
		cmd.Flags().StringVar(&listFilter, "filter", "", "filter by path pattern (glob)")
	}
}

var listCmd = &cobra.Command{
	Use:        "list",
	Short:      "List pack contents",
	SuggestFor: []string{"ls"},
	Long: `List artifacts, attestations, or sources in an evidence pack.

Examples:
  epack list artifacts evidence.epack
  epack list attestations evidence.epack
  epack list sources evidence.epack`,
}

var listArtifactsCmd = &cobra.Command{
	Use:   "artifacts <pack>",
	Short: "List artifacts in the pack",
	Long: `List all artifacts declared in the pack manifest.

Examples:
  # List artifact paths
  epack list artifacts evidence.epack

  # Detailed listing with size and content type
  epack list artifacts -l evidence.epack

  # Filter by path pattern
  epack list artifacts --filter "*.json" evidence.epack`,
	Args: cobra.ExactArgs(1),
	RunE: runListArtifacts,
}

var listAttestationsCmd = &cobra.Command{
	Use:   "attestations <pack>",
	Short: "List attestations in the pack",
	Long: `List all attestation files in the pack.

Examples:
  epack list attestations evidence.epack
  epack list attestations -l evidence.epack`,
	Args: cobra.ExactArgs(1),
	RunE: runListAttestations,
}

var listSourcesCmd = &cobra.Command{
	Use:   "sources <pack>",
	Short: "List sources in the pack",
	Long: `List all source collectors declared in the manifest.

Examples:
  epack list sources evidence.epack`,
	Args: cobra.ExactArgs(1),
	RunE: runListSources,
}

func runListArtifacts(cmd *cobra.Command, args []string) error {
	packPath := args[0]
	out := outputWriter()

	p, err := pack.Open(packPath)
	if err != nil {
		return packOpenError(packPath, err)
	}
	defer func() { _ = p.Close() }()

	manifest := p.Manifest()

	// Filter artifacts if pattern provided
	artifacts := manifest.Artifacts
	if listFilter != "" {
		if _, err := filepath.Match(listFilter, ""); err != nil {
			return exitError("invalid filter pattern %q: %v", listFilter, err)
		}
		artifacts = filterArtifacts(artifacts, listFilter)
	}

	// JSON output
	if out.IsJSON() {
		return out.JSON(artifacts)
	}

	// Human-readable output
	if len(artifacts) == 0 {
		out.Print("No artifacts found\n")
		return nil
	}

	if listLong {
		table := out.Table()
		table.Header("PATH", "SIZE", "TYPE", "DIGEST")
		for _, a := range artifacts {
			size := ""
			if a.Size != nil {
				size = output.FormatBytesFromJSON(a.Size)
			}
			contentType := a.ContentType
			if contentType == "" {
				contentType = "-"
			}
			digest := output.FormatDigest(a.Digest)
			table.Row(a.Path, size, contentType, digest)
		}
		_ = table.Flush()
	} else {
		for _, a := range artifacts {
			out.Print("%s\n", a.Path)
		}
	}

	return nil
}

func runListAttestations(cmd *cobra.Command, args []string) error {
	packPath := args[0]
	out := outputWriter()

	p, err := pack.Open(packPath)
	if err != nil {
		return packOpenError(packPath, err)
	}
	defer func() { _ = p.Close() }()

	attestations := p.ListAttestations()

	// Filter if pattern provided
	if listFilter != "" {
		if _, err := filepath.Match(listFilter, ""); err != nil {
			return exitError("invalid filter pattern %q: %v", listFilter, err)
		}
		attestations = filterStrings(attestations, listFilter)
	}

	// JSON output
	if out.IsJSON() {
		return out.JSON(attestations)
	}

	// Human-readable output
	if len(attestations) == 0 {
		out.Print("No attestations found\n")
		return nil
	}

	for _, a := range attestations {
		out.Print("%s\n", a)
	}

	return nil
}

func runListSources(cmd *cobra.Command, args []string) error {
	packPath := args[0]
	out := outputWriter()

	p, err := pack.Open(packPath)
	if err != nil {
		return packOpenError(packPath, err)
	}
	defer func() { _ = p.Close() }()

	manifest := p.Manifest()

	// JSON output
	if out.IsJSON() {
		return out.JSON(manifest.Sources)
	}

	// Human-readable output
	if len(manifest.Sources) == 0 {
		out.Print("No sources found\n")
		return nil
	}

	if listLong {
		table := out.Table()
		table.Header("NAME", "VERSION", "ARTIFACTS")
		for _, s := range manifest.Sources {
			version := s.Version
			if version == "" {
				version = "-"
			}
			artifactCount := "-"
			if len(s.Artifacts) > 0 {
				artifactCount = strings.Join(s.Artifacts, ", ")
			}
			table.Row(s.Name, version, artifactCount)
		}
		_ = table.Flush()
	} else {
		for _, s := range manifest.Sources {
			if s.Version != "" {
				out.Print("%s:%s\n", s.Name, s.Version)
			} else {
				out.Print("%s\n", s.Name)
			}
		}
	}

	return nil
}

func filterArtifacts(artifacts []pack.Artifact, pattern string) []pack.Artifact {
	var result []pack.Artifact
	for _, a := range artifacts {
		if matchPath(a.Path, pattern) {
			result = append(result, a)
		}
	}
	return result
}

func filterStrings(items []string, pattern string) []string {
	var result []string
	for _, item := range items {
		if matchPath(item, pattern) {
			result = append(result, item)
		}
	}
	return result
}

func matchPath(path, pattern string) bool {
	// Extract just the filename for simple patterns
	name := filepath.Base(path)

	// Try matching against the full path first
	if matched, _ := filepath.Match(pattern, path); matched {
		return true
	}
	// Then try matching against just the filename
	if matched, _ := filepath.Match(pattern, name); matched {
		return true
	}
	return false
}
