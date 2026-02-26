package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/locktivity/epack/internal/cli/output"
	"github.com/locktivity/epack/pack"
	"github.com/spf13/cobra"
)

var (
	inspectDigest  bool
	inspectRaw     bool
	inspectSummary bool
)

func init() {
	rootCmd.AddCommand(inspectCmd)

	inspectCmd.Flags().BoolVar(&inspectDigest, "digest", false, "show only pack_digest")
	inspectCmd.Flags().BoolVar(&inspectRaw, "raw", false, "output raw manifest.json")
	inspectCmd.Flags().BoolVar(&inspectSummary, "summary", false, "condensed summary")
}

var inspectCmd = &cobra.Command{
	Use:        "inspect <pack>",
	Short:      "Display pack manifest and metadata",
	SuggestFor: []string{"info", "show", "view", "inpsect"},
	Long: `Inspect displays the contents and metadata of an evidence pack.

The default output shows a human-readable summary including stream,
pack digest, timestamps, artifact counts, and attestation status.

Examples:
  # Display pack information
  epack inspect evidence.epack

  # Get just the pack digest (for scripting)
  DIGEST=$(epack inspect --digest evidence.epack)

  # Output as JSON
  epack inspect --json evidence.epack

  # Show raw manifest.json
  epack inspect --raw evidence.epack`,
	Args: cobra.ExactArgs(1),
	RunE: runInspect,
}

func runInspect(cmd *cobra.Command, args []string) error {
	packPath := args[0]
	out := outputWriter()

	p, err := pack.Open(packPath)
	if err != nil {
		return packOpenError(packPath, err)
	}
	defer func() { _ = p.Close() }()

	manifest := p.Manifest()

	// --digest: just output the pack digest
	if inspectDigest {
		out.Println(manifest.PackDigest)
		return nil
	}

	// --raw: output raw manifest JSON
	if inspectRaw {
		data, err := json.MarshalIndent(manifest, "", "  ")
		if err != nil {
			return exitError("failed to marshal manifest: %v", err)
		}
		out.Println(string(data))
		return nil
	}

	attestations := p.ListAttestations()

	// --json: structured JSON output
	if out.IsJSON() {
		return out.JSON(inspectOutput{
			SpecVersion:      manifest.SpecVersion,
			Stream:           manifest.Stream,
			PackDigest:       manifest.PackDigest,
			GeneratedAt:      manifest.GeneratedAt,
			ArtifactCount:    len(manifest.Artifacts),
			AttestationCount: len(attestations),
			Sources:          manifest.Sources,
			Artifacts:        manifest.Artifacts,
			Attestations:     attestations,
		})
	}

	// --summary: condensed output
	if inspectSummary {
		out.Print("%s  %s  %d artifacts  %d attestations\n",
			manifest.Stream, output.FormatDigest(manifest.PackDigest), len(manifest.Artifacts), len(attestations))
		return nil
	}

	// Default: human-readable output
	palette := out.Palette()

	out.Print("Evidence Pack: %s\n", palette.Bold(packPath))
	out.Print("%s\n\n", palette.Dim("────────────────────────────────────"))

	out.KeyValue("Stream", manifest.Stream)
	out.KeyValue("Pack Digest", manifest.PackDigest)
	out.KeyValue("Generated At", manifest.GeneratedAt)
	out.KeyValue("Spec Version", manifest.SpecVersion)

	// Sources
	if len(manifest.Sources) > 0 {
		out.Section("Sources")
		for _, s := range manifest.Sources {
			if s.Version != "" {
				out.Print("  %s %s\n", s.Name, palette.Dim("v"+s.Version))
			} else {
				out.Print("  %s\n", s.Name)
			}
		}
	}

	// Artifacts summary
	out.Section(fmt.Sprintf("Artifacts (%d)", len(manifest.Artifacts)))
	if len(manifest.Artifacts) > 0 {
		table := out.Table()
		for _, a := range manifest.Artifacts {
			size := ""
			if a.Size != nil {
				size = output.FormatBytesFromJSON(a.Size)
			}
			contentType := a.ContentType
			if contentType == "" {
				contentType = palette.Dim("-")
			}
			table.Row("  "+a.Path, size, contentType)
		}
		_ = table.Flush()
	}

	// Attestations
	out.Section(fmt.Sprintf("Attestations (%d)", len(attestations)))
	if len(attestations) > 0 {
		for _, a := range attestations {
			out.Print("  %s\n", a)
		}
	} else {
		out.Print("  %s\n", palette.Dim("none"))
	}

	out.Println()
	return nil
}

type inspectOutput struct {
	SpecVersion      string          `json:"spec_version"`
	Stream           string          `json:"stream"`
	PackDigest       string          `json:"pack_digest"`
	GeneratedAt      string          `json:"generated_at"`
	ArtifactCount    int             `json:"artifact_count"`
	AttestationCount int             `json:"attestation_count"`
	Sources          []pack.Source   `json:"sources"`
	Artifacts        []pack.Artifact `json:"artifacts"`
	Attestations     []string        `json:"attestations"`
}
