package cmd

import (
	"fmt"

	"github.com/locktivity/epack/internal/cli/output"
	"github.com/locktivity/epack/pack"
	"github.com/locktivity/epack/pack/diff"
	"github.com/spf13/cobra"
)

var (
	diffArtifact string
	diffContext  int
)

func init() {
	rootCmd.AddCommand(diffCmd)

	diffCmd.Flags().StringVarP(&diffArtifact, "artifact", "a", "", "compare a specific artifact by path")
	diffCmd.Flags().IntVarP(&diffContext, "context", "C", 3, "lines of context for text diffs")
}

var diffCmd = &cobra.Command{
	Use:        "diff <pack1> <pack2>",
	Short:      "Compare two evidence packs",
	SuggestFor: []string{"compare", "cmp"},
	Long: `Diff compares two evidence packs and shows the differences.

By default, it shows a summary of which artifacts were added, removed,
or changed between the two packs.

Use --artifact to compare a specific artifact's contents. For JSON artifacts,
it shows a structured diff highlighting changed fields. For text artifacts,
it shows a traditional line-based diff.

Examples:
  # Compare two packs
  epack diff old.epack new.epack

  # Compare a specific artifact
  epack diff old.epack new.epack --artifact artifacts/config.json

  # JSON output for scripting
  epack diff --json old.epack new.epack`,
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) < 2 {
			return fmt.Errorf("requires two pack paths\n\nUsage: epack diff <pack1> <pack2>")
		}
		if len(args) > 2 {
			return fmt.Errorf("accepts at most 2 arguments, received %d", len(args))
		}
		return nil
	},
	RunE: runDiff,
}

func runDiff(cmd *cobra.Command, args []string) error {
	pack1Path := args[0]
	pack2Path := args[1]
	out := outputWriter()

	// Open both packs
	p1, err := pack.Open(pack1Path)
	if err != nil {
		return exitError("failed to open %s: %v", pack1Path, err)
	}
	defer func() { _ = p1.Close() }()

	p2, err := pack.Open(pack2Path)
	if err != nil {
		return exitError("failed to open %s: %v", pack2Path, err)
	}
	defer func() { _ = p2.Close() }()

	if diffArtifact != "" {
		return diffSingleArtifact(out, p1, p2, diffArtifact)
	}
	result := diff.Packs(p1, p2)
	if out.IsJSON() {
		return out.JSON(buildDiffJSONOutput(pack1Path, pack2Path, result))
	}
	return renderDiffHumanOutput(out, pack1Path, pack2Path, result)
}

func buildDiffJSONOutput(pack1Path, pack2Path string, result *diff.Result) diffOutput {
	return diffOutput{
		Pack1: diffPackInfo{
			Path:       pack1Path,
			Stream:     result.Pack1.Stream,
			PackDigest: result.Pack1.PackDigest,
		},
		Pack2: diffPackInfo{
			Path:       pack2Path,
			Stream:     result.Pack2.Stream,
			PackDigest: result.Pack2.PackDigest,
		},
		Added:     result.Added,
		Removed:   result.Removed,
		Changed:   result.Changed,
		Unchanged: result.Unchanged,
		Summary: diffSummary{
			AddedCount:     len(result.Added),
			RemovedCount:   len(result.Removed),
			ChangedCount:   len(result.Changed),
			UnchangedCount: len(result.Unchanged),
		},
	}
}

func renderDiffHumanOutput(out *output.Writer, pack1Path, pack2Path string, result *diff.Result) error {
	palette := out.Palette()

	out.Print("Comparing evidence packs\n")
	out.Print("%s\n\n", palette.Dim("────────────────────────────────────"))

	out.Print("  %s %s\n", palette.Dim("Pack 1:"), pack1Path)
	out.Print("           %s %s\n", palette.Dim("Stream:"), result.Pack1.Stream)
	out.Print("           %s %s\n\n", palette.Dim("Digest:"), output.FormatDigest(result.Pack1.PackDigest))

	out.Print("  %s %s\n", palette.Dim("Pack 2:"), pack2Path)
	out.Print("           %s %s\n", palette.Dim("Stream:"), result.Pack2.Stream)
	out.Print("           %s %s\n", palette.Dim("Digest:"), output.FormatDigest(result.Pack2.PackDigest))

	if result.IsIdentical() {
		out.Print("\n%s\n", palette.Green("Packs are identical"))
		return nil
	}

	printDiffSection(out, palette, "Added", palette.Green("+"), result.Added)
	printDiffSection(out, palette, "Removed", palette.Red("-"), result.Removed)
	printChangedSection(out, palette, result.Changed)

	summary := result.Summary()
	out.Print("\n%s %d added, %d removed, %d changed, %d unchanged\n",
		palette.Dim("Summary:"),
		summary.Added, summary.Removed, summary.Changed, summary.Unchanged)

	return nil
}

func printDiffSection(out *output.Writer, palette *output.Palette, name, marker string, paths []string) {
	if len(paths) == 0 {
		return
	}
	out.Section(fmt.Sprintf("%s (%d)", name, len(paths)))
	for _, path := range paths {
		out.Print("  %s %s\n", marker, path)
	}
}

func printChangedSection(out *output.Writer, palette *output.Palette, changed []string) {
	if len(changed) == 0 {
		return
	}
	printDiffSection(out, palette, "Changed", palette.Yellow("~"), changed)
	out.Print("\n  %s\n", palette.Dim("Use --artifact <path> to see content differences"))
}

func diffSingleArtifact(out *output.Writer, p1, p2 *pack.Pack, artifactPath string) error {
	palette := out.Palette()

	result, err := diff.Content(p1, p2, artifactPath)
	if err != nil {
		return exitError("failed to diff artifact: %v", err)
	}

	out.Print("Artifact %s\n", palette.Bold(artifactPath))
	out.Print("%s\n\n", palette.Dim("────────────────────────────────────"))

	switch result.Status {
	case diff.ContentNotFound:
		return exitError("artifact %q not found in either pack", artifactPath)
	case diff.ContentOnlyInPack1:
		out.Print("%s Artifact only exists in pack 1\n", palette.Red("-"))
		return nil
	case diff.ContentOnlyInPack2:
		out.Print("%s Artifact only exists in pack 2\n", palette.Green("+"))
		return nil
	case diff.ContentIdentical:
		out.Print("%s\n", palette.Green("Contents are identical"))
		return nil
	case diff.ContentDifferent:
		if result.IsJSON {
			return renderJSONChanges(out, result.JSONChanges)
		}
		return renderTextDiff(out, result.TextDiff)
	}

	return nil
}

func renderJSONChanges(out *output.Writer, changes []diff.JSONChange) error {
	palette := out.Palette()

	for _, change := range changes {
		switch change.Type {
		case diff.JSONAdded:
			out.Print("%s %s: %s\n", palette.Green("+"), change.Path, diff.FormatJSONValue(change.NewValue))
		case diff.JSONRemoved:
			out.Print("%s %s: %s\n", palette.Red("-"), change.Path, diff.FormatJSONValue(change.OldValue))
		case diff.JSONChanged:
			out.Print("%s %s:\n", palette.Yellow("~"), change.Path)
			out.Print("  %s %s\n", palette.Red("-"), diff.FormatJSONValue(change.OldValue))
			out.Print("  %s %s\n", palette.Green("+"), diff.FormatJSONValue(change.NewValue))
		}
	}

	return nil
}

func renderTextDiff(out *output.Writer, lines []diff.LineDiff) error {
	palette := out.Palette()

	for _, line := range lines {
		switch line.Type {
		case diff.LineEqual:
			out.Print("  %s\n", line.Line)
		case diff.LineAdded:
			out.Print("%s %s\n", palette.Green("+"), line.Line)
		case diff.LineRemoved:
			out.Print("%s %s\n", palette.Red("-"), line.Line)
		}
	}

	return nil
}

type diffOutput struct {
	Pack1     diffPackInfo `json:"pack1"`
	Pack2     diffPackInfo `json:"pack2"`
	Added     []string     `json:"added"`
	Removed   []string     `json:"removed"`
	Changed   []string     `json:"changed"`
	Unchanged []string     `json:"unchanged"`
	Summary   diffSummary  `json:"summary"`
}

type diffPackInfo struct {
	Path       string `json:"path"`
	Stream     string `json:"stream"`
	PackDigest string `json:"pack_digest"`
}

type diffSummary struct {
	AddedCount     int `json:"added_count"`
	RemovedCount   int `json:"removed_count"`
	ChangedCount   int `json:"changed_count"`
	UnchangedCount int `json:"unchanged_count"`
}
