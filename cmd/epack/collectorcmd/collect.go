//go:build components

package collectorcmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/locktivity/epack/internal/cli/output"
	"github.com/locktivity/epack/internal/collector"
	"github.com/locktivity/epack/internal/component/lockfile"
	"github.com/locktivity/epack/internal/limits"
	"github.com/locktivity/epack/pack"
	"github.com/spf13/cobra"
)

var (
	collectConfigPath string
	collectFrozen     bool
	collectOutput     string
	collectTimeout    time.Duration
	collectProgress   string
)

func newCollectCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "collect",
		Short: "Collect evidence (auto-lock, sync, run)",
		Long: `One-command workflow to collect evidence and build a pack.

In non-frozen mode (default), this command:
  1. Locks collectors if lockfile is missing or stale (for platforms in config)
  2. Syncs (downloads) any missing collectors for current platform
  3. Runs all collectors
  4. Builds an evidence pack

In frozen mode (--frozen), this command:
  1. Verifies lockfile exists and matches config exactly
  2. Verifies all collectors are installed with correct digests
  3. Runs all collectors
  4. Builds an evidence pack

Use frozen mode in CI to ensure reproducible builds.

Platforms:
  Specify platforms to lock in epack.yaml:
    platforms: [linux/amd64, darwin/arm64]

  If not specified, only the current platform is locked.

Examples:
  epack collect                        # Auto-lock, sync, run, build
  epack collect --frozen               # CI mode: strict verification
  epack collect -c epack.yaml          # Use specific config file`,
		RunE: runCollect,
	}

	cmd.Flags().StringVarP(&collectConfigPath, "config", "c", "epack.yaml",
		"path to epack config file")
	cmd.Flags().BoolVar(&collectFrozen, "frozen", false,
		"fail on any mismatch (CI mode)")
	cmd.Flags().StringVarP(&collectOutput, "output", "o", "",
		"output pack file (default: evidence-<timestamp>.epack)")
	cmd.Flags().DurationVar(&collectTimeout, "timeout", time.Duration(limits.DefaultCollectorTimeout),
		"timeout per collector execution (e.g., 30s, 2m)")
	cmd.Flags().StringVar(&collectProgress, "progress", defaultProgressMode(),
		"progress display mode: auto, tty, plain, json, quiet (env: EPACK_PROGRESS)")

	return cmd
}

func runCollect(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	out := getOutput(cmd)
	if err := validateProgressMode(collectProgress); err != nil {
		return err
	}

	cfg, err := loadConfig(collectConfigPath)
	if err != nil {
		return err
	}

	workDir, err := resolveWorkDir()
	if err != nil {
		return err
	}

	// Build options from flags
	opts := collector.CollectOpts{
		Secure: collector.SecureRunOptions{
			Frozen:  collectFrozen,
			Timeout: collectTimeout,
		},
		WorkDir:    workDir,
		OutputPath: collectOutput,
	}

	// Show in-progress collection status (spinner in TTY, heartbeat in CI/non-TTY).
	progress := startCollectionProgress(ctx, out, collectFrozen, collectProgress)
	opts.OnCollectorEvent = progress.OnCollectorEvent

	// Track duration
	startTime := time.Now()

	// Run collection
	result, err := collector.Collect(ctx, cfg, opts)
	progress.Done(err == nil)

	duration := time.Since(startTime)

	// Print progress regardless of error
	printCollectProgress(out, result, collectFrozen)

	if err != nil {
		return handleCollectorError(err)
	}

	// Print success output
	return printCollectResults(out, result, duration)
}

// printCollectProgress prints the progress information from collection.
func printCollectProgress(out *output.Writer, result *collector.CollectWorkflowResult, frozen bool) {
	if result == nil {
		return
	}

	// Print lock results (non-frozen mode only)
	if len(result.LockResults) > 0 {
		out.Print("Locking collectors...\n")
		for _, r := range result.LockResults {
			status := "locked"
			if r.Updated {
				status = "updated"
			} else if r.IsNew {
				status = "added"
			}
			out.Print("  %s %s@%s\n", status, r.Name, r.Version)
		}
	}

	// Print sync results
	for _, r := range result.SyncResults {
		if r.Skipped {
			// External collector, skip
		} else if r.Installed {
			out.Print("  installed %s@%s\n", r.Name, r.Version)
		} else if r.Verified {
			out.Print("  verified %s@%s\n", r.Name, r.Version)
		}
	}

	// Print collector results
	for _, r := range result.CollectorResults {
		if !r.Success {
			out.Print("  FAILED %s: %v\n", r.Collector, r.Error)
		} else {
			out.Print("  collected %s\n", r.Collector)
		}
	}

	// Remind user to commit lockfile if it was updated
	if result.LockfileUpdated {
		out.Print("\nLockfile was updated. Remember to commit %s\n", lockfile.FileName)
	}
}

// printCollectResults prints the final results of collection.
func printCollectResults(out *output.Writer, result *collector.CollectWorkflowResult, duration time.Duration) error {
	out.Print("Building evidence pack...\n")

	// Output results
	if out.IsJSON() {
		absPath, _ := filepath.Abs(result.PackPath)
		return out.JSON(map[string]interface{}{
			"pack":        absPath,
			"stream":      result.Stream,
			"collectors":  len(result.CollectorResults),
			"failures":    result.Failures,
			"duration_ms": duration.Milliseconds(),
		})
	}

	// Get pack file size
	packSize := int64(0)
	if info, err := os.Stat(result.PackPath); err == nil {
		packSize = info.Size()
	}

	// Count successful collectors
	successful := len(result.CollectorResults) - result.Failures

	// Print summary
	out.Print("\n✓ Evidence pack created in %s\n", formatDuration(duration))
	out.Print("\nSummary:\n")
	out.Print("  • Collectors: %d successful", successful)
	if result.Failures > 0 {
		out.Print(", %d failed", result.Failures)
	}
	out.Print("\n")
	out.Print("  • Pack size:  %s\n", formatBytes(packSize))
	out.Print("  • Stream:     %s\n", result.Stream)

	// Print evidence summary (what was actually collected)
	printEvidenceSummary(out, result.PackPath)

	out.Print("\nOutput: %s\n", result.PackPath)

	// Post-command hints
	p := out.Palette()
	out.Print("\n%s\n", p.Dim("Next steps:"))
	out.Print("%s  epack sign %s     %s\n", p.Dim("  •"), result.PackPath, p.Dim("# Sign the pack"))
	out.Print("%s  epack inspect %s  %s\n", p.Dim("  •"), result.PackPath, p.Dim("# View contents"))
	out.Print("%s  epack push <remote> %s  %s\n", p.Dim("  •"), result.PackPath, p.Dim("# Push to registry"))

	return nil
}

// formatDuration formats a duration into a human-readable string.
func formatDuration(d time.Duration) string {
	if d < time.Second {
		return fmt.Sprintf("%dms", d.Milliseconds())
	}
	if d < time.Minute {
		return fmt.Sprintf("%.1fs", d.Seconds())
	}
	mins := int(d.Minutes())
	secs := d.Seconds() - float64(mins*60)
	return fmt.Sprintf("%dm%.1fs", mins, secs)
}

// formatBytes formats bytes into a human-readable string.
func formatBytes(bytes int64) string {
	const (
		KB = 1024
		MB = 1024 * KB
		GB = 1024 * MB
	)
	switch {
	case bytes >= GB:
		return fmt.Sprintf("%.1f GB", float64(bytes)/GB)
	case bytes >= MB:
		return fmt.Sprintf("%.1f MB", float64(bytes)/MB)
	case bytes >= KB:
		return fmt.Sprintf("%.1f KB", float64(bytes)/KB)
	default:
		return fmt.Sprintf("%d bytes", bytes)
	}
}

// printEvidenceSummary shows what evidence was collected from each source.
func printEvidenceSummary(out *output.Writer, packPath string) {
	// Open the pack to read the manifest
	p, err := pack.Open(packPath)
	if err != nil {
		// Don't fail collection - just skip the summary
		out.Verbose("Could not open pack for summary: %v\n", err)
		return
	}
	defer func() { _ = p.Close() }()

	manifest := p.Manifest()
	if len(manifest.Sources) == 0 && len(manifest.Artifacts) == 0 {
		return
	}

	palette := out.Palette()
	out.Print("\n%s\n", palette.Bold("Evidence Collected:"))

	// Group artifacts by source
	artifactsBySource := make(map[string][]pack.Artifact)
	for _, artifact := range manifest.Artifacts {
		source := findSourceForArtifact(manifest, artifact.Path)
		artifactsBySource[source] = append(artifactsBySource[source], artifact)
	}

	// Print each source and its artifacts
	for _, source := range manifest.Sources {
		artifacts := artifactsBySource[source.Name]
		if len(artifacts) == 0 {
			continue
		}

		out.Print("\n  %s\n", palette.Cyan(source.Name))

		for _, artifact := range artifacts {
			// Build artifact description
			desc := formatArtifactSummary(artifact)
			out.Print("    • %s\n", desc)
		}
	}

	// Print any artifacts without a source (shouldn't happen, but be safe)
	if orphans := artifactsBySource[""]; len(orphans) > 0 {
		out.Print("\n  %s\n", palette.Cyan("(other)"))
		for _, artifact := range orphans {
			desc := formatArtifactSummary(artifact)
			out.Print("    • %s\n", desc)
		}
	}

	// Show compliance controls if any artifacts have them
	controls := collectControls(manifest.Artifacts)
	if len(controls) > 0 {
		out.Print("\n  %s %s\n", palette.Dim("Controls:"), strings.Join(controls, ", "))
	}
}

// findSourceForArtifact finds which source contributed an artifact.
func findSourceForArtifact(manifest pack.Manifest, artifactPath string) string {
	for _, source := range manifest.Sources {
		for _, path := range source.Artifacts {
			if path == artifactPath {
				return source.Name
			}
		}
	}
	return ""
}

// formatArtifactSummary creates a human-readable summary of an artifact.
func formatArtifactSummary(artifact pack.Artifact) string {
	// Prefer display name, fall back to path
	name := artifact.DisplayName
	if name == "" {
		// Extract meaningful name from path like "artifacts/github-posture/posture.json"
		name = filepath.Base(artifact.Path)
		if name == "" {
			name = artifact.Path
		}
	}

	// Add description if available
	if artifact.Description != "" {
		// Keep description short for summary
		desc := artifact.Description
		if len(desc) > 60 {
			desc = desc[:57] + "..."
		}
		return fmt.Sprintf("%s: %s", name, desc)
	}

	// Add content type hint if no description
	if artifact.ContentType != "" && artifact.ContentType != "application/json" {
		return fmt.Sprintf("%s (%s)", name, artifact.ContentType)
	}

	return name
}

// collectControls gathers unique compliance controls from all artifacts.
func collectControls(artifacts []pack.Artifact) []string {
	seen := make(map[string]struct{})
	var controls []string

	for _, artifact := range artifacts {
		for _, ctrl := range artifact.Controls {
			if _, ok := seen[ctrl]; !ok {
				seen[ctrl] = struct{}{}
				controls = append(controls, ctrl)
			}
		}
	}

	return controls
}
