//go:build components

package collectorcmd

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/locktivity/epack/internal/cli/output"
	"github.com/locktivity/epack/internal/collector"
	"github.com/locktivity/epack/internal/component/lockfile"
	"github.com/locktivity/epack/internal/limits"
	"github.com/spf13/cobra"
)

var (
	collectConfigPath string
	collectFrozen     bool
	collectOutput     string
	collectTimeout    time.Duration
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
		"output pack file (default: evidence-<timestamp>.pack)")
	cmd.Flags().DurationVar(&collectTimeout, "timeout", time.Duration(limits.DefaultCollectorTimeout),
		"timeout per collector execution (e.g., 30s, 2m)")

	return cmd
}

func runCollect(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	out := getOutput(cmd)

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
		WorkDir:    workDir,
		OutputPath: collectOutput,
		Frozen:     collectFrozen,
		Timeout:    collectTimeout,
	}

	// Print mode header
	if collectFrozen {
		out.Print("Collecting evidence (frozen mode)...\n")
	} else {
		out.Print("Collecting evidence...\n")
	}

	// Track duration
	startTime := time.Now()

	// Run collection
	result, err := collector.Collect(ctx, cfg, opts)

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
	out.Print("\nOutput: %s\n", result.PackPath)

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
