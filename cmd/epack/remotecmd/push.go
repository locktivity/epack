//go:build components

package remotecmd

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/locktivity/epack/internal/cli/output"
	"github.com/locktivity/epack/internal/component/config"
	"github.com/locktivity/epack/internal/componenttypes"
	"github.com/locktivity/epack/internal/detach"
	"github.com/locktivity/epack/internal/project"
	"github.com/locktivity/epack/internal/push"
	"github.com/locktivity/epack/internal/securityaudit"
	"github.com/locktivity/epack/internal/securitypolicy"
	"github.com/locktivity/epack/pack"
	"github.com/spf13/cobra"
)

var (
	pushEnv                   string
	pushWorkspace             string
	pushLabels                []string
	pushNotes                 string
	pushRunsPaths             []string
	pushNoRuns                bool
	pushYes                   bool
	pushDryRun                bool
	pushDetach                bool
	pushInsecureAllowUnpinned bool
)

func newPushCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "push <remote> <pack>",
		Short: "Push a pack to a remote registry",
		Long: `Push uploads an evidence pack to a remote registry.

The pack is verified locally before upload. After upload, a release
is created in the remote registry with optional labels and notes.

Run records are automatically synced after push unless --no-runs is set.

Exit codes:
  0  Pack pushed successfully
  1  Push failed (authentication error, network error, etc.)
  2  Pack malformed/cannot open

Examples:
  # Push to Locktivity
  epack push locktivity packs/acme-prod.epack

  # Push with labels
  epack push locktivity packs/acme-prod.epack --label monthly --label soc2

  # Push to staging environment
  epack push locktivity packs/acme-prod.epack --env staging

  # Push with release notes
  epack push locktivity packs/acme-prod.epack --notes "February release"

  # Push without syncing runs
  epack push locktivity packs/acme-prod.epack --no-runs

  # Preview what would be pushed (dry-run)
  epack push locktivity packs/acme-prod.epack --dry-run

  # Push in background (returns immediately)
  epack push locktivity packs/acme-prod.epack --detach`,
		Args: cobra.ExactArgs(2),
		RunE: runPush,
	}

	cmd.Flags().StringVar(&pushEnv, "env", "", "environment to use (applies config from environments.<env>)")
	cmd.Flags().StringVar(&pushWorkspace, "workspace", "", "override target workspace")
	cmd.Flags().StringSliceVar(&pushLabels, "label", nil, "release label (can be repeated)")
	cmd.Flags().StringVar(&pushNotes, "notes", "", "release notes")
	cmd.Flags().StringSliceVar(&pushRunsPaths, "runs-path", nil, "additional path to search for run results")
	cmd.Flags().BoolVar(&pushNoRuns, "no-runs", false, "skip run syncing")
	cmd.Flags().BoolVarP(&pushYes, "yes", "y", false, "non-interactive mode (skip prompts)")
	cmd.Flags().BoolVar(&pushDryRun, "dry-run", false, "show what would be pushed without uploading")
	cmd.Flags().BoolVarP(&pushDetach, "detach", "d", false, "run in background and return immediately")
	// Support env var for insecure-allow-unpinned
	pushInsecureAllowUnpinned = componenttypes.InsecureAllowUnpinnedFromEnv()
	cmd.Flags().BoolVar(&pushInsecureAllowUnpinned, "insecure-allow-unpinned", pushInsecureAllowUnpinned,
		"allow using adapters not pinned in lockfile (NOT RECOMMENDED)")

	return cmd
}

func runPush(cmd *cobra.Command, args []string) error {
	remoteName := args[0]
	packPath := args[1]
	out := outputWriter()
	ctx := cmdContext(cmd)
	if err := validatePushFlags(); err != nil {
		return exitError("push failed: %v", err)
	}

	// Check pack exists
	packInfo, err := os.Stat(packPath)
	if os.IsNotExist(err) {
		return exitError("pack not found: %s", packPath)
	}
	if err != nil {
		return exitError("checking pack: %v", err)
	}

	// Dry-run mode: show what would be pushed without executing
	if pushDryRun {
		return runPushDryRun(remoteName, packPath, packInfo.Size(), out)
	}

	// Detach mode: spawn background process and return immediately
	if pushDetach {
		return runPushDetached(cmd, args, out)
	}

	// Verbose logging
	out.Verbose("Pushing to remote %q\n", remoteName)
	if pushEnv != "" {
		out.Verbose("Using environment: %s\n", pushEnv)
	}

	// Track current step spinner and progress bar
	var currentSpinner *output.Spinner
	var progressBar *output.ProgressBar

	// Track duration
	startTime := time.Now()

	// Build options with step callbacks for multi-step progress
	opts := push.Options{
		Secure: struct{ Frozen bool }{
			Frozen: false,
		},
		Unsafe: struct{ AllowUnpinned bool }{
			AllowUnpinned: pushInsecureAllowUnpinned,
		},
		Remote:         remoteName,
		PackPath:       packPath,
		Environment:    pushEnv,
		Workspace:      pushWorkspace,
		Labels:         pushLabels,
		Notes:          pushNotes,
		RunsPaths:      pushRunsPaths,
		NoRuns:         pushNoRuns,
		NonInteractive: pushYes,
		Stderr:         os.Stderr,
		OnStep: func(step string, started bool) {
			if out.IsQuiet() || out.IsJSON() {
				return
			}
			if started {
				// Stop any existing progress bar before starting new spinner
				if progressBar != nil {
					progressBar = nil
				}
				currentSpinner = out.StartSpinner(step)
			} else if currentSpinner != nil {
				currentSpinner.Success(step)
				currentSpinner = nil
			}
		},
		OnUploadProgress: func(written, total int64) {
			if out.IsQuiet() || out.IsJSON() {
				return
			}
			// Stop spinner, switch to progress bar for upload
			if currentSpinner != nil {
				currentSpinner.Stop()
				currentSpinner = nil
				progressBar = out.StartProgress("Uploading", total)
			}
			if progressBar != nil {
				progressBar.Update(written)
			}
		},
		PromptInstallAdapter: func(remoteName, adapterName string) bool {
			// Don't prompt in non-interactive modes
			if out.IsQuiet() || out.IsJSON() || !out.IsTTY() || pushYes {
				return false
			}
			// Stop current spinner before prompting
			if currentSpinner != nil {
				currentSpinner.Stop()
				currentSpinner = nil
			}
			// Prompt user
			return out.PromptConfirm(
				"Adapter %q for remote %q is not installed. Install now?",
				adapterName, remoteName,
			)
		},
	}

	result, err := push.Push(ctx, opts)
	if err != nil {
		// Clean up any active UI
		if progressBar != nil {
			progressBar.Fail("Upload failed")
		} else if currentSpinner != nil {
			currentSpinner.Fail("Push failed")
		}
		return exitError("push failed: %v", err)
	}

	// Clean up progress bar if it was still active (upload completed)
	if progressBar != nil {
		progressBar.Done("Uploaded")
	}

	// Show run sync results
	if len(result.SyncedRuns) > 0 || len(result.FailedRuns) > 0 {
		out.Verbose("Synced %d runs, %d failed\n", len(result.SyncedRuns), len(result.FailedRuns))
	}

	// Output result
	if out.IsJSON() {
		return out.JSON(map[string]interface{}{
			"pushed":        true,
			"remote":        remoteName,
			"pack":          packPath,
			"release_id":    result.Release.ReleaseID,
			"canonical_ref": result.Release.CanonicalRef,
			"links":         result.Links,
			"synced_runs":   result.SyncedRuns,
			"failed_runs":   result.FailedRuns,
			"receipt_path":  result.ReceiptPath,
		})
	}

	duration := time.Since(startTime)

	out.Print("\n✓ Pushed to %s in %s\n", remoteName, formatPushDuration(duration))
	out.Print("\nRelease:\n")
	out.Print("  • ID:      %s\n", result.Release.ReleaseID)
	if result.Release.CanonicalRef != "" {
		out.Print("  • Ref:     %s\n", result.Release.CanonicalRef)
	}
	if len(result.SyncedRuns) > 0 {
		out.Print("  • Runs:    %d synced\n", len(result.SyncedRuns))
	}
	if viewURL, ok := result.Links["view"]; ok {
		out.Print("\nView:  %s\n", viewURL)
	}
	if shareURL, ok := result.Links["share"]; ok {
		out.Print("Share: %s\n", shareURL)
	}

	// Post-command hints
	p := out.Palette()
	out.Print("\n%s\n", p.Dim("Next steps:"))
	out.Print("%s  epack pull %s           %s\n", p.Dim("  •"), remoteName, p.Dim("# Pull on another machine"))
	out.Print("%s  epack remote whoami %s  %s\n", p.Dim("  •"), remoteName, p.Dim("# Check auth status"))

	return nil
}

func validatePushFlags() error {
	if err := (securitypolicy.ExecutionPolicy{
		Frozen:        false,
		AllowUnpinned: pushInsecureAllowUnpinned,
	}).Enforce(); err != nil {
		return err
	}
	if err := securitypolicy.EnforceStrictProduction("push_cli", pushInsecureAllowUnpinned); err != nil {
		return err
	}
	if pushInsecureAllowUnpinned {
		securityaudit.Emit(securityaudit.Event{
			Type:        securityaudit.EventInsecureBypass,
			Component:   "push",
			Name:        "push",
			Description: "push command running with insecure unpinned override",
			Attrs: map[string]string{
				"insecure_allow_unpinned": "true",
			},
		})
	}
	return nil
}

// formatPushDuration formats a duration into a human-readable string.
func formatPushDuration(d time.Duration) string {
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

// runPushDryRun shows what would be pushed without actually pushing.
func runPushDryRun(remoteName, packPath string, packSize int64, out *output.Writer) error {
	// Open pack to get metadata
	p, err := pack.Open(packPath)
	if err != nil {
		return exitErrorWithCode(ExitMalformedPack, "failed to open pack: %v", err)
	}
	defer func() { _ = p.Close() }()

	manifest := p.Manifest()

	// Count artifacts
	artifactCount := 0
	for _, artifact := range manifest.Artifacts {
		if artifact.Type == "embedded" {
			artifactCount++
		}
	}

	attestationCount := len(p.ListAttestations())

	// Try to load remote config for additional context
	var workspace, environment string
	var configLabels []string

	projectRoot, err := project.FindRoot("")
	if err == nil {
		configPath := filepath.Join(projectRoot, "epack.yaml")
		if cfg, err := config.Load(configPath); err == nil {
			if remoteCfg, ok := cfg.Remotes[remoteName]; ok {
				workspace = remoteCfg.Target.Workspace
				environment = remoteCfg.Target.Environment
				configLabels = remoteCfg.Release.Labels

				// Apply environment overrides
				if pushEnv != "" {
					if envCfg, ok := cfg.Environments[pushEnv]; ok {
						if envRemoteCfg, ok := envCfg.Remotes[remoteName]; ok {
							if envRemoteCfg.Target.Workspace != "" {
								workspace = envRemoteCfg.Target.Workspace
							}
							if envRemoteCfg.Target.Environment != "" {
								environment = envRemoteCfg.Target.Environment
							}
							if len(envRemoteCfg.Release.Labels) > 0 {
								configLabels = envRemoteCfg.Release.Labels
							}
						}
					}
				}
			}
		}
	}

	// CLI workspace override takes precedence
	if pushWorkspace != "" {
		workspace = pushWorkspace
	}

	// Merge labels from config and CLI
	allLabels := append([]string{}, configLabels...)
	allLabels = append(allLabels, pushLabels...)

	// JSON output
	if out.IsJSON() {
		return out.JSON(map[string]interface{}{
			"dry_run":      true,
			"remote":       remoteName,
			"pack":         packPath,
			"stream":       manifest.Stream,
			"size":         packSize,
			"artifacts":    artifactCount,
			"attestations": attestationCount,
			"workspace":    workspace,
			"environment":  environment,
			"labels":       allLabels,
			"notes":        pushNotes,
			"sync_runs":    !pushNoRuns,
		})
	}

	// Human-readable output
	palette := out.Palette()
	out.Print("Would push %s → %s\n\n", packPath, remoteName)

	out.Print("%s\n", palette.Bold("Pack:"))
	out.Print("  Path:         %s\n", packPath)
	out.Print("  Stream:       %s\n", manifest.Stream)
	out.Print("  Size:         %s\n", output.FormatBytes(packSize))
	out.Print("  Artifacts:    %d\n", artifactCount)
	if attestationCount > 0 {
		out.Print("  Attestations: %d\n", attestationCount)
	}

	out.Print("\n%s\n", palette.Bold("Target:"))
	out.Print("  Remote:       %s\n", remoteName)
	if workspace != "" {
		out.Print("  Workspace:    %s\n", workspace)
	}
	if environment != "" {
		out.Print("  Environment:  %s\n", environment)
	}
	if pushEnv != "" {
		out.Print("  Config env:   %s\n", pushEnv)
	}

	if len(allLabels) > 0 || pushNotes != "" {
		out.Print("\n%s\n", palette.Bold("Release:"))
		if len(allLabels) > 0 {
			out.Print("  Labels:       %v\n", allLabels)
		}
		if pushNotes != "" {
			out.Print("  Notes:        %s\n", pushNotes)
		}
	}

	out.Print("\n%s\n", palette.Bold("Options:"))
	out.Print("  Sync runs:    %v\n", !pushNoRuns)

	return nil
}

// runPushDetached spawns a background push process and returns immediately.
func runPushDetached(cmd *cobra.Command, args []string, out *output.Writer) error {
	// Build flags for detached execution (without --detach to avoid infinite loop)
	flags := detach.BuildPushFlags(
		pushEnv,
		pushWorkspace,
		pushNotes,
		pushLabels,
		pushRunsPaths,
		pushNoRuns,
		pushYes,
	)

	// Spawn background process
	result, err := detach.Spawn(detach.Options{
		Command: "push",
		Args:    args,
		Flags:   flags,
	})
	if err != nil {
		return exitError("failed to start background process: %v", err)
	}

	// Output result
	if out.IsJSON() {
		return out.JSON(map[string]interface{}{
			"detached": true,
			"job_id":   result.JobID,
			"pid":      result.PID,
			"log_path": result.LogPath,
		})
	}

	out.Success("Push started in background")
	out.Print("  Job ID:  %s\n", result.JobID)
	out.Print("  PID:     %d\n", result.PID)
	out.Print("  Log:     %s\n", result.LogPath)
	out.Print("\n")
	out.Print("Check status with: epack jobs %s\n", result.JobID)
	out.Print("View logs with:    tail -f %s\n", result.LogPath)

	return nil
}
