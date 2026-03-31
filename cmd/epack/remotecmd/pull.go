//go:build components

package remotecmd

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/locktivity/epack/internal/cli/output"
	"github.com/locktivity/epack/internal/component/config"
	"github.com/locktivity/epack/internal/componenttypes"
	"github.com/locktivity/epack/internal/detach"
	"github.com/locktivity/epack/internal/project"
	"github.com/locktivity/epack/internal/pull"
	"github.com/locktivity/epack/internal/remote"
	"github.com/locktivity/epack/internal/securityaudit"
	"github.com/locktivity/epack/internal/securitypolicy"
	"github.com/spf13/cobra"
)

var (
	pullEnv                   string
	pullWorkspace             string
	pullOutput                string
	pullDigest                string
	pullReleaseID             string
	pullVersion               string
	pullForce                 bool
	pullVerify                bool
	pullDryRun                bool
	pullDetach                bool
	pullInsecureAllowUnpinned bool
)

func newPullCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "pull <remote> [ref]",
		Short: "Pull a pack from a remote registry",
		Long: `Pull downloads an evidence pack from a remote registry.

By default, pulls the latest release. Use --digest, --release, or --version
to pull a specific pack. The pack is verified after download unless --verify=false.

Exit codes:
  0  Pack pulled successfully
  1  Pull failed (authentication error, network error, etc.)
  2  Pack verification failed

Examples:
  # Pull latest pack
  epack pull locktivity

  # Pull to specific output path
  epack pull locktivity -o ./packs/evidence.epack

  # Pull specific version
  epack pull locktivity --version v1.2.3

  # Pull by release ID
  epack pull locktivity --release rel_abc123

  # Pull by digest (immutable, for reproducibility)
  epack pull locktivity --digest sha256:abc123...

  # Pull from staging environment
  epack pull locktivity --env staging

  # Preview what would be pulled (dry-run)
  epack pull locktivity --dry-run

  # Pull in background (returns immediately)
  epack pull locktivity --detach

  # Pull and overwrite existing file
  epack pull locktivity --force`,
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) < 1 {
				return fmt.Errorf(`missing remote name argument

Usage: epack pull <remote> [ref]

The optional [ref] can be a version (v1.2.3), release ID (rel_xxx), or digest (sha256:xxx).
Use --output to specify the output path.

Examples:
  epack pull locktivity                    # Pull latest
  epack pull locktivity v1.2.3             # Pull specific version
  epack pull locktivity -o ./evidence.epack # Specify output path
  epack pull locktivity --dry-run`)
			}
			if len(args) > 2 {
				return fmt.Errorf("too many arguments: expected 1-2, got %d", len(args))
			}
			return nil
		},
		RunE: runPull,
	}

	cmd.Flags().StringVar(&pullEnv, "env", "", "environment to use (applies config from environments.<env>)")
	cmd.Flags().StringVar(&pullWorkspace, "workspace", "", "override target workspace")
	cmd.Flags().StringVarP(&pullOutput, "output", "o", "", "output path (default: ./<stream>.epack)")
	cmd.Flags().StringVar(&pullDigest, "digest", "", "pull specific pack by digest (immutable)")
	cmd.Flags().StringVar(&pullReleaseID, "release", "", "pull specific release by ID")
	cmd.Flags().StringVar(&pullVersion, "version", "", "pull specific version")
	cmd.Flags().BoolVar(&pullForce, "force", false, "overwrite existing file")
	cmd.Flags().BoolVar(&pullVerify, "verify", true, "verify pack integrity after download")
	cmd.Flags().BoolVar(&pullDryRun, "dry-run", false, "show what would be pulled without downloading")
	cmd.Flags().BoolVarP(&pullDetach, "detach", "d", false, "run in background and return immediately")
	// Support env var for insecure-allow-unpinned
	pullInsecureAllowUnpinned = componenttypes.InsecureAllowUnpinnedFromEnv()
	cmd.Flags().BoolVar(&pullInsecureAllowUnpinned, "insecure-allow-unpinned", pullInsecureAllowUnpinned,
		"allow using adapters not pinned in lockfile (NOT RECOMMENDED)")

	return cmd
}

func runPull(cmd *cobra.Command, args []string) error {
	remoteName := args[0]
	out := outputWriter()
	ctx := cmdContext(cmd)

	ref := buildPullRef(args)
	if handled, err := handlePullModes(cmd, args, remoteName, ref, out); handled || err != nil {
		return err
	}

	resolvedRemoteCfg, err := resolveRemoteConfigForCommand(remoteName, pullEnv)
	if err != nil {
		return exitError("pull failed: %v", err)
	}
	if err := validatePullFlags(os.Stderr, resolvedRemoteCfg); err != nil {
		return exitError("pull failed: %v", err)
	}

	out.Verbose("Pulling from remote %q\n", remoteName)
	if pullEnv != "" {
		out.Verbose("Using environment: %s\n", pullEnv)
	}

	startTime := time.Now()
	ui := newCommandUI(out, "Downloading", "Download failed", "Pull failed")

	opts := pull.Options{
		Secure: struct{ Frozen bool }{
			Frozen: false,
		},
		Unsafe: struct{ AllowUnpinned bool }{
			AllowUnpinned: pullInsecureAllowUnpinned,
		},
		Remote:             remoteName,
		Ref:                ref,
		OutputPath:         pullOutput,
		Force:              pullForce,
		Environment:        pullEnv,
		Workspace:          pullWorkspace,
		Verify:             pullVerify,
		Stderr:             os.Stderr,
		OnStep:             ui.onStep,
		OnDownloadProgress: ui.onProgress,
		PromptInstallAdapter: func(remoteName, adapterName string) bool {
			return ui.promptInstallAdapter(remoteName, adapterName, true)
		},
	}

	result, err := pull.Pull(ctx, opts)
	if err != nil {
		ui.fail()
		return exitError("pull failed: %v", err)
	}

	ui.done("Downloaded")
	return outputPullResult(out, remoteName, result, time.Since(startTime))
}

func buildPullRef(args []string) remote.PackRef {
	switch {
	case pullDigest != "":
		return remote.PackRef{Digest: pullDigest}
	case pullReleaseID != "":
		return remote.PackRef{ReleaseID: pullReleaseID}
	case pullVersion != "":
		return remote.PackRef{Version: pullVersion}
	case len(args) > 1:
		return parsePositionalPullRef(args[1])
	default:
		return remote.PackRef{Latest: true}
	}
}

func parsePositionalPullRef(refArg string) remote.PackRef {
	if len(refArg) > 7 && refArg[:7] == "sha256:" {
		return remote.PackRef{Digest: refArg}
	}
	if len(refArg) > 4 && refArg[:4] == "rel_" {
		return remote.PackRef{ReleaseID: refArg}
	}
	return remote.PackRef{Version: refArg}
}

func handlePullModes(cmd *cobra.Command, args []string, remoteName string, ref remote.PackRef, out *output.Writer) (bool, error) {
	if pullDryRun {
		return true, runPullDryRun(remoteName, ref, out)
	}
	if pullDetach {
		return true, runPullDetached(cmd, args, out)
	}
	return false, nil
}

func outputPullResult(out *output.Writer, remoteName string, result *pull.Result, duration time.Duration) error {
	if out.IsJSON() {
		return out.JSON(map[string]interface{}{
			"pulled":       true,
			"remote":       remoteName,
			"output_path":  result.OutputPath,
			"digest":       result.Pack.Digest,
			"size":         result.Pack.SizeBytes,
			"stream":       result.Pack.Stream,
			"release_id":   result.Pack.ReleaseID,
			"version":      result.Pack.Version,
			"verified":     result.Verified,
			"receipt_path": result.ReceiptPath,
		})
	}

	out.Print("\n✓ Pulled from %s in %s\n", remoteName, formatPullDuration(duration))
	out.Print("\nPack:\n")
	out.Print("  • Stream:  %s\n", result.Pack.Stream)
	out.Print("  • Size:    %s\n", output.FormatBytes(result.Pack.SizeBytes))
	if result.Pack.Version != "" {
		out.Print("  • Version: %s\n", result.Pack.Version)
	}
	if result.Pack.ReleaseID != "" {
		out.Print("  • Release: %s\n", result.Pack.ReleaseID)
	}
	if result.Verified {
		out.Print("  • Verified\n")
	}
	out.Print("\nOutput: %s\n", result.OutputPath)

	p := out.Palette()
	out.Print("\n%s\n", p.Dim("Next steps:"))
	out.Print("%s  epack inspect %s   %s\n", p.Dim("  •"), result.OutputPath, p.Dim("# View pack contents"))
	out.Print("%s  epack verify %s    %s\n", p.Dim("  •"), result.OutputPath, p.Dim("# Verify signatures"))
	out.Print("%s  epack list artifacts %s  %s\n", p.Dim("  •"), result.OutputPath, p.Dim("# List artifacts"))
	return nil
}

func validatePullFlags(stderr io.Writer, remoteCfg *config.RemoteConfig) error {
	if err := (securitypolicy.ExecutionPolicy{
		Frozen:        false,
		AllowUnpinned: pullInsecureAllowUnpinned,
	}).Enforce(); err != nil {
		return err
	}

	state, err := inspectRemoteInsecureState(remoteCfg)
	if err != nil {
		return err
	}
	warnRemoteCustomEndpoints(stderr, state.override)

	hasUnsafeOverrides := pullInsecureAllowUnpinned || state.override.Active()
	if err := securitypolicy.EnforceStrictProduction("pull_cli", hasUnsafeOverrides); err != nil {
		return err
	}
	if hasUnsafeOverrides {
		attrs := map[string]string{}
		if pullInsecureAllowUnpinned {
			attrs["insecure_allow_unpinned"] = "true"
		}
		mergeAuditAttrs(attrs, state.attrs)
		securityaudit.Emit(securityaudit.Event{
			Type:        securityaudit.EventInsecureBypass,
			Component:   "pull",
			Name:        "pull",
			Description: "pull command running with insecure execution override",
			Attrs:       attrs,
		})
	}
	return nil
}

// formatPullDuration formats a duration into a human-readable string.
func formatPullDuration(d time.Duration) string {
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

// runPullDryRun shows what would be pulled without actually pulling.
func runPullDryRun(remoteName string, ref remote.PackRef, out *output.Writer) error {
	// Try to load remote config for context
	var workspace, environment string

	projectRoot, err := project.FindRoot("")
	if err == nil {
		configPath := filepath.Join(projectRoot, "epack.yaml")
		if cfg, err := config.Load(configPath); err == nil {
			if remoteCfg, ok := cfg.Remotes[remoteName]; ok {
				workspace = remoteCfg.Target.Workspace
				environment = remoteCfg.Target.Environment

				// Apply environment overrides
				if pullEnv != "" {
					if envCfg, ok := cfg.Environments[pullEnv]; ok {
						if envRemoteCfg, ok := envCfg.Remotes[remoteName]; ok {
							if envRemoteCfg.Target.Workspace != "" {
								workspace = envRemoteCfg.Target.Workspace
							}
							if envRemoteCfg.Target.Environment != "" {
								environment = envRemoteCfg.Target.Environment
							}
						}
					}
				}
			}
		}
	}

	// CLI workspace override takes precedence
	if pullWorkspace != "" {
		workspace = pullWorkspace
	}

	// Determine reference description
	refDesc := "latest"
	if ref.Digest != "" {
		refDesc = "digest: " + ref.Digest
	} else if ref.ReleaseID != "" {
		refDesc = "release: " + ref.ReleaseID
	} else if ref.Version != "" {
		refDesc = "version: " + ref.Version
	}

	// Determine output path description
	outputDesc := pullOutput
	if outputDesc == "" {
		outputDesc = "./<stream>.epack (auto-generated)"
	}

	// JSON output
	if out.IsJSON() {
		return out.JSON(map[string]interface{}{
			"dry_run":     true,
			"remote":      remoteName,
			"ref":         refDesc,
			"output":      pullOutput,
			"workspace":   workspace,
			"environment": environment,
			"force":       pullForce,
			"verify":      pullVerify,
		})
	}

	// Human-readable output
	palette := out.Palette()
	out.Print("Would pull from %s\n\n", remoteName)

	out.Print("%s\n", palette.Bold("Source:"))
	out.Print("  Remote:      %s\n", remoteName)
	out.Print("  Reference:   %s\n", refDesc)
	if workspace != "" {
		out.Print("  Workspace:   %s\n", workspace)
	}
	if environment != "" {
		out.Print("  Environment: %s\n", environment)
	}
	if pullEnv != "" {
		out.Print("  Config env:  %s\n", pullEnv)
	}

	out.Print("\n%s\n", palette.Bold("Destination:"))
	out.Print("  Output:      %s\n", outputDesc)
	out.Print("  Force:       %v\n", pullForce)

	out.Print("\n%s\n", palette.Bold("Options:"))
	out.Print("  Verify:      %v\n", pullVerify)

	return nil
}

// runPullDetached spawns a background pull process and returns immediately.
func runPullDetached(cmd *cobra.Command, args []string, out *output.Writer) error {
	// Build flags for detached execution (without --detach to avoid infinite loop)
	flags := detach.BuildPullFlags(
		pullEnv,
		pullWorkspace,
		pullOutput,
		pullDigest,
		pullReleaseID,
		pullVersion,
		pullForce,
		pullVerify,
	)

	// Spawn background process
	result, err := detach.Spawn(detach.Options{
		Command: "pull",
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

	out.Success("Pull started in background")
	out.Print("  Job ID:  %s\n", result.JobID)
	out.Print("  PID:     %d\n", result.PID)
	out.Print("  Log:     %s\n", result.LogPath)
	out.Print("\n")
	out.Print("Check status with: epack jobs %s\n", result.JobID)
	out.Print("View logs with:    tail -f %s\n", result.LogPath)

	return nil
}
