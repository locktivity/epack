//go:build components

package componentcmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/locktivity/epack/cmd/epack/utilitycmd"
	"github.com/locktivity/epack/internal/cli/output"
	"github.com/locktivity/epack/internal/component/config"
	"github.com/locktivity/epack/internal/component/lockfile"
	"github.com/locktivity/epack/internal/component/sync"
	"github.com/locktivity/epack/internal/exitcode"
	"github.com/locktivity/epack/internal/platform"
	"github.com/spf13/cobra"
)

var (
	installConfigPath   string
	installFrozen       bool
	installAllPlatforms bool
	installPlatforms    string
)

func newInstallCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "install",
		Short: "Lock and sync dependencies",
		Long: `Resolve versions and download dependencies in one command.

This command locks collectors, tools, and remotes if needed, then syncs (downloads)
any missing binaries for the current platform. It's equivalent to running
'epack lock' followed by 'epack sync'.

Subcommands:
  epack install tool <name>        Install a tool from the catalog
  epack install collector <name>   Install a collector from the catalog
  epack install remote <name>      Install a remote from the catalog
  epack install utility <name>     Install a user-global utility

In non-frozen mode (default):
  1. Locks collectors/tools/remotes if lockfile is missing or stale
  2. Downloads any missing binaries for the current platform
  3. Verifies Sigstore signatures and digests

In frozen mode (--frozen):
  1. Verifies lockfile exists and matches config
  2. Verifies all binaries are installed with correct digests
  (No downloads or lockfile updates)

Use frozen mode in CI to ensure reproducible builds.

Examples:
  epack install                    # Lock if needed, download binaries
  epack install tool ask           # Install a tool from catalog
  epack install collector github   # Install a collector from catalog
  epack install remote locktivity  # Install a remote from catalog
  epack install utility viewer     # Install a user-global utility
  epack install --all-platforms    # Lock all platforms, download current
  epack install --frozen           # CI: verify only, no changes

See also:
  epack lock      Lock dependencies without downloading
  epack sync      Download from existing lockfile
  epack collect   Lock, sync, run collectors, and build pack`,
		RunE: runInstall,
	}

	cmd.Flags().StringVarP(&installConfigPath, "config", "c", "epack.yaml",
		"path to epack config file")
	cmd.Flags().BoolVar(&installFrozen, "frozen", false,
		"fail on any mismatch (CI mode)")
	cmd.Flags().BoolVar(&installAllPlatforms, "all-platforms", false,
		"lock all available platforms")
	cmd.Flags().StringVar(&installPlatforms, "platform", "",
		"platforms to lock (comma-separated, e.g., linux/amd64,darwin/arm64)")

	// Add subcommands for installing from catalog
	cmd.AddCommand(newInstallToolCommand())
	cmd.AddCommand(newInstallCollectorCommand())
	cmd.AddCommand(newInstallRemoteCommand())
	cmd.AddCommand(utilitycmd.NewInstallUtilityCommand())

	return cmd
}

func runInstall(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	out := getOutput(cmd)

	cfg, err := loadConfig(installConfigPath)
	if err != nil {
		return err
	}

	workDir, err := resolveWorkDir()
	if err != nil {
		return err
	}

	if installFrozen {
		return runInstallFrozen(ctx, cfg, workDir, out)
	}
	return runInstallAuto(ctx, cfg, workDir, out)
}

// runInstallFrozen runs in strict CI mode: no auto-lock, no downloads.
func runInstallFrozen(ctx context.Context, cfg *config.JobConfig, workDir string, out *output.Writer) error {
	out.Print("Installing dependencies (frozen mode)...\n")

	syncer := sync.NewSyncer(workDir)

	syncOpts := sync.SyncOpts{
		Secure: sync.SyncSecureOptions{
			Frozen: true,
		},
	}

	results, err := syncer.Sync(ctx, cfg, syncOpts)
	if err != nil {
		return handleComponentError(err)
	}

	for _, r := range results {
		if r.Verified {
			out.Print("  verified %s@%s\n", r.Name, r.Version)
		}
	}

	out.Print("\nAll dependencies verified\n")
	return nil
}

// runInstallAuto runs with auto-lock and auto-sync.
func runInstallAuto(ctx context.Context, cfg *config.JobConfig, workDir string, out *output.Writer) error {
	out.Print("Installing dependencies...\n")

	lockfilePath := filepath.Join(workDir, lockfile.FileName)
	platform := platform.Key(runtime.GOOS, runtime.GOARCH)

	// Check if we need to lock
	needsLock := false
	lockfileUpdated := false

	if cfg.HasSourceComponents() {
		lf, err := lockfile.Load(lockfilePath)
		if os.IsNotExist(err) {
			needsLock = true
		} else if err != nil {
			return &exitError{
				Exit:    exitcode.General,
				Message: fmt.Sprintf("loading lockfile: %v", err),
			}
		} else {
			// Check if lockfile needs updating (collectors and tools)
			needsLock = lockfileNeedsUpdate(cfg, lf, platform)
		}
	}

	if needsLock {
		out.Print("Locking dependencies...\n")
		locker := sync.NewLocker(workDir)

		// Determine platforms to lock
		platforms := parseCommaSeparated(installPlatforms)
		if installAllPlatforms {
			platforms = nil // Let locker discover all platforms
		} else if len(platforms) == 0 {
			// Use config platforms or default to current
			platforms = cfg.Platforms
			if len(platforms) == 0 {
				platforms = []string{platform}
			}
		}

		lockOpts := sync.LockOpts{
			AllPlatforms: installAllPlatforms,
			Platforms:    platforms,
		}

		results, err := locker.Lock(ctx, cfg, lockOpts)
		if err != nil {
			return handleComponentError(err)
		}

		for _, r := range results {
			status := "locked"
			if r.Updated {
				status = "updated"
			} else if r.IsNew {
				status = "added"
			}
			out.Print("  %s %s@%s (%s)\n", status, r.Name, r.Version, strings.Join(r.Platforms, ", "))
		}
		lockfileUpdated = true
	}

	// Sync (download missing binaries)
	syncer := sync.NewSyncer(workDir)
	syncOpts := sync.SyncOpts{
		Secure: sync.SyncSecureOptions{
			Frozen: false,
		},
	}

	syncResults, err := syncer.Sync(ctx, cfg, syncOpts)
	if err != nil {
		return handleComponentError(err)
	}

	for _, r := range syncResults {
		if r.Skipped {
			// External binary, skip output
		} else if r.Installed {
			out.Print("  installed %s@%s\n", r.Name, r.Version)
		} else if r.Verified {
			out.Print("  verified %s@%s\n", r.Name, r.Version)
		}
	}

	out.Print("\nAll dependencies installed\n")

	// Remind user to commit lockfile if it was updated
	if lockfileUpdated {
		out.Print("Lockfile was updated. Remember to commit %s\n", lockfile.FileName)
	}

	return nil
}
