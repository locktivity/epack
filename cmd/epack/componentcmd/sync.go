//go:build components

package componentcmd

import (
	"fmt"
	"os"

	"github.com/locktivity/epack/internal/component/sync"
	"github.com/locktivity/epack/internal/exitcode"
	"github.com/locktivity/epack/internal/securityaudit"
	"github.com/locktivity/epack/internal/securitypolicy"
	"github.com/spf13/cobra"
)

var (
	syncConfigPath         string
	syncFrozen             bool
	syncInsecureSkipVerify bool
)

func newSyncCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sync",
		Short: "Install collectors and tools from lockfile",
		Long: `Download and install collectors and tools according to lockfile.

This command reads epack.lock.yaml and installs any missing collectors
and tools for the current platform. It verifies Sigstore signatures and
binary digests before installation.

Installed binaries are placed in:
  .epack/collectors/<name>/<version>/<os>-<arch>/<binary>
  .epack/tools/<name>/<version>/<os>-<arch>/<binary>

Modes:
  Default: Install missing binaries, verify existing ones
  --frozen: CI mode - fail on any mismatch, missing platform, or drift

Examples:
  epack sync             # Install/verify collectors and tools
  epack sync --frozen    # CI mode: strict verification

See also:
  epack install   Lock if needed and download binaries (recommended)
  epack lock      Lock dependencies without downloading`,
		RunE: runSync,
	}

	cmd.Flags().StringVarP(&syncConfigPath, "config", "c", "epack.yaml",
		"path to epack config file")
	cmd.Flags().BoolVar(&syncFrozen, "frozen", false,
		"fail on any mismatch or missing platform (CI mode)")
	cmd.Flags().BoolVar(&syncInsecureSkipVerify, "insecure-skip-verify", false,
		"skip signature and digest verification (NOT for CI use)")

	return cmd
}

func runSync(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	out := getOutput(cmd)

	if err := validateSyncFlags(); err != nil {
		return err
	}

	// Warn about insecure mode
	if syncInsecureSkipVerify {
		fmt.Fprintln(os.Stderr, "WARNING: Running with --insecure-skip-verify. Signature and digest checks disabled.")
	}

	cfg, err := loadConfig(syncConfigPath)
	if err != nil {
		return err
	}

	workDir, err := resolveWorkDir()
	if err != nil {
		return err
	}

	syncer := sync.NewSyncer(workDir)

	opts := sync.SyncOpts{
		Secure: sync.SyncSecureOptions{
			Frozen: syncFrozen,
		},
		Unsafe: sync.SyncUnsafeOverrides{
			SkipVerify: syncInsecureSkipVerify,
		},
	}

	if syncFrozen {
		out.Print("Syncing dependencies (frozen mode)...\n")
	} else {
		out.Print("Syncing dependencies...\n")
	}

	results, err := syncer.Sync(ctx, cfg, opts)
	if err != nil {
		return handleComponentError(err)
	}

	// Output results
	if out.IsJSON() {
		return out.JSON(map[string]interface{}{
			"synced": results,
		})
	}

	for _, r := range results {
		if r.Skipped {
			out.Print("  external %s\n", r.Name)
		} else if r.Installed {
			out.Print("  installed %s@%s\n", r.Name, r.Version)
		} else if r.Verified {
			out.Print("  verified %s@%s\n", r.Name, r.Version)
		}
	}

	out.Print("\nAll dependencies synced successfully\n")

	return nil
}

func validateSyncFlags() error {
	if syncFrozen && syncInsecureSkipVerify {
		return &exitError{
			Exit:    exitcode.General,
			Message: "cannot combine --frozen with --insecure-skip-verify",
		}
	}
	if err := securitypolicy.EnforceStrictProduction("component_sync_cli", syncInsecureSkipVerify); err != nil {
		return err
	}
	if syncInsecureSkipVerify {
		securityaudit.Emit(securityaudit.Event{
			Type:        securityaudit.EventInsecureBypass,
			Component:   "component_sync",
			Name:        "sync",
			Description: "component sync command running with insecure skip-verify override",
			Attrs: map[string]string{
				"insecure_skip_verify": "true",
			},
		})
	}
	return nil
}
