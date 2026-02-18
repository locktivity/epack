//go:build components

package componentcmd

import (
	"strings"

	"github.com/locktivity/epack/internal/component/lockfile"
	"github.com/locktivity/epack/internal/component/sync"
	"github.com/spf13/cobra"
)

var (
	lockConfigPath   string
	lockAllPlatforms bool
	lockPlatforms    string
)

func newLockCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "lock",
		Short: "Lock collector and tool dependencies",
		Long: `Resolve collector and tool sources, verify signatures, and write lockfile.

This command fetches releases from GitHub, verifies Sigstore signatures,
and writes version + digest information to epack.lock.yaml.

The lockfile captures:
  - Resolved version (e.g., v1.2.3 from ^1.2)
  - Signer identity (OIDC issuer, repository URI, ref)
  - Platform-specific binary digests

Platforms:
  By default, only the current platform is locked. Use --all-platforms
  to lock all available platforms, or --platform to specify platforms.

Examples:
  epack lock                          # Lock current platform
  epack lock --all-platforms          # Lock all platforms
  epack lock --platform linux/amd64   # Lock specific platform
  epack lock --platform linux/amd64,darwin/arm64

See also:
  epack install   Lock if needed and download binaries (recommended)
  epack sync      Download binaries from existing lockfile`,
		RunE: runLock,
	}

	cmd.Flags().StringVarP(&lockConfigPath, "config", "c", "epack.yaml",
		"path to epack config file")
	cmd.Flags().BoolVar(&lockAllPlatforms, "all-platforms", false,
		"lock all available platforms (replaces existing)")
	cmd.Flags().StringVar(&lockPlatforms, "platform", "",
		"platforms to lock (comma-separated, e.g., linux/amd64,darwin/arm64)")

	return cmd
}

func runLock(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	out := getOutput(cmd)

	cfg, err := loadConfig(lockConfigPath)
	if err != nil {
		return err
	}

	platforms := parseCommaSeparated(lockPlatforms)

	workDir, err := resolveWorkDir()
	if err != nil {
		return err
	}

	locker := sync.NewLocker(workDir)

	opts := sync.LockOpts{
		AllPlatforms: lockAllPlatforms,
		Platforms:    platforms,
	}

	out.Print("Locking dependencies...\n")

	results, err := locker.Lock(ctx, cfg, opts)
	if err != nil {
		return handleComponentError(err)
	}

	// Output results
	if out.IsJSON() {
		return out.JSON(map[string]interface{}{
			"locked": results,
		})
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

	out.Print("\nLockfile written to %s\n", lockfile.FileName)

	return nil
}
