//go:build components

package componentcmd

import (
	"github.com/locktivity/epack/internal/component/sync"
	"github.com/spf13/cobra"
)

var (
	updateConfigPath string
)

func newUpdateCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "update [components...]",
		Short: "Update component dependencies",
		Long: `Update specific collectors or tools to latest matching version.

If no components are specified, updates all collectors and tools.
Components are identified by name - the command will find whether
each is a collector or tool in your config.

Examples:
  epack update                    # Update all collectors and tools
  epack update github             # Update only 'github' component
  epack update github aws ask     # Update multiple components`,
		RunE: runUpdate,
	}

	cmd.Flags().StringVarP(&updateConfigPath, "config", "c", "epack.yaml",
		"path to epack config file")

	return cmd
}

// NewUpdateCommand returns the update command (epack update).
func NewUpdateCommand() *cobra.Command {
	return newUpdateCommand()
}

func runUpdate(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	out := getOutput(cmd)

	cfg, err := loadConfig(updateConfigPath)
	if err != nil {
		return err
	}

	// Filter to specified components if any
	if len(args) > 0 {
		cfg, err = filterConfigComponents(cfg, args)
		if err != nil {
			return err
		}
	}

	workDir, err := resolveWorkDirFromConfigPath(updateConfigPath)
	if err != nil {
		return err
	}

	locker := sync.NewLocker(workDir)

	opts := sync.LockOpts{
		// Update preserves existing platforms
	}

	out.Print("Updating dependencies...\n")

	results, err := locker.Lock(ctx, cfg, opts)
	if err != nil {
		return handleComponentError(err)
	}

	// Output results
	if out.IsJSON() {
		return out.JSON(map[string]interface{}{
			"updated": results,
		})
	}

	for _, r := range results {
		if r.Updated {
			out.Print("  updated %s@%s\n", r.Name, r.Version)
		} else {
			out.Print("  unchanged %s@%s\n", r.Name, r.Version)
		}
	}

	out.Print("\nLockfile updated\n")

	return nil
}
