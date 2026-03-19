//go:build components

package componentcmd

import (
	"github.com/locktivity/epack/errors"
	"github.com/locktivity/epack/internal/cli/output"
	"github.com/locktivity/epack/internal/cmdutil"
	"github.com/locktivity/epack/internal/component/config"
	"github.com/locktivity/epack/internal/component/lockfile"
	"github.com/spf13/cobra"
)

// Re-export types and functions from cmdutil for internal use.
// These are unexported to keep the package API clean.

type exitError = errors.Error

func getOutput(cmd *cobra.Command) *output.Writer {
	return cmdutil.GetOutput(cmd)
}

func loadConfig(path string) (*config.JobConfig, error) {
	return cmdutil.LoadConfig(path)
}

func resolveWorkDirFromConfigPath(configPath string) (string, error) {
	return cmdutil.ResolveWorkDirFromConfigPath(configPath)
}

func parseCommaSeparated(s string) []string {
	return cmdutil.ParseCommaSeparated(s)
}

func handleComponentError(err error) error {
	return cmdutil.HandleError(err)
}

func filterConfigComponents(cfg *config.JobConfig, names []string) (*config.JobConfig, error) {
	return cmdutil.FilterConfigComponents(cfg, names)
}

func lockfileNeedsUpdate(cfg *config.JobConfig, lf *lockfile.LockFile, currentPlatform, workDir string) bool {
	return cmdutil.LockfileNeedsUpdate(cfg, lf, currentPlatform, workDir)
}
