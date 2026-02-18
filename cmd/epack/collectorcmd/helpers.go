//go:build components

package collectorcmd

import (
	"github.com/locktivity/epack/internal/cli/output"
	"github.com/locktivity/epack/internal/cmdutil"
	"github.com/locktivity/epack/internal/component/config"
	"github.com/spf13/cobra"
)

// Re-export types and functions from cmdutil for internal use.
// These are unexported to keep the package API clean.

func getOutput(cmd *cobra.Command) *output.Writer {
	return cmdutil.GetOutput(cmd)
}

func loadConfig(path string) (*config.JobConfig, error) {
	return cmdutil.LoadConfig(path)
}

func resolveWorkDir() (string, error) {
	return cmdutil.ResolveWorkDir()
}

func parseCommaSeparated(s string) []string {
	return cmdutil.ParseCommaSeparated(s)
}

func handleCollectorError(err error) error {
	return cmdutil.HandleError(err)
}

func validateCollectorNames(cfg *config.JobConfig, names []string) error {
	return cmdutil.ValidateCollectorNames(cfg, names)
}

func filterConfigCollectors(cfg *config.JobConfig, names []string) (*config.JobConfig, error) {
	return cmdutil.FilterConfigCollectors(cfg, names)
}
