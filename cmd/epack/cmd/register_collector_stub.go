//go:build !components

package cmd

import (
	"fmt"

	"github.com/locktivity/epack/errors"
	"github.com/locktivity/epack/internal/exitcode"
	"github.com/spf13/cobra"
)

// ComponentsEnabled indicates whether collector and tool commands are available.
const ComponentsEnabled = false

// registerCollectorCommands adds stub commands that explain
// how to get the full version with collector support.
func registerCollectorCommands(root *cobra.Command) {
	stubRunE := func(cmd *cobra.Command, args []string) error {
		_, _ = fmt.Fprintln(cmd.ErrOrStderr(), "Error: this command is not available in epack-core.")
		_, _ = fmt.Fprintln(cmd.ErrOrStderr())
		_, _ = fmt.Fprintln(cmd.ErrOrStderr(), "For collector and tool support, install 'epack' (full version).")
		_, _ = fmt.Fprintln(cmd.ErrOrStderr(), "See: https://github.com/locktivity/epack#installation")
		return &errors.Error{Code: errors.InvalidInput, Exit: exitcode.General, Message: "command not available in epack-core"}
	}

	root.AddCommand(&cobra.Command{
		Use:   "collector",
		Short: "Manage evidence collectors (not available in this build)",
		Long: `Collector commands are not available in epack-core.

The collector feature allows you to orchestrate evidence-gathering binaries
with cryptographic (Sigstore) verification.

For collector support, install 'epack' (full version).
See: https://github.com/locktivity/epack#installation`,
		RunE: stubRunE,
	})

	root.AddCommand(&cobra.Command{
		Use:   "lock",
		Short: "Lock collector and tool dependencies (not available in this build)",
		Long: `Lock command is not available in epack-core.

For dependency management, install 'epack' (full version).
See: https://github.com/locktivity/epack#installation`,
		RunE: stubRunE,
	})

	root.AddCommand(&cobra.Command{
		Use:   "sync",
		Short: "Install collectors and tools from lockfile (not available in this build)",
		Long: `Sync command is not available in epack-core.

For dependency management, install 'epack' (full version).
See: https://github.com/locktivity/epack#installation`,
		RunE: stubRunE,
	})
}
