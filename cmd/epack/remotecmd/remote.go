//go:build components

package remotecmd

import (
	"github.com/spf13/cobra"
)

// newRemoteCommand creates the 'epack remote' command.
func newRemoteCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "remote",
		Short: "Manage remote registries",
		Long: `Commands for managing remote registries.

Remotes are external registries where evidence packs can be pushed and pulled.
Each remote is configured in epack.yaml with its adapter, target, and auth settings.

Examples:
  # List configured remotes
  epack remote list

  # Sign in to a remote from this machine
  epack remote login locktivity

  # Fetch a configuration the remote generated
  epack remote clone northwind-production

  # Show authentication status for a remote
  epack remote whoami locktivity

  # Show auth status for all remotes
  epack remote whoami`,
	}

	// Add subcommands
	cmd.AddCommand(newCloneCommand())
	cmd.AddCommand(newListCommand())
	cmd.AddCommand(newLoginCommand())
	cmd.AddCommand(newReportLockCommand())
	cmd.AddCommand(newWhoamiCommand())
	cmd.AddCommand(newUpdateCommand())

	return cmd
}
