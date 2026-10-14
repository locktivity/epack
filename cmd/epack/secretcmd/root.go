//go:build components

// Package secretcmd implements 'epack secret': the values a configuration
// lists under secrets:, kept in the operating system keychain for one
// configuration on one remote and approved for the components that read
// them.
package secretcmd

import (
	"github.com/spf13/cobra"
)

// NewCommand returns the secret command tree.
func NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "secret",
		Short: "Keep a configuration's secrets in your keychain",
		Long: `Keep the variables a configuration lists under secrets: in your keychain,
scoped to this configuration, so a run finds them in any terminal.

The environment always wins: a variable set in the shell reaches the
components that list it as it does today. A stored value is approved for the
components that read it as they are now; when a later revision changes one of
them, or adds one, the secret needs approval again before a run uses it.

Run these commands in a configuration folder, the one 'epack remote clone'
created. Runs and checks never prompt; only these commands do.

Examples:
  epack secret setup                       # walk every missing and unapproved secret
  epack secret set AZURE_CLIENT_SECRET     # paste one value, hidden
  epack secret set OKTA_PRIVATE_KEY --from-file ~/Downloads/okta.pem
  epack secret approve                     # review what changed and approve
  epack secret list
  epack secret remove AZURE_CLIENT_SECRET`,
	}
	cmd.AddCommand(newSetupCommand())
	cmd.AddCommand(newSetCommand())
	cmd.AddCommand(newApproveCommand())
	cmd.AddCommand(newListCommand())
	cmd.AddCommand(newRemoveCommand())
	return cmd
}
