//go:build components

package utilitycmd

import (
	"fmt"

	"github.com/locktivity/epack/internal/userconfig"
	"github.com/spf13/cobra"
)

func newRemoveCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "remove <name>",
		Aliases: []string{"rm", "uninstall"},
		Short:   "Remove an installed utility",
		Long: `Remove a utility from ~/.epack/bin/.

The utility binary and its lockfile entry are removed.

EXAMPLES

  # Remove a utility
  epack utility remove viewer`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]

			syncer := userconfig.NewUtilitySyncer()
			if err := syncer.Remove(name); err != nil {
				return fmt.Errorf("removing utility: %w", err)
			}

			fmt.Printf("Removed %s\n", name)
			return nil
		},
	}

	return cmd
}
