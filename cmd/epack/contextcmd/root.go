//go:build components

package contextcmd

import "github.com/spf13/cobra"

// NewCommand returns the context command tree.
func NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "context",
		Short: "Emit runtime build context metadata",
	}
	cmd.AddCommand(newBuildCommand())
	return cmd
}
