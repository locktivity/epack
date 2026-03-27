//go:build components

package hookscmd

import (
	"os"

	"github.com/locktivity/epack/internal/hooks"
	"github.com/spf13/cobra"
)

func newRunCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "run <hook>",
		Short: "Run a portable hook from .epack/hooks",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return hooks.Runner{
				Stdout: os.Stdout,
				Stderr: os.Stderr,
			}.Run(cmd.Context(), args[0])
		},
	}
}
