//go:build components

package hookscmd

import (
	"fmt"
	"os"
	"path"

	"github.com/locktivity/epack/internal/hooks"
	"github.com/locktivity/epack/internal/project"
	"github.com/locktivity/epack/internal/remoteconfig"
	"github.com/spf13/cobra"
)

func newRunCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "run <hook>",
		Short: "Run a portable hook from .epack/hooks",
		Long: `Run a portable hook from .epack/hooks.

In a folder fetched from a remote, a hook that still matches the template the
remote delivered is the remote's script and is not run. Edit it to make it
yours.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if root, err := project.FindRoot(""); err == nil {
				template, err := remoteconfig.IsRemoteTemplate(root, path.Join(".epack", "hooks", args[0]+".sh"))
				if err != nil {
					return err
				}
				if template {
					_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "%s.sh is the remote's template and was not run; edit it to add your own steps\n", args[0])
					return nil
				}
			}
			return hooks.Runner{
				Stdout: os.Stdout,
				Stderr: os.Stderr,
			}.Run(cmd.Context(), args[0])
		},
	}
}
