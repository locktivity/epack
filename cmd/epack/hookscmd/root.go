//go:build components

package hookscmd

import "github.com/spf13/cobra"

// NewCommand returns the hooks command tree.
func NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "hooks",
		Short: "Run portable project hooks",
		Long: `Run portable project hooks from .epack/hooks.

Hooks are executed via sh so generated runners can call the same command
across Unix shells, Git Bash, and WSL without relying on executable bits.`,
	}
	cmd.AddCommand(newRunCommand())
	return cmd
}
