//go:build components

package cmd

import (
	"github.com/locktivity/epack/cmd/epack/utilitycmd"
	"github.com/spf13/cobra"
)

// registerUtilityCommands adds the utility command tree to the root command.
func registerUtilityCommands(root *cobra.Command) {
	root.AddCommand(utilitycmd.NewCommand())
}
