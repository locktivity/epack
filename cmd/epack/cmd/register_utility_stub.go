//go:build !components

package cmd

import "github.com/spf13/cobra"

// registerUtilityCommands adds a stub utility command that explains
// the minimal build doesn't include component support.
func registerUtilityCommands(root *cobra.Command) {
	// In minimal builds, utility commands are not available.
	// Users need to build with -tags components to get utility support.
}
