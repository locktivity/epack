//go:build components

// Package utilitycmd implements the utility subcommand group for epack.
// This package is only included when built with -tags components.
package utilitycmd

import (
	"github.com/locktivity/epack/internal/componenttypes"
	"github.com/spf13/cobra"
)

var insecureAllowUnpinned bool

// NewCommand returns the utility command tree with all subcommands.
func NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "utility",
		Aliases: []string{"util"},
		Short:   "Manage and run user-installed utilities",
		Long: `Manage and run globally installed epack utilities.

Utilities are standalone helper applications that complement the epack ecosystem.
Unlike collectors and tools (which are project-specific), utilities are installed
globally for the current user and stored in ~/.epack/.

RUNNING UTILITIES

Run an installed utility by name:

  epack utility viewer pack.epack
  epack utility exporter evidence.epack --format xlsx

The utility binary is verified against its lockfile digest before execution
to ensure it hasn't been tampered with (TOCTOU-safe).

INSTALLATION

Utilities are installed from the catalog with Sigstore verification:

  epack utility install viewer

The binary is installed to ~/.epack/bin/ and tracked in ~/.epack/utilities.lock.

EXAMPLES

  # Install a utility from catalog
  epack utility install viewer

  # Install a specific version
  epack utility install viewer@v1.0.0

  # List installed utilities
  epack utility list

  # Run an installed utility
  epack utility viewer pack.epack

  # Remove a utility
  epack utility remove viewer`,
		// Enable passing unknown commands through to dispatch
		DisableFlagParsing: false,
		// Handle unknown subcommands as utility dispatch
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return cmd.Help()
			}
			// First arg is utility name, rest are args to pass through
			return dispatchUtility(cmd, args[0], args[1:], insecureAllowUnpinned)
		},
	}

	// Support env var for insecure-allow-unpinned
	insecureAllowUnpinned = componenttypes.InsecureAllowUnpinnedFromEnv()
	cmd.Flags().BoolVar(&insecureAllowUnpinned, "insecure-allow-unpinned", insecureAllowUnpinned,
		"skip digest verification for installed utilities (NOT RECOMMENDED)")

	cmd.AddCommand(newInstallCommand())
	cmd.AddCommand(newListCommand())
	cmd.AddCommand(newRemoveCommand())

	return cmd
}
