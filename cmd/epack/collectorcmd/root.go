//go:build components

// Package collectorcmd implements the collector subcommand group for epack.
// This package is only included when built with -tags components.
//
// Collector-specific commands:
//   - epack collector run       Run collectors and build pack
//   - epack collect             Auto-lock, sync, run, build pack
//
// Shared component commands (lock, sync, install, update, init, new) are in componentcmd.
package collectorcmd

import (
	"github.com/spf13/cobra"
)

// NewCommand returns the collector command tree with all subcommands.
func NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "collector",
		Short: "Manage evidence collectors",
		Long: `Manage evidence collectors and run evidence collection.

The collector command group is for running collectors and managing
collector-specific operations.

Quick Start:
  For most use cases, use 'epack collect' which handles everything:
    epack collect                 # Auto-lock, sync, run, build pack

Commands:
  epack collector run            # Run collectors and build pack

For dependency management, use top-level commands:
  epack lock                     # Lock collectors and tools
  epack sync                     # Install from lockfile
  epack update                   # Update to latest versions`,
	}

	// Add subcommands - only run is collector-specific now
	cmd.AddCommand(newRunCommand())

	return cmd
}

// NewCollectCommand returns the top-level collect command (epack collect).
// This is separate from the collector subcommand group.
func NewCollectCommand() *cobra.Command {
	return newCollectCommand()
}
