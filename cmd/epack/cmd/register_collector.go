//go:build components

package cmd

import (
	"github.com/locktivity/epack/cmd/epack/collectorcmd"
	"github.com/locktivity/epack/cmd/epack/componentcmd"
	"github.com/locktivity/epack/cmd/epack/remotecmd"
	"github.com/locktivity/epack/cmd/epack/sdkcmd"
	"github.com/spf13/cobra"
)

// ComponentsEnabled indicates whether collector and tool commands are available.
const ComponentsEnabled = true

// registerCollectorCommands adds the collector command tree to the root command.
func registerCollectorCommands(root *cobra.Command) {
	// Add 'epack collector' subcommand group (run only - update moved to top-level)
	root.AddCommand(collectorcmd.NewCommand())

	// Add 'epack collect' as a top-level shortcut (auto-lock, sync, run)
	root.AddCommand(collectorcmd.NewCollectCommand())

	// Add 'epack new' for creating new projects
	root.AddCommand(componentcmd.NewNewCommand())

	// Add 'epack init' for initializing existing directories
	root.AddCommand(componentcmd.NewInitCommand())

	// Add 'epack lock', 'epack sync', 'epack install', and 'epack update' as top-level commands
	// These handle both collectors and tools
	root.AddCommand(componentcmd.NewLockCommand())
	root.AddCommand(componentcmd.NewSyncCommand())
	root.AddCommand(componentcmd.NewInstallCommand())
	root.AddCommand(componentcmd.NewUpdateCommand())

	// Add 'epack status' for project status
	root.AddCommand(componentcmd.NewStatusCommand())

	// Add 'epack sdk' for component SDK development tools
	root.AddCommand(sdkcmd.NewCommand())

	// Add 'epack pull' and 'epack push' for remote registry operations
	root.AddCommand(remotecmd.NewPullCommand())
	root.AddCommand(remotecmd.NewPushCommand())
}
