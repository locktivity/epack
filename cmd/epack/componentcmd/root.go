//go:build components

// Package componentcmd implements shared commands for both collectors and tools.
// This includes lock, sync, install, update, init, and new commands.
package componentcmd

import (
	"github.com/spf13/cobra"
)

// NewLockCommand returns the lock command (epack lock).
// This is a top-level command that locks both collectors and tools.
func NewLockCommand() *cobra.Command {
	return newLockCommand()
}

// NewSyncCommand returns the sync command (epack sync).
// This is a top-level command that syncs both collectors and tools.
func NewSyncCommand() *cobra.Command {
	return newSyncCommand()
}

// NewInstallCommand returns the install command (epack install).
// This is a top-level command that locks (if needed) and syncs both collectors and tools.
func NewInstallCommand() *cobra.Command {
	return newInstallCommand()
}

// NewInitCommand returns the init command (epack init).
func NewInitCommand() *cobra.Command {
	return newInitCommand()
}

// NewNewCommand returns the new command (epack new).
// This creates a new project directory with scaffolded configuration.
func NewNewCommand() *cobra.Command {
	return newNewCommand()
}

// NewStatusCommand returns the status command (epack status).
// This shows the current state of the epack project.
func NewStatusCommand() *cobra.Command {
	return newStatusCommand()
}
