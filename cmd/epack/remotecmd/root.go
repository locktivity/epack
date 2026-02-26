//go:build components

// Package remotecmd implements remote registry commands for epack.
// This package is only included when built with -tags components.
//
// Remote commands:
//   - epack pull         Pull a pack from a remote registry
//   - epack push         Push a pack to a remote registry
//   - epack remote list  List configured remotes
//   - epack remote whoami Show authentication status
package remotecmd

import (
	"github.com/spf13/cobra"
)

// NewPullCommand returns the pull command (epack pull).
func NewPullCommand() *cobra.Command {
	return newPullCommand()
}

// NewPushCommand returns the push command (epack push).
func NewPushCommand() *cobra.Command {
	return newPushCommand()
}

// NewRemoteCommand returns the remote command (epack remote).
func NewRemoteCommand() *cobra.Command {
	return newRemoteCommand()
}
