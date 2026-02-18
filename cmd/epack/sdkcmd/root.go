//go:build components

// Package sdkcmd implements the sdk subcommand group for epack.
// This package provides tools for component SDK authors.
package sdkcmd

import (
	"github.com/spf13/cobra"
)

// NewCommand returns the sdk command tree with all subcommands.
func NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sdk",
		Short: "Component SDK development tools",
		Long: `Tools for building components with the epack Component SDK.

The Component SDK allows you to create tools, collectors, remotes, and utilities
that extend epack's functionality.

SCAFFOLDING

Create a new component project with all the boilerplate:

  epack sdk new tool my-analyzer
  epack sdk new collector github-posture
  epack sdk new utility pack-viewer

DEVELOPMENT

Run your component locally without installation:

  epack sdk run ./my-component args...
  epack sdk run --watch .              # Auto-rebuild on changes

TESTING

Run conformance tests to verify your component:

  epack sdk test ./my-component
  epack sdk test .                     # Build and test

MOCK DATA

Generate sample inputs for testing:

  epack sdk mock tool                  # Sample evidence pack
  epack sdk mock collector             # Sample config and env`,
	}

	cmd.AddCommand(newNewCommand())
	cmd.AddCommand(newRunCommand())
	cmd.AddCommand(newTestCommand())
	cmd.AddCommand(newMockCommand())

	return cmd
}
