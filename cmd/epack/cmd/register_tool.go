//go:build components

package cmd

import (
	"github.com/locktivity/epack/cmd/epack/toolcmd"
	"github.com/spf13/cobra"
)

// registerToolCommands adds the tool command tree to the root command.
// It also discovers configured tools and registers them as top-level commands.
func registerToolCommands(root *cobra.Command) {
	// Add 'epack tool' subcommand group (list, dispatch)
	root.AddCommand(toolcmd.NewCommand())

	// Discover and register configured tools as top-level commands
	registerConfiguredTools(root)
}

// registerConfiguredTools discovers tools from epack.yaml and registers them
// as top-level commands for ergonomic access (e.g., 'epack ask' instead of 'epack tool ask').
//
// This follows the pattern used by kubectl (plugins as top-level commands),
// git (aliases), and gh (extensions). The goal is to make common tools feel
// like first-class citizens while still supporting 'epack tool <name>' as fallback.
//
// Tool discovery is best-effort: if epack.yaml doesn't exist or has errors,
// tools are simply not registered. Users can always use 'epack tool <name>'.
func registerConfiguredTools(root *cobra.Command) {
	// Get configured tool names from toolcmd package
	// This keeps the internal/component import in toolcmd, respecting the boundary
	toolNames := toolcmd.GetConfiguredToolNames()

	// Register each configured tool as a top-level command
	for _, name := range toolNames {
		// Skip if command already exists (built-in commands take precedence)
		if commandExists(root, name) {
			continue
		}

		// Create top-level command that dispatches to the tool
		toolCmd := toolcmd.NewRunCommand(name, "Run the "+name+" tool")
		root.AddCommand(toolCmd)
	}
}

// commandExists checks if a command with the given name already exists.
func commandExists(root *cobra.Command, name string) bool {
	for _, cmd := range root.Commands() {
		if cmd.Name() == name {
			return true
		}
	}
	return false
}
