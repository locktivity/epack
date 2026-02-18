//go:build components

// Package toolcmd implements the tool subcommand group for epack.
// This package is only included when built with -tags components.
package toolcmd

import (
	"fmt"

	"github.com/locktivity/epack/internal/tool"
	"github.com/spf13/cobra"
)

// NewCommand returns the tool command tree with all subcommands.
func NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "tool",
		Short: "Run tools on evidence packs",
		Long: `Run tools that operate on signed evidence packs.

Tools are standalone binaries that operate on packs and produce derived outputs.
Unlike collectors (which gather evidence), tools process existing pack contents.

INVOCATION STYLES

Configured tools (in epack.yaml) are promoted to top-level commands:

  epack ask --pack vendor.pack "What controls exist?"
  epack policy --pack vendor.pack

For tools not in epack.yaml, use the explicit dispatch syntax:

  epack tool <name> --pack <pack> [tool-flags]

WRAPPER FLAGS

These flags control the wrapper behavior and must appear before tool arguments:

  --pack, -p <path>        Specify pack path
  --output-dir, -o <path>  Override output location
  --json                   Enable JSON output mode
  --quiet, -q              Suppress progress output

Wrapper flags can also be set via environment variables:

  EPACK_PACK         Path to evidence pack
  EPACK_OUTPUT_DIR   Override output directory
  EPACK_JSON=true    Enable JSON output mode
  EPACK_QUIET=true   Suppress progress output

CLI flags take precedence over environment variables.

OUTPUT LOCATION

Tool outputs are written to:
  <pack>.epack/tools/<name>/<run-id>/   (when --pack is specified)
  ~/.local/state/epack/tools/<name>/    (without pack, on Linux)

EXAMPLES

  # List available tools
  epack tool list

  # Run a configured tool (top-level)
  epack ask --pack vendor.pack "What controls exist?"

  # Run with environment variables
  EPACK_PACK=vendor.pack epack ask "What controls exist?"

  # Run a tool not in epack.yaml (explicit dispatch)
  epack tool custom --pack vendor.pack

  # Get tool capabilities
  epack tool info ask`,
		// Handle dynamic tool dispatch when the first arg isn't a known subcommand
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return cmd.Help()
			}

			// First arg is the tool name, rest are passed through
			toolName := args[0]
			toolArgs := args[1:]

			return dispatchTool(cmd, toolName, toolArgs)
		},
		// Don't validate args - we handle unknown subcommands as tool names
		Args:               cobra.ArbitraryArgs,
		DisableFlagParsing: true,
	}

	// Add subcommands - these will be checked before RunE is called
	cmd.AddCommand(newListCommand())
	cmd.AddCommand(newInfoCommand())
	cmd.AddCommand(newSourceCommand())
	cmd.AddCommand(newVerifyCommand())
	cmd.AddCommand(newCatalogCommand())

	return cmd
}

// NewRunCommand creates a standalone command for running a specific tool.
// This is registered directly under the root command for configured tools,
// enabling ergonomic invocation like 'epack ask' instead of 'epack tool ask'.
func NewRunCommand(toolName, description string) *cobra.Command {
	return &cobra.Command{
		Use:   toolName + " [--pack <path>] [--output-dir <path>] [--json] [--quiet] [tool-args...]",
		Short: description,
		Long: fmt.Sprintf(`Run the %s tool on an evidence pack.

Wrapper flags:
  --pack, -p <path>        Specify pack path (or set EPACK_PACK)
  --output-dir, -o <path>  Override output location (or set EPACK_OUTPUT_DIR)
  --json                   Enable JSON output mode (or set EPACK_JSON=true)
  --quiet, -q              Suppress progress output (or set EPACK_QUIET=true)

All other arguments are passed to the tool.

Examples:
  epack %s --pack vendor.pack
  EPACK_PACK=vendor.pack epack %s
  epack %s -p vendor.pack --json`, toolName, toolName, toolName, toolName),
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return dispatchTool(cmd, toolName, args)
		},
	}
}

// GetConfiguredToolNames returns the names of tools configured in epack.yaml.
// This is used by cmd/epack/cmd to register configured tools as top-level commands.
// Returns nil if no epack.yaml is found or if there's an error loading it.
func GetConfiguredToolNames() []string {
	// Delegate to internal/tool service layer
	return tool.GetConfiguredToolNames("")
}
