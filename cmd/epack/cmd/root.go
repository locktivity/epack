// Package cmd implements the epack CLI commands.
package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/locktivity/epack/errors"
	"github.com/locktivity/epack/internal/cli/output"
	"github.com/locktivity/epack/internal/exitcode"
	"github.com/locktivity/epack/internal/redact"
	"github.com/spf13/cobra"
)

var (
	// Global flags
	quiet    bool
	jsonOut  bool
	noColor  bool
	verbose  bool
	noRedact bool // SECURITY: Redaction is ON by default; this flag disables it
	ciMode   bool // CI mode: disable spinners, add timestamps

	// Output writer for consistent formatting
	out *output.Writer
)

// ExitSuccess indicates successful command execution.
const ExitSuccess = 0

// ExitFailure indicates general command failure.
const ExitFailure = 1

// ExitMalformedPack indicates the pack cannot be opened or parsed.
const ExitMalformedPack = 2

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "epack",
	Short: "Create, sign, and verify evidence packs",
	Long: `epack is a CLI for working with evidence packs.

Evidence packs bundle artifacts with cryptographic attestations for
compliance, audit, and supply chain security use cases.

Examples:
  # Build a pack from JSON artifacts
  epack build evidence.pack ./reports/*.json --stream myorg/prod

  # Sign with keyless (opens browser for authentication)
  epack sign evidence.pack

  # Verify pack integrity and attestations
  epack verify evidence.pack

  # Inspect pack contents
  epack inspect evidence.pack`,
	SilenceUsage:  true,
	SilenceErrors: true,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		// SECURITY: Redaction is enabled by default for safety.
		// It can be disabled via --no-redact or EPACK_NO_REDACT env var.
		// This prevents accidental secret leakage in error messages.
		if !noRedact && os.Getenv("EPACK_NO_REDACT") == "" {
			redact.Enable()
		}

		// Initialize output writer with current settings
		// CI mode is auto-detected from common CI environment variables
		isCI := ciMode || os.Getenv("CI") != "" || os.Getenv("GITHUB_ACTIONS") != ""
		out = output.New(os.Stdout, os.Stderr, output.Options{
			Quiet:   quiet,
			JSON:    jsonOut,
			NoColor: noColor || os.Getenv("NO_COLOR") != "" || isCI,
			Verbose: verbose,
			CI:      isCI,
		})
		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
		// When epack is run with no subcommand, show a helpful quickstart
		printQuickstart(cmd)
	},
}

// printQuickstart shows a helpful getting started message
func printQuickstart(cmd *cobra.Command) {
	w := outputWriter()
	p := w.Palette()

	_, _ = fmt.Fprintln(cmd.OutOrStdout(), p.Bold("epack")+" - Evidence Pack Builder")
	_, _ = fmt.Fprintln(cmd.OutOrStdout())
	_, _ = fmt.Fprintln(cmd.OutOrStdout(), p.Bold("Quick Start:"))
	_, _ = fmt.Fprintln(cmd.OutOrStdout())
	_, _ = fmt.Fprintln(cmd.OutOrStdout(), p.Dim("  # Create a new project"))
	_, _ = fmt.Fprintln(cmd.OutOrStdout(), "  epack new my-pipeline")
	_, _ = fmt.Fprintln(cmd.OutOrStdout())
	_, _ = fmt.Fprintln(cmd.OutOrStdout(), p.Dim("  # Or initialize in existing directory"))
	_, _ = fmt.Fprintln(cmd.OutOrStdout(), "  epack init")
	_, _ = fmt.Fprintln(cmd.OutOrStdout())
	_, _ = fmt.Fprintln(cmd.OutOrStdout(), p.Dim("  # Run collectors and build a pack"))
	_, _ = fmt.Fprintln(cmd.OutOrStdout(), "  epack collect")
	_, _ = fmt.Fprintln(cmd.OutOrStdout())
	_, _ = fmt.Fprintln(cmd.OutOrStdout(), p.Dim("  # Sign the pack (opens browser for authentication)"))
	_, _ = fmt.Fprintln(cmd.OutOrStdout(), "  epack sign evidence.pack")
	_, _ = fmt.Fprintln(cmd.OutOrStdout())
	_, _ = fmt.Fprintln(cmd.OutOrStdout(), p.Dim("  # Verify pack integrity and attestations"))
	_, _ = fmt.Fprintln(cmd.OutOrStdout(), "  epack verify evidence.pack")
	_, _ = fmt.Fprintln(cmd.OutOrStdout())
	_, _ = fmt.Fprintln(cmd.OutOrStdout(), p.Dim("  # Push pack to a remote registry"))
	_, _ = fmt.Fprintln(cmd.OutOrStdout(), "  epack push locktivity evidence.pack")
	_, _ = fmt.Fprintln(cmd.OutOrStdout())
	_, _ = fmt.Fprintln(cmd.OutOrStdout(), p.Dim("  # Pull pack from a remote registry"))
	_, _ = fmt.Fprintln(cmd.OutOrStdout(), "  epack pull locktivity")
	_, _ = fmt.Fprintln(cmd.OutOrStdout())
	_, _ = fmt.Fprintln(cmd.OutOrStdout(), p.Bold("Commands:"))
	_, _ = fmt.Fprintln(cmd.OutOrStdout(), "  new        Create a new evidence pack project")
	_, _ = fmt.Fprintln(cmd.OutOrStdout(), "  init       Initialize epack in current directory")
	_, _ = fmt.Fprintln(cmd.OutOrStdout(), "  collect    Run collectors and build evidence pack")
	_, _ = fmt.Fprintln(cmd.OutOrStdout(), "  install    Lock and sync dependencies")
	_, _ = fmt.Fprintln(cmd.OutOrStdout(), "  lock       Lock collector and tool dependencies")
	_, _ = fmt.Fprintln(cmd.OutOrStdout(), "  sync       Install collectors and tools from lockfile")
	_, _ = fmt.Fprintln(cmd.OutOrStdout(), "  build      Build an evidence pack from artifacts")
	_, _ = fmt.Fprintln(cmd.OutOrStdout(), "  sign       Sign an evidence pack")
	_, _ = fmt.Fprintln(cmd.OutOrStdout(), "  verify     Verify pack integrity and attestations")
	_, _ = fmt.Fprintln(cmd.OutOrStdout(), "  inspect    Show pack contents and metadata")
	_, _ = fmt.Fprintln(cmd.OutOrStdout(), "  list       List pack artifacts, attestations, or sources")
	_, _ = fmt.Fprintln(cmd.OutOrStdout(), "  extract    Extract artifacts from a pack")
	_, _ = fmt.Fprintln(cmd.OutOrStdout(), "  merge      Merge multiple packs into one")
	_, _ = fmt.Fprintln(cmd.OutOrStdout(), "  diff       Compare two packs")
	_, _ = fmt.Fprintln(cmd.OutOrStdout(), "  push       Push pack to a remote registry")
	_, _ = fmt.Fprintln(cmd.OutOrStdout(), "  pull       Pull pack from a remote registry")
	_, _ = fmt.Fprintln(cmd.OutOrStdout(), "  status     Show project status")
	_, _ = fmt.Fprintln(cmd.OutOrStdout(), "  jobs       List background jobs")
	_, _ = fmt.Fprintln(cmd.OutOrStdout(), "  collector  Run collectors")
	_, _ = fmt.Fprintln(cmd.OutOrStdout(), "  tool       Run tools on evidence packs")
	_, _ = fmt.Fprintln(cmd.OutOrStdout())
	_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Run "+p.Cyan("epack <command> --help")+" for detailed usage.")
}

// Execute runs the root command.
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	// Global flags available to all commands
	rootCmd.PersistentFlags().BoolVarP(&quiet, "quiet", "q", false, "suppress non-essential output")
	rootCmd.PersistentFlags().BoolVar(&jsonOut, "json", false, "output in JSON format")
	rootCmd.PersistentFlags().BoolVar(&noColor, "no-color", false, "disable colored output")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "verbose output")
	rootCmd.PersistentFlags().BoolVar(&noRedact, "no-redact", false,
		"disable redaction of secrets in errors/logs (env: EPACK_NO_REDACT)")
	rootCmd.PersistentFlags().BoolVar(&ciMode, "ci", false,
		"CI mode: disable spinners, add timestamps (auto-detected from CI/GITHUB_ACTIONS env)")

	// Register collector commands (full build) or stub (minimal build).
	// This is controlled by build tags - see register_collector.go and register_collector_stub.go.
	registerCollectorCommands(rootCmd)

	// Register tool commands (full build) or stub (minimal build).
	// This is controlled by build tags - see register_tool.go and register_tool_stub.go.
	registerToolCommands(rootCmd)

	// Register utility commands (full build) or stub (minimal build).
	// This is controlled by build tags - see register_utility.go and register_utility_stub.go.
	registerUtilityCommands(rootCmd)
}

// outputWriter returns the current output writer, initializing if needed.
func outputWriter() *output.Writer {
	if out == nil {
		out = output.New(os.Stdout, os.Stderr, output.Options{})
	}
	return out
}

// cmdContext returns the context from a cobra.Command, or context.Background() if cmd is nil.
// This allows run functions to be called directly in tests without full Cobra setup.
func cmdContext(cmd *cobra.Command) context.Context {
	if cmd == nil {
		return context.Background()
	}
	return cmd.Context()
}

// exitError returns an Error with the general error code.
// The error message is redacted and will be printed by main.go (single rendering boundary).
func exitError(format string, args ...interface{}) error {
	msg := fmt.Sprintf(format, args...)
	msg = redact.Error(msg)
	return &errors.Error{Code: errors.InvalidInput, Exit: exitcode.General, Message: msg}
}

// exitErrorWithCode returns an Error with the specified code.
// The error message is redacted and will be printed by main.go (single rendering boundary).
func exitErrorWithCode(code int, format string, args ...interface{}) error {
	msg := fmt.Sprintf(format, args...)
	msg = redact.Error(msg)
	return &errors.Error{Code: errors.InvalidInput, Exit: code, Message: msg}
}

// packOpenError returns a user-friendly error for pack open failures.
// It distinguishes between common error types and provides actionable guidance.
func packOpenError(packPath string, err error) error {
	if os.IsNotExist(err) {
		return exitError("pack file not found: %s\n\nCheck the file path and try again.", packPath)
	}
	if os.IsPermission(err) {
		return exitError("permission denied: %s\n\nCheck file permissions: ls -la %s", packPath, packPath)
	}
	// For other errors (corrupted, invalid format, etc.)
	return exitErrorWithCode(ExitMalformedPack, "failed to open pack %s: %v\n\nThe file may be corrupted or not a valid evidence pack.", packPath, err)
}
