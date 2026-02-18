//go:build components

package toolcmd

import (
	"encoding/json"
	"fmt"

	"github.com/locktivity/epack/errors"
	"github.com/locktivity/epack/internal/exitcode"
	"github.com/locktivity/epack/internal/tool"
	"github.com/spf13/cobra"
)

func newVerifyCommand() *cobra.Command {
	var jsonOutput bool

	cmd := &cobra.Command{
		Use:   "verify <tool-name>",
		Short: "Verify a tool's installation against the lockfile",
		Long: `Verify a tool's installation against the lockfile.

Checks that:
1. The tool is installed
2. The binary digest matches the lockfile
3. The lockfile entry is valid

This command does NOT re-verify Sigstore signatures - it only checks
that the installed binary matches what was locked during sync.

Examples:
  epack tool verify ai        # Verify epack-tool-ai installation
  epack tool verify policy    # Verify epack-tool-policy installation
  epack tool verify ai --json # Output as JSON`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runVerify(cmd, args[0], jsonOutput)
		},
	}

	cmd.Flags().BoolVar(&jsonOutput, "json", false, "Output in JSON format")

	return cmd
}

func runVerify(cmd *cobra.Command, toolName string, jsonOutput bool) error {
	// Delegate to service layer
	result, err := tool.VerifyTool(toolName, "")
	if err != nil {
		return err
	}

	return outputVerifyResult(cmd, result, jsonOutput)
}

func outputVerifyResult(cmd *cobra.Command, result *tool.ToolVerification, jsonOutput bool) error {
	if jsonOutput {
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		return enc.Encode(result)
	}

	out := cmd.OutOrStdout()

	_, _ = fmt.Fprintf(out, "Tool:     %s\n", result.Name)
	_, _ = fmt.Fprintf(out, "Platform: %s\n", result.Platform)
	_, _ = fmt.Fprintf(out, "Status:   %s\n", result.Status)

	if result.Version != "" {
		_, _ = fmt.Fprintf(out, "Version:  %s\n", result.Version)
	}

	if result.InstallPath != "" {
		_, _ = fmt.Fprintf(out, "Path:     %s\n", result.InstallPath)
	}

	_, _ = fmt.Fprintf(out, "Installed: %v\n", result.Installed)

	if result.ExpectedDigest != "" {
		_, _ = fmt.Fprintf(out, "\nDigests:\n")
		_, _ = fmt.Fprintf(out, "  Expected: %s\n", result.ExpectedDigest)
		if result.ActualDigest != "" {
			_, _ = fmt.Fprintf(out, "  Actual:   %s\n", result.ActualDigest)
			if result.DigestMatch {
				_, _ = fmt.Fprintf(out, "  Match:    yes\n")
			} else {
				_, _ = fmt.Fprintf(out, "  Match:    NO - MISMATCH\n")
			}
		}
	}

	if result.Error != "" {
		_, _ = fmt.Fprintf(out, "\nError: %s\n", result.Error)
	}

	// Return error for non-verified status (non-zero exit)
	if result.Status != "verified" {
		msg := fmt.Sprintf("tool verification failed (%s)", result.Status)
		if result.Error != "" {
			msg = fmt.Sprintf("tool verification failed (%s): %s", result.Status, result.Error)
		}
		return &errors.Error{
			Code:    errors.DigestMismatch,
			Exit:    exitcode.ToolVerifyFailed,
			Message: msg,
		}
	}

	return nil
}
