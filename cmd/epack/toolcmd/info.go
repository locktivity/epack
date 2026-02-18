//go:build components

package toolcmd

import (
	"context"
	"encoding/json"
	"fmt"
	"runtime"

	"github.com/locktivity/epack/internal/platform"
	"github.com/locktivity/epack/internal/tool"
	"github.com/spf13/cobra"
)

func newInfoCommand() *cobra.Command {
	var jsonOutput bool

	cmd := &cobra.Command{
		Use:   "info <tool-name>",
		Short: "Show detailed information about a tool",
		Long: `Show detailed information about a tool.

Queries the tool's --capabilities endpoint and displays the response.
Also shows lockfile information if the tool is configured in epack.yaml.

Examples:
  epack tool info ai        # Show info about epack-tool-ai
  epack tool info policy    # Show info about epack-tool-policy
  epack tool info ai --json # Output as JSON`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runInfo(cmd, args[0], jsonOutput)
		},
	}

	cmd.Flags().BoolVar(&jsonOutput, "json", false, "Output in JSON format")

	return cmd
}

func runInfo(cmd *cobra.Command, toolName string, jsonOutput bool) error {
	ctx := context.Background()
	if cmd != nil && cmd.Context() != nil {
		ctx = cmd.Context()
	}

	// Delegate to service layer
	info, err := tool.GetToolInfo(ctx, toolName, "")
	if err != nil {
		return err
	}

	if jsonOutput {
		return outputInfoJSON(cmd, info)
	}
	return outputInfoTable(cmd, info)
}

func outputInfoJSON(cmd *cobra.Command, info *tool.ToolInfo) error {
	enc := json.NewEncoder(cmd.OutOrStdout())
	enc.SetIndent("", "  ")
	return enc.Encode(info)
}

func outputInfoTable(cmd *cobra.Command, info *tool.ToolInfo) error {
	out := cmd.OutOrStdout()

	_, _ = fmt.Fprintf(out, "Tool: %s\n", info.Name)
	_, _ = fmt.Fprintln(out)

	if info.BinaryPath != "" {
		_, _ = fmt.Fprintf(out, "Binary Path: %s\n", info.BinaryPath)
	}

	if info.Capabilities != nil {
		_, _ = fmt.Fprintln(out, "\nCapabilities:")
		_, _ = fmt.Fprintf(out, "  Name:             %s\n", info.Capabilities.Name)
		_, _ = fmt.Fprintf(out, "  Version:          %s\n", info.Capabilities.Version)
		_, _ = fmt.Fprintf(out, "  Protocol Version: %d\n", info.Capabilities.ProtocolVersion)
		if info.Capabilities.Description != "" {
			_, _ = fmt.Fprintf(out, "  Description:      %s\n", info.Capabilities.Description)
		}
		_, _ = fmt.Fprintf(out, "  Requires Pack:    %v\n", info.Capabilities.RequiresPack)
		_, _ = fmt.Fprintf(out, "  Network:          %v\n", info.Capabilities.Network)
		if info.Capabilities.Publisher != "" {
			_, _ = fmt.Fprintf(out, "  Publisher:        %s\n", info.Capabilities.Publisher)
		}
		if info.Capabilities.Repo != "" {
			_, _ = fmt.Fprintf(out, "  Repository:       %s\n", info.Capabilities.Repo)
		}
	} else if info.Error != "" {
		_, _ = fmt.Fprintf(out, "\nCapabilities: Error - %s\n", info.Error)
	}

	if info.Lockfile != nil {
		_, _ = fmt.Fprintln(out, "\nLockfile Entry:")
		_, _ = fmt.Fprintf(out, "  Version: %s\n", info.Lockfile.Version)
		if info.Lockfile.Source != "" {
			_, _ = fmt.Fprintf(out, "  Source:  %s\n", info.Lockfile.Source)
		}

		// Display signing identity (establishes supply chain trust)
		if info.Lockfile.Signer != nil {
			_, _ = fmt.Fprintln(out, "  Signing Identity:")
			_, _ = fmt.Fprintf(out, "    Issuer:  %s\n", info.Lockfile.Signer.Issuer)
			if info.Lockfile.Signer.Subject != "" {
				_, _ = fmt.Fprintf(out, "    Subject: %s\n", info.Lockfile.Signer.Subject)
			}
		}

		currentPlatform := platform.Key(runtime.GOOS, runtime.GOARCH)
		_, _ = fmt.Fprintln(out, "  Platforms:")
		for platform, pinfo := range info.Lockfile.Platforms {
			marker := ""
			if platform == currentPlatform {
				marker = " (current)"
			}
			_, _ = fmt.Fprintf(out, "    %s%s:\n", platform, marker)
			_, _ = fmt.Fprintf(out, "      Digest: %s\n", pinfo.Digest)
			if pinfo.Asset != "" {
				_, _ = fmt.Fprintf(out, "      Asset:  %s\n", pinfo.Asset)
			}
		}
	}

	return nil
}
