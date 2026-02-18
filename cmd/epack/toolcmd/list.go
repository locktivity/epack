//go:build components

package toolcmd

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/locktivity/epack/internal/catalog"
	"github.com/locktivity/epack/internal/componenttypes"
	"github.com/locktivity/epack/internal/tool"
	"github.com/spf13/cobra"
)

// ListedTool extends DiscoveredTool with display-only fields (like publisher from catalog).
type ListedTool struct {
	tool.DiscoveredTool
	Publisher string `json:"publisher,omitempty"` // From catalog (display only)
}

func newListCommand() *cobra.Command {
	var jsonOutput bool
	var probe bool

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List available tools",
		Long: `List available tools from PATH and lockfile.

By default, no tools are executed - capabilities are derived from lockfile
metadata only. Use --probe to query --capabilities from all discovered tools.

SECURITY NOTE: --probe executes discovered binaries. Only use when you trust
the tools in your PATH and lockfile.

Status values:
  verified    Tool is in lockfile with valid digest
  unverified  Tool is in PATH but not in lockfile
  managed     Tool is in lockfile but not yet synced

Examples:
  epack tool list           # List tools (no execution, lockfile metadata only)
  epack tool list --probe   # Probe --capabilities from all tools (executes binaries)
  epack tool list --json    # Output in JSON format`,
		RunE: func(cmd *cobra.Command, args []string) error {
			tools := discoverToolsWithStatus(probe)

			if jsonOutput {
				return outputJSON(cmd, tools)
			}
			return outputTableWithStatus(cmd, tools)
		},
	}

	cmd.Flags().BoolVar(&jsonOutput, "json", false, "Output in JSON format")
	cmd.Flags().BoolVar(&probe, "probe", false, "Probe --capabilities from all tools (executes binaries)")

	return cmd
}

// discoverToolsWithStatus finds tools from both PATH and lockfile, with verification status.
// Enriches tools with catalog metadata (publisher) for display purposes only.
// SECURITY: When probe is true, this executes discovered binaries to query capabilities.
func discoverToolsWithStatus(probe bool) []ListedTool {
	// Delegate to service layer for discovery
	// When probe is true, both managed and PATH tools are probed
	discovered := tool.DiscoverTools(tool.DiscoverOptions{
		ProbePATH:    probe,
		ProbeManaged: probe,
	})

	// Load catalog for display enrichment (best-effort, display only)
	// This data is NOT used for trust/execution decisions - those come from lockfile
	var cat *catalog.Catalog
	if c, _, err := catalog.ReadCatalog(); err == nil {
		cat = c
	}

	// Convert to ListedTool and enrich with catalog metadata
	var result []ListedTool
	for _, t := range discovered {
		listed := ListedTool{DiscoveredTool: t}
		// Enrich with catalog data (display only - does NOT affect trust/execution)
		if cat != nil {
			toolName := strings.TrimPrefix(t.BinaryName, componenttypes.ToolBinaryPrefix)
			if catalogTool, ok := cat.FindByName(toolName); ok {
				listed.Publisher = catalogTool.Publisher
			}
		}
		result = append(result, listed)
	}

	return result
}

func outputJSON(cmd *cobra.Command, tools []ListedTool) error {
	enc := json.NewEncoder(cmd.OutOrStdout())
	enc.SetIndent("", "  ")
	return enc.Encode(tools)
}

func outputTableWithStatus(cmd *cobra.Command, tools []ListedTool) error {
	if len(tools) == 0 {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "No tools found.")
		_, _ = fmt.Fprintln(cmd.OutOrStdout())
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Tools can be:")
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "  - Binaries named epack-tool-<name> in your PATH")
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "  - Defined in epack.yaml and synced via 'epack sync'")
		return nil
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%-20s %-10s %-15s %-12s %-8s %s\n", "NAME", "VERSION", "PUBLISHER", "STATUS", "SOURCE", "DESCRIPTION")
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%-20s %-10s %-15s %-12s %-8s %s\n", "----", "-------", "---------", "------", "------", "-----------")

	for _, t := range tools {
		name := strings.TrimPrefix(t.BinaryName, componenttypes.ToolBinaryPrefix)
		version := "?"
		publisher := "-"
		description := ""

		if t.Capabilities != nil {
			version = t.Capabilities.Version
			description = t.Capabilities.Description
		} else if t.Error != "" {
			description = fmt.Sprintf("(error: %s)", t.Error)
		} else if t.Status == tool.StatusManaged {
			description = "(not synced - run 'epack sync')"
		}

		if t.Publisher != "" {
			publisher = t.Publisher
			if len(publisher) > 15 {
				publisher = publisher[:12] + "..."
			}
		}

		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%-20s %-10s %-15s %-12s %-8s %s\n",
			name,
			version,
			publisher,
			t.Status,
			t.Source,
			description,
		)
	}

	return nil
}
