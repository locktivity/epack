//go:build components

package toolcmd

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/locktivity/epack/internal/catalog"
	"github.com/spf13/cobra"
)

func newCatalogCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "catalog",
		Short: "Manage the tool catalog",
		Long: `Manage the tool catalog for discovering available tools.

The catalog is a cached index of tools from registries, used for discovery.
It does NOT affect tool verification or execution - those are governed by
the lockfile.

Commands:
  search   Search the cached catalog (offline)
  refresh  Fetch the latest catalog from the registry

Examples:
  epack tool catalog search policy
  epack tool catalog refresh`,
	}

	cmd.AddCommand(newCatalogSearchCommand())
	cmd.AddCommand(newCatalogRefreshCommand())

	return cmd
}

func newCatalogSearchCommand() *cobra.Command {
	var jsonOutput bool

	cmd := &cobra.Command{
		Use:   "search [query]",
		Short: "Search the tool catalog (offline)",
		Long: `Search the cached tool catalog for matching tools.

This command searches the locally cached catalog and does not make
network requests. Results are ranked by relevance:
  1. Exact name matches
  2. Name prefix matches
  3. Matches in name, description, or publisher

If no query is provided, lists all tools in the catalog.

Examples:
  epack tool catalog search policy     # Find tools matching 'policy'
  epack tool catalog search            # List all cataloged tools
  epack tool catalog search ask --json # Output as JSON`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			query := ""
			if len(args) > 0 {
				query = args[0]
			}
			return runCatalogSearch(cmd, query, jsonOutput)
		},
	}

	cmd.Flags().BoolVar(&jsonOutput, "json", false, "Output in JSON format")

	return cmd
}

func newCatalogRefreshCommand() *cobra.Command {
	var jsonOutput bool
	var catalogURL string
	var insecureAllowHTTP bool

	cmd := &cobra.Command{
		Use:     "refresh",
		Aliases: []string{"update"},
		Short:   "Fetch the latest catalog from the registry",
		Long: `Fetch the latest tool catalog from the configured registry.

This command fetches the catalog index and caches it locally for
offline searching. It uses conditional requests (ETag/Last-Modified)
to avoid re-downloading unchanged catalogs.

Note: This command requires network access.

Examples:
  epack tool catalog refresh
  epack tool catalog refresh --json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCatalogRefresh(cmd, catalogURL, jsonOutput, insecureAllowHTTP)
		},
	}

	cmd.Flags().BoolVar(&jsonOutput, "json", false, "Output in JSON format")
	cmd.Flags().StringVar(&catalogURL, "url", "", "Override catalog URL (for testing)")
	cmd.Flags().BoolVar(&insecureAllowHTTP, "insecure-allow-http", false, "Allow HTTP for testing (INSECURE)")
	_ = cmd.Flags().MarkHidden("url")                 // Hidden flag for testing
	_ = cmd.Flags().MarkHidden("insecure-allow-http") // Hidden flag for testing

	return cmd
}

// CatalogSearchResult is the JSON output structure for catalog search.
type CatalogSearchResult struct {
	Query   string                    `json:"query"`
	Count   int                       `json:"count"`
	Results []CatalogSearchResultTool `json:"results"`
}

// CatalogSearchResultTool represents a tool in search results.
type CatalogSearchResultTool struct {
	Name             string `json:"name"`
	Publisher        string `json:"publisher,omitempty"`
	Description      string `json:"description,omitempty"`
	Latest           string `json:"latest,omitempty"`
	RepoURL          string `json:"repo_url,omitempty"`
	MatchType        string `json:"match_type"` // "exact", "prefix", "substring"
	ProtocolVersions []int  `json:"protocol_versions,omitempty"`
}

func runCatalogSearch(cmd *cobra.Command, query string, jsonOutput bool) error {
	// Read the cached catalog
	cat, warnings, err := catalog.ReadCatalog()
	if err != nil {
		if errors.Is(err, catalog.ErrNoCatalog) {
			return noCatalogError(cmd, jsonOutput)
		}
		return fmt.Errorf("reading catalog: %w", err)
	}

	// Log warnings (non-fatal)
	for _, w := range warnings {
		_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "warning: %s\n", w)
	}

	// Search
	results := cat.Search(query)

	if jsonOutput {
		return outputCatalogSearchJSON(cmd, query, results)
	}
	return outputCatalogSearchTable(cmd, query, results)
}

func noCatalogError(cmd *cobra.Command, jsonOutput bool) error {
	if jsonOutput {
		result := CatalogSearchResult{
			Query:   "",
			Count:   0,
			Results: []CatalogSearchResultTool{},
		}
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		_ = enc.Encode(result)
	}

	return fmt.Errorf("no cached catalog found\n\nRun 'epack tool catalog refresh' to fetch the catalog")
}

func outputCatalogSearchJSON(cmd *cobra.Command, query string, results []catalog.SearchResult) error {
	output := CatalogSearchResult{
		Query:   query,
		Count:   len(results),
		Results: make([]CatalogSearchResultTool, len(results)),
	}

	for i, r := range results {
		output.Results[i] = CatalogSearchResultTool{
			Name:             r.Component.Name,
			Publisher:        r.Component.Publisher,
			Description:      r.Component.Description,
			Latest:           r.Component.Latest,
			RepoURL:          r.Component.RepoURL,
			MatchType:        matchTypeName(r.MatchType),
			ProtocolVersions: r.Component.ProtocolVersions,
		}
	}

	enc := json.NewEncoder(cmd.OutOrStdout())
	enc.SetIndent("", "  ")
	return enc.Encode(output)
}

func outputCatalogSearchTable(cmd *cobra.Command, query string, results []catalog.SearchResult) error {
	out := cmd.OutOrStdout()

	if len(results) == 0 {
		if query == "" {
			_, _ = fmt.Fprintln(out, "No tools in catalog.")
		} else {
			_, _ = fmt.Fprintf(out, "No tools matching %q found.\n", query)
		}
		return nil
	}

	// Header
	if query == "" {
		_, _ = fmt.Fprintf(out, "Found %d tools in catalog:\n\n", len(results))
	} else {
		_, _ = fmt.Fprintf(out, "Found %d tools matching %q:\n\n", len(results), query)
	}

	_, _ = fmt.Fprintf(out, "%-20s %-15s %-10s %s\n", "NAME", "PUBLISHER", "LATEST", "DESCRIPTION")
	_, _ = fmt.Fprintf(out, "%-20s %-15s %-10s %s\n", "----", "---------", "------", "-----------")

	for _, r := range results {
		name := r.Component.Name
		publisher := r.Component.Publisher
		if publisher == "" {
			publisher = "-"
		}
		latest := r.Component.Latest
		if latest == "" {
			latest = "-"
		}
		description := r.Component.Description
		if len(description) > 50 {
			description = description[:47] + "..."
		}

		_, _ = fmt.Fprintf(out, "%-20s %-15s %-10s %s\n", name, publisher, latest, description)
	}

	return nil
}

func matchTypeName(mt catalog.MatchType) string {
	switch mt {
	case catalog.MatchExact:
		return "exact"
	case catalog.MatchPrefix:
		return "prefix"
	case catalog.MatchSubstring:
		return "substring"
	default:
		return "unknown"
	}
}

// CatalogRefreshResult is the JSON output structure for catalog refresh.
type CatalogRefreshResult struct {
	Updated    bool   `json:"updated"`
	Status     string `json:"status"` // "ok", "not_modified", "error"
	HTTPStatus int    `json:"http_status,omitempty"`
	SourceURL  string `json:"source_url,omitempty"`
	ToolCount  int    `json:"tool_count,omitempty"`
	Error      string `json:"error,omitempty"`
}

func runCatalogRefresh(cmd *cobra.Command, catalogURL string, jsonOutput bool, insecureAllowHTTP bool) error {
	out := cmd.OutOrStdout()

	// Get cached meta for conditional request headers
	cachedMeta := catalog.GetCachedMeta()

	opts := catalog.FetchOptions{
		URL:                  catalogURL,
		InsecureAllowHTTP: insecureAllowHTTP,
	}
	if cachedMeta != nil {
		opts.ETag = cachedMeta.ETag
		opts.LastModified = cachedMeta.LastModified
	}

	if !jsonOutput {
		_, _ = fmt.Fprint(out, "Fetching catalog...")
	}

	result, err := catalog.FetchCatalog(cmd.Context(), opts)
	if err != nil {
		if jsonOutput {
			_ = outputRefreshJSON(cmd, &CatalogRefreshResult{
				Updated: false,
				Status:  "error",
				Error:   err.Error(),
			})
		}
		return fmt.Errorf("fetching catalog: %w", err)
	}

	// Build output
	output := CatalogRefreshResult{
		Updated:    result.Updated,
		Status:     string(result.Status),
		HTTPStatus: result.HTTPStatus,
		SourceURL:  catalogURL,
	}

	if result.Error != nil {
		output.Error = result.Error.Error()
	}

	// Get tool count if catalog was updated or already exists
	if result.Updated || result.Status == catalog.MetaStatusNotModified {
		if cat, _, err := catalog.ReadCatalog(); err == nil {
			output.ToolCount = len(cat.Tools)
		}
	}

	if jsonOutput {
		return outputRefreshJSON(cmd, &output)
	}

	// Human output
	switch result.Status {
	case catalog.MetaStatusOK:
		_, _ = fmt.Fprintf(out, " updated (%d tools)\n", output.ToolCount)
	case catalog.MetaStatusNotModified:
		_, _ = fmt.Fprintf(out, " not modified (%d tools cached)\n", output.ToolCount)
	case catalog.MetaStatusError:
		_, _ = fmt.Fprintf(out, " error: %s\n", output.Error)
		return fmt.Errorf("catalog refresh failed: %s", output.Error)
	}

	return nil
}

func outputRefreshJSON(cmd *cobra.Command, result *CatalogRefreshResult) error {
	enc := json.NewEncoder(cmd.OutOrStdout())
	enc.SetIndent("", "  ")
	return enc.Encode(result)
}
