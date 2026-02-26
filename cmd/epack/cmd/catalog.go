//go:build components

package cmd

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/locktivity/epack/internal/catalog"
	"github.com/locktivity/epack/internal/securityaudit"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(newCatalogCommand())
}

func newCatalogCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "catalog",
		Short: "Search the component catalog",
		Long: `Search the component catalog for collectors, tools, remotes, and utilities.

The catalog is a cached index of components from registries, used for discovery.
It does NOT affect component verification or execution - those are governed by
the lockfile.

Commands:
  search   Search the cached catalog (offline)
  refresh  Fetch the latest catalog from the registry

Examples:
  epack catalog search policy
  epack catalog search --kind utility viewer
  epack catalog refresh`,
	}

	cmd.AddCommand(newUnifiedCatalogSearchCommand())
	cmd.AddCommand(newUnifiedCatalogRefreshCommand())

	return cmd
}

func newUnifiedCatalogSearchCommand() *cobra.Command {
	var jsonOutput bool
	var kindFilter string

	cmd := &cobra.Command{
		Use:   "search [query]",
		Short: "Search the component catalog (offline)",
		Long: `Search the cached component catalog for matching components.

This command searches the locally cached catalog and does not make
network requests. Results are ranked by relevance:
  1. Exact name matches
  2. Name prefix matches
  3. Matches in name, description, or publisher

If no query is provided, lists all components (or all of the specified kind).

Examples:
  epack catalog search policy                    # Find all components matching 'policy'
  epack catalog search --kind tool policy        # Find tools matching 'policy'
  epack catalog search --kind utility viewer     # Find utilities matching 'viewer'
  epack catalog search --kind collector          # List all collectors
  epack catalog search                           # List all components
  epack catalog search --json                    # Output as JSON`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			query := ""
			if len(args) > 0 {
				query = args[0]
			}
			return runUnifiedCatalogSearch(cmd, query, kindFilter, jsonOutput)
		},
	}

	cmd.Flags().BoolVar(&jsonOutput, "json", false, "Output in JSON format")
	cmd.Flags().StringVarP(&kindFilter, "kind", "k", "", "Filter by component kind (collector, tool, remote, utility)")

	return cmd
}

func newUnifiedCatalogRefreshCommand() *cobra.Command {
	var jsonOutput bool
	var catalogURL string
	var insecureAllowHTTP bool

	cmd := &cobra.Command{
		Use:     "refresh",
		Aliases: []string{"update"},
		Short:   "Fetch the latest catalog from the registry",
		Long: `Fetch the latest component catalog from the configured registry.

This command fetches the catalog index and caches it locally for
offline searching. It uses conditional requests (ETag/Last-Modified)
to avoid re-downloading unchanged catalogs.

Note: This command requires network access.

Examples:
  epack catalog refresh
  epack catalog refresh --json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runUnifiedCatalogRefresh(cmd, catalogURL, jsonOutput, insecureAllowHTTP)
		},
	}

	cmd.Flags().BoolVar(&jsonOutput, "json", false, "Output in JSON format")
	cmd.Flags().StringVar(&catalogURL, "url", "", "Override catalog URL (for testing)")
	cmd.Flags().BoolVar(&insecureAllowHTTP, "insecure-allow-http", false, "Allow HTTP for testing (INSECURE)")
	_ = cmd.Flags().MarkHidden("url")
	_ = cmd.Flags().MarkHidden("insecure-allow-http")

	return cmd
}

// UnifiedCatalogSearchResult is the JSON output structure for catalog search.
type UnifiedCatalogSearchResult struct {
	Query   string                           `json:"query"`
	Kind    string                           `json:"kind,omitempty"`
	Count   int                              `json:"count"`
	Results []UnifiedCatalogSearchResultItem `json:"results"`
}

// UnifiedCatalogSearchResultItem represents a component in search results.
type UnifiedCatalogSearchResultItem struct {
	Name             string `json:"name"`
	Kind             string `json:"kind"`
	Publisher        string `json:"publisher,omitempty"`
	Description      string `json:"description,omitempty"`
	Latest           string `json:"latest,omitempty"`
	RepoURL          string `json:"repo_url,omitempty"`
	MatchType        string `json:"match_type"`
	ProtocolVersions []int  `json:"protocol_versions,omitempty"`
}

func runUnifiedCatalogSearch(cmd *cobra.Command, query, kindFilter string, jsonOutput bool) error {
	// Read the cached catalog
	cat, warnings, err := catalog.ReadCatalog()
	if err != nil {
		if errors.Is(err, catalog.ErrNoCatalog) {
			return noCatalogErrorUnified(cmd, jsonOutput)
		}
		return fmt.Errorf("reading catalog: %w", err)
	}

	// Log warnings (non-fatal)
	for _, w := range warnings {
		_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "warning: %s\n", w)
	}

	// Build search options
	opts := catalog.SearchOptions{}
	if kindFilter != "" {
		switch kindFilter {
		case "collector":
			opts.Kind = catalog.KindCollector
		case "tool":
			opts.Kind = catalog.KindTool
		case "remote":
			opts.Kind = catalog.KindRemote
		case "utility":
			opts.Kind = catalog.KindUtility
		default:
			return fmt.Errorf("invalid kind %q: must be collector, tool, remote, or utility", kindFilter)
		}
	}

	// Search
	var results []catalog.SearchResult
	if opts.Kind == "" {
		results = cat.SearchAll(query)
	} else {
		results = cat.SearchWithOptions(query, opts)
	}

	if jsonOutput {
		return outputUnifiedCatalogSearchJSON(cmd, query, kindFilter, results)
	}
	return outputUnifiedCatalogSearchTable(cmd, query, kindFilter, results)
}

func noCatalogErrorUnified(cmd *cobra.Command, jsonOutput bool) error {
	if jsonOutput {
		result := UnifiedCatalogSearchResult{
			Query:   "",
			Count:   0,
			Results: []UnifiedCatalogSearchResultItem{},
		}
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		_ = enc.Encode(result)
	}

	return fmt.Errorf("no cached catalog found\n\nRun 'epack catalog refresh' to fetch the catalog")
}

func outputUnifiedCatalogSearchJSON(cmd *cobra.Command, query, kindFilter string, results []catalog.SearchResult) error {
	output := UnifiedCatalogSearchResult{
		Query:   query,
		Kind:    kindFilter,
		Count:   len(results),
		Results: make([]UnifiedCatalogSearchResultItem, len(results)),
	}

	for i, r := range results {
		output.Results[i] = UnifiedCatalogSearchResultItem{
			Name:             r.Component.Name,
			Kind:             string(r.Component.Kind),
			Publisher:        r.Component.Publisher,
			Description:      r.Component.Description,
			Latest:           r.Component.Latest,
			RepoURL:          r.Component.RepoURL,
			MatchType:        matchTypeNameUnified(r.MatchType),
			ProtocolVersions: r.Component.ProtocolVersions,
		}
	}

	enc := json.NewEncoder(cmd.OutOrStdout())
	enc.SetIndent("", "  ")
	return enc.Encode(output)
}

func outputUnifiedCatalogSearchTable(cmd *cobra.Command, query, kindFilter string, results []catalog.SearchResult) error {
	out := cmd.OutOrStdout()

	if len(results) == 0 {
		if query == "" && kindFilter == "" {
			_, _ = fmt.Fprintln(out, "No components in catalog.")
		} else if query == "" {
			_, _ = fmt.Fprintf(out, "No %ss in catalog.\n", kindFilter)
		} else if kindFilter == "" {
			_, _ = fmt.Fprintf(out, "No components matching %q found.\n", query)
		} else {
			_, _ = fmt.Fprintf(out, "No %ss matching %q found.\n", kindFilter, query)
		}
		return nil
	}

	// Header
	if query == "" && kindFilter == "" {
		_, _ = fmt.Fprintf(out, "Found %d components in catalog:\n\n", len(results))
	} else if query == "" {
		_, _ = fmt.Fprintf(out, "Found %d %ss in catalog:\n\n", len(results), kindFilter)
	} else if kindFilter == "" {
		_, _ = fmt.Fprintf(out, "Found %d components matching %q:\n\n", len(results), query)
	} else {
		_, _ = fmt.Fprintf(out, "Found %d %ss matching %q:\n\n", len(results), kindFilter, query)
	}

	_, _ = fmt.Fprintf(out, "%-20s %-10s %-15s %-10s %s\n", "NAME", "KIND", "PUBLISHER", "LATEST", "DESCRIPTION")
	_, _ = fmt.Fprintf(out, "%-20s %-10s %-15s %-10s %s\n", "----", "----", "---------", "------", "-----------")

	for _, r := range results {
		name := r.Component.Name
		kind := string(r.Component.Kind)
		if kind == "" {
			kind = "tool" // Default for backwards compatibility
		}
		publisher := r.Component.Publisher
		if publisher == "" {
			publisher = "-"
		}
		latest := r.Component.Latest
		if latest == "" {
			latest = "-"
		}
		description := r.Component.Description
		if len(description) > 40 {
			description = description[:37] + "..."
		}

		_, _ = fmt.Fprintf(out, "%-20s %-10s %-15s %-10s %s\n", name, kind, publisher, latest, description)
	}

	return nil
}

func matchTypeNameUnified(mt catalog.MatchType) string {
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

func runUnifiedCatalogRefresh(cmd *cobra.Command, catalogURL string, jsonOutput bool, insecureAllowHTTP bool) error {
	out := cmd.OutOrStdout()
	if insecureAllowHTTP {
		securityaudit.Emit(securityaudit.Event{
			Type:        securityaudit.EventInsecureBypass,
			Component:   "catalog",
			Name:        "refresh",
			Description: "catalog refresh running with insecure HTTP override",
			Attrs: map[string]string{
				"insecure_allow_http": "true",
			},
		})
	}

	// Get cached meta for conditional request headers
	cachedMeta := catalog.GetCachedMeta()

	opts := catalog.FetchOptions{
		URL:               catalogURL,
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
			_ = outputUnifiedRefreshJSON(cmd, &UnifiedCatalogRefreshResult{
				Updated: false,
				Status:  "error",
				Error:   err.Error(),
			})
		}
		return fmt.Errorf("fetching catalog: %w", err)
	}

	// Build output
	output := UnifiedCatalogRefreshResult{
		Updated:    result.Updated,
		Status:     string(result.Status),
		HTTPStatus: result.HTTPStatus,
		SourceURL:  catalogURL,
	}

	if result.Error != nil {
		output.Error = result.Error.Error()
	}

	// Get component count if catalog was updated or already exists
	if result.Updated || result.Status == catalog.MetaStatusNotModified {
		if cat, _, err := catalog.ReadCatalog(); err == nil {
			output.ComponentCount = len(cat.AllComponents())
		}
	}

	if jsonOutput {
		return outputUnifiedRefreshJSON(cmd, &output)
	}

	// Human output
	switch result.Status {
	case catalog.MetaStatusOK:
		_, _ = fmt.Fprintf(out, " updated (%d components)\n", output.ComponentCount)
	case catalog.MetaStatusNotModified:
		_, _ = fmt.Fprintf(out, " not modified (%d components cached)\n", output.ComponentCount)
	case catalog.MetaStatusError:
		_, _ = fmt.Fprintf(out, " error: %s\n", output.Error)
		return fmt.Errorf("catalog refresh failed: %s", output.Error)
	}

	return nil
}

// UnifiedCatalogRefreshResult is the JSON output structure for catalog refresh.
type UnifiedCatalogRefreshResult struct {
	Updated        bool   `json:"updated"`
	Status         string `json:"status"`
	HTTPStatus     int    `json:"http_status,omitempty"`
	SourceURL      string `json:"source_url,omitempty"`
	ComponentCount int    `json:"component_count,omitempty"`
	Error          string `json:"error,omitempty"`
}

func outputUnifiedRefreshJSON(cmd *cobra.Command, result *UnifiedCatalogRefreshResult) error {
	enc := json.NewEncoder(cmd.OutOrStdout())
	enc.SetIndent("", "  ")
	return enc.Encode(result)
}
