package schema

import (
	"sort"
	"strings"

	"github.com/locktivity/epack/internal/componenttypes"
)

// SearchResult represents a component from a search with its match type.
type SearchResult struct {
	Component CatalogComponent
	MatchType MatchType
}

// SearchOptions configures search behavior.
type SearchOptions struct {
	Kind componenttypes.ComponentKind // Filter by kind (empty = all kinds)
}

// MatchType indicates how the component matched the search query.
type MatchType int

const (
	MatchExact     MatchType = iota // Exact name match
	MatchPrefix                     // Name starts with query
	MatchSubstring                  // Name, description, or publisher contains query
)

// Search finds tools matching the query string.
// Results are ranked by relevance: exact > prefix > substring.
// Within each bucket, results are sorted by name then publisher for stability.
// This is a backwards-compatible wrapper that searches only tools.
func (c *Catalog) Search(query string) []SearchResult {
	return c.SearchWithOptions(query, SearchOptions{Kind: componenttypes.KindTool})
}

// SearchAll finds components of all kinds matching the query string.
// Results are ranked by relevance: exact > prefix > substring.
func (c *Catalog) SearchAll(query string) []SearchResult {
	return c.SearchWithOptions(query, SearchOptions{})
}

// SearchWithOptions finds components matching the query with configurable options.
// Results are ranked by relevance: exact > prefix > substring.
// Within each bucket, results are sorted by name then publisher for stability.
func (c *Catalog) SearchWithOptions(query string, opts SearchOptions) []SearchResult {
	// Get components to search based on kind filter
	var components []CatalogComponent
	if opts.Kind == "" {
		components = c.AllComponents()
	} else {
		components = c.ComponentsByKind(opts.Kind)
	}

	if query == "" {
		// Empty query returns all matching components, sorted by name
		results := make([]SearchResult, len(components))
		for i, comp := range components {
			results[i] = SearchResult{Component: comp, MatchType: MatchSubstring}
		}
		sortResultsBucket(results)
		return results
	}

	query = strings.ToLower(query)

	var exact, prefix, substring []SearchResult

	for _, comp := range components {
		name := strings.ToLower(comp.Name)

		if name == query {
			exact = append(exact, SearchResult{Component: comp, MatchType: MatchExact})
		} else if strings.HasPrefix(name, query) {
			prefix = append(prefix, SearchResult{Component: comp, MatchType: MatchPrefix})
		} else if matchesSubstring(comp, query) {
			substring = append(substring, SearchResult{Component: comp, MatchType: MatchSubstring})
		}
	}

	// Sort each bucket for deterministic results
	sortResultsBucket(exact)
	sortResultsBucket(prefix)
	sortResultsBucket(substring)

	// Combine buckets in order of relevance
	results := make([]SearchResult, 0, len(exact)+len(prefix)+len(substring))
	results = append(results, exact...)
	results = append(results, prefix...)
	results = append(results, substring...)

	return results
}

// matchesSubstring checks if the query matches name, description, or publisher.
func matchesSubstring(comp CatalogComponent, query string) bool {
	name := strings.ToLower(comp.Name)
	desc := strings.ToLower(comp.Description)
	pub := strings.ToLower(comp.Publisher)

	return strings.Contains(name, query) ||
		strings.Contains(desc, query) ||
		strings.Contains(pub, query)
}

// sortResultsBucket sorts results by name, then publisher for stability.
func sortResultsBucket(results []SearchResult) {
	sort.SliceStable(results, func(i, j int) bool {
		if results[i].Component.Name != results[j].Component.Name {
			return results[i].Component.Name < results[j].Component.Name
		}
		return results[i].Component.Publisher < results[j].Component.Publisher
	})
}

// FindByName finds a component by exact name match in the Tools array.
// Returns the component and true if found, or zero value and false if not found.
// Returns a copy to avoid pointer aliasing issues if the underlying slice is modified.
//
// Note: For backwards compatibility, this searches only the Tools array.
// Use FindByNameAndKind to search other component types.
//
// Uses O(n) linear search which is acceptable for catalogs under 5000 components.
// For larger catalogs, consider building a name index on first access.
func (c *Catalog) FindByName(name string) (CatalogComponent, bool) {
	for i := range c.Tools {
		if c.Tools[i].Name == name {
			return c.Tools[i], true
		}
	}
	return CatalogComponent{}, false
}

// FindByNameAndKind finds a component by exact name and kind match.
func (c *Catalog) FindByNameAndKind(name string, kind componenttypes.ComponentKind) (CatalogComponent, bool) {
	components := c.ComponentsByKind(kind)
	for i := range components {
		if components[i].Name == name {
			return components[i], true
		}
	}
	return CatalogComponent{}, false
}
