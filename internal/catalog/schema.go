package catalog

import (
	"github.com/locktivity/epack/internal/catalog/schema"
)

// SchemaVersion is the current catalog schema version.
const SchemaVersion = schema.SchemaVersion

// MetaVersion is the current meta file version.
const MetaVersion = schema.MetaVersion

// Catalog is the component catalog schema v1.
// This is INFORMATIONAL ONLY - never use for security decisions.
type Catalog = schema.Catalog

// CatalogSource identifies where the catalog was fetched from.
type CatalogSource = schema.CatalogSource

// CatalogComponent contains display information about a component.
// NOTE: No trust assertions (verified_by, signatures, etc.) - catalog is for discovery only.
type CatalogComponent = schema.CatalogComponent

// MetaStatus represents the outcome of the last catalog fetch attempt.
type MetaStatus = schema.MetaStatus

const (
	MetaStatusOK          = schema.MetaStatusOK          // Successful fetch, catalog updated
	MetaStatusNotModified = schema.MetaStatusNotModified // 304 response, cache still valid
	MetaStatusError       = schema.MetaStatusError       // Fetch failed
)

// CatalogMeta stores metadata about the cached catalog.
// Stored separately from catalog.json for easy debugging.
type CatalogMeta = schema.CatalogMeta

// ParseCatalog parses catalog JSON with tolerant decoding.
// Unknown fields are silently ignored for forward compatibility.
func ParseCatalog(data []byte) (*Catalog, error) {
	return schema.ParseCatalog(data)
}

// ParseMeta parses meta JSON with strict decoding.
// Unknown fields cause an error since we control this format.
func ParseMeta(data []byte) (*CatalogMeta, error) {
	return schema.ParseMeta(data)
}

// FindComponentByName finds a component by exact name match.
// Returns the component and true if found, or zero value and false if not found.
// This is a convenience wrapper that avoids callers needing to import the schema package.
func FindComponentByName(c *Catalog, name string) (CatalogComponent, bool) {
	return c.FindByName(name)
}

// SearchComponents finds components matching the query string.
// Results are ranked by relevance: exact > prefix > substring.
// This is a convenience wrapper that avoids callers needing to import the schema package.
func SearchComponents(c *Catalog, query string) []SearchResult {
	return c.Search(query)
}
