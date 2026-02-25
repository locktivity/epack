// Package schema provides the component catalog schema types and parsing.
//
// SECURITY BOUNDARY: This package is for DISCOVERY ONLY.
// Catalog data must NEVER influence:
//   - Which binary gets executed
//   - Whether a binary is considered verified
//   - What digest is expected
//   - What signer identity is shown as "trusted"
//
// The lockfile and verification are the ONLY security sources of truth.
// Catalog provides publisher names and descriptions for display purposes.
package schema

import (
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/locktivity/epack/internal/componenttypes"
	"github.com/locktivity/epack/internal/jsonutil"
)

// SchemaVersion is the current catalog schema version.
const SchemaVersion = 1

// MetaVersion is the current meta file version.
const MetaVersion = 1

// Catalog is the component catalog schema v1.
// This is INFORMATIONAL ONLY - never use for security decisions.
type Catalog struct {
	SchemaVersion int           `json:"schema_version"` // Always 1
	GeneratedAt   string        `json:"generated_at"`   // RFC3339 timestamp
	Source        CatalogSource `json:"source"`

	// Component arrays by kind.
	// Tools is kept for backwards compatibility; new catalogs should use the kind arrays.
	Tools      []CatalogComponent `json:"tools,omitempty"`
	Collectors []CatalogComponent `json:"collectors,omitempty"`
	Remotes    []CatalogComponent `json:"remotes,omitempty"`
	Utilities  []CatalogComponent `json:"utilities,omitempty"`
}

// CatalogSource identifies where the catalog was fetched from.
type CatalogSource struct {
	Registry string `json:"registry"`      // "github", "locktivity"
	URL      string `json:"url,omitempty"` // Source URL
}

// CatalogComponent contains display information about a component.
// NOTE: No trust assertions (verified_by, signatures, etc.) - catalog is for discovery only.
type CatalogComponent struct {
	Name             string                       `json:"name"`
	Kind             componenttypes.ComponentKind `json:"kind,omitempty"` // "collector", "tool", "remote", "utility"
	Publisher        string                       `json:"publisher,omitempty"`
	RepoURL          string                       `json:"repo_url,omitempty"` // Canonical: "https://github.com/org/repo" (no trailing slash)
	Homepage         string                       `json:"homepage,omitempty"` // Optional docs/landing page
	Description      string                       `json:"description,omitempty"`
	ProtocolVersions []int                        `json:"protocol_versions,omitempty"` // e.g., [1]
	Latest           string                       `json:"latest,omitempty"`            // Latest version hint
	Dependencies     []string                     `json:"dependencies,omitempty"`      // Install-time dependencies (component names)
}

// MetaStatus represents the outcome of the last catalog fetch attempt.
type MetaStatus string

const (
	MetaStatusOK          MetaStatus = "ok"           // Successful fetch, catalog updated
	MetaStatusNotModified MetaStatus = "not_modified" // 304 response, cache still valid
	MetaStatusError       MetaStatus = "error"        // Fetch failed
)

// CatalogMeta stores metadata about the cached catalog.
// Stored separately from catalog.json for easy debugging.
type CatalogMeta struct {
	MetaVersion    int        `json:"meta_version"`               // Always 1
	LastStatus     MetaStatus `json:"last_status"`                // "ok", "not_modified", "error"
	ETag           string     `json:"etag,omitempty"`             // HTTP ETag for conditional requests
	LastModified   string     `json:"last_modified,omitempty"`    // HTTP Last-Modified header
	FetchedAt      string     `json:"fetched_at,omitempty"`       // Last SUCCESSFUL fetch (RFC3339)
	SourceURL      string     `json:"source_url,omitempty"`       // URL catalog was fetched from
	LastAttemptAt  string     `json:"last_attempt_at,omitempty"`  // Last attempt timestamp (success or fail)
	LastError      string     `json:"last_error,omitempty"`       // Truncated error message on failure
	LastHTTPStatus int        `json:"last_http_status,omitempty"` // HTTP status code on last attempt
}

// AllComponents returns all components from the catalog, regardless of kind.
// Components from the Tools array (for backwards compatibility) are included
// with Kind set to "tool" if not already specified.
func (c *Catalog) AllComponents() []CatalogComponent {
	var all []CatalogComponent

	// Add tools (with kind defaulting to "tool" for backwards compatibility)
	for _, t := range c.Tools {
		if t.Kind == "" {
			t.Kind = componenttypes.KindTool
		}
		all = append(all, t)
	}

	// Add other component types
	for _, comp := range c.Collectors {
		if comp.Kind == "" {
			comp.Kind = componenttypes.KindCollector
		}
		all = append(all, comp)
	}
	for _, comp := range c.Remotes {
		if comp.Kind == "" {
			comp.Kind = componenttypes.KindRemote
		}
		all = append(all, comp)
	}
	for _, comp := range c.Utilities {
		if comp.Kind == "" {
			comp.Kind = componenttypes.KindUtility
		}
		all = append(all, comp)
	}

	return all
}

// ComponentsByKind returns components of a specific kind.
// Returns a defensive copy to prevent callers from modifying internal state.
func (c *Catalog) ComponentsByKind(kind componenttypes.ComponentKind) []CatalogComponent {
	switch kind {
	case componenttypes.KindCollector:
		return slices.Clone(c.Collectors)
	case componenttypes.KindTool:
		return slices.Clone(c.Tools)
	case componenttypes.KindRemote:
		return slices.Clone(c.Remotes)
	case componenttypes.KindUtility:
		return slices.Clone(c.Utilities)
	default:
		return nil
	}
}

// Validate checks catalog structure and sanitizes fields.
// Invalid fields are blanked rather than causing parse failure.
// Returns warnings for any sanitized fields.
func (c *Catalog) Validate() []string {
	var warnings []string

	// Validate all component arrays
	validateComponents := func(components []CatalogComponent, defaultKind componenttypes.ComponentKind) {
		for i := range components {
			comp := &components[i]

			// Validate and sanitize repo_url
			if comp.RepoURL != "" {
				if sanitized := ValidateRepoURL(comp.RepoURL); sanitized != comp.RepoURL {
					warnings = append(warnings, string(defaultKind)+" "+comp.Name+": invalid repo_url blanked")
					comp.RepoURL = sanitized
				}
			}

			// Validate and sanitize homepage
			if comp.Homepage != "" {
				if sanitized := ValidateURL(comp.Homepage); sanitized != comp.Homepage {
					warnings = append(warnings, string(defaultKind)+" "+comp.Name+": invalid homepage blanked")
					comp.Homepage = sanitized
				}
			}
		}
	}

	validateComponents(c.Tools, componenttypes.KindTool)
	validateComponents(c.Collectors, componenttypes.KindCollector)
	validateComponents(c.Remotes, componenttypes.KindRemote)
	validateComponents(c.Utilities, componenttypes.KindUtility)

	return warnings
}

// ValidateRepoURL checks if a repo URL is valid.
// Returns empty string if invalid.
// Valid: must be HTTPS, no trailing slash.
func ValidateRepoURL(url string) string {
	if url == "" {
		return ""
	}
	if !strings.HasPrefix(url, "https://") {
		return "" // Must be HTTPS
	}
	if strings.HasSuffix(url, "/") {
		return "" // No trailing slash
	}
	// Basic sanity: must have at least one path component
	if !strings.Contains(url[8:], "/") {
		return "" // Need at least https://host/path
	}
	return url
}

// ValidateURL checks if a URL is valid for display purposes.
// Returns empty string if invalid.
func ValidateURL(url string) string {
	if url == "" {
		return ""
	}
	if !strings.HasPrefix(url, "https://") && !strings.HasPrefix(url, "http://") {
		return "" // Must be HTTP(S)
	}
	return url
}

// ParseCatalog parses catalog JSON with tolerant decoding.
// Unknown fields are silently ignored for forward compatibility.
//
// SECURITY: Validates no duplicate keys to prevent ambiguous overrides.
// While catalog data is informational only, duplicate keys could cause
// confusion in tool display or search results.
func ParseCatalog(data []byte) (*Catalog, error) {
	catalog, err := jsonutil.DecodeNoDup[Catalog](data)
	if err != nil {
		return nil, fmt.Errorf("parsing catalog: %w", err)
	}
	return &catalog, nil
}

// ParseMeta parses meta JSON with strict decoding.
// Unknown fields cause an error since we control this format.
// Trailing JSON values also cause an error to prevent concatenated payloads.
//
// SECURITY: Validates no duplicate keys to prevent ambiguous overrides.
func ParseMeta(data []byte) (*CatalogMeta, error) {
	// Validate no duplicate keys first
	if err := jsonutil.ValidateNoDuplicateKeys(data); err != nil {
		return nil, fmt.Errorf("meta contains duplicate keys: %w", err)
	}

	var meta CatalogMeta
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&meta); err != nil {
		return nil, err
	}
	// Enforce no trailing data - prevents accepting concatenated JSON like {"x":1}{"y":2}
	// dec.More() only checks for another JSON token, so we also try to decode another value.
	// If that succeeds or returns a non-EOF error, there's trailing data.
	var extra any
	if err := dec.Decode(&extra); err == nil {
		return nil, fmt.Errorf("unexpected trailing JSON value after meta")
	} else if err != io.EOF {
		// There's non-JSON trailing data or malformed JSON
		return nil, fmt.Errorf("unexpected trailing data after JSON")
	}
	return &meta, nil
}
