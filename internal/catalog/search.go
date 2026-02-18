package catalog

import (
	"github.com/locktivity/epack/internal/catalog/schema"
	"github.com/locktivity/epack/internal/componenttypes"
)

// SearchResult represents a component from a search with its match type.
type SearchResult = schema.SearchResult

// SearchOptions configures search behavior.
type SearchOptions = schema.SearchOptions

// MatchType indicates how the component matched the search query.
type MatchType = schema.MatchType

// ComponentKind identifies the type of component.
type ComponentKind = componenttypes.ComponentKind

const (
	MatchExact     = schema.MatchExact     // Exact name match
	MatchPrefix    = schema.MatchPrefix    // Name starts with query
	MatchSubstring = schema.MatchSubstring // Name, description, or publisher contains query
)

const (
	KindCollector = componenttypes.KindCollector
	KindTool      = componenttypes.KindTool
	KindRemote    = componenttypes.KindRemote
	KindUtility   = componenttypes.KindUtility
)
