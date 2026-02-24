package catalog

import (
	stderrors "errors"
	"fmt"
	"strings"

	"github.com/locktivity/epack/errors"
)

// ErrNotFound is returned when a component is not found in the catalog.
var ErrNotFound = errors.E(errors.ComponentNotFound, "component not found in catalog", nil)

// GitHubHTTPSPrefix is the required prefix for GitHub repository URLs.
const GitHubHTTPSPrefix = "https://github.com/"

// LookupResult contains the result of looking up a component in the catalog.
type LookupResult struct {
	Name         string   // Component name (e.g., "ai")
	RepoPath     string   // Repository path extracted from RepoURL (e.g., "locktivity/epack-tool-ai")
	Source       string   // Full source string for config (e.g., "locktivity/epack-tool-ai@^1.0")
	Publisher    string   // Publisher name from catalog
	Description  string   // Component description
	Latest       string   // Latest version hint from catalog
	Dependencies []string // Install-time dependencies (component names)
}

// LookupComponent finds a component by exact name in the cached catalog and constructs
// the source string for use in epack.yaml.
//
// The constraint parameter specifies the version constraint to use in the source string.
// If constraint is "latest" or empty, only the repo path is used (no @constraint suffix).
//
// Returns ErrNoCatalog if no cached catalog exists.
// Returns ErrNotFound if the component is not in the catalog.
func LookupComponent(name string, constraint string) (*LookupResult, error) {
	catalog, _, err := ReadCatalog()
	if err != nil {
		return nil, err
	}

	return LookupComponentInCatalog(catalog, name, constraint)
}

// LookupComponentInCatalog finds a component in the provided catalog.
// This is useful when you already have the catalog loaded and want to avoid re-reading it.
func LookupComponentInCatalog(catalog *Catalog, name string, constraint string) (*LookupResult, error) {
	// FindByName is inherited from schema.Catalog via type alias
	component, found := catalog.FindByName(name)
	if !found {
		return nil, fmt.Errorf("%w: %q", ErrNotFound, name)
	}

	// Extract owner/repo from RepoURL (e.g., "https://github.com/locktivity/epack-tool-ai" -> "locktivity/epack-tool-ai")
	repoPath, err := extractRepoPath(component.RepoURL)
	if err != nil {
		return nil, fmt.Errorf("component %q has invalid repo_url: %w", name, err)
	}

	// Build the source string with version
	var source string
	if constraint != "" && !strings.EqualFold(constraint, "latest") {
		// User specified an explicit constraint
		source = repoPath + "@" + constraint
	} else if component.Latest != "" {
		// Use latest version from catalog
		source = repoPath + "@" + component.Latest
	} else {
		return nil, fmt.Errorf("component %q has no releases in the catalog", name)
	}

	return &LookupResult{
		Name:         component.Name,
		RepoPath:     repoPath,
		Source:       source,
		Publisher:    component.Publisher,
		Description:  component.Description,
		Latest:       component.Latest,
		Dependencies: component.Dependencies,
	}, nil
}

// extractRepoPath extracts "owner/repo" from a GitHub URL.
// Expects URLs like "https://github.com/owner/repo".
func extractRepoPath(repoURL string) (string, error) {
	if repoURL == "" {
		return "", stderrors.New("repo_url is empty")
	}

	if !strings.HasPrefix(repoURL, GitHubHTTPSPrefix) {
		return "", fmt.Errorf("unsupported repo URL format: must start with %s", GitHubHTTPSPrefix)
	}

	path := strings.TrimPrefix(repoURL, GitHubHTTPSPrefix)
	path = strings.TrimSuffix(path, "/")

	// Validate it has owner/repo format
	parts := strings.Split(path, "/")
	if len(parts) < 2 {
		return "", stderrors.New("repo URL must have owner/repo format")
	}

	// Only take owner/repo, ignore any additional path segments
	return parts[0] + "/" + parts[1], nil
}
