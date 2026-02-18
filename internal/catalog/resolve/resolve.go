package resolve

import (
	"fmt"
	"strings"

	"github.com/locktivity/epack/errors"
	"github.com/locktivity/epack/internal/catalog"
)

// ErrCircularDependency is returned when a circular dependency is detected.
var ErrCircularDependency = errors.E(errors.CircularDependency, "circular dependency detected", nil)

// ErrDependencyNotFound is returned when a dependency is not found in the catalog.
var ErrDependencyNotFound = errors.E(errors.DependencyNotFound, "dependency not found in catalog", nil)

// ResolvedDependency represents a component in the resolved dependency order.
type ResolvedDependency struct {
	Name       string // Component name
	IsDirect   bool   // True if this was the originally requested component
	DependedBy string // Name of the component that depends on this one (empty for direct)
}

// ResolveDependencies resolves all transitive dependencies for a component and returns
// them in topological order (dependencies first, requested component last).
//
// Uses depth-first search with cycle detection.
//
// Returns ErrCircularDependency if a circular dependency is detected.
// Returns ErrDependencyNotFound if a dependency is not found in the catalog.
func ResolveDependencies(cat *catalog.Catalog, name string) ([]ResolvedDependency, error) {
	// Track visited nodes and nodes currently in the recursion stack (for cycle detection)
	visited := make(map[string]bool)
	inStack := make(map[string]bool)

	// Track who depends on whom for better error messages
	dependedBy := make(map[string]string)

	// Result in reverse topological order (we'll reverse at the end)
	var result []ResolvedDependency

	// DFS helper
	var visit func(componentName string, path []string) error
	visit = func(componentName string, path []string) error {
		// Check for cycle
		if inStack[componentName] {
			return fmt.Errorf("%w: %s", ErrCircularDependency, formatCyclePath(path, componentName))
		}

		// Skip if already fully processed
		if visited[componentName] {
			return nil
		}

		// Mark as in current recursion stack
		inStack[componentName] = true
		newPath := append(path, componentName)

		// Find component in catalog
		component, found := catalog.FindComponentByName(cat, componentName)
		if !found {
			if len(path) > 0 {
				return fmt.Errorf("%w: %q (required by %q)", ErrDependencyNotFound, componentName, path[len(path)-1])
			}
			return fmt.Errorf("%w: %q", catalog.ErrNotFound, componentName)
		}

		// Recursively visit dependencies first
		for _, dep := range component.Dependencies {
			dependedBy[dep] = componentName
			if err := visit(dep, newPath); err != nil {
				return err
			}
		}

		// Mark as fully visited (remove from stack)
		inStack[componentName] = false
		visited[componentName] = true

		// Add to result (dependencies come first due to DFS post-order)
		result = append(result, ResolvedDependency{
			Name:       componentName,
			IsDirect:   componentName == name,
			DependedBy: dependedBy[componentName],
		})

		return nil
	}

	// Start DFS from the requested component
	if err := visit(name, nil); err != nil {
		return nil, err
	}

	return result, nil
}

// ResolveDependencyNames is a convenience function that returns just the component names
// in dependency order.
func ResolveDependencyNames(cat *catalog.Catalog, name string) ([]string, error) {
	deps, err := ResolveDependencies(cat, name)
	if err != nil {
		return nil, err
	}

	names := make([]string, len(deps))
	for i, dep := range deps {
		names[i] = dep.Name
	}
	return names, nil
}

// formatCyclePath builds a readable cycle path for error messages.
// Example: "a → b → c → a"
func formatCyclePath(path []string, cycleTo string) string {
	for i, p := range path {
		if p == cycleTo {
			cyclePath := append(path[i:], cycleTo)
			return strings.Join(cyclePath, " → ")
		}
	}
	// Fallback if cycleTo not found in path (shouldn't happen if called correctly)
	return strings.Join(append(path, cycleTo), " → ")
}
