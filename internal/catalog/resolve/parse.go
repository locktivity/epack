package resolve

import (
	"fmt"
	"strings"

	"github.com/locktivity/epack/internal/component/config"
	"github.com/locktivity/epack/internal/component/semver"
)

// ParsedComponent represents a parsed component argument like "ask" or "ask@^1.0".
type ParsedComponent struct {
	Name       string // Component name (e.g., "ask")
	Constraint string // Version constraint (e.g., "^1.0", "latest", "v1.2.3")
}

// ParseComponentArg parses a component argument in the format "name" or "name@constraint".
//
// Examples:
//
//	"ask"        -> {Name: "ask", Constraint: "latest"}
//	"ask@latest" -> {Name: "ask", Constraint: "latest"}
//	"ask@^1.0"   -> {Name: "ask", Constraint: "^1.0"}
//	"ask@v1.2.3" -> {Name: "ask", Constraint: "v1.2.3"}
//	"ask@~1.2"   -> {Name: "ask", Constraint: "~1.2"}
func ParseComponentArg(arg string) (*ParsedComponent, error) {
	arg = strings.TrimSpace(arg)
	if arg == "" {
		return nil, fmt.Errorf("component argument cannot be empty")
	}

	// Split on first "@" to separate name from constraint
	name, constraint, hasConstraint := strings.Cut(arg, "@")

	name = strings.TrimSpace(name)
	if name == "" {
		return nil, fmt.Errorf("component name cannot be empty")
	}

	// Default to "latest" if no constraint specified
	if !hasConstraint {
		constraint = "latest"
	} else {
		constraint = strings.TrimSpace(constraint)
		if constraint == "" {
			return nil, fmt.Errorf("version constraint cannot be empty after '@'")
		}
	}

	// Validate the component name
	if err := config.ValidateToolName(name); err != nil {
		return nil, fmt.Errorf("invalid component name: %w", err)
	}

	// Validate the constraint using semver package
	if _, err := semver.ParseConstraint(constraint); err != nil {
		return nil, fmt.Errorf("invalid version constraint %q: %w", constraint, err)
	}

	return &ParsedComponent{
		Name:       name,
		Constraint: constraint,
	}, nil
}

// IsLatest returns true if the constraint is "latest".
func (p *ParsedComponent) IsLatest() bool {
	return strings.EqualFold(p.Constraint, "latest")
}
