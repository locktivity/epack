package yamlpolicy

import (
	"bytes"
	"fmt"

	"github.com/locktivity/epack/internal/limits"
	"gopkg.in/yaml.v3"
)

// ValidateBeforeParse performs all security checks that must happen before YAML parsing.
// This includes size limit enforcement and alias bomb detection.
//
// SECURITY: Call this BEFORE yaml.Unmarshal to prevent DoS attacks.
func ValidateBeforeParse(data []byte, maxSize int64) error {
	// Check size limit
	if int64(len(data)) > maxSize {
		return fmt.Errorf("YAML data too large: %d bytes exceeds limit of %d bytes",
			len(data), maxSize)
	}

	// Check for alias bombs
	if err := CheckAliasAbuse(data); err != nil {
		return err
	}

	return nil
}

// CheckAliasAbuse scans raw YAML for potential alias bomb patterns BEFORE parsing.
// This prevents DoS attacks where aliases expand exponentially.
//
// YAML alias bombs work by defining anchors and then referencing them multiple times,
// causing exponential expansion. For example:
//
//	a: &a ["x","x"]
//	b: &b [*a,*a]
//	c: &c [*b,*b]  # Now c has 8 elements
//	d: &d [*c,*c]  # Now d has 16 elements
//
// We detect this by parsing the YAML into nodes WITHOUT expanding aliases,
// then checking the ratio of alias references to anchors.
//
// SECURITY: This must be called BEFORE yaml.Unmarshal, which expands aliases during parsing.
func CheckAliasAbuse(data []byte) error {
	// Parse into yaml.Node tree - this preserves alias/anchor structure
	// without expanding aliases (unlike yaml.Unmarshal to a Go type)
	var root yaml.Node
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&root); err != nil {
		// Let the main Unmarshal report syntax errors
		return nil
	}

	// Count anchors and aliases in the node tree
	// SECURITY: Use recursion guard to prevent stack overflow from deeply nested YAML.
	var anchors, aliases int
	guard := limits.NewRecursionGuard(limits.MaxRecursionDepth)
	if err := countAliasesWithGuard(&root, &anchors, &aliases, guard); err != nil {
		return fmt.Errorf("YAML nesting too deep: %w", err)
	}

	// If there are many more alias references than anchors, it's suspicious.
	// Normal YAML might have 1-2 aliases per anchor. Bombs have many more.
	// With 10 anchors and 100 aliases each, expansion could be 10^100 nodes.
	if anchors > 0 && aliases > anchors*limits.MaxYAMLAliasExpansion {
		return fmt.Errorf("potential YAML alias bomb detected: %d aliases for %d anchors (max ratio %d:1)",
			aliases, anchors, limits.MaxYAMLAliasExpansion)
	}

	// Also check absolute limits - even a single anchor with many aliases is dangerous
	if aliases > limits.MaxYAMLAliasExpansion*10 {
		return fmt.Errorf("potential YAML alias bomb detected: %d aliases exceeds limit", aliases)
	}

	return nil
}

// countAliasesWithGuard recursively counts anchors and aliases in a YAML node tree.
// SECURITY: Uses a recursion guard to prevent stack overflow from deeply nested YAML.
func countAliasesWithGuard(node *yaml.Node, anchors, aliases *int, guard *limits.RecursionGuard) error {
	if node == nil {
		return nil
	}

	if err := guard.Enter(); err != nil {
		return err
	}
	defer guard.Leave()

	if node.Anchor != "" {
		*anchors++
	}
	if node.Kind == yaml.AliasNode {
		*aliases++
	}

	for _, child := range node.Content {
		if err := countAliasesWithGuard(child, anchors, aliases, guard); err != nil {
			return err
		}
	}
	return nil
}

// countAliases recursively counts anchors and aliases in a YAML node tree.
// This is a convenience wrapper that uses the default recursion limit.
func countAliases(node *yaml.Node, anchors, aliases *int) {
	guard := limits.NewRecursionGuard(limits.MaxRecursionDepth)
	// Ignore error since we're using the default limit which is generous
	_ = countAliasesWithGuard(node, anchors, aliases, guard)
}

// CountAliasesInNode counts anchors and aliases in a YAML node tree.
// Returns (anchorCount, aliasCount).
// Exported for testing and advanced use cases.
func CountAliasesInNode(node *yaml.Node) (anchors, aliases int) {
	countAliases(node, &anchors, &aliases)
	return anchors, aliases
}
