// Package yamlutil provides utilities for deterministic YAML serialization.
package yamlutil

import (
	"bytes"
	"sort"

	"github.com/locktivity/epack/internal/safeyaml"
)

// MarshalDeterministic serializes a value with deterministic map ordering.
// This ensures output is consistent across runs, preventing spurious diffs
// and enabling reliable content comparison.
func MarshalDeterministic(v interface{}) ([]byte, error) {
	// First, marshal to a safeyaml.Node tree
	var node safeyaml.Node
	if err := node.Encode(v); err != nil {
		return nil, err
	}

	// Sort all map nodes recursively
	SortYAMLNode(&node)

	// Marshal the sorted node tree to bytes
	var buf bytes.Buffer
	enc := safeyaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&node); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// SortYAMLNode recursively sorts all map keys in a YAML node tree.
func SortYAMLNode(node *safeyaml.Node) {
	if node == nil {
		return
	}

	switch node.Kind {
	case safeyaml.DocumentNode:
		// Document contains content nodes
		for _, child := range node.Content {
			SortYAMLNode(child)
		}

	case safeyaml.MappingNode:
		// MappingNode.Content is [key1, val1, key2, val2, ...]
		// We need to sort by keys while keeping key-value pairs together
		if len(node.Content) > 2 {
			// Build pairs
			type kvPair struct {
				key   *safeyaml.Node
				value *safeyaml.Node
			}
			pairs := make([]kvPair, 0, len(node.Content)/2)
			for i := 0; i < len(node.Content); i += 2 {
				pairs = append(pairs, kvPair{
					key:   node.Content[i],
					value: node.Content[i+1],
				})
			}

			// Sort pairs by key value
			sort.Slice(pairs, func(i, j int) bool {
				return pairs[i].key.Value < pairs[j].key.Value
			})

			// Rebuild content in sorted order
			node.Content = make([]*safeyaml.Node, 0, len(pairs)*2)
			for _, pair := range pairs {
				node.Content = append(node.Content, pair.key, pair.value)
			}
		}

		// Recursively sort values
		for i := 1; i < len(node.Content); i += 2 {
			SortYAMLNode(node.Content[i])
		}

	case safeyaml.SequenceNode:
		// Recursively sort sequence elements (but don't reorder them)
		for _, child := range node.Content {
			SortYAMLNode(child)
		}
	}
}
