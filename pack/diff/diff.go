// Package diff provides comparison utilities for evidence packs.
package diff

import (
	"sort"

	"github.com/locktivity/epack/pack"
)

// Result contains the differences between two packs.
type Result struct {
	Pack1 PackInfo `json:"pack1"`
	Pack2 PackInfo `json:"pack2"`

	Added     []string `json:"added"`     // Paths only in pack2
	Removed   []string `json:"removed"`   // Paths only in pack1
	Changed   []string `json:"changed"`   // Paths in both with different digests
	Unchanged []string `json:"unchanged"` // Paths in both with same digest
}

// PackInfo contains identifying information about a pack.
type PackInfo struct {
	Stream     string `json:"stream"`
	PackDigest string `json:"pack_digest"`
}

// IsIdentical returns true if the packs have no differences.
func (r *Result) IsIdentical() bool {
	return len(r.Added) == 0 && len(r.Removed) == 0 && len(r.Changed) == 0
}

// Summary returns counts of each difference type.
func (r *Result) Summary() Summary {
	return Summary{
		Added:     len(r.Added),
		Removed:   len(r.Removed),
		Changed:   len(r.Changed),
		Unchanged: len(r.Unchanged),
	}
}

// Summary contains counts of differences.
type Summary struct {
	Added     int `json:"added_count"`
	Removed   int `json:"removed_count"`
	Changed   int `json:"changed_count"`
	Unchanged int `json:"unchanged_count"`
}

// Packs compares two packs and returns the differences.
func Packs(p1, p2 *pack.Pack) *Result {
	m1, m2 := p1.Manifest(), p2.Manifest()

	result := &Result{
		Pack1:     PackInfo{Stream: m1.Stream, PackDigest: m1.PackDigest},
		Pack2:     PackInfo{Stream: m2.Stream, PackDigest: m2.PackDigest},
		Added:     []string{},
		Removed:   []string{},
		Changed:   []string{},
		Unchanged: []string{},
	}

	artifacts1 := buildArtifactMap(m1.Artifacts)
	artifacts2 := buildArtifactMap(m2.Artifacts)

	// Check for removed/changed artifacts
	for path, a1 := range artifacts1 {
		if a2, exists := artifacts2[path]; exists {
			if a1.Digest != a2.Digest {
				result.Changed = append(result.Changed, path)
			} else {
				result.Unchanged = append(result.Unchanged, path)
			}
		} else {
			result.Removed = append(result.Removed, path)
		}
	}

	// Check for added artifacts
	for path := range artifacts2 {
		if _, exists := artifacts1[path]; !exists {
			result.Added = append(result.Added, path)
		}
	}

	// Sort for deterministic output
	sort.Strings(result.Added)
	sort.Strings(result.Removed)
	sort.Strings(result.Changed)
	sort.Strings(result.Unchanged)

	return result
}

func buildArtifactMap(artifacts []pack.Artifact) map[string]pack.Artifact {
	m := make(map[string]pack.Artifact)
	for _, a := range artifacts {
		m[a.Path] = a
	}
	return m
}
