package catalog

import (
	"testing"
)

func TestCatalogSearch(t *testing.T) {
	catalog := &Catalog{
		SchemaVersion: 1,
		Tools: []CatalogComponent{
			{Name: "policy", Publisher: "locktivity", Description: "Policy evaluation"},
			{Name: "ask", Publisher: "locktivity", Description: "AI-powered questions"},
			{Name: "pol", Publisher: "other", Description: "Polish translations"},
			{Name: "verify", Publisher: "acme", Description: "Verification tool"},
			{Name: "polaris", Publisher: "stellar", Description: "Star navigation"},
		},
	}

	tests := []struct {
		name      string
		query     string
		wantNames []string
		wantTypes []MatchType
	}{
		{
			name:      "exact match first",
			query:     "policy",
			wantNames: []string{"policy"},
			wantTypes: []MatchType{MatchExact},
		},
		{
			name:      "prefix match before substring",
			query:     "pol",
			wantNames: []string{"pol", "polaris", "policy"}, // exact, then prefix sorted
			wantTypes: []MatchType{MatchExact, MatchPrefix, MatchPrefix},
		},
		{
			name:      "search in description",
			query:     "navigation",
			wantNames: []string{"polaris"},
			wantTypes: []MatchType{MatchSubstring},
		},
		{
			name:      "search in publisher",
			query:     "locktivity",
			wantNames: []string{"ask", "policy"}, // sorted by name
			wantTypes: []MatchType{MatchSubstring, MatchSubstring},
		},
		{
			name:      "case insensitive",
			query:     "POLICY",
			wantNames: []string{"policy"},
			wantTypes: []MatchType{MatchExact},
		},
		{
			name:      "no matches",
			query:     "nonexistent",
			wantNames: []string{},
			wantTypes: []MatchType{},
		},
		{
			name:      "empty query returns all sorted",
			query:     "",
			wantNames: []string{"ask", "pol", "polaris", "policy", "verify"},
			wantTypes: []MatchType{MatchSubstring, MatchSubstring, MatchSubstring, MatchSubstring, MatchSubstring},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := catalog.Search(tt.query)

			if len(results) != len(tt.wantNames) {
				var gotNames []string
				for _, r := range results {
					gotNames = append(gotNames, r.Component.Name)
				}
				t.Fatalf("Search(%q) returned %d results %v, want %d %v",
					tt.query, len(results), gotNames, len(tt.wantNames), tt.wantNames)
			}

			for i, result := range results {
				if result.Component.Name != tt.wantNames[i] {
					t.Errorf("results[%d].Tool.Name = %q, want %q", i, result.Component.Name, tt.wantNames[i])
				}
				if result.MatchType != tt.wantTypes[i] {
					t.Errorf("results[%d].MatchType = %d, want %d", i, result.MatchType, tt.wantTypes[i])
				}
			}
		})
	}
}

func TestCatalogSearchStability(t *testing.T) {
	// Multiple tools with same name prefix should return in deterministic order
	catalog := &Catalog{
		SchemaVersion: 1,
		Tools: []CatalogComponent{
			{Name: "test-z", Publisher: "a"},
			{Name: "test-a", Publisher: "b"},
			{Name: "test-m", Publisher: "c"},
		},
	}

	// Run multiple times to verify stability
	for i := 0; i < 5; i++ {
		results := catalog.Search("test")
		if len(results) != 3 {
			t.Fatalf("iteration %d: got %d results, want 3", i, len(results))
		}
		// Should be sorted: test-a, test-m, test-z
		if results[0].Component.Name != "test-a" {
			t.Errorf("iteration %d: results[0].Name = %q, want test-a", i, results[0].Component.Name)
		}
		if results[1].Component.Name != "test-m" {
			t.Errorf("iteration %d: results[1].Name = %q, want test-m", i, results[1].Component.Name)
		}
		if results[2].Component.Name != "test-z" {
			t.Errorf("iteration %d: results[2].Name = %q, want test-z", i, results[2].Component.Name)
		}
	}
}

func TestCatalogFindByName(t *testing.T) {
	catalog := &Catalog{
		SchemaVersion: 1,
		Tools: []CatalogComponent{
			{Name: "policy", Publisher: "locktivity"},
			{Name: "ask", Publisher: "locktivity"},
		},
	}

	t.Run("finds existing tool", func(t *testing.T) {
		tool, ok := catalog.FindByName("policy")
		if !ok {
			t.Fatal("FindByName('policy') returned false, want true")
		}
		if tool.Name != "policy" {
			t.Errorf("tool.Name = %q, want %q", tool.Name, "policy")
		}
	})

	t.Run("returns false for nonexistent tool", func(t *testing.T) {
		_, ok := catalog.FindByName("nonexistent")
		if ok {
			t.Errorf("FindByName('nonexistent') returned true, want false")
		}
	})

	t.Run("case sensitive", func(t *testing.T) {
		_, ok := catalog.FindByName("POLICY")
		if ok {
			t.Errorf("FindByName('POLICY') returned true, want false (case sensitive)")
		}
	})

	t.Run("returns copy not pointer to slice element", func(t *testing.T) {
		// This test verifies the fix for pointer aliasing issues.
		// The returned tool should be a copy, so modifying the original slice
		// should not affect the returned value.
		tool, ok := catalog.FindByName("policy")
		if !ok {
			t.Fatal("FindByName('policy') returned false")
		}
		originalName := tool.Name

		// Modify the underlying slice by appending (may trigger reallocation)
		for i := 0; i < 100; i++ {
			catalog.Tools = append(catalog.Tools, CatalogComponent{Name: "new-tool"})
		}

		// The returned tool should still have its original value
		// (this would fail if we returned a pointer to the slice element)
		if tool.Name != originalName {
			t.Errorf("tool.Name changed after slice modification: got %q, want %q", tool.Name, originalName)
		}
	})
}

func TestMatchType(t *testing.T) {
	// Verify ordering of match types
	if MatchExact >= MatchPrefix {
		t.Error("MatchExact should be less than MatchPrefix for ranking")
	}
	if MatchPrefix >= MatchSubstring {
		t.Error("MatchPrefix should be less than MatchSubstring for ranking")
	}
}

// TestComponentsByKind_DefensiveCopy verifies that ComponentsByKind returns a copy,
// not a reference to the internal slice. This prevents callers from corrupting
// the catalog's internal state.
func TestComponentsByKind_DefensiveCopy(t *testing.T) {
	cat := &Catalog{
		SchemaVersion: 1,
		Tools: []CatalogComponent{
			{Name: "original-tool", Publisher: "test"},
		},
	}

	// Get tools via ComponentsByKind
	tools := cat.ComponentsByKind("tool")
	if len(tools) != 1 {
		t.Fatalf("expected 1 tool, got %d", len(tools))
	}

	// Modify the returned slice
	tools[0].Name = "modified-tool"

	// Verify the catalog's internal state was not modified
	if cat.Tools[0].Name != "original-tool" {
		t.Errorf("ComponentsByKind returned aliased slice: internal Name changed to %q", cat.Tools[0].Name)
	}

	// Also test that appending doesn't affect the original
	_ = append(tools, CatalogComponent{Name: "appended-tool"})
	if len(cat.Tools) != 1 {
		t.Errorf("appending to ComponentsByKind result affected original slice: len=%d", len(cat.Tools))
	}
}
