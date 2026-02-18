package resolve

import (
	"errors"
	"testing"

	"github.com/locktivity/epack/internal/catalog"
	"github.com/locktivity/epack/internal/catalog/schema"
)

func TestResolveDependencies(t *testing.T) {
	// Build a test catalog with dependencies:
	// ai -> index
	// policy -> ai, index (index is also transitive via ai)
	// standalone -> (no deps)
	// circular1 -> circular2 -> circular1 (cycle)
	cat := &catalog.Catalog{
		SchemaVersion: 1,
		Tools: []schema.CatalogComponent{
			{
				Name:         "ai",
				RepoURL:      "https://github.com/locktivity/epack-tool-ai",
				Dependencies: []string{"index"},
			},
			{
				Name:         "index",
				RepoURL:      "https://github.com/locktivity/epack-index",
				Dependencies: nil,
			},
			{
				Name:         "policy",
				RepoURL:      "https://github.com/locktivity/epack-policy",
				Dependencies: []string{"ai", "index"},
			},
			{
				Name:         "standalone",
				RepoURL:      "https://github.com/locktivity/epack-standalone",
				Dependencies: nil,
			},
			{
				Name:         "circular1",
				RepoURL:      "https://github.com/test/circular1",
				Dependencies: []string{"circular2"},
			},
			{
				Name:         "circular2",
				RepoURL:      "https://github.com/test/circular2",
				Dependencies: []string{"circular1"},
			},
			{
				Name:         "self-referential",
				RepoURL:      "https://github.com/test/self",
				Dependencies: []string{"self-referential"},
			},
			{
				Name:         "deep-chain",
				RepoURL:      "https://github.com/test/deep-chain",
				Dependencies: []string{"level1"},
			},
			{
				Name:         "level1",
				RepoURL:      "https://github.com/test/level1",
				Dependencies: []string{"level2"},
			},
			{
				Name:         "level2",
				RepoURL:      "https://github.com/test/level2",
				Dependencies: []string{"level3"},
			},
			{
				Name:         "level3",
				RepoURL:      "https://github.com/test/level3",
				Dependencies: nil,
			},
		},
	}

	tests := []struct {
		name      string
		toolName  string
		wantNames []string
		wantErr   error
	}{
		{
			name:      "no dependencies",
			toolName:  "standalone",
			wantNames: []string{"standalone"},
		},
		{
			name:      "single dependency",
			toolName:  "ai",
			wantNames: []string{"index", "ai"},
		},
		{
			name:      "transitive dependencies with dedup",
			toolName:  "policy",
			wantNames: []string{"index", "ai", "policy"},
		},
		{
			name:      "deep chain",
			toolName:  "deep-chain",
			wantNames: []string{"level3", "level2", "level1", "deep-chain"},
		},
		{
			name:     "circular dependency",
			toolName: "circular1",
			wantErr:  ErrCircularDependency,
		},
		{
			name:     "self-referential",
			toolName: "self-referential",
			wantErr:  ErrCircularDependency,
		},
		{
			name:     "tool not found",
			toolName: "nonexistent",
			wantErr:  catalog.ErrNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			deps, err := ResolveDependencies(cat, tt.toolName)

			if tt.wantErr != nil {
				if err == nil {
					t.Fatalf("expected error %v, got nil", tt.wantErr)
				}
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("expected error %v, got %v", tt.wantErr, err)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			// Extract names
			gotNames := make([]string, len(deps))
			for i, dep := range deps {
				gotNames[i] = dep.Name
			}

			if !slicesEqual(gotNames, tt.wantNames) {
				t.Errorf("got names %v, want %v", gotNames, tt.wantNames)
			}

			// Verify the requested tool is marked as direct
			lastDep := deps[len(deps)-1]
			if !lastDep.IsDirect {
				t.Errorf("expected last dependency %q to have IsDirect=true", lastDep.Name)
			}
			if lastDep.Name != tt.toolName {
				t.Errorf("expected last dependency to be %q, got %q", tt.toolName, lastDep.Name)
			}

			// Verify dependencies are marked as not direct
			for i := 0; i < len(deps)-1; i++ {
				if deps[i].IsDirect {
					t.Errorf("expected dependency %q to have IsDirect=false", deps[i].Name)
				}
			}
		})
	}
}

func TestResolveDependencies_DependedByTracking(t *testing.T) {
	cat := &catalog.Catalog{
		SchemaVersion: 1,
		Tools: []schema.CatalogComponent{
			{
				Name:         "ai",
				RepoURL:      "https://github.com/locktivity/epack-tool-ai",
				Dependencies: []string{"index"},
			},
			{
				Name:         "index",
				RepoURL:      "https://github.com/locktivity/epack-index",
				Dependencies: nil,
			},
		},
	}

	deps, err := ResolveDependencies(cat, "ai")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(deps) != 2 {
		t.Fatalf("expected 2 dependencies, got %d", len(deps))
	}

	// index should be depended by ai
	indexDep := deps[0]
	if indexDep.Name != "index" {
		t.Errorf("expected first dep to be 'index', got %q", indexDep.Name)
	}
	if indexDep.DependedBy != "ai" {
		t.Errorf("expected index.DependedBy to be 'ai', got %q", indexDep.DependedBy)
	}

	// ai is the direct request, so DependedBy should be empty
	aiDep := deps[1]
	if aiDep.Name != "ai" {
		t.Errorf("expected second dep to be 'ai', got %q", aiDep.Name)
	}
	if aiDep.DependedBy != "" {
		t.Errorf("expected ai.DependedBy to be empty, got %q", aiDep.DependedBy)
	}
}

func TestResolveDependencies_MissingDependency(t *testing.T) {
	cat := &catalog.Catalog{
		SchemaVersion: 1,
		Tools: []schema.CatalogComponent{
			{
				Name:         "broken",
				RepoURL:      "https://github.com/test/broken",
				Dependencies: []string{"missing"},
			},
		},
	}

	_, err := ResolveDependencies(cat, "broken")
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if !errors.Is(err, ErrDependencyNotFound) {
		t.Errorf("expected ErrDependencyNotFound, got %v", err)
	}

	// Error should mention which tool requires the missing dependency
	if !containsString(err.Error(), "missing") || !containsString(err.Error(), "broken") {
		t.Errorf("error should mention both 'missing' and 'broken': %v", err)
	}
}

func TestResolveDependencyNames(t *testing.T) {
	cat := &catalog.Catalog{
		SchemaVersion: 1,
		Tools: []schema.CatalogComponent{
			{
				Name:         "ai",
				RepoURL:      "https://github.com/locktivity/epack-tool-ai",
				Dependencies: []string{"index"},
			},
			{
				Name:         "index",
				RepoURL:      "https://github.com/locktivity/epack-index",
				Dependencies: nil,
			},
		},
	}

	names, err := ResolveDependencyNames(cat, "ai")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := []string{"index", "ai"}
	if !slicesEqual(names, want) {
		t.Errorf("got %v, want %v", names, want)
	}
}

func slicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func containsString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
