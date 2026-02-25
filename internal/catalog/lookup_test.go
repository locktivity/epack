package catalog

import (
	"errors"
	"testing"

	"github.com/locktivity/epack/internal/catalog/schema"
)

func TestLookupComponentInCatalog(t *testing.T) {
	catalog := &Catalog{
		SchemaVersion: 1,
		Tools: []schema.CatalogComponent{
			{
				Name:         "ai",
				Publisher:    "Locktivity",
				RepoURL:      "https://github.com/locktivity/epack-tool-ai",
				Description:  "AI-powered Q&A over pack contents",
				Latest:       "v2.0.1",
				Dependencies: []string{"index"},
			},
			{
				Name:         "index",
				Publisher:    "Locktivity",
				RepoURL:      "https://github.com/locktivity/epack-index",
				Description:  "Index evidence packs for searching",
				Latest:       "v1.2.0",
				Dependencies: nil,
			},
			{
				Name:      "no-repo",
				Publisher: "Test",
				RepoURL:   "",
			},
			{
				Name:      "bad-repo",
				Publisher: "Test",
				RepoURL:   "not-a-valid-url",
			},
			{
				Name:      "no-releases",
				Publisher: "Test",
				RepoURL:   "https://github.com/test/no-releases",
				Latest:    "",
			},
		},
		Collectors: []schema.CatalogComponent{
			{
				Name:        "github",
				Publisher:   "Locktivity",
				RepoURL:     "https://github.com/locktivity/epack-collector-github",
				Description: "Collects GitHub organization security posture metrics",
				Latest:      "v0.1.0",
			},
		},
	}

	tests := []struct {
		name           string
		componentName  string
		kind           ComponentKind
		constraint     string
		wantName       string
		wantRepoPath   string
		wantSource     string
		wantDeps       []string
		wantErr        bool
		wantErrContain string
	}{
		{
			name:          "tool found with latest constraint",
			componentName: "ai",
			kind:          KindTool,
			constraint:    "latest",
			wantName:      "ai",
			wantRepoPath:  "locktivity/epack-tool-ai",
			wantSource:    "locktivity/epack-tool-ai@v2.0.1",
			wantDeps:      []string{"index"},
		},
		{
			name:          "tool found with empty constraint",
			componentName: "ai",
			kind:          KindTool,
			constraint:    "",
			wantName:      "ai",
			wantRepoPath:  "locktivity/epack-tool-ai",
			wantSource:    "locktivity/epack-tool-ai@v2.0.1",
			wantDeps:      []string{"index"},
		},
		{
			name:          "tool found with caret constraint",
			componentName: "ai",
			kind:          KindTool,
			constraint:    "^2.0",
			wantName:      "ai",
			wantRepoPath:  "locktivity/epack-tool-ai",
			wantSource:    "locktivity/epack-tool-ai@^2.0",
			wantDeps:      []string{"index"},
		},
		{
			name:          "tool found with exact version",
			componentName: "ai",
			kind:          KindTool,
			constraint:    "v2.0.1",
			wantName:      "ai",
			wantRepoPath:  "locktivity/epack-tool-ai",
			wantSource:    "locktivity/epack-tool-ai@v2.0.1",
			wantDeps:      []string{"index"},
		},
		{
			name:          "tool with no dependencies",
			componentName: "index",
			kind:          KindTool,
			constraint:    "latest",
			wantName:      "index",
			wantRepoPath:  "locktivity/epack-index",
			wantSource:    "locktivity/epack-index@v1.2.0",
			wantDeps:      nil,
		},
		{
			name:          "collector found",
			componentName: "github",
			kind:          KindCollector,
			constraint:    "latest",
			wantName:      "github",
			wantRepoPath:  "locktivity/epack-collector-github",
			wantSource:    "locktivity/epack-collector-github@v0.1.0",
			wantDeps:      nil,
		},
		{
			name:          "collector with version constraint",
			componentName: "github",
			kind:          KindCollector,
			constraint:    "^0.1",
			wantName:      "github",
			wantRepoPath:  "locktivity/epack-collector-github",
			wantSource:    "locktivity/epack-collector-github@^0.1",
			wantDeps:      nil,
		},
		{
			name:           "tool not found",
			componentName:  "nonexistent",
			kind:           KindTool,
			constraint:     "latest",
			wantErr:        true,
			wantErrContain: "not found",
		},
		{
			name:           "collector not found",
			componentName:  "nonexistent",
			kind:           KindCollector,
			constraint:     "latest",
			wantErr:        true,
			wantErrContain: "not found",
		},
		{
			name:           "tool name searched as collector fails",
			componentName:  "ai",
			kind:           KindCollector,
			constraint:     "latest",
			wantErr:        true,
			wantErrContain: "not found",
		},
		{
			name:           "collector name searched as tool fails",
			componentName:  "github",
			kind:           KindTool,
			constraint:     "latest",
			wantErr:        true,
			wantErrContain: "not found",
		},
		{
			name:           "empty repo url",
			componentName:  "no-repo",
			kind:           KindTool,
			constraint:     "latest",
			wantErr:        true,
			wantErrContain: "repo_url is empty",
		},
		{
			name:           "invalid repo url",
			componentName:  "bad-repo",
			kind:           KindTool,
			constraint:     "latest",
			wantErr:        true,
			wantErrContain: "unsupported repo URL format",
		},
		{
			name:           "component with no releases",
			componentName:  "no-releases",
			kind:           KindTool,
			constraint:     "latest",
			wantErr:        true,
			wantErrContain: "no releases in the catalog",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := LookupComponentInCatalog(catalog, tt.componentName, tt.kind, tt.constraint)

			if tt.wantErr {
				if err == nil {
					t.Errorf("LookupComponentInCatalog() expected error, got nil")
					return
				}
				if tt.wantErrContain != "" && !containsString(err.Error(), tt.wantErrContain) {
					t.Errorf("LookupComponentInCatalog() error = %v, want error containing %q", err, tt.wantErrContain)
				}
				return
			}

			if err != nil {
				t.Errorf("LookupComponentInCatalog() unexpected error: %v", err)
				return
			}

			if got.Name != tt.wantName {
				t.Errorf("Name = %q, want %q", got.Name, tt.wantName)
			}
			if got.RepoPath != tt.wantRepoPath {
				t.Errorf("RepoPath = %q, want %q", got.RepoPath, tt.wantRepoPath)
			}
			if got.Source != tt.wantSource {
				t.Errorf("Source = %q, want %q", got.Source, tt.wantSource)
			}
			if !slicesEqual(got.Dependencies, tt.wantDeps) {
				t.Errorf("Dependencies = %v, want %v", got.Dependencies, tt.wantDeps)
			}
		})
	}
}

func TestExtractRepoPath(t *testing.T) {
	tests := []struct {
		name    string
		repoURL string
		want    string
		wantErr bool
	}{
		{
			name:    "standard github url",
			repoURL: "https://github.com/locktivity/epack-tool-ai",
			want:    "locktivity/epack-tool-ai",
		},
		{
			name:    "github url with trailing slash",
			repoURL: "https://github.com/locktivity/epack-tool-ai/",
			want:    "locktivity/epack-tool-ai",
		},
		{
			name:    "github url with extra path",
			repoURL: "https://github.com/locktivity/epack-tool-ai/tree/main",
			want:    "locktivity/epack-tool-ai",
		},
		{
			name:    "empty url",
			repoURL: "",
			wantErr: true,
		},
		{
			name:    "non-github url",
			repoURL: "https://gitlab.com/owner/repo",
			wantErr: true,
		},
		{
			name:    "http url (not https)",
			repoURL: "http://github.com/owner/repo",
			wantErr: true,
		},
		{
			name:    "missing repo name",
			repoURL: "https://github.com/owner",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := extractRepoPath(tt.repoURL)

			if tt.wantErr {
				if err == nil {
					t.Errorf("extractRepoPath(%q) expected error, got nil", tt.repoURL)
				}
				return
			}

			if err != nil {
				t.Errorf("extractRepoPath(%q) unexpected error: %v", tt.repoURL, err)
				return
			}

			if got != tt.want {
				t.Errorf("extractRepoPath(%q) = %q, want %q", tt.repoURL, got, tt.want)
			}
		})
	}
}

func TestErrNotFound(t *testing.T) {
	catalog := &Catalog{
		SchemaVersion: 1,
		Tools:         []schema.CatalogComponent{},
	}

	_, err := LookupComponentInCatalog(catalog, "nonexistent", KindTool, "latest")
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if !errors.Is(err, ErrNotFound) {
		t.Errorf("expected errors.Is(err, ErrNotFound) to be true, got false; err = %v", err)
	}
}

// containsString checks if s contains substr (case-sensitive).
func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && findSubstring(s, substr)))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// slicesEqual compares two string slices for equality.
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
