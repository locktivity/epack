package catalog

import (
	"testing"

	"github.com/locktivity/epack/internal/catalog/schema"
)

func TestParseCatalog(t *testing.T) {
	tests := []struct {
		name    string
		json    string
		wantErr bool
		check   func(*testing.T, *Catalog)
	}{
		{
			name: "valid minimal catalog",
			json: `{
				"schema_version": 1,
				"generated_at": "2026-02-20T16:00:00Z",
				"source": {"registry": "github"},
				"tools": []
			}`,
			wantErr: false,
			check: func(t *testing.T, c *Catalog) {
				if c.SchemaVersion != 1 {
					t.Errorf("schema_version = %d, want 1", c.SchemaVersion)
				}
				if len(c.Tools) != 0 {
					t.Errorf("tools = %d, want 0", len(c.Tools))
				}
			},
		},
		{
			name: "valid catalog with tools",
			json: `{
				"schema_version": 1,
				"generated_at": "2026-02-20T16:00:00Z",
				"source": {"registry": "github", "url": "https://example.com/catalog.json"},
				"tools": [
					{
						"name": "policy",
						"publisher": "locktivity",
						"repo_url": "https://github.com/locktivity/epack-policy",
						"description": "Policy evaluation tool",
						"protocol_versions": [1],
						"latest": "1.2.3"
					}
				]
			}`,
			wantErr: false,
			check: func(t *testing.T, c *Catalog) {
				if len(c.Tools) != 1 {
					t.Fatalf("tools = %d, want 1", len(c.Tools))
				}
				tool := c.Tools[0]
				if tool.Name != "policy" {
					t.Errorf("tool.Name = %q, want %q", tool.Name, "policy")
				}
				if tool.Publisher != "locktivity" {
					t.Errorf("tool.Publisher = %q, want %q", tool.Publisher, "locktivity")
				}
				if tool.RepoURL != "https://github.com/locktivity/epack-policy" {
					t.Errorf("tool.RepoURL = %q, want correct URL", tool.RepoURL)
				}
			},
		},
		{
			name: "tolerates unknown fields",
			json: `{
				"schema_version": 1,
				"generated_at": "2026-02-20T16:00:00Z",
				"source": {"registry": "github"},
				"tools": [],
				"future_field": "ignored"
			}`,
			wantErr: false,
			check: func(t *testing.T, c *Catalog) {
				// Should parse without error, unknown field ignored
				if c.SchemaVersion != 1 {
					t.Errorf("schema_version = %d, want 1", c.SchemaVersion)
				}
			},
		},
		{
			name:    "invalid json",
			json:    `{not valid`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			catalog, err := ParseCatalog([]byte(tt.json))
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseCatalog() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.check != nil && catalog != nil {
				tt.check(t, catalog)
			}
		})
	}
}

func TestParseMeta(t *testing.T) {
	tests := []struct {
		name    string
		json    string
		wantErr bool
		check   func(*testing.T, *CatalogMeta)
	}{
		{
			name: "valid meta",
			json: `{
				"meta_version": 1,
				"last_status": "ok",
				"etag": "\"abc123\"",
				"fetched_at": "2026-02-20T16:00:00Z",
				"source_url": "https://example.com/catalog.json"
			}`,
			wantErr: false,
			check: func(t *testing.T, m *CatalogMeta) {
				if m.MetaVersion != 1 {
					t.Errorf("meta_version = %d, want 1", m.MetaVersion)
				}
				if m.LastStatus != MetaStatusOK {
					t.Errorf("last_status = %q, want %q", m.LastStatus, MetaStatusOK)
				}
				if m.ETag != `"abc123"` {
					t.Errorf("etag = %q, want %q", m.ETag, `"abc123"`)
				}
			},
		},
		{
			name: "rejects unknown fields (strict)",
			json: `{
				"meta_version": 1,
				"last_status": "ok",
				"unknown_field": "should fail"
			}`,
			wantErr: true,
		},
		{
			name:    "invalid json",
			json:    `{not valid`,
			wantErr: true,
		},
		{
			name:    "rejects trailing json data",
			json:    `{"meta_version":1,"last_status":"ok"}{"extra":"payload"}`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			meta, err := ParseMeta([]byte(tt.json))
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseMeta() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.check != nil && meta != nil {
				tt.check(t, meta)
			}
		})
	}
}

func TestCatalogValidate(t *testing.T) {
	tests := []struct {
		name         string
		catalog      *Catalog
		wantWarnings int
		checkTool    func(*testing.T, *CatalogComponent)
	}{
		{
			name: "valid repo_url unchanged",
			catalog: &Catalog{
				Tools: []CatalogComponent{
					{Name: "test", RepoURL: "https://github.com/org/repo"},
				},
			},
			wantWarnings: 0,
			checkTool: func(t *testing.T, tool *CatalogComponent) {
				if tool.RepoURL != "https://github.com/org/repo" {
					t.Errorf("RepoURL = %q, want unchanged", tool.RepoURL)
				}
			},
		},
		{
			name: "http repo_url blanked",
			catalog: &Catalog{
				Tools: []CatalogComponent{
					{Name: "test", RepoURL: "http://github.com/org/repo"},
				},
			},
			wantWarnings: 1,
			checkTool: func(t *testing.T, tool *CatalogComponent) {
				if tool.RepoURL != "" {
					t.Errorf("RepoURL = %q, want blank (http not allowed)", tool.RepoURL)
				}
			},
		},
		{
			name: "trailing slash repo_url blanked",
			catalog: &Catalog{
				Tools: []CatalogComponent{
					{Name: "test", RepoURL: "https://github.com/org/repo/"},
				},
			},
			wantWarnings: 1,
			checkTool: func(t *testing.T, tool *CatalogComponent) {
				if tool.RepoURL != "" {
					t.Errorf("RepoURL = %q, want blank (trailing slash)", tool.RepoURL)
				}
			},
		},
		{
			name: "no path repo_url blanked",
			catalog: &Catalog{
				Tools: []CatalogComponent{
					{Name: "test", RepoURL: "https://github.com"},
				},
			},
			wantWarnings: 1,
			checkTool: func(t *testing.T, tool *CatalogComponent) {
				if tool.RepoURL != "" {
					t.Errorf("RepoURL = %q, want blank (no path)", tool.RepoURL)
				}
			},
		},
		{
			name: "invalid homepage blanked",
			catalog: &Catalog{
				Tools: []CatalogComponent{
					{Name: "test", Homepage: "ftp://example.com"},
				},
			},
			wantWarnings: 1,
			checkTool: func(t *testing.T, tool *CatalogComponent) {
				if tool.Homepage != "" {
					t.Errorf("Homepage = %q, want blank (ftp not allowed)", tool.Homepage)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			warnings := tt.catalog.Validate()
			if len(warnings) != tt.wantWarnings {
				t.Errorf("Validate() returned %d warnings, want %d: %v", len(warnings), tt.wantWarnings, warnings)
			}
			if tt.checkTool != nil && len(tt.catalog.Tools) > 0 {
				tt.checkTool(t, &tt.catalog.Tools[0])
			}
		})
	}
}

func TestValidateRepoURL(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"", ""},
		{"https://github.com/org/repo", "https://github.com/org/repo"},
		{"https://gitlab.com/org/repo", "https://gitlab.com/org/repo"},
		{"http://github.com/org/repo", ""},   // http not allowed
		{"https://github.com/org/repo/", ""}, // trailing slash
		{"https://github.com", ""},           // no path
		{"git://github.com/org/repo", ""},    // wrong scheme
		{"github.com/org/repo", ""},          // missing scheme
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := schema.ValidateRepoURL(tt.input)
			if got != tt.want {
				t.Errorf("ValidateRepoURL(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestMetaStatus(t *testing.T) {
	// Verify status constants
	if MetaStatusOK != "ok" {
		t.Errorf("MetaStatusOK = %q, want %q", MetaStatusOK, "ok")
	}
	if MetaStatusNotModified != "not_modified" {
		t.Errorf("MetaStatusNotModified = %q, want %q", MetaStatusNotModified, "not_modified")
	}
	if MetaStatusError != "error" {
		t.Errorf("MetaStatusError = %q, want %q", MetaStatusError, "error")
	}
}
