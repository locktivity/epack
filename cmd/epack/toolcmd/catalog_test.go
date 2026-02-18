//go:build components

package toolcmd

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/locktivity/epack/internal/catalog"
)

func TestCatalogSearchCommand(t *testing.T) {
	// Setup: use temp dir for cache
	tmpDir := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", tmpDir)

	// Create a test catalog
	testCatalog := &catalog.Catalog{
		SchemaVersion: 1,
		GeneratedAt:   "2026-02-20T16:00:00Z",
		Source:        catalog.CatalogSource{Registry: "test"},
		Tools: []catalog.CatalogComponent{
			{Name: "policy", Publisher: "locktivity", Description: "Policy evaluation tool", Latest: "1.2.3"},
			{Name: "ask", Publisher: "locktivity", Description: "AI-powered questions", Latest: "2.0.0"},
			{Name: "verify", Publisher: "acme", Description: "Verification helper", Latest: "0.5.0"},
		},
	}

	if err := catalog.WriteCatalog(testCatalog); err != nil {
		t.Fatalf("WriteCatalog() error = %v", err)
	}

	tests := []struct {
		name       string
		args       []string
		wantInOut  []string
		wantNotOut []string
		wantErr    bool
	}{
		{
			name:      "search with no query lists all",
			args:      []string{"catalog", "search"},
			wantInOut: []string{"policy", "ask", "verify", "Found 3 tools"},
		},
		{
			name:      "search with query filters results",
			args:      []string{"catalog", "search", "policy"},
			wantInOut: []string{"policy", "locktivity"},
			wantNotOut: []string{"ask", "verify"},
		},
		{
			name:      "search by publisher",
			args:      []string{"catalog", "search", "locktivity"},
			wantInOut: []string{"policy", "ask"},
			wantNotOut: []string{"verify"},
		},
		{
			name:      "search no results",
			args:      []string{"catalog", "search", "nonexistent"},
			wantInOut: []string{"No tools matching"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := NewCommand()
			var stdout, stderr bytes.Buffer
			cmd.SetOut(&stdout)
			cmd.SetErr(&stderr)
			cmd.SetArgs(tt.args)

			err := cmd.Execute()
			if (err != nil) != tt.wantErr {
				t.Errorf("Execute() error = %v, wantErr %v", err, tt.wantErr)
			}

			out := stdout.String()
			for _, want := range tt.wantInOut {
				if !strings.Contains(out, want) {
					t.Errorf("output missing %q\nGot: %s", want, out)
				}
			}
			for _, notWant := range tt.wantNotOut {
				if strings.Contains(out, notWant) {
					t.Errorf("output contains unwanted %q\nGot: %s", notWant, out)
				}
			}
		})
	}
}

func TestCatalogSearchJSON(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", tmpDir)

	testCatalog := &catalog.Catalog{
		SchemaVersion: 1,
		GeneratedAt:   "2026-02-20T16:00:00Z",
		Source:        catalog.CatalogSource{Registry: "test"},
		Tools: []catalog.CatalogComponent{
			{Name: "policy", Publisher: "locktivity", Description: "Policy tool", Latest: "1.0.0"},
		},
	}

	if err := catalog.WriteCatalog(testCatalog); err != nil {
		t.Fatalf("WriteCatalog() error = %v", err)
	}

	cmd := NewCommand()
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetArgs([]string{"catalog", "search", "policy", "--json"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	var result CatalogSearchResult
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("json.Unmarshal() error = %v\nOutput: %s", err, stdout.String())
	}

	if result.Query != "policy" {
		t.Errorf("result.Query = %q, want %q", result.Query, "policy")
	}
	if result.Count != 1 {
		t.Errorf("result.Count = %d, want 1", result.Count)
	}
	if len(result.Results) != 1 {
		t.Fatalf("len(result.Results) = %d, want 1", len(result.Results))
	}
	if result.Results[0].Name != "policy" {
		t.Errorf("result.Results[0].Name = %q, want %q", result.Results[0].Name, "policy")
	}
	if result.Results[0].MatchType != "exact" {
		t.Errorf("result.Results[0].MatchType = %q, want %q", result.Results[0].MatchType, "exact")
	}
}

func TestCatalogSearchNoCatalog(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", tmpDir)

	// Don't create a catalog - should error with helpful message

	cmd := NewCommand()
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetArgs([]string{"catalog", "search", "anything"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("Execute() error = nil, want error about no catalog")
	}

	errMsg := err.Error()
	if !strings.Contains(errMsg, "no cached catalog") {
		t.Errorf("error = %q, want error containing 'no cached catalog'", errMsg)
	}
	if !strings.Contains(errMsg, "refresh") {
		t.Errorf("error = %q, want error mentioning 'refresh'", errMsg)
	}
}

func TestCatalogRefreshWithMockServer(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", tmpDir)

	catalogJSON := `{
		"schema_version": 1,
		"generated_at": "2026-02-20T16:00:00Z",
		"source": {"registry": "test"},
		"tools": [
			{"name": "policy", "publisher": "locktivity", "latest": "1.0.0"},
			{"name": "ask", "publisher": "locktivity", "latest": "2.0.0"}
		]
	}`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"test-etag"`)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(catalogJSON))
	}))
	defer server.Close()

	cmd := NewCommand()
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetArgs([]string{"catalog", "refresh", "--url", server.URL, "--insecure-allow-http"})

	err := cmd.Execute()
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	out := stdout.String()
	if !strings.Contains(out, "updated") {
		t.Errorf("output = %q, want 'updated'", out)
	}
	if !strings.Contains(out, "2 tools") {
		t.Errorf("output = %q, want '2 tools'", out)
	}

	// Verify catalog was cached
	cat, _, err := catalog.ReadCatalog()
	if err != nil {
		t.Fatalf("ReadCatalog() error = %v", err)
	}
	if len(cat.Tools) != 2 {
		t.Errorf("len(cat.Tools) = %d, want 2", len(cat.Tools))
	}
}

func TestCatalogRefreshJSON(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", tmpDir)

	catalogJSON := `{
		"schema_version": 1,
		"generated_at": "2026-02-20T16:00:00Z",
		"source": {"registry": "test"},
		"tools": [{"name": "policy"}]
	}`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(catalogJSON))
	}))
	defer server.Close()

	cmd := NewCommand()
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetArgs([]string{"catalog", "refresh", "--url", server.URL, "--insecure-allow-http", "--json"})

	err := cmd.Execute()
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	var result CatalogRefreshResult
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("json.Unmarshal() error = %v\nOutput: %s", err, stdout.String())
	}

	if !result.Updated {
		t.Error("result.Updated = false, want true")
	}
	if result.Status != "ok" {
		t.Errorf("result.Status = %q, want %q", result.Status, "ok")
	}
	if result.ToolCount != 1 {
		t.Errorf("result.ToolCount = %d, want 1", result.ToolCount)
	}
}

func TestCatalogRefreshNotModified(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", tmpDir)

	catalogJSON := `{
		"schema_version": 1,
		"generated_at": "2026-02-20T16:00:00Z",
		"source": {"registry": "test"},
		"tools": [{"name": "policy"}]
	}`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") == `"test-etag"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"test-etag"`)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(catalogJSON))
	}))
	defer server.Close()

	// First refresh
	cmd := NewCommand()
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetArgs([]string{"catalog", "refresh", "--url", server.URL, "--insecure-allow-http"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("First Execute() error = %v", err)
	}

	// Second refresh should get 304
	cmd2 := NewCommand()
	var stdout2 bytes.Buffer
	cmd2.SetOut(&stdout2)
	cmd2.SetArgs([]string{"catalog", "refresh", "--url", server.URL, "--insecure-allow-http"})
	if err := cmd2.Execute(); err != nil {
		t.Fatalf("Second Execute() error = %v", err)
	}

	out := stdout2.String()
	if !strings.Contains(out, "not modified") {
		t.Errorf("output = %q, want 'not modified'", out)
	}
}

func TestCatalogUpdateAlias(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", tmpDir)

	catalogJSON := `{"schema_version": 1, "generated_at": "", "source": {}, "tools": []}`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(catalogJSON))
	}))
	defer server.Close()

	// "update" should work as alias for "refresh"
	cmd := NewCommand()
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetArgs([]string{"catalog", "update", "--url", server.URL, "--insecure-allow-http"})

	err := cmd.Execute()
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	out := stdout.String()
	if !strings.Contains(out, "updated") {
		t.Errorf("output = %q, want 'updated' (update should alias to refresh)", out)
	}
}
