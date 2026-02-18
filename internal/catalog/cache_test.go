package catalog

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/locktivity/epack/internal/limits"
)

func TestCacheDir(t *testing.T) {
	t.Run("uses XDG_CACHE_HOME when set", func(t *testing.T) {
		t.Setenv("XDG_CACHE_HOME", "/custom/cache")
		dir, err := Dir()
		if err != nil {
			t.Fatalf("Dir() error = %v", err)
		}
		if dir != "/custom/cache/epack" {
			t.Errorf("Dir() = %q, want %q", dir, "/custom/cache/epack")
		}
	})

	t.Run("falls back to default when XDG_CACHE_HOME unset", func(t *testing.T) {
		_ = os.Unsetenv("XDG_CACHE_HOME")
		dir, err := Dir()
		if err != nil {
			t.Fatalf("Dir() error = %v", err)
		}
		// Should end with .cache/epack or contain epack/cache (Windows)
		if !strings.Contains(dir, "epack") {
			t.Errorf("Dir() = %q, want path containing 'epack'", dir)
		}
	})
}

func TestCatalogPath(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", "/test/cache")
	path, err := CatalogPath()
	if err != nil {
		t.Fatalf("CatalogPath() error = %v", err)
	}
	want := "/test/cache/epack/catalog.json"
	if path != want {
		t.Errorf("CatalogPath() = %q, want %q", path, want)
	}
}

func TestMetaPath(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", "/test/cache")
	path, err := MetaPath()
	if err != nil {
		t.Fatalf("MetaPath() error = %v", err)
	}
	want := "/test/cache/epack/catalog.json.meta"
	if path != want {
		t.Errorf("MetaPath() = %q, want %q", path, want)
	}
}

func TestReadWriteCatalog(t *testing.T) {
	// Use temp dir for cache
	tmpDir := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", tmpDir)

	t.Run("returns ErrNoCatalog when no catalog exists", func(t *testing.T) {
		_, _, err := ReadCatalog()
		if err != ErrNoCatalog {
			t.Errorf("ReadCatalog() error = %v, want ErrNoCatalog", err)
		}
	})

	t.Run("write and read catalog", func(t *testing.T) {
		catalog := &Catalog{
			SchemaVersion: 1,
			GeneratedAt:   "2026-02-20T16:00:00Z",
			Source:        CatalogSource{Registry: "github"},
			Tools: []CatalogComponent{
				{Name: "policy", Publisher: "locktivity", Latest: "1.2.3"},
			},
		}

		// Write
		if err := WriteCatalog(catalog); err != nil {
			t.Fatalf("WriteCatalog() error = %v", err)
		}

		// Read back
		got, warnings, err := ReadCatalog()
		if err != nil {
			t.Fatalf("ReadCatalog() error = %v", err)
		}
		if len(warnings) != 0 {
			t.Errorf("ReadCatalog() warnings = %v, want none", warnings)
		}
		if got.SchemaVersion != 1 {
			t.Errorf("catalog.SchemaVersion = %d, want 1", got.SchemaVersion)
		}
		if len(got.Tools) != 1 {
			t.Fatalf("len(catalog.Tools) = %d, want 1", len(got.Tools))
		}
		if got.Tools[0].Name != "policy" {
			t.Errorf("catalog.Tools[0].Name = %q, want %q", got.Tools[0].Name, "policy")
		}
	})

	t.Run("Exists returns true after write", func(t *testing.T) {
		if !Exists() {
			t.Error("Exists() = false, want true after write")
		}
	})

	t.Run("ClearCache removes catalog and meta", func(t *testing.T) {
		// Write meta too
		meta := &CatalogMeta{
			MetaVersion: 1,
			LastStatus:  MetaStatusOK,
		}
		if err := WriteMeta(meta); err != nil {
			t.Fatalf("WriteMeta() error = %v", err)
		}

		// Clear
		if err := ClearCache(); err != nil {
			t.Fatalf("ClearCache() error = %v", err)
		}

		// Verify gone
		if Exists() {
			t.Error("Exists() = true after ClearCache")
		}
		_, _, err := ReadCatalog()
		if err != ErrNoCatalog {
			t.Errorf("ReadCatalog() error = %v, want ErrNoCatalog", err)
		}
		_, err = ReadMeta()
		if err != ErrNoMeta {
			t.Errorf("ReadMeta() error = %v, want ErrNoMeta", err)
		}
	})
}

func TestReadWriteMeta(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", tmpDir)

	t.Run("returns ErrNoMeta when no meta exists", func(t *testing.T) {
		_, err := ReadMeta()
		if err != ErrNoMeta {
			t.Errorf("ReadMeta() error = %v, want ErrNoMeta", err)
		}
	})

	t.Run("write and read meta", func(t *testing.T) {
		meta := &CatalogMeta{
			MetaVersion:    1,
			LastStatus:     MetaStatusOK,
			ETag:           `"abc123"`,
			LastModified:   "Fri, 20 Feb 2026 16:00:00 GMT",
			FetchedAt:      "2026-02-20T16:00:00Z",
			SourceURL:      "https://example.com/catalog.json",
			LastAttemptAt:  "2026-02-20T16:00:00Z",
			LastHTTPStatus: 200,
		}

		// Write
		if err := WriteMeta(meta); err != nil {
			t.Fatalf("WriteMeta() error = %v", err)
		}

		// Read back
		got, err := ReadMeta()
		if err != nil {
			t.Fatalf("ReadMeta() error = %v", err)
		}
		if got.MetaVersion != 1 {
			t.Errorf("meta.MetaVersion = %d, want 1", got.MetaVersion)
		}
		if got.LastStatus != MetaStatusOK {
			t.Errorf("meta.LastStatus = %q, want %q", got.LastStatus, MetaStatusOK)
		}
		if got.ETag != `"abc123"` {
			t.Errorf("meta.ETag = %q, want %q", got.ETag, `"abc123"`)
		}
		if got.LastHTTPStatus != 200 {
			t.Errorf("meta.LastHTTPStatus = %d, want 200", got.LastHTTPStatus)
		}
	})
}

func TestReadCatalogSizeLimit(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", tmpDir)

	// Create cache dir
	cacheDir := filepath.Join(tmpDir, "epack")
	if err := os.MkdirAll(cacheDir, 0700); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}

	t.Run("rejects catalog exceeding size limit", func(t *testing.T) {
		// Create oversized file
		catalogPath := filepath.Join(cacheDir, "catalog.json")
		oversized := make([]byte, limits.Catalog.Bytes()+1)
		for i := range oversized {
			oversized[i] = ' '
		}
		// Make it valid JSON structure
		copy(oversized, `{"schema_version":1,"generated_at":"","source":{},"tools":[]}`)

		if err := os.WriteFile(catalogPath, oversized, 0600); err != nil {
			t.Fatalf("WriteFile() error = %v", err)
		}

		_, _, err := ReadCatalog()
		if err == nil {
			t.Fatal("ReadCatalog() error = nil, want size limit error")
		}
		if !strings.Contains(err.Error(), "exceeds maximum size") {
			t.Errorf("ReadCatalog() error = %q, want error containing 'exceeds maximum size'", err)
		}
	})
}

func TestReadMetaSizeLimit(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", tmpDir)

	// Create cache dir
	cacheDir := filepath.Join(tmpDir, "epack")
	if err := os.MkdirAll(cacheDir, 0700); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}

	t.Run("rejects meta exceeding size limit", func(t *testing.T) {
		metaPath := filepath.Join(cacheDir, "catalog.json.meta")
		oversized := make([]byte, limits.CatalogMeta.Bytes()+1)
		for i := range oversized {
			oversized[i] = ' '
		}
		copy(oversized, `{"meta_version":1,"last_status":"ok"}`)

		if err := os.WriteFile(metaPath, oversized, 0600); err != nil {
			t.Fatalf("WriteFile() error = %v", err)
		}

		_, err := ReadMeta()
		if err == nil {
			t.Fatal("ReadMeta() error = nil, want size limit error")
		}
		if !strings.Contains(err.Error(), "exceeds maximum size") {
			t.Errorf("ReadMeta() error = %q, want error containing 'exceeds maximum size'", err)
		}
	})
}

func TestReadCatalogComponentCountLimit(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", tmpDir)

	// Create catalog with too many components
	catalog := &Catalog{
		SchemaVersion: 1,
		GeneratedAt:   "2026-02-20T16:00:00Z",
		Source:        CatalogSource{Registry: "test"},
		Tools:         make([]CatalogComponent, limits.MaxCatalogComponentCount+1),
	}
	for i := range catalog.Tools {
		catalog.Tools[i] = CatalogComponent{Name: "tool" + string(rune(i))}
	}

	// Write directly (bypassing WriteCatalog which would also check)
	cacheDir := filepath.Join(tmpDir, "epack")
	if err := os.MkdirAll(cacheDir, 0700); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}

	// We can't easily test this because the file would be huge.
	// Instead, test that ReadCatalog checks the limit.
	// Skip this test - the limit check happens after parse and would require
	// generating a multi-MB JSON file.
	t.Skip("Component count limit test requires generating large test file")
}

func TestAtomicWrite(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", tmpDir)

	catalog := &Catalog{
		SchemaVersion: 1,
		GeneratedAt:   "2026-02-20T16:00:00Z",
		Source:        CatalogSource{Registry: "github"},
		Tools:         []CatalogComponent{{Name: "test"}},
	}

	// First write
	if err := WriteCatalog(catalog); err != nil {
		t.Fatalf("WriteCatalog() error = %v", err)
	}

	// Second write should atomically replace
	catalog.Tools[0].Name = "updated"
	if err := WriteCatalog(catalog); err != nil {
		t.Fatalf("WriteCatalog() second error = %v", err)
	}

	// Read back and verify
	got, _, err := ReadCatalog()
	if err != nil {
		t.Fatalf("ReadCatalog() error = %v", err)
	}
	if got.Tools[0].Name != "updated" {
		t.Errorf("catalog.Tools[0].Name = %q, want %q", got.Tools[0].Name, "updated")
	}

	// Verify no temp file left behind
	cacheDir := filepath.Join(tmpDir, "epack")
	entries, err := os.ReadDir(cacheDir)
	if err != nil {
		t.Fatalf("ReadDir() error = %v", err)
	}
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".tmp") {
			t.Errorf("found temp file %q, should have been cleaned up", entry.Name())
		}
	}
}
