package catalog

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestFetchCatalog(t *testing.T) {
	// Setup temp cache dir
	tmpDir := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", tmpDir)

	catalogJSON := `{
		"schema_version": 1,
		"generated_at": "2026-02-20T16:00:00Z",
		"source": {"registry": "test"},
		"tools": [
			{"name": "policy", "publisher": "locktivity", "latest": "1.0.0"}
		]
	}`

	t.Run("successful fetch", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("ETag", `"abc123"`)
			w.Header().Set("Last-Modified", "Fri, 20 Feb 2026 16:00:00 GMT")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(catalogJSON))
		}))
		defer server.Close()

		result, err := FetchCatalog(context.Background(), FetchOptions{
			URL:               server.URL,
			HTTPClient:        server.Client(),
			InsecureAllowHTTP: true,
		})

		if err != nil {
			t.Fatalf("FetchCatalog() error = %v", err)
		}
		if !result.Updated {
			t.Error("result.Updated = false, want true")
		}
		if result.Status != MetaStatusOK {
			t.Errorf("result.Status = %q, want %q", result.Status, MetaStatusOK)
		}
		if result.HTTPStatus != 200 {
			t.Errorf("result.HTTPStatus = %d, want 200", result.HTTPStatus)
		}

		// Verify catalog was written
		cat, _, err := ReadCatalog()
		if err != nil {
			t.Fatalf("ReadCatalog() error = %v", err)
		}
		if len(cat.Tools) != 1 {
			t.Errorf("len(cat.Tools) = %d, want 1", len(cat.Tools))
		}

		// Verify meta was written
		meta, err := ReadMeta()
		if err != nil {
			t.Fatalf("ReadMeta() error = %v", err)
		}
		if meta.ETag != `"abc123"` {
			t.Errorf("meta.ETag = %q, want %q", meta.ETag, `"abc123"`)
		}
		if meta.LastStatus != MetaStatusOK {
			t.Errorf("meta.LastStatus = %q, want %q", meta.LastStatus, MetaStatusOK)
		}
	})

	t.Run("304 not modified", func(t *testing.T) {
		// Clear cache first
		_ = ClearCache()

		// First fetch to populate cache
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check for conditional headers
			if r.Header.Get("If-None-Match") == `"abc123"` {
				w.WriteHeader(http.StatusNotModified)
				return
			}
			w.Header().Set("ETag", `"abc123"`)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(catalogJSON))
		}))
		defer server.Close()

		// First fetch
		result1, err := FetchCatalog(context.Background(), FetchOptions{
			URL:               server.URL,
			HTTPClient:        server.Client(),
			InsecureAllowHTTP: true,
		})
		if err != nil {
			t.Fatalf("First FetchCatalog() error = %v", err)
		}
		if !result1.Updated {
			t.Error("First fetch: result.Updated = false, want true")
		}

		// Second fetch with ETag should get 304
		result2, err := FetchCatalog(context.Background(), FetchOptions{
			URL:               server.URL,
			HTTPClient:        server.Client(),
			InsecureAllowHTTP: true,
			ETag:              `"abc123"`,
		})
		if err != nil {
			t.Fatalf("Second FetchCatalog() error = %v", err)
		}
		if result2.Updated {
			t.Error("Second fetch: result.Updated = true, want false")
		}
		if result2.Status != MetaStatusNotModified {
			t.Errorf("result.Status = %q, want %q", result2.Status, MetaStatusNotModified)
		}
		if result2.HTTPStatus != 304 {
			t.Errorf("result.HTTPStatus = %d, want 304", result2.HTTPStatus)
		}
	})

	t.Run("If-Modified-Since header", func(t *testing.T) {
		_ = ClearCache()

		lastMod := "Fri, 20 Feb 2026 16:00:00 GMT"
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("If-Modified-Since") == lastMod {
				w.WriteHeader(http.StatusNotModified)
				return
			}
			w.Header().Set("Last-Modified", lastMod)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(catalogJSON))
		}))
		defer server.Close()

		// Fetch with Last-Modified
		result, err := FetchCatalog(context.Background(), FetchOptions{
			URL:               server.URL,
			HTTPClient:        server.Client(),
			LastModified:      lastMod,
			InsecureAllowHTTP: true,
		})
		if err != nil {
			t.Fatalf("FetchCatalog() error = %v", err)
		}
		if result.Updated {
			t.Error("result.Updated = true, want false (304)")
		}
		if result.Status != MetaStatusNotModified {
			t.Errorf("result.Status = %q, want %q", result.Status, MetaStatusNotModified)
		}
	})

	t.Run("server error", func(t *testing.T) {
		_ = ClearCache()

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()

		result, err := FetchCatalog(context.Background(), FetchOptions{
			URL:               server.URL,
			HTTPClient:        server.Client(),
			InsecureAllowHTTP: true,
		})

		if err != nil {
			t.Fatalf("FetchCatalog() error = %v (should return result with error)", err)
		}
		if result.Updated {
			t.Error("result.Updated = true, want false")
		}
		if result.Status != MetaStatusError {
			t.Errorf("result.Status = %q, want %q", result.Status, MetaStatusError)
		}
		if result.HTTPStatus != 500 {
			t.Errorf("result.HTTPStatus = %d, want 500", result.HTTPStatus)
		}
		if result.Error == nil {
			t.Error("result.Error = nil, want error")
		}

		// Verify meta records the error
		meta, err := ReadMeta()
		if err != nil {
			t.Fatalf("ReadMeta() error = %v", err)
		}
		if meta.LastStatus != MetaStatusError {
			t.Errorf("meta.LastStatus = %q, want %q", meta.LastStatus, MetaStatusError)
		}
		if meta.LastError == "" {
			t.Error("meta.LastError is empty, want error message")
		}
	})

	t.Run("invalid JSON", func(t *testing.T) {
		_ = ClearCache()

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{not valid json`))
		}))
		defer server.Close()

		result, err := FetchCatalog(context.Background(), FetchOptions{
			URL:               server.URL,
			HTTPClient:        server.Client(),
			InsecureAllowHTTP: true,
		})

		if err != nil {
			t.Fatalf("FetchCatalog() error = %v", err)
		}
		if result.Updated {
			t.Error("result.Updated = true, want false")
		}
		if result.Status != MetaStatusError {
			t.Errorf("result.Status = %q, want %q", result.Status, MetaStatusError)
		}
	})

	t.Run("context cancellation", func(t *testing.T) {
		_ = ClearCache()

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(100 * time.Millisecond)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(catalogJSON))
		}))
		defer server.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		defer cancel()

		result, err := FetchCatalog(ctx, FetchOptions{
			URL:               server.URL,
			HTTPClient:        server.Client(),
			InsecureAllowHTTP: true,
		})

		if err != nil {
			t.Fatalf("FetchCatalog() error = %v", err)
		}
		if result.Updated {
			t.Error("result.Updated = true, want false")
		}
		if result.Status != MetaStatusError {
			t.Errorf("result.Status = %q, want %q", result.Status, MetaStatusError)
		}
	})
}

func TestFetchCatalogSizeLimit(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", tmpDir)

	t.Run("rejects oversized Content-Length", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Claim huge Content-Length
			w.Header().Set("Content-Length", "999999999999")
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		result, err := FetchCatalog(context.Background(), FetchOptions{
			URL:               server.URL,
			HTTPClient:        server.Client(),
			InsecureAllowHTTP: true,
		})

		if err != nil {
			t.Fatalf("FetchCatalog() error = %v", err)
		}
		if result.Status != MetaStatusError {
			t.Errorf("result.Status = %q, want %q", result.Status, MetaStatusError)
		}
	})
}

func TestFetchCatalogSecurity(t *testing.T) {
	t.Run("rejects HTTP without InsecureAllowHTTP", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		}))
		defer server.Close()

		_, err := FetchCatalog(context.Background(), FetchOptions{
			URL:        server.URL,
			HTTPClient: server.Client(),
			// InsecureAllowHTTP: false (default)
		})

		if err == nil {
			t.Fatal("FetchCatalog() error = nil, want error for HTTP without InsecureAllowHTTP")
		}
		if got := err.Error(); got != `catalog URL must use https scheme, got "http"` {
			t.Errorf("error = %q, want https scheme error", got)
		}
	})

	t.Run("rejects untrusted host", func(t *testing.T) {
		_, err := FetchCatalog(context.Background(), FetchOptions{
			URL: "https://evil.example.com/catalog.json",
		})

		if err == nil {
			t.Fatal("FetchCatalog() error = nil, want error for untrusted host")
		}
		if got := err.Error(); got != `catalog host "evil.example.com" not in allowlist` {
			t.Errorf("error = %q, want host not in allowlist error", got)
		}
	})

	t.Run("accepts trusted host", func(t *testing.T) {
		// This test verifies that trusted hosts pass validation
		// (will fail with network error, but that's after URL validation)
		_, err := FetchCatalog(context.Background(), FetchOptions{
			URL: "https://registry.epack.dev/catalog.json",
			HTTPClient: &http.Client{
				Transport: &http.Transport{},
				Timeout:   1 * time.Millisecond, // Very short timeout to fail fast
			},
		})

		// Should not fail with URL validation error
		if err != nil {
			t.Fatalf("FetchCatalog() unexpected error = %v", err)
		}
		// Network error is returned as FetchResult.Error, not function error
	})
}

func TestGetCachedMeta(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", tmpDir)

	t.Run("returns nil when no meta", func(t *testing.T) {
		meta := GetCachedMeta()
		if meta != nil {
			t.Errorf("GetCachedMeta() = %v, want nil", meta)
		}
	})

	t.Run("returns meta when exists", func(t *testing.T) {
		testMeta := &CatalogMeta{
			MetaVersion: MetaVersion,
			LastStatus:  MetaStatusOK,
			ETag:        `"test123"`,
		}
		if err := WriteMeta(testMeta); err != nil {
			t.Fatalf("WriteMeta() error = %v", err)
		}

		meta := GetCachedMeta()
		if meta == nil {
			t.Fatal("GetCachedMeta() = nil, want meta")
		}
		if meta.ETag != `"test123"` {
			t.Errorf("meta.ETag = %q, want %q", meta.ETag, `"test123"`)
		}
	})
}
