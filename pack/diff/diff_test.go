package diff

import (
	"path/filepath"
	"testing"

	"github.com/locktivity/epack/pack"
	"github.com/locktivity/epack/pack/builder"
)

func TestPacks_Identical(t *testing.T) {
	p1 := createTestPack(t, "test/stream", map[string][]byte{
		"artifacts/a.json": []byte(`{"key": "value"}`),
		"artifacts/b.txt":  []byte("hello"),
	})
	defer func() { _ = p1.Close() }()

	p2 := createTestPack(t, "test/stream", map[string][]byte{
		"artifacts/a.json": []byte(`{"key": "value"}`),
		"artifacts/b.txt":  []byte("hello"),
	})
	defer func() { _ = p2.Close() }()

	result := Packs(p1, p2)

	if !result.IsIdentical() {
		t.Errorf("expected identical packs, got added=%v removed=%v changed=%v",
			result.Added, result.Removed, result.Changed)
	}
	if len(result.Unchanged) != 2 {
		t.Errorf("expected 2 unchanged, got %d", len(result.Unchanged))
	}
}

func TestPacks_Added(t *testing.T) {
	p1 := createTestPack(t, "test/stream", map[string][]byte{
		"artifacts/a.json": []byte(`{}`),
	})
	defer func() { _ = p1.Close() }()

	p2 := createTestPack(t, "test/stream", map[string][]byte{
		"artifacts/a.json": []byte(`{}`),
		"artifacts/b.json": []byte(`{}`),
	})
	defer func() { _ = p2.Close() }()

	result := Packs(p1, p2)

	if len(result.Added) != 1 || result.Added[0] != "artifacts/b.json" {
		t.Errorf("expected [artifacts/b.json] added, got %v", result.Added)
	}
	if len(result.Removed) != 0 {
		t.Errorf("expected no removed, got %v", result.Removed)
	}
}

func TestPacks_Removed(t *testing.T) {
	p1 := createTestPack(t, "test/stream", map[string][]byte{
		"artifacts/a.json": []byte(`{}`),
		"artifacts/b.json": []byte(`{}`),
	})
	defer func() { _ = p1.Close() }()

	p2 := createTestPack(t, "test/stream", map[string][]byte{
		"artifacts/a.json": []byte(`{}`),
	})
	defer func() { _ = p2.Close() }()

	result := Packs(p1, p2)

	if len(result.Removed) != 1 || result.Removed[0] != "artifacts/b.json" {
		t.Errorf("expected [artifacts/b.json] removed, got %v", result.Removed)
	}
	if len(result.Added) != 0 {
		t.Errorf("expected no added, got %v", result.Added)
	}
}

func TestPacks_Changed(t *testing.T) {
	p1 := createTestPack(t, "test/stream", map[string][]byte{
		"artifacts/a.json": []byte(`{"version": 1}`),
	})
	defer func() { _ = p1.Close() }()

	p2 := createTestPack(t, "test/stream", map[string][]byte{
		"artifacts/a.json": []byte(`{"version": 2}`),
	})
	defer func() { _ = p2.Close() }()

	result := Packs(p1, p2)

	if len(result.Changed) != 1 || result.Changed[0] != "artifacts/a.json" {
		t.Errorf("expected [artifacts/a.json] changed, got %v", result.Changed)
	}
	if len(result.Unchanged) != 0 {
		t.Errorf("expected no unchanged, got %v", result.Unchanged)
	}
}

func TestPacks_Mixed(t *testing.T) {
	p1 := createTestPack(t, "test/stream", map[string][]byte{
		"artifacts/keep.json":    []byte(`{}`),
		"artifacts/change.json":  []byte(`{"v": 1}`),
		"artifacts/removed.json": []byte(`{}`),
	})
	defer func() { _ = p1.Close() }()

	p2 := createTestPack(t, "test/stream", map[string][]byte{
		"artifacts/keep.json":   []byte(`{}`),
		"artifacts/change.json": []byte(`{"v": 2}`),
		"artifacts/added.json":  []byte(`{}`),
	})
	defer func() { _ = p2.Close() }()

	result := Packs(p1, p2)

	if len(result.Added) != 1 {
		t.Errorf("expected 1 added, got %v", result.Added)
	}
	if len(result.Removed) != 1 {
		t.Errorf("expected 1 removed, got %v", result.Removed)
	}
	if len(result.Changed) != 1 {
		t.Errorf("expected 1 changed, got %v", result.Changed)
	}
	if len(result.Unchanged) != 1 {
		t.Errorf("expected 1 unchanged, got %v", result.Unchanged)
	}

	summary := result.Summary()
	if summary.Added != 1 || summary.Removed != 1 || summary.Changed != 1 || summary.Unchanged != 1 {
		t.Errorf("unexpected summary: %+v", summary)
	}
}

func TestResult_IsIdentical(t *testing.T) {
	tests := []struct {
		name     string
		result   Result
		expected bool
	}{
		{"empty", Result{}, true},
		{"only unchanged", Result{Unchanged: []string{"a"}}, true},
		{"has added", Result{Added: []string{"a"}}, false},
		{"has removed", Result{Removed: []string{"a"}}, false},
		{"has changed", Result{Changed: []string{"a"}}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.result.IsIdentical(); got != tt.expected {
				t.Errorf("IsIdentical() = %v, want %v", got, tt.expected)
			}
		})
	}
}

// createTestPack creates a temporary pack for testing.
func createTestPack(t *testing.T, stream string, artifacts map[string][]byte) *pack.Pack {
	t.Helper()

	dir := t.TempDir()
	packPath := filepath.Join(dir, "test.epack")

	b := builder.New(stream)
	for path, content := range artifacts {
		if err := b.AddBytes(path, content); err != nil {
			t.Fatalf("failed to add artifact %s: %v", path, err)
		}
	}

	if err := b.Build(packPath); err != nil {
		t.Fatalf("failed to build pack: %v", err)
	}

	p, err := pack.Open(packPath)
	if err != nil {
		t.Fatalf("failed to open pack: %v", err)
	}

	return p
}
