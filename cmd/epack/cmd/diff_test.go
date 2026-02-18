package cmd

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/locktivity/epack/internal/cli/output"
	"github.com/locktivity/epack/pack"
	"github.com/locktivity/epack/pack/builder"
	"github.com/locktivity/epack/pack/diff"
)

// createTestPack creates a test pack with the given artifacts.
// artifacts is a map of path -> content.
// The builder sorts artifacts by path, so output is deterministic.
func createTestPack(t *testing.T, stream string, artifacts map[string][]byte) string {
	t.Helper()
	b := builder.New(stream)
	for path, content := range artifacts {
		if err := b.AddBytes(path, content); err != nil {
			t.Fatalf("AddBytes(%q) failed: %v", path, err)
		}
	}
	outputPath := filepath.Join(t.TempDir(), "test.pack")
	if err := b.Build(outputPath); err != nil {
		t.Fatalf("Build failed: %v", err)
	}
	return outputPath
}

func TestDiffPacks_AddedRemovedChanged(t *testing.T) {
	// Create pack1 with artifacts a, b, c
	pack1 := createTestPack(t, "test/v1", map[string][]byte{
		"artifacts/a.json": []byte(`{"value": 1}`),
		"artifacts/b.json": []byte(`{"value": 2}`),
		"artifacts/c.json": []byte(`{"value": 3}`),
	})

	// Create pack2 with artifacts b (changed), c (same), d (new)
	pack2 := createTestPack(t, "test/v2", map[string][]byte{
		"artifacts/b.json": []byte(`{"value": 200}`), // changed
		"artifacts/c.json": []byte(`{"value": 3}`),   // same
		"artifacts/d.json": []byte(`{"value": 4}`),   // added
	})

	// Open both packs
	p1, err := pack.Open(pack1)
	if err != nil {
		t.Fatalf("Open pack1 failed: %v", err)
	}
	defer func() { _ = p1.Close() }()

	p2, err := pack.Open(pack2)
	if err != nil {
		t.Fatalf("Open pack2 failed: %v", err)
	}
	defer func() { _ = p2.Close() }()

	// Use diff.Packs
	result := diff.Packs(p1, p2)

	// Verify
	if len(result.Added) != 1 || result.Added[0] != "artifacts/d.json" {
		t.Errorf("added = %v, want [artifacts/d.json]", result.Added)
	}
	if len(result.Removed) != 1 || result.Removed[0] != "artifacts/a.json" {
		t.Errorf("removed = %v, want [artifacts/a.json]", result.Removed)
	}
	if len(result.Changed) != 1 || result.Changed[0] != "artifacts/b.json" {
		t.Errorf("changed = %v, want [artifacts/b.json]", result.Changed)
	}
	if len(result.Unchanged) != 1 || result.Unchanged[0] != "artifacts/c.json" {
		t.Errorf("unchanged = %v, want [artifacts/c.json]", result.Unchanged)
	}
}

func TestDiffPacks_Identical(t *testing.T) {
	// Create two identical packs
	content := map[string][]byte{
		"artifacts/a.json": []byte(`{"value": 1}`),
		"artifacts/b.json": []byte(`{"value": 2}`),
	}
	pack1 := createTestPack(t, "test/v1", content)
	pack2 := createTestPack(t, "test/v1", content)

	p1, err := pack.Open(pack1)
	if err != nil {
		t.Fatalf("Open pack1 failed: %v", err)
	}
	defer func() { _ = p1.Close() }()

	p2, err := pack.Open(pack2)
	if err != nil {
		t.Fatalf("Open pack2 failed: %v", err)
	}
	defer func() { _ = p2.Close() }()

	// Use diff.Packs
	result := diff.Packs(p1, p2)

	if !result.IsIdentical() {
		t.Errorf("expected identical packs")
	}
	if len(result.Added) != 0 {
		t.Errorf("added = %d, want 0", len(result.Added))
	}
	if len(result.Removed) != 0 {
		t.Errorf("removed = %d, want 0", len(result.Removed))
	}
	if len(result.Changed) != 0 {
		t.Errorf("changed = %d, want 0", len(result.Changed))
	}
	if len(result.Unchanged) != 2 {
		t.Errorf("unchanged = %d, want 2", len(result.Unchanged))
	}
}

func TestDiffArtifactContent_JSON(t *testing.T) {
	// Create two packs with JSON content that differs
	pack1 := createTestPack(t, "test/v1", map[string][]byte{
		"artifacts/config.json": []byte(`{"name": "app", "version": "1.0", "debug": false}`),
	})
	pack2 := createTestPack(t, "test/v2", map[string][]byte{
		"artifacts/config.json": []byte(`{"name": "app", "version": "2.0", "debug": true, "new": "field"}`),
	})

	p1, err := pack.Open(pack1)
	if err != nil {
		t.Fatalf("Open pack1 failed: %v", err)
	}
	defer func() { _ = p1.Close() }()

	p2, err := pack.Open(pack2)
	if err != nil {
		t.Fatalf("Open pack2 failed: %v", err)
	}
	defer func() { _ = p2.Close() }()

	// Read artifact content
	data1, err := p1.ReadArtifact("artifacts/config.json")
	if err != nil {
		t.Fatalf("ReadArtifact pack1 failed: %v", err)
	}
	data2, err := p2.ReadArtifact("artifacts/config.json")
	if err != nil {
		t.Fatalf("ReadArtifact pack2 failed: %v", err)
	}

	// Parse JSON
	var json1, json2 map[string]interface{}
	if err := json.Unmarshal(data1, &json1); err != nil {
		t.Fatalf("Unmarshal data1 failed: %v", err)
	}
	if err := json.Unmarshal(data2, &json2); err != nil {
		t.Fatalf("Unmarshal data2 failed: %v", err)
	}

	// Verify differences
	if json1["name"] != json2["name"] {
		t.Error("name should be equal")
	}
	if json1["version"] == json2["version"] {
		t.Error("version should differ")
	}
	if json1["debug"] == json2["debug"] {
		t.Error("debug should differ")
	}
	if _, exists := json1["new"]; exists {
		t.Error("new should not exist in json1")
	}
	if _, exists := json2["new"]; !exists {
		t.Error("new should exist in json2")
	}
}

func TestDiffArtifactContent_Text(t *testing.T) {
	// Create two packs with text content that differs
	pack1 := createTestPack(t, "test/v1", map[string][]byte{
		"artifacts/readme.txt": []byte("Line 1\nLine 2\nLine 3"),
	})
	pack2 := createTestPack(t, "test/v2", map[string][]byte{
		"artifacts/readme.txt": []byte("Line 1\nLine 2 modified\nLine 3\nLine 4"),
	})

	p1, err := pack.Open(pack1)
	if err != nil {
		t.Fatalf("Open pack1 failed: %v", err)
	}
	defer func() { _ = p1.Close() }()

	p2, err := pack.Open(pack2)
	if err != nil {
		t.Fatalf("Open pack2 failed: %v", err)
	}
	defer func() { _ = p2.Close() }()

	// Use diff.Content
	result, err := diff.Content(p1, p2, "artifacts/readme.txt")
	if err != nil {
		t.Fatalf("diff.Content failed: %v", err)
	}

	if result.Status != diff.ContentDifferent {
		t.Errorf("Status = %v, want ContentDifferent", result.Status)
	}
	if result.IsJSON {
		t.Error("IsJSON = true, want false")
	}

	// Count operations
	var additions, removals, equals int
	for _, d := range result.TextDiff {
		switch d.Type {
		case diff.LineAdded:
			additions++
		case diff.LineRemoved:
			removals++
		case diff.LineEqual:
			equals++
		}
	}

	// Line 1 and Line 3 should be equal
	// Line 2 removed, Line 2 modified added
	// Line 4 added
	if equals != 2 {
		t.Errorf("equals = %d, want 2", equals)
	}
	if additions < 2 {
		t.Errorf("additions = %d, want at least 2", additions)
	}
	if removals < 1 {
		t.Errorf("removals = %d, want at least 1", removals)
	}
}

func TestDiffArtifactContent_Identical(t *testing.T) {
	content := []byte(`{"same": "content"}`)
	pack1 := createTestPack(t, "test/v1", map[string][]byte{
		"artifacts/data.json": content,
	})
	pack2 := createTestPack(t, "test/v2", map[string][]byte{
		"artifacts/data.json": content,
	})

	p1, err := pack.Open(pack1)
	if err != nil {
		t.Fatalf("Open pack1 failed: %v", err)
	}
	defer func() { _ = p1.Close() }()

	p2, err := pack.Open(pack2)
	if err != nil {
		t.Fatalf("Open pack2 failed: %v", err)
	}
	defer func() { _ = p2.Close() }()

	data1, _ := p1.ReadArtifact("artifacts/data.json")
	data2, _ := p2.ReadArtifact("artifacts/data.json")

	if !bytes.Equal(data1, data2) {
		t.Error("contents should be equal")
	}
}

func TestDiffArtifactContent_OnlyInOnePack(t *testing.T) {
	pack1 := createTestPack(t, "test/v1", map[string][]byte{
		"artifacts/only1.json": []byte(`{"only": "pack1"}`),
	})
	pack2 := createTestPack(t, "test/v2", map[string][]byte{
		"artifacts/only2.json": []byte(`{"only": "pack2"}`),
	})

	p1, err := pack.Open(pack1)
	if err != nil {
		t.Fatalf("Open pack1 failed: %v", err)
	}
	defer func() { _ = p1.Close() }()

	p2, err := pack.Open(pack2)
	if err != nil {
		t.Fatalf("Open pack2 failed: %v", err)
	}
	defer func() { _ = p2.Close() }()

	// only1.json should not be readable from pack2
	_, err = p2.ReadArtifact("artifacts/only1.json")
	if err == nil {
		t.Error("expected error reading only1.json from pack2")
	}

	// only2.json should not be readable from pack1
	_, err = p1.ReadArtifact("artifacts/only2.json")
	if err == nil {
		t.Error("expected error reading only2.json from pack1")
	}
}

func TestDiffOutput_JSON(t *testing.T) {
	// Test that diffOutput struct serializes correctly
	output := diffOutput{
		Pack1: diffPackInfo{
			Path:       "/path/to/pack1",
			Stream:     "test/v1",
			PackDigest: "sha256:abc123",
		},
		Pack2: diffPackInfo{
			Path:       "/path/to/pack2",
			Stream:     "test/v2",
			PackDigest: "sha256:def456",
		},
		Added:     []string{"artifacts/new.json"},
		Removed:   []string{"artifacts/old.json"},
		Changed:   []string{"artifacts/modified.json"},
		Unchanged: []string{"artifacts/same.json"},
		Summary: diffSummary{
			AddedCount:     1,
			RemovedCount:   1,
			ChangedCount:   1,
			UnchangedCount: 1,
		},
	}

	data, err := json.Marshal(output)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	// Verify it can be unmarshaled back
	var decoded diffOutput
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if decoded.Pack1.Stream != "test/v1" {
		t.Errorf("Pack1.Stream = %q, want %q", decoded.Pack1.Stream, "test/v1")
	}
	if len(decoded.Added) != 1 {
		t.Errorf("len(Added) = %d, want 1", len(decoded.Added))
	}
	if decoded.Summary.AddedCount != 1 {
		t.Errorf("Summary.AddedCount = %d, want 1", decoded.Summary.AddedCount)
	}
}

func TestDiffNestedJSON(t *testing.T) {
	// Test diffing nested JSON structures using diff.Content
	pack1 := createTestPack(t, "test/v1", map[string][]byte{
		"artifacts/config.json": []byte(`{"name": "app", "config": {"debug": false, "timeout": 30}, "items": ["a", "b"]}`),
	})
	pack2 := createTestPack(t, "test/v2", map[string][]byte{
		"artifacts/config.json": []byte(`{"name": "app", "config": {"debug": true, "timeout": 60, "newKey": "value"}, "items": ["a", "b", "c"]}`),
	})

	p1, err := pack.Open(pack1)
	if err != nil {
		t.Fatalf("Open pack1 failed: %v", err)
	}
	defer func() { _ = p1.Close() }()

	p2, err := pack.Open(pack2)
	if err != nil {
		t.Fatalf("Open pack2 failed: %v", err)
	}
	defer func() { _ = p2.Close() }()

	result, err := diff.Content(p1, p2, "artifacts/config.json")
	if err != nil {
		t.Fatalf("diff.Content failed: %v", err)
	}

	if result.Status != diff.ContentDifferent {
		t.Errorf("Status = %v, want ContentDifferent", result.Status)
	}
	if !result.IsJSON {
		t.Error("IsJSON = false, want true")
	}

	// Should have changes for config.debug, config.timeout, config.newKey, and items[2]
	if len(result.JSONChanges) < 4 {
		t.Errorf("expected at least 4 JSON changes, got %d", len(result.JSONChanges))
	}
}

func TestDiffEmptyArrays(t *testing.T) {
	// Ensure empty slices are initialized properly for JSON output
	added := []string{}
	removed := []string{}
	changed := []string{}
	unchanged := []string{}

	diffOut := diffOutput{
		Added:     added,
		Removed:   removed,
		Changed:   changed,
		Unchanged: unchanged,
	}

	data, err := json.Marshal(diffOut)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	// Should contain empty arrays, not null
	if strings.Contains(string(data), "null") {
		t.Errorf("JSON output contains null instead of empty array: %s", data)
	}
	if !strings.Contains(string(data), `"added":[]`) {
		t.Errorf("JSON output missing empty added array: %s", data)
	}
}

// Golden file tests for diff output

func TestDiff_GoldenHuman(t *testing.T) {
	// Create two packs with differences
	pack1Path := createTestPack(t, "test/v1", map[string][]byte{
		"artifacts/a.json": []byte(`{"value": 1}`),
		"artifacts/b.json": []byte(`{"value": 2}`),
		"artifacts/c.json": []byte(`{"value": 3}`),
	})
	pack2Path := createTestPack(t, "test/v2", map[string][]byte{
		"artifacts/b.json": []byte(`{"value": 200}`),
		"artifacts/c.json": []byte(`{"value": 3}`),
		"artifacts/d.json": []byte(`{"value": 4}`),
	})

	var buf bytes.Buffer
	var errBuf bytes.Buffer
	out = output.New(&buf, &errBuf, output.Options{
		Quiet:   false,
		JSON:    false,
		NoColor: true,
		Verbose: false,
	})

	diffArtifact = ""
	diffContext = 3

	err := runDiff(nil, []string{pack1Path, pack2Path})
	if err != nil {
		t.Fatalf("runDiff failed: %v", err)
	}

	got := buf.String()
	normalized := NormalizeTruncatedDigests(got)
	normalized = NormalizeTempPaths(normalized)

	assertGolden(t, goldenPath("diff_human"), normalized)
}

func TestDiff_GoldenJSON(t *testing.T) {
	pack1Path := createTestPack(t, "test/v1", map[string][]byte{
		"artifacts/a.json": []byte(`{"value": 1}`),
		"artifacts/b.json": []byte(`{"value": 2}`),
	})
	pack2Path := createTestPack(t, "test/v2", map[string][]byte{
		"artifacts/b.json": []byte(`{"value": 200}`),
		"artifacts/c.json": []byte(`{"value": 3}`),
	})

	var buf bytes.Buffer
	var errBuf bytes.Buffer
	out = output.New(&buf, &errBuf, output.Options{
		Quiet:   false,
		JSON:    true,
		NoColor: true,
		Verbose: false,
	})

	diffArtifact = ""
	diffContext = 3

	err := runDiff(nil, []string{pack1Path, pack2Path})
	if err != nil {
		t.Fatalf("runDiff failed: %v", err)
	}

	got := buf.String()
	normalized := NormalizeDigests(got)
	normalized = NormalizeTempPaths(normalized)

	assertGolden(t, goldenPath("diff_json"), normalized)
}

func TestDiff_GoldenIdentical(t *testing.T) {
	content := map[string][]byte{
		"artifacts/a.json": []byte(`{"value": 1}`),
		"artifacts/b.json": []byte(`{"value": 2}`),
	}
	pack1Path := createTestPack(t, "test/v1", content)
	pack2Path := createTestPack(t, "test/v1", content)

	var buf bytes.Buffer
	var errBuf bytes.Buffer
	out = output.New(&buf, &errBuf, output.Options{
		Quiet:   false,
		JSON:    false,
		NoColor: true,
		Verbose: false,
	})

	diffArtifact = ""
	diffContext = 3

	err := runDiff(nil, []string{pack1Path, pack2Path})
	if err != nil {
		t.Fatalf("runDiff failed: %v", err)
	}

	got := buf.String()
	normalized := NormalizeTruncatedDigests(got)
	normalized = NormalizeTempPaths(normalized)

	assertGolden(t, goldenPath("diff_identical"), normalized)
}

func TestDiff_GoldenArtifactJSON(t *testing.T) {
	pack1Path := createTestPack(t, "test/v1", map[string][]byte{
		"artifacts/config.json": []byte(`{"name": "app", "version": "1.0", "debug": false}`),
	})
	pack2Path := createTestPack(t, "test/v2", map[string][]byte{
		"artifacts/config.json": []byte(`{"name": "app", "version": "2.0", "debug": true, "new": "field"}`),
	})

	var buf bytes.Buffer
	var errBuf bytes.Buffer
	out = output.New(&buf, &errBuf, output.Options{
		Quiet:   false,
		JSON:    false,
		NoColor: true,
		Verbose: false,
	})

	diffArtifact = "artifacts/config.json"
	diffContext = 3

	err := runDiff(nil, []string{pack1Path, pack2Path})
	if err != nil {
		t.Fatalf("runDiff failed: %v", err)
	}

	got := buf.String()
	assertGolden(t, goldenPath("diff_artifact_json"), got)
}

func TestDiff_GoldenArtifactText(t *testing.T) {
	pack1Path := createTestPack(t, "test/v1", map[string][]byte{
		"artifacts/readme.txt": []byte("Line 1\nLine 2\nLine 3"),
	})
	pack2Path := createTestPack(t, "test/v2", map[string][]byte{
		"artifacts/readme.txt": []byte("Line 1\nLine 2 modified\nLine 3\nLine 4"),
	})

	var buf bytes.Buffer
	var errBuf bytes.Buffer
	out = output.New(&buf, &errBuf, output.Options{
		Quiet:   false,
		JSON:    false,
		NoColor: true,
		Verbose: false,
	})

	diffArtifact = "artifacts/readme.txt"
	diffContext = 3

	err := runDiff(nil, []string{pack1Path, pack2Path})
	if err != nil {
		t.Fatalf("runDiff failed: %v", err)
	}

	got := buf.String()
	assertGolden(t, goldenPath("diff_artifact_text"), got)
}
