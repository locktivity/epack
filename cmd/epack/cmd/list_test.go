package cmd

import (
	"bytes"
	"testing"

	"github.com/locktivity/epack/internal/cli/output"
	"github.com/locktivity/epack/pack"
)

func TestMatchPath(t *testing.T) {
	tests := []struct {
		path    string
		pattern string
		want    bool
	}{
		// Match against filename
		{"artifacts/data.json", "*.json", true},
		{"artifacts/config.yaml", "*.json", false},
		{"artifacts/data.json", "data.json", true},

		// Match against full path
		{"artifacts/data.json", "artifacts/*.json", true},
		{"artifacts/subdir/data.json", "artifacts/*.json", false},

		// No match
		{"artifacts/data.json", "*.yaml", false},
		{"artifacts/data.json", "other.json", false},
	}

	for _, tt := range tests {
		t.Run(tt.path+"_"+tt.pattern, func(t *testing.T) {
			got := matchPath(tt.path, tt.pattern)
			if got != tt.want {
				t.Errorf("matchPath(%q, %q) = %v, want %v", tt.path, tt.pattern, got, tt.want)
			}
		})
	}
}

func TestFilterArtifacts(t *testing.T) {
	artifacts := []pack.Artifact{
		{Path: "artifacts/config.json"},
		{Path: "artifacts/data.json"},
		{Path: "artifacts/readme.txt"},
		{Path: "artifacts/schema.yaml"},
	}

	tests := []struct {
		pattern string
		want    int
	}{
		{"*.json", 2},
		{"*.txt", 1},
		{"*.yaml", 1},
		{"*.xml", 0},
		{"config.*", 1},
	}

	for _, tt := range tests {
		t.Run(tt.pattern, func(t *testing.T) {
			result := filterArtifacts(artifacts, tt.pattern)
			if len(result) != tt.want {
				t.Errorf("filterArtifacts(pattern=%q) returned %d, want %d", tt.pattern, len(result), tt.want)
			}
		})
	}
}

func TestFilterStrings(t *testing.T) {
	items := []string{
		"attestations/user1.sigstore.json",
		"attestations/user2.sigstore.json",
		"attestations/ci.sigstore.json",
	}

	tests := []struct {
		pattern string
		want    int
	}{
		{"*.json", 3},
		{"user*.sigstore.json", 2},
		{"ci.*", 1},
		{"*.yaml", 0},
	}

	for _, tt := range tests {
		t.Run(tt.pattern, func(t *testing.T) {
			result := filterStrings(items, tt.pattern)
			if len(result) != tt.want {
				t.Errorf("filterStrings(pattern=%q) returned %d, want %d", tt.pattern, len(result), tt.want)
			}
		})
	}
}

func TestListArtifacts_Integration(t *testing.T) {
	// Create a pack with multiple artifacts
	packPath := createTestPack(t, "test/list", map[string][]byte{
		"artifacts/a.json":    []byte(`{}`),
		"artifacts/b.json":    []byte(`{}`),
		"artifacts/readme.md": []byte(`# README`),
	})

	p, err := pack.Open(packPath)
	if err != nil {
		t.Fatalf("Failed to open pack: %v", err)
	}
	defer func() { _ = p.Close() }()

	manifest := p.Manifest()

	// Verify artifact count
	if len(manifest.Artifacts) != 3 {
		t.Errorf("len(Artifacts) = %d, want 3", len(manifest.Artifacts))
	}

	// Test filtering
	jsonArtifacts := filterArtifacts(manifest.Artifacts, "*.json")
	if len(jsonArtifacts) != 2 {
		t.Errorf("filterArtifacts(*.json) = %d, want 2", len(jsonArtifacts))
	}

	mdArtifacts := filterArtifacts(manifest.Artifacts, "*.md")
	if len(mdArtifacts) != 1 {
		t.Errorf("filterArtifacts(*.md) = %d, want 1", len(mdArtifacts))
	}
}

func TestListSources_Integration(t *testing.T) {
	packPath := createTestPack(t, "test/sources", map[string][]byte{
		"artifacts/test.json": []byte(`{}`),
	})

	p, err := pack.Open(packPath)
	if err != nil {
		t.Fatalf("Failed to open pack: %v", err)
	}
	defer func() { _ = p.Close() }()

	manifest := p.Manifest()

	// Empty sources is valid
	if manifest.Sources == nil {
		t.Error("Sources should not be nil")
	}
}

// Golden file tests for list output

func TestListArtifacts_GoldenHuman(t *testing.T) {
	packPath := createTestPack(t, "test/golden-list", map[string][]byte{
		"artifacts/config.json": []byte(`{"key": "value"}`),
		"artifacts/data.json":   []byte(`{"items": [1, 2, 3]}`),
		"artifacts/readme.md":   []byte(`# README`),
	})

	var buf bytes.Buffer
	var errBuf bytes.Buffer
	out = output.New(&buf, &errBuf, output.Options{
		Quiet:   false,
		JSON:    false,
		NoColor: true,
		Verbose: false,
	})

	// Reset flags
	listFilter = ""
	listLong = false

	err := runListArtifacts(nil, []string{packPath})
	if err != nil {
		t.Fatalf("runListArtifacts failed: %v", err)
	}

	got := buf.String()
	assertGolden(t, goldenPath("list_artifacts_human"), got)
}

func TestListArtifacts_GoldenLong(t *testing.T) {
	packPath := createTestPack(t, "test/golden-list-long", map[string][]byte{
		"artifacts/config.json": []byte(`{"key": "value"}`),
		"artifacts/data.json":   []byte(`{"items": [1, 2, 3]}`),
	})

	var buf bytes.Buffer
	var errBuf bytes.Buffer
	out = output.New(&buf, &errBuf, output.Options{
		Quiet:   false,
		JSON:    false,
		NoColor: true,
		Verbose: false,
	})

	listFilter = ""
	listLong = true

	err := runListArtifacts(nil, []string{packPath})
	if err != nil {
		t.Fatalf("runListArtifacts failed: %v", err)
	}

	got := buf.String()
	normalized := NormalizeDigests(got)

	assertGolden(t, goldenPath("list_artifacts_long"), normalized)
}

func TestListArtifacts_GoldenJSON(t *testing.T) {
	packPath := createTestPack(t, "test/golden-list-json", map[string][]byte{
		"artifacts/data.json": []byte(`{"test": true}`),
	})

	var buf bytes.Buffer
	var errBuf bytes.Buffer
	out = output.New(&buf, &errBuf, output.Options{
		Quiet:   false,
		JSON:    true,
		NoColor: true,
		Verbose: false,
	})

	listFilter = ""
	listLong = false

	err := runListArtifacts(nil, []string{packPath})
	if err != nil {
		t.Fatalf("runListArtifacts failed: %v", err)
	}

	got := buf.String()
	normalized := NormalizeDigests(got)

	assertGolden(t, goldenPath("list_artifacts_json"), normalized)
}
