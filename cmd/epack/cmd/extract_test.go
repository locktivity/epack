package cmd

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/locktivity/epack/internal/cli/output"
	"github.com/locktivity/epack/pack/builder"
)

// Golden file tests for extract output

func TestExtract_GoldenHuman(t *testing.T) {
	// Create a test pack with artifacts
	packPath := createTestPackForExtract(t, "test/extract", map[string][]byte{
		"artifacts/config.json": []byte(`{"key": "value"}`),
		"artifacts/data.json":   []byte(`{"items": [1, 2, 3]}`),
	})

	outputDir := t.TempDir()

	var buf bytes.Buffer
	var errBuf bytes.Buffer
	out = output.New(&buf, &errBuf, output.Options{
		Quiet:   false,
		JSON:    false,
		NoColor: true,
		Verbose: false,
	})

	// Reset flags
	extractOutput = outputDir
	extractAll = true
	extractFilter = ""
	extractForce = false

	err := runExtract(nil, []string{packPath})
	if err != nil {
		t.Fatalf("runExtract failed: %v", err)
	}

	got := buf.String()
	normalized := NormalizeTempPaths(got)

	assertGolden(t, goldenPath("extract_human"), normalized)
}

func TestExtract_GoldenJSON(t *testing.T) {
	// Create a test pack with artifacts
	packPath := createTestPackForExtract(t, "test/extract", map[string][]byte{
		"artifacts/config.json": []byte(`{"key": "value"}`),
		"artifacts/data.json":   []byte(`{"items": [1, 2, 3]}`),
	})

	outputDir := t.TempDir()

	var buf bytes.Buffer
	var errBuf bytes.Buffer
	out = output.New(&buf, &errBuf, output.Options{
		Quiet:   false,
		JSON:    true,
		NoColor: true,
		Verbose: false,
	})

	// Reset flags
	extractOutput = outputDir
	extractAll = true
	extractFilter = ""
	extractForce = false

	err := runExtract(nil, []string{packPath})
	if err != nil {
		t.Fatalf("runExtract failed: %v", err)
	}

	got := buf.String()
	normalized := NormalizeTempPaths(got)

	assertGolden(t, goldenPath("extract_json"), normalized)
}

func TestExtract_GoldenEmpty(t *testing.T) {
	// Create a test pack with artifacts but use a filter that matches nothing
	packPath := createTestPackForExtract(t, "test/extract", map[string][]byte{
		"artifacts/config.json": []byte(`{"key": "value"}`),
	})

	outputDir := t.TempDir()

	var buf bytes.Buffer
	var errBuf bytes.Buffer
	out = output.New(&buf, &errBuf, output.Options{
		Quiet:   false,
		JSON:    false,
		NoColor: true,
		Verbose: false,
	})

	// Reset flags - use filter that matches nothing (not --all, since filter is ignored with --all)
	extractOutput = outputDir
	extractAll = false
	extractFilter = "*.xml" // No XML files in the pack
	extractForce = false

	err := runExtract(nil, []string{packPath})
	if err != nil {
		t.Fatalf("runExtract failed: %v", err)
	}

	got := buf.String()
	assertGolden(t, goldenPath("extract_empty"), got)
}

func TestExtract_GoldenDryRun(t *testing.T) {
	// Create a test pack with artifacts
	packPath := createTestPackForExtract(t, "test/extract", map[string][]byte{
		"artifacts/config.json": []byte(`{"key": "value"}`),
		"artifacts/data.json":   []byte(`{"items": [1, 2, 3]}`),
	})

	outputDir := t.TempDir()

	var buf bytes.Buffer
	var errBuf bytes.Buffer
	out = output.New(&buf, &errBuf, output.Options{
		Quiet:   false,
		JSON:    false,
		NoColor: true,
		Verbose: false,
	})

	// Reset flags
	extractOutput = outputDir
	extractAll = true
	extractFilter = ""
	extractForce = false
	extractDryRun = true
	defer func() { extractDryRun = false }()

	err := runExtract(nil, []string{packPath})
	if err != nil {
		t.Fatalf("runExtract failed: %v", err)
	}

	got := buf.String()
	normalized := NormalizeTempPaths(got)

	assertGolden(t, goldenPath("extract_dryrun"), normalized)
}

func TestExtract_GoldenDryRunJSON(t *testing.T) {
	// Create a test pack with artifacts
	packPath := createTestPackForExtract(t, "test/extract", map[string][]byte{
		"artifacts/config.json": []byte(`{"key": "value"}`),
		"artifacts/data.json":   []byte(`{"items": [1, 2, 3]}`),
	})

	outputDir := t.TempDir()

	var buf bytes.Buffer
	var errBuf bytes.Buffer
	out = output.New(&buf, &errBuf, output.Options{
		Quiet:   false,
		JSON:    true,
		NoColor: true,
		Verbose: false,
	})

	// Reset flags
	extractOutput = outputDir
	extractAll = true
	extractFilter = ""
	extractForce = false
	extractDryRun = true
	defer func() { extractDryRun = false }()

	err := runExtract(nil, []string{packPath})
	if err != nil {
		t.Fatalf("runExtract failed: %v", err)
	}

	got := buf.String()
	normalized := NormalizeTempPaths(got)

	assertGolden(t, goldenPath("extract_dryrun_json"), normalized)
}

// createTestPackForExtract creates a temporary pack for testing extract.
func createTestPackForExtract(t *testing.T, stream string, artifacts map[string][]byte) string {
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

	return packPath
}
