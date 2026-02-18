package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/locktivity/epack/internal/cli/output"
	"github.com/locktivity/epack/pack"
	"github.com/locktivity/epack/pack/builder"
)

func TestParseSource(t *testing.T) {
	tests := []struct {
		input       string
		wantName    string
		wantVersion string
	}{
		{"github:1.0.0", "github", "1.0.0"},
		{"github", "github", ""},
		{"collector:2.0", "collector", "2.0"},
		{"my-source:v1.2.3", "my-source", "v1.2.3"},
		{"source:", "source", ""},
		{":version", "", "version"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			name, version := parseSource(tt.input)
			if name != tt.wantName {
				t.Errorf("parseSource(%q) name = %q, want %q", tt.input, name, tt.wantName)
			}
			if version != tt.wantVersion {
				t.Errorf("parseSource(%q) version = %q, want %q", tt.input, version, tt.wantVersion)
			}
		})
	}
}

func TestParseFileSpec(t *testing.T) {
	tests := []struct {
		input    string
		wantSrc  string
		wantDest string
	}{
		{"./file.json:artifacts/dest.json", "./file.json", "artifacts/dest.json"},
		{"./file.json", "./file.json", ""},
		{"/path/to/file:artifacts/file", "/path/to/file", "artifacts/file"},
		{"file.json", "file.json", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			src, dest := parseFileSpec(tt.input)
			if src != tt.wantSrc {
				t.Errorf("parseFileSpec(%q) src = %q, want %q", tt.input, src, tt.wantSrc)
			}
			if dest != tt.wantDest {
				t.Errorf("parseFileSpec(%q) dest = %q, want %q", tt.input, dest, tt.wantDest)
			}
		})
	}
}

func TestBuildCommand_CreatesValidPack(t *testing.T) {
	// Create temp directory with test artifacts
	tmpDir := t.TempDir()

	// Create test artifact files
	artifact1 := filepath.Join(tmpDir, "data1.json")
	artifact2 := filepath.Join(tmpDir, "data2.json")
	if err := os.WriteFile(artifact1, []byte(`{"key": "value1"}`), 0644); err != nil {
		t.Fatalf("Failed to write artifact1: %v", err)
	}
	if err := os.WriteFile(artifact2, []byte(`{"key": "value2"}`), 0644); err != nil {
		t.Fatalf("Failed to write artifact2: %v", err)
	}

	// Build pack using the builder directly (since we can't easily call the CLI)
	outputPath := filepath.Join(tmpDir, "test.pack")

	// Use the pack builder library directly
	b := builder.New("test/stream")
	if err := b.AddFile("artifacts/data1.json", artifact1); err != nil {
		t.Fatalf("AddFile failed: %v", err)
	}
	if err := b.AddFile("artifacts/data2.json", artifact2); err != nil {
		t.Fatalf("AddFile failed: %v", err)
	}
	b.AddSource("github", "1.0.0")
	if err := b.Build(outputPath); err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	// Verify the pack
	p, err := pack.Open(outputPath)
	if err != nil {
		t.Fatalf("Failed to open pack: %v", err)
	}
	defer func() { _ = p.Close() }()

	manifest := p.Manifest()
	if manifest.Stream != "test/stream" {
		t.Errorf("Stream = %q, want %q", manifest.Stream, "test/stream")
	}
	if len(manifest.Artifacts) != 2 {
		t.Errorf("len(Artifacts) = %d, want 2", len(manifest.Artifacts))
	}
	if len(manifest.Sources) != 1 {
		t.Errorf("len(Sources) = %d, want 1", len(manifest.Sources))
	}
	if manifest.Sources[0].Name != "github" {
		t.Errorf("Source name = %q, want %q", manifest.Sources[0].Name, "github")
	}
	if manifest.Sources[0].Version != "1.0.0" {
		t.Errorf("Source version = %q, want %q", manifest.Sources[0].Version, "1.0.0")
	}
}

func TestBuildCommand_EmptyPack(t *testing.T) {
	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "empty.pack")

	b := builder.New("test/empty")
	if err := b.Build(outputPath); err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	p, err := pack.Open(outputPath)
	if err != nil {
		t.Fatalf("Failed to open pack: %v", err)
	}
	defer func() { _ = p.Close() }()

	manifest := p.Manifest()
	if len(manifest.Artifacts) != 0 {
		t.Errorf("len(Artifacts) = %d, want 0", len(manifest.Artifacts))
	}
}

// Golden file tests for build output

func TestBuild_GoldenHuman(t *testing.T) {
	tmpDir := t.TempDir()

	// Create test artifact
	artifactPath := filepath.Join(tmpDir, "data.json")
	if err := os.WriteFile(artifactPath, []byte(`{"key": "value"}`), 0644); err != nil {
		t.Fatalf("Failed to write artifact: %v", err)
	}

	outputPath := filepath.Join(tmpDir, "test.pack")

	var buf bytes.Buffer
	var errBuf bytes.Buffer
	out = output.New(&buf, &errBuf, output.Options{
		Quiet:   false,
		JSON:    false,
		NoColor: true,
		Verbose: false,
	})

	// Reset flags
	buildStream = "test/golden-build"
	buildSources = nil
	buildFiles = nil
	buildStdin = ""
	buildContentType = ""
	buildOutput = ""
	buildForce = false

	err := runBuild(nil, []string{outputPath, artifactPath})
	if err != nil {
		t.Fatalf("runBuild failed: %v", err)
	}

	got := buf.String()
	normalized := NormalizeTempPaths(got)

	assertGolden(t, goldenPath("build_human"), normalized)
}

func TestBuild_GoldenJSON(t *testing.T) {
	tmpDir := t.TempDir()

	// Create test artifact
	artifactPath := filepath.Join(tmpDir, "data.json")
	if err := os.WriteFile(artifactPath, []byte(`{"key": "value"}`), 0644); err != nil {
		t.Fatalf("Failed to write artifact: %v", err)
	}

	outputPath := filepath.Join(tmpDir, "test.pack")

	var buf bytes.Buffer
	var errBuf bytes.Buffer
	out = output.New(&buf, &errBuf, output.Options{
		Quiet:   false,
		JSON:    true,
		NoColor: true,
		Verbose: false,
	})

	// Reset flags
	buildStream = "test/golden-build"
	buildSources = nil
	buildFiles = nil
	buildStdin = ""
	buildContentType = ""
	buildOutput = ""
	buildForce = false

	err := runBuild(nil, []string{outputPath, artifactPath})
	if err != nil {
		t.Fatalf("runBuild failed: %v", err)
	}

	got := buf.String()
	normalized := NormalizeTempPaths(got)

	assertGolden(t, goldenPath("build_json"), normalized)
}
