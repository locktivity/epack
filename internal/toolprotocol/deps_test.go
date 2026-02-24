package toolprotocol

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCheckDependencies_NilCaps(t *testing.T) {
	missing := CheckDependencies(nil, "/some/path")
	if len(missing) != 0 {
		t.Errorf("expected no missing deps for nil caps, got %v", missing)
	}
}

func TestCheckDependencies_EmptyPackSidecar(t *testing.T) {
	caps := &Capabilities{
		RequiresTools: []string{"index"},
	}
	missing := CheckDependencies(caps, "")
	if len(missing) != 0 {
		t.Errorf("expected no missing deps for empty sidecar (packless), got %v", missing)
	}
}

func TestCheckDependencies_NoDeps(t *testing.T) {
	caps := &Capabilities{
		Name: "ask",
	}
	missing := CheckDependencies(caps, "/some/path")
	if len(missing) != 0 {
		t.Errorf("expected no missing deps when none required, got %v", missing)
	}
}

func TestCheckDependencies_MissingTool(t *testing.T) {
	tmpDir := t.TempDir()
	packSidecar := filepath.Join(tmpDir, "test.pack.runs")
	if err := os.MkdirAll(packSidecar, 0755); err != nil {
		t.Fatal(err)
	}

	caps := &Capabilities{
		RequiresTools: []string{"index"},
	}

	missing := CheckDependencies(caps, packSidecar)
	if len(missing) != 1 {
		t.Fatalf("expected 1 missing dep, got %d", len(missing))
	}
	if missing[0].Tool != "index" {
		t.Errorf("expected missing tool=index, got %s", missing[0].Tool)
	}
}

func TestCheckDependencies_ToolWithSuccessfulRun(t *testing.T) {
	tmpDir := t.TempDir()
	packSidecar := filepath.Join(tmpDir, "test.pack.runs")
	toolRunDir := filepath.Join(packSidecar, "tools", "index", "2026-01-01T00-00-00-000000Z-000000")
	if err := os.MkdirAll(toolRunDir, 0755); err != nil {
		t.Fatal(err)
	}

	// Write a successful result.json
	result := &Result{
		SchemaVersion: 1,
		Status:        StatusSuccess,
		Tool:          ToolInfo{Name: "index", Version: "1.0.0"},
		Wrapper:       WrapperInfo{Name: "epack", Version: "0.1.0"},
		RunID:         "2026-01-01T00-00-00-000000Z-000000",
		StartedAt:     "2026-01-01T00:00:00Z",
		CompletedAt:   "2026-01-01T00:00:01Z",
		Inputs:        map[string]any{},
		Outputs:       []OutputEntry{},
		Errors:        []ErrorEntry{},
		Warnings:      []ErrorEntry{},
	}
	if err := WriteResultAtomic(toolRunDir, result); err != nil {
		t.Fatal(err)
	}

	caps := &Capabilities{
		RequiresTools: []string{"index"},
	}

	missing := CheckDependencies(caps, packSidecar)
	if len(missing) != 0 {
		t.Errorf("expected no missing deps when tool has successful run, got %v", missing)
	}
}

func TestCheckDependencies_ToolWithFailedRun(t *testing.T) {
	tmpDir := t.TempDir()
	packSidecar := filepath.Join(tmpDir, "test.pack.runs")
	toolRunDir := filepath.Join(packSidecar, "tools", "index", "2026-01-01T00-00-00-000000Z-000000")
	if err := os.MkdirAll(toolRunDir, 0755); err != nil {
		t.Fatal(err)
	}

	// Write a failed result.json
	result := &Result{
		SchemaVersion: 1,
		Status:        StatusFailure,
		Tool:          ToolInfo{Name: "index", Version: "1.0.0"},
		Wrapper:       WrapperInfo{Name: "epack", Version: "0.1.0"},
		RunID:         "2026-01-01T00-00-00-000000Z-000000",
		StartedAt:     "2026-01-01T00:00:00Z",
		CompletedAt:   "2026-01-01T00:00:01Z",
		Inputs:        map[string]any{},
		Outputs:       []OutputEntry{},
		Errors:        []ErrorEntry{{Code: "TEST", Message: "test error"}},
		Warnings:      []ErrorEntry{},
	}
	if err := WriteResultAtomic(toolRunDir, result); err != nil {
		t.Fatal(err)
	}

	caps := &Capabilities{
		RequiresTools: []string{"index"},
	}

	missing := CheckDependencies(caps, packSidecar)
	if len(missing) != 1 {
		t.Fatalf("expected 1 missing dep (failed run doesn't count), got %d", len(missing))
	}
}

func TestCheckDependencies_MissingOutput(t *testing.T) {
	tmpDir := t.TempDir()
	packSidecar := filepath.Join(tmpDir, "test.pack.runs")
	if err := os.MkdirAll(packSidecar, 0755); err != nil {
		t.Fatal(err)
	}

	caps := &Capabilities{
		RequiresOutputs: []string{"index/outputs/embeddings.json"},
	}

	missing := CheckDependencies(caps, packSidecar)
	if len(missing) != 1 {
		t.Fatalf("expected 1 missing output, got %d", len(missing))
	}
	if missing[0].Output != "index/outputs/embeddings.json" {
		t.Errorf("expected missing output=index/outputs/embeddings.json, got %s", missing[0].Output)
	}
	if missing[0].Tool != "index" {
		t.Errorf("expected tool=index extracted from path, got %s", missing[0].Tool)
	}
}

func TestCheckDependencies_OutputExists(t *testing.T) {
	tmpDir := t.TempDir()
	packSidecar := filepath.Join(tmpDir, "test.pack.runs")
	outputPath := filepath.Join(packSidecar, "tools", "index", "outputs", "embeddings.json")
	if err := os.MkdirAll(filepath.Dir(outputPath), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(outputPath, []byte("{}"), 0644); err != nil {
		t.Fatal(err)
	}

	caps := &Capabilities{
		RequiresOutputs: []string{"index/outputs/embeddings.json"},
	}

	missing := CheckDependencies(caps, packSidecar)
	if len(missing) != 0 {
		t.Errorf("expected no missing deps when output exists, got %v", missing)
	}
}

func TestFormatDependencyErrors_SingleTool(t *testing.T) {
	missing := []DependencyError{{Tool: "index"}}
	msg := FormatDependencyErrors(missing)
	expected := "required tool 'index' has not been run"
	if msg != expected {
		t.Errorf("expected %q, got %q", expected, msg)
	}
}

func TestFormatDependencyErrors_SingleToolWithOutput(t *testing.T) {
	missing := []DependencyError{{Tool: "index", Output: "index/outputs/embeddings.json"}}
	msg := FormatDependencyErrors(missing)
	if msg == "" {
		t.Error("expected non-empty message")
	}
	// Should mention the tool and output
	if !contains(msg, "index") {
		t.Errorf("message should mention tool: %s", msg)
	}
}

func TestFormatDependencyErrors_MultipleTools(t *testing.T) {
	missing := []DependencyError{
		{Tool: "index"},
		{Tool: "normalize"},
	}
	msg := FormatDependencyErrors(missing)
	if !contains(msg, "index") || !contains(msg, "normalize") {
		t.Errorf("message should mention both tools: %s", msg)
	}
}

func TestFormatDependencyErrors_Empty(t *testing.T) {
	msg := FormatDependencyErrors(nil)
	if msg != "" {
		t.Errorf("expected empty message for no errors, got %q", msg)
	}
}

func TestLatestRunDir(t *testing.T) {
	tmpDir := t.TempDir()
	packSidecar := filepath.Join(tmpDir, "test.pack.runs")
	toolDir := filepath.Join(packSidecar, "tools", "index")

	// Create multiple run directories
	runs := []string{
		"2026-01-01T00-00-00-000000Z-000000",
		"2026-01-02T00-00-00-000000Z-000000",
		"2026-01-01T12-00-00-000000Z-000000",
	}
	for _, run := range runs {
		if err := os.MkdirAll(filepath.Join(toolDir, run), 0755); err != nil {
			t.Fatal(err)
		}
	}

	latest := LatestRunDir(packSidecar, "index")
	expected := filepath.Join(toolDir, "2026-01-02T00-00-00-000000Z-000000")
	if latest != expected {
		t.Errorf("expected %s, got %s", expected, latest)
	}
}

func TestLatestRunDir_NoRuns(t *testing.T) {
	tmpDir := t.TempDir()
	packSidecar := filepath.Join(tmpDir, "test.pack.runs")
	if err := os.MkdirAll(packSidecar, 0755); err != nil {
		t.Fatal(err)
	}

	latest := LatestRunDir(packSidecar, "index")
	if latest != "" {
		t.Errorf("expected empty string for no runs, got %s", latest)
	}
}

func TestSplitPath(t *testing.T) {
	tests := []struct {
		input    string
		expected []string
	}{
		{"index/outputs/embeddings.json", []string{"index", "outputs", "embeddings.json"}},
		{"index", []string{"index"}},
		{"a/b/c/d", []string{"a", "b", "c", "d"}},
	}

	for _, tc := range tests {
		got := splitPath(tc.input)
		if len(got) != len(tc.expected) {
			t.Errorf("splitPath(%q) = %v, expected %v", tc.input, got, tc.expected)
			continue
		}
		for i := range got {
			if got[i] != tc.expected[i] {
				t.Errorf("splitPath(%q)[%d] = %q, expected %q", tc.input, i, got[i], tc.expected[i])
			}
		}
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
