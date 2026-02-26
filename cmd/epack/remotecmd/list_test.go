//go:build components

package remotecmd

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/locktivity/epack/internal/cli/output"
)

func TestRunList_NoRemotes(t *testing.T) {
	// Create temp project with no remotes
	projectDir := t.TempDir()
	configContent := `stream: test/stream
collectors:
  github:
    source: owner/repo@v1.0.0
`
	if err := os.WriteFile(filepath.Join(projectDir, "epack.yaml"), []byte(configContent), 0644); err != nil {
		t.Fatalf("writing config: %v", err)
	}

	// Change to project dir
	oldWd, _ := os.Getwd()
	if err := os.Chdir(projectDir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	defer func() { _ = os.Chdir(oldWd) }()

	// Capture output
	var stdout, stderr bytes.Buffer
	out = output.New(&stdout, &stderr, output.Options{})
	defer func() { out = nil }()

	// Run list
	cmd := newListCommand()
	err := cmd.Execute()
	if err != nil {
		t.Fatalf("runList() error = %v", err)
	}

	// Check output mentions no remotes
	outStr := stdout.String()
	if !strings.Contains(outStr, "No remotes configured") {
		t.Errorf("output should mention no remotes, got: %s", outStr)
	}
}

func TestRunList_WithRemotes(t *testing.T) {
	// Create temp project with remotes
	projectDir := t.TempDir()
	configContent := `stream: test/stream
collectors:
  github:
    source: owner/repo@v1.0.0
remotes:
  locktivity:
    source: locktivity/epack-remote-locktivity@v1
    target:
      workspace: acme
      environment: prod
    endpoint: https://api.example.com
  backup:
    binary: /usr/local/bin/backup-adapter
    adapter: backup
    target:
      workspace: backup-ws
`
	if err := os.WriteFile(filepath.Join(projectDir, "epack.yaml"), []byte(configContent), 0644); err != nil {
		t.Fatalf("writing config: %v", err)
	}

	// Change to project dir
	oldWd, _ := os.Getwd()
	if err := os.Chdir(projectDir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	defer func() { _ = os.Chdir(oldWd) }()

	// Capture output
	var stdout, stderr bytes.Buffer
	out = output.New(&stdout, &stderr, output.Options{})
	defer func() { out = nil }()

	// Run list
	cmd := newListCommand()
	err := cmd.Execute()
	if err != nil {
		t.Fatalf("runList() error = %v", err)
	}

	// Check output contains both remotes
	outStr := stdout.String()
	if !strings.Contains(outStr, "locktivity") {
		t.Errorf("output should contain 'locktivity', got: %s", outStr)
	}
	if !strings.Contains(outStr, "backup") {
		t.Errorf("output should contain 'backup', got: %s", outStr)
	}
	if !strings.Contains(outStr, "acme") {
		t.Errorf("output should contain workspace 'acme', got: %s", outStr)
	}
	if !strings.Contains(outStr, "prod") {
		t.Errorf("output should contain environment 'prod', got: %s", outStr)
	}
}

func TestRunList_JSONOutput(t *testing.T) {
	// Create temp project with remotes
	projectDir := t.TempDir()
	configContent := `stream: test/stream
collectors:
  github:
    source: owner/repo@v1.0.0
remotes:
  locktivity:
    source: locktivity/epack-remote-locktivity@v1
    target:
      workspace: acme
`
	if err := os.WriteFile(filepath.Join(projectDir, "epack.yaml"), []byte(configContent), 0644); err != nil {
		t.Fatalf("writing config: %v", err)
	}

	// Change to project dir
	oldWd, _ := os.Getwd()
	if err := os.Chdir(projectDir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	defer func() { _ = os.Chdir(oldWd) }()

	// Capture output with JSON mode
	var stdout, stderr bytes.Buffer
	out = output.New(&stdout, &stderr, output.Options{JSON: true})
	defer func() { out = nil }()

	// Run list
	cmd := newListCommand()
	err := cmd.Execute()
	if err != nil {
		t.Fatalf("runList() error = %v", err)
	}

	// Parse JSON output
	var result struct {
		Remotes []struct {
			Name      string `json:"name"`
			Adapter   string `json:"adapter"`
			Source    string `json:"source"`
			Workspace string `json:"workspace"`
		} `json:"remotes"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("parsing JSON output: %v\noutput was: %s", err, stdout.String())
	}

	if len(result.Remotes) != 1 {
		t.Errorf("expected 1 remote, got %d", len(result.Remotes))
	}
	if result.Remotes[0].Name != "locktivity" {
		t.Errorf("remote name = %q, want %q", result.Remotes[0].Name, "locktivity")
	}
	if result.Remotes[0].Workspace != "acme" {
		t.Errorf("workspace = %q, want %q", result.Remotes[0].Workspace, "acme")
	}
}

func TestRunList_JSONOutput_NoRemotes(t *testing.T) {
	// Create temp project with no remotes
	projectDir := t.TempDir()
	configContent := `stream: test/stream
collectors:
  github:
    source: owner/repo@v1.0.0
`
	if err := os.WriteFile(filepath.Join(projectDir, "epack.yaml"), []byte(configContent), 0644); err != nil {
		t.Fatalf("writing config: %v", err)
	}

	// Change to project dir
	oldWd, _ := os.Getwd()
	if err := os.Chdir(projectDir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	defer func() { _ = os.Chdir(oldWd) }()

	// Capture output with JSON mode
	var stdout, stderr bytes.Buffer
	out = output.New(&stdout, &stderr, output.Options{JSON: true})
	defer func() { out = nil }()

	// Run list
	cmd := newListCommand()
	err := cmd.Execute()
	if err != nil {
		t.Fatalf("runList() error = %v", err)
	}

	// Parse JSON output
	var result struct {
		Remotes []interface{} `json:"remotes"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("parsing JSON output: %v", err)
	}

	if len(result.Remotes) != 0 {
		t.Errorf("expected 0 remotes, got %d", len(result.Remotes))
	}
}

func TestRunList_NotInProject(t *testing.T) {
	// Create temp dir without epack.yaml
	tmpDir := t.TempDir()

	// Change to temp dir
	oldWd, _ := os.Getwd()
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	defer func() { _ = os.Chdir(oldWd) }()

	// Capture output
	var stdout, stderr bytes.Buffer
	out = output.New(&stdout, &stderr, output.Options{})
	defer func() { out = nil }()

	// Run list - should error
	cmd := newListCommand()
	err := cmd.Execute()
	if err == nil {
		t.Error("expected error when not in project")
	}
}

func TestRunList_SortsRemoteNames(t *testing.T) {
	// Create temp project with multiple remotes
	projectDir := t.TempDir()
	configContent := `stream: test/stream
collectors:
  github:
    source: owner/repo@v1.0.0
remotes:
  zebra:
    source: z/adapter@v1
  alpha:
    source: a/adapter@v1
  middle:
    source: m/adapter@v1
`
	if err := os.WriteFile(filepath.Join(projectDir, "epack.yaml"), []byte(configContent), 0644); err != nil {
		t.Fatalf("writing config: %v", err)
	}

	// Change to project dir
	oldWd, _ := os.Getwd()
	if err := os.Chdir(projectDir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	defer func() { _ = os.Chdir(oldWd) }()

	// Capture output with JSON mode for easier parsing
	var stdout, stderr bytes.Buffer
	out = output.New(&stdout, &stderr, output.Options{JSON: true})
	defer func() { out = nil }()

	// Run list
	cmd := newListCommand()
	err := cmd.Execute()
	if err != nil {
		t.Fatalf("runList() error = %v", err)
	}

	// Parse JSON output
	var result struct {
		Remotes []struct {
			Name string `json:"name"`
		} `json:"remotes"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("parsing JSON output: %v", err)
	}

	if len(result.Remotes) != 3 {
		t.Fatalf("expected 3 remotes, got %d", len(result.Remotes))
	}

	// Check alphabetical order
	expected := []string{"alpha", "middle", "zebra"}
	for i, want := range expected {
		if result.Remotes[i].Name != want {
			t.Errorf("remote[%d] = %q, want %q", i, result.Remotes[i].Name, want)
		}
	}
}
