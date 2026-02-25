package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAddTool(t *testing.T) {
	// Create a temp directory for test files
	tmpDir := t.TempDir()

	t.Run("add to existing tools section", func(t *testing.T) {
		configPath := filepath.Join(tmpDir, "add_existing.yaml")
		initialContent := `stream: test
tools:
  existing:
    source: owner/existing@v1
`
		if err := os.WriteFile(configPath, []byte(initialContent), 0644); err != nil {
			t.Fatal(err)
		}

		err := AddTool(configPath, "new-tool", ToolConfig{Source: "owner/new-tool@^1.0"})
		if err != nil {
			t.Fatalf("AddTool() error = %v", err)
		}

		// Read back and verify
		data, err := os.ReadFile(configPath)
		if err != nil {
			t.Fatal(err)
		}

		content := string(data)
		if !strings.Contains(content, "new-tool") {
			t.Error("new-tool not found in config")
		}
		if !strings.Contains(content, "owner/new-tool@^1.0") {
			t.Error("source not found in config")
		}
		if !strings.Contains(content, "existing") {
			t.Error("existing tool was removed")
		}
	})

	t.Run("create tools section if missing", func(t *testing.T) {
		configPath := filepath.Join(tmpDir, "no_tools.yaml")
		initialContent := `stream: test
collectors:
  github:
    source: owner/github@v1
`
		if err := os.WriteFile(configPath, []byte(initialContent), 0644); err != nil {
			t.Fatal(err)
		}

		err := AddTool(configPath, "ai", ToolConfig{Source: "owner/ai@latest"})
		if err != nil {
			t.Fatalf("AddTool() error = %v", err)
		}

		data, err := os.ReadFile(configPath)
		if err != nil {
			t.Fatal(err)
		}

		content := string(data)
		if !strings.Contains(content, "tools:") {
			t.Error("tools section not created")
		}
		if !strings.Contains(content, "ai") {
			t.Error("ai not found in config")
		}
		// Verify collectors are preserved
		if !strings.Contains(content, "collectors:") {
			t.Error("collectors section was removed")
		}
	})

	t.Run("error if tool already exists", func(t *testing.T) {
		configPath := filepath.Join(tmpDir, "duplicate.yaml")
		initialContent := `stream: test
tools:
  ai:
    source: owner/ai@v1
`
		if err := os.WriteFile(configPath, []byte(initialContent), 0644); err != nil {
			t.Fatal(err)
		}

		err := AddTool(configPath, "ai", ToolConfig{Source: "owner/ai@v2"})
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !errors.Is(err, ErrAlreadyExists) {
			t.Errorf("expected ErrAlreadyExists, got %v", err)
		}
	})
}

func TestAddCollector(t *testing.T) {
	tmpDir := t.TempDir()

	t.Run("add collector", func(t *testing.T) {
		configPath := filepath.Join(tmpDir, "add_collector.yaml")
		initialContent := `stream: test
`
		if err := os.WriteFile(configPath, []byte(initialContent), 0644); err != nil {
			t.Fatal(err)
		}

		err := AddCollector(configPath, "github", CollectorConfig{Source: "owner/github@^1.0"})
		if err != nil {
			t.Fatalf("AddCollector() error = %v", err)
		}

		data, err := os.ReadFile(configPath)
		if err != nil {
			t.Fatal(err)
		}

		content := string(data)
		if !strings.Contains(content, "collectors:") {
			t.Error("collectors section not created")
		}
		if !strings.Contains(content, "github") {
			t.Error("github not found in config")
		}
	})
}

func TestHasTool(t *testing.T) {
	tmpDir := t.TempDir()

	t.Run("tool exists", func(t *testing.T) {
		configPath := filepath.Join(tmpDir, "has_tool.yaml")
		content := `tools:
  ai:
    source: owner/ai@v1
`
		if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}

		exists, err := HasTool(configPath, "ai")
		if err != nil {
			t.Fatal(err)
		}
		if !exists {
			t.Error("expected tool to exist")
		}
	})

	t.Run("tool does not exist", func(t *testing.T) {
		configPath := filepath.Join(tmpDir, "has_tool2.yaml")
		content := `tools:
  other:
    source: owner/other@v1
`
		if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}

		exists, err := HasTool(configPath, "ai")
		if err != nil {
			t.Fatal(err)
		}
		if exists {
			t.Error("expected tool to not exist")
		}
	})

	t.Run("no tools section", func(t *testing.T) {
		configPath := filepath.Join(tmpDir, "no_tools_section.yaml")
		content := `stream: test
`
		if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}

		exists, err := HasTool(configPath, "ai")
		if err != nil {
			t.Fatal(err)
		}
		if exists {
			t.Error("expected tool to not exist")
		}
	})

	t.Run("file does not exist", func(t *testing.T) {
		exists, err := HasTool(filepath.Join(tmpDir, "nonexistent.yaml"), "ai")
		if err != nil {
			t.Fatal(err)
		}
		if exists {
			t.Error("expected tool to not exist when file doesn't exist")
		}
	})
}

func TestHasCollector(t *testing.T) {
	tmpDir := t.TempDir()

	t.Run("collector exists", func(t *testing.T) {
		configPath := filepath.Join(tmpDir, "has_collector.yaml")
		content := `collectors:
  github:
    source: owner/github@v1
`
		if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}

		exists, err := HasCollector(configPath, "github")
		if err != nil {
			t.Fatal(err)
		}
		if !exists {
			t.Error("expected collector to exist")
		}
	})
}

func TestAddCollector_NullSection(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "null_section.yaml")

	content := `stream: test
collectors:
  # This is a comment - section value is null
  # deps:
  #   source: owner/deps@v1
`
	if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	err := AddCollector(configPath, "github", CollectorConfig{Source: "owner/github@v1"})
	if err != nil {
		t.Fatalf("AddCollector() error = %v", err)
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}

	result := string(data)
	if !strings.Contains(result, "github:") {
		t.Error("github collector not added")
	}
	if !strings.Contains(result, "owner/github@v1") {
		t.Error("source not added")
	}
	if strings.Contains(result, "!!null") {
		t.Error("output contains !!null tag")
	}
}

func TestAddRemote(t *testing.T) {
	tmpDir := t.TempDir()

	t.Run("add remote to empty config", func(t *testing.T) {
		configPath := filepath.Join(tmpDir, "add_remote.yaml")
		if err := os.WriteFile(configPath, []byte("stream: test\n"), 0644); err != nil {
			t.Fatal(err)
		}

		err := AddRemote(configPath, "locktivity", RemoteConfig{Source: "owner/remote@v1"})
		if err != nil {
			t.Fatalf("AddRemote() error = %v", err)
		}

		data, err := os.ReadFile(configPath)
		if err != nil {
			t.Fatal(err)
		}

		result := string(data)
		if !strings.Contains(result, "remotes:") {
			t.Error("remotes section not created")
		}
		if !strings.Contains(result, "locktivity:") {
			t.Error("locktivity remote not added")
		}
	})

	t.Run("add remote to null section", func(t *testing.T) {
		configPath := filepath.Join(tmpDir, "null_remote.yaml")
		content := `stream: test
remotes:
  # commented out
`
		if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}

		err := AddRemote(configPath, "locktivity", RemoteConfig{Source: "owner/remote@v1"})
		if err != nil {
			t.Fatalf("AddRemote() error = %v", err)
		}

		data, err := os.ReadFile(configPath)
		if err != nil {
			t.Fatal(err)
		}

		result := string(data)
		if !strings.Contains(result, "locktivity:") {
			t.Error("locktivity remote not added")
		}
	})
}

func TestHasRemote(t *testing.T) {
	tmpDir := t.TempDir()

	t.Run("remote exists", func(t *testing.T) {
		configPath := filepath.Join(tmpDir, "has_remote.yaml")
		content := `remotes:
  locktivity:
    source: owner/remote@v1
`
		if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}

		exists, err := HasRemote(configPath, "locktivity")
		if err != nil {
			t.Fatal(err)
		}
		if !exists {
			t.Error("expected remote to exist")
		}
	})

	t.Run("remote does not exist", func(t *testing.T) {
		configPath := filepath.Join(tmpDir, "no_remote.yaml")
		content := `stream: test
`
		if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}

		exists, err := HasRemote(configPath, "locktivity")
		if err != nil {
			t.Fatal(err)
		}
		if exists {
			t.Error("expected remote to not exist")
		}
	})
}
