package dispatch

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/locktivity/epack/errors"
	"github.com/locktivity/epack/internal/component/config"
	"github.com/locktivity/epack/internal/component/lockfile"
	"github.com/locktivity/epack/internal/project"
)

// TestImportGuard ensures the dispatch package never imports internal/catalog.
//
// SECURITY BOUNDARY: The dispatch package handles tool execution and must only
// trust the lockfile for execution decisions. Catalog data is for discovery/display
// only and must never influence which binary to run, what digest to verify, or
// what signer to trust.
//
// This test enforces that boundary by failing if any file in internal/dispatch
// imports internal/catalog.
func TestImportGuard(t *testing.T) {
	// Find the directory containing this test
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working directory: %v", err)
	}

	// Ensure we're in the dispatch package directory
	if !strings.HasSuffix(wd, "internal/dispatch") {
		t.Skipf("skipping import guard test: not in internal/dispatch directory (in %s)", wd)
	}

	fset := token.NewFileSet()

	// Parse all Go files in the dispatch package
	entries, err := os.ReadDir(wd)
	if err != nil {
		t.Fatalf("failed to read directory: %v", err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if !strings.HasSuffix(entry.Name(), ".go") {
			continue
		}
		// Skip test files for the import analysis
		if strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}

		filePath := filepath.Join(wd, entry.Name())
		file, err := parser.ParseFile(fset, filePath, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("failed to parse %s: %v", entry.Name(), err)
		}

		for _, imp := range file.Imports {
			// Strip quotes from import path
			importPath := strings.Trim(imp.Path.Value, `"`)

			// Check for catalog import
			if strings.Contains(importPath, "internal/catalog") {
				t.Errorf("SECURITY VIOLATION: %s imports %s\n"+
					"The dispatch package must NOT import internal/catalog.\n"+
					"Catalog data is for discovery/display only.\n"+
					"Tool execution decisions must come exclusively from the lockfile.",
					entry.Name(), importPath)
			}
		}
	}
}

// TestErrorExported verifies errors.Error is properly exported.
func TestErrorExported(t *testing.T) {
	err := &errors.Error{Code: errors.InvalidInput, Exit: 42, Message: "test error"}
	if err.ExitCode() != 42 {
		t.Errorf("Error.ExitCode() = %d, want %d", err.ExitCode(), 42)
	}
	if err.Error() != "test error" {
		t.Errorf("Error.Error() = %q, want %q", err.Error(), "test error")
	}
}

// TestWrapperFlagsExported verifies WrapperFlags is properly exported.
func TestWrapperFlagsExported(t *testing.T) {
	flags := WrapperFlags{
		PackPath:     "/path/to/pack",
		OutputDir:    "/output",
		JSONMode:     true,
		QuietMode:    true,
		HasSeparator: true,
	}

	if flags.PackPath != "/path/to/pack" {
		t.Errorf("PackPath = %q, want %q", flags.PackPath, "/path/to/pack")
	}
	if !flags.JSONMode {
		t.Error("JSONMode = false, want true")
	}
}

// TestFindProjectRoot verifies project.FindRoot works correctly.
func TestFindProjectRoot(t *testing.T) {
	// Create a temp directory with epack.yaml
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "epack.yaml")
	if err := os.WriteFile(configPath, []byte("collectors: []"), 0644); err != nil {
		t.Fatalf("failed to write epack.yaml: %v", err)
	}

	// Should find the project root
	found, err := project.FindRoot(tmpDir)
	if err != nil {
		t.Fatalf("project.FindRoot error: %v", err)
	}
	if found != tmpDir {
		t.Errorf("project.FindRoot = %q, want %q", found, tmpDir)
	}

	// Should error when no epack.yaml exists
	emptyDir := t.TempDir()
	_, err = project.FindRoot(emptyDir)
	if err == nil {
		t.Error("expected error when no epack.yaml exists")
	}
}

func TestLoadToolConfigReturnsProjectRoot(t *testing.T) {
	tmpDir := t.TempDir()
	subDir := filepath.Join(tmpDir, "nested", "dir")
	if err := os.MkdirAll(subDir, 0755); err != nil {
		t.Fatalf("failed to create subdir: %v", err)
	}

	configPath := filepath.Join(tmpDir, "epack.yaml")
	configData := []byte("tools:\n  validate:\n    binary: /bin/echo\n")
	if err := os.WriteFile(configPath, configData, 0644); err != nil {
		t.Fatalf("failed to write epack.yaml: %v", err)
	}

	lockfilePath := filepath.Join(tmpDir, lockfile.FileName)
	lockfileData := []byte("schema_version: 1\ntools:\n  validate:\n    kind: external\n    platforms: {}\n")
	if err := os.WriteFile(lockfilePath, lockfileData, 0644); err != nil {
		t.Fatalf("failed to write lockfile: %v", err)
	}

	toolCfg, loadedLockfile, projectRoot, err := loadToolConfig(subDir, "validate")
	if err != nil {
		t.Fatalf("loadToolConfig() error = %v", err)
	}
	if projectRoot != tmpDir {
		t.Fatalf("projectRoot = %q, want %q", projectRoot, tmpDir)
	}
	if toolCfg.Binary != "/bin/echo" {
		t.Fatalf("toolCfg.Binary = %q, want %q", toolCfg.Binary, "/bin/echo")
	}
	if loadedLockfile == nil {
		t.Fatal("loadedLockfile is nil")
	}
	if _, ok := loadedLockfile.GetTool("validate"); !ok {
		t.Fatal("loadedLockfile missing validate tool entry")
	}
}

func TestBuildProtocolEnvIncludesProjectRoot(t *testing.T) {
	env := buildProtocolEnv(protocolEnvInput{
		toolName:       "validate",
		runID:          "run-123",
		runDir:         "/tmp/run",
		packPath:       "/tmp/pack.epack",
		packDigest:     "sha256:abc",
		projectRoot:    "/repo/root",
		startedAt:      testTime(t),
		toolCfg:        config.ToolConfig{},
		configFilePath: "/tmp/config.json",
		flags:          WrapperFlags{},
	})

	if !containsEnv(env, "EPACK_PROJECT_ROOT=/repo/root") {
		t.Fatalf("EPACK_PROJECT_ROOT not found in env: %v", env)
	}
}

func testTime(t *testing.T) time.Time {
	t.Helper()
	return mustParseTime(t, "2026-03-19T12:00:00Z")
}

func mustParseTime(t *testing.T, value string) time.Time {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		t.Fatalf("time.Parse(%q): %v", value, err)
	}
	return parsed
}

func containsEnv(env []string, want string) bool {
	for _, item := range env {
		if item == want {
			return true
		}
	}
	return false
}
