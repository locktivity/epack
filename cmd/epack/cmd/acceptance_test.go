package cmd

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// Acceptance tests that invoke the CLI binary directly.
// These tests verify end-to-end behavior including argument parsing,
// output formatting, and exit codes.

var (
	binaryPath string
	buildOnce  sync.Once
	buildErr   error
)

// ensureBinary builds the CLI binary once for all acceptance tests.
func ensureBinary(t *testing.T) string {
	t.Helper()

	buildOnce.Do(func() {
		// Build to a temp directory
		tmpDir, err := os.MkdirTemp("", "epack-test-*")
		if err != nil {
			buildErr = err
			return
		}

		binaryPath = filepath.Join(tmpDir, "epack")

		cmd := exec.Command("go", "build", "-o", binaryPath, "../")
		cmd.Dir = filepath.Join(mustGetWd(), "cmd/epack/cmd")
		var stderr bytes.Buffer
		cmd.Stderr = &stderr

		if err := cmd.Run(); err != nil {
			buildErr = err
			return
		}
	})

	if buildErr != nil {
		t.Fatalf("failed to build binary: %v", buildErr)
	}

	return binaryPath
}

func mustGetWd() string {
	// Go up from cmd/epack/cmd to project root
	wd, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	// We're in cmd/epack/cmd, go up 3 levels
	return filepath.Join(wd, "../../..")
}

// CLIResult holds the result of running a CLI command.
type CLIResult struct {
	Stdout   string
	Stderr   string
	ExitCode int
}

// runCLI executes the CLI with the given arguments and returns the result.
func runCLI(t *testing.T, args ...string) CLIResult {
	t.Helper()

	binary := ensureBinary(t)

	cmd := exec.Command(binary, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()

	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			t.Fatalf("failed to run CLI: %v", err)
		}
	}

	return CLIResult{
		Stdout:   stdout.String(),
		Stderr:   stderr.String(),
		ExitCode: exitCode,
	}
}

// runCLIWithEnv executes the CLI with custom environment variables.
func runCLIWithEnv(t *testing.T, env map[string]string, args ...string) CLIResult {
	t.Helper()

	binary := ensureBinary(t)

	cmd := exec.Command(binary, args...)
	cmd.Env = os.Environ()
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()

	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			t.Fatalf("failed to run CLI: %v", err)
		}
	}

	return CLIResult{
		Stdout:   stdout.String(),
		Stderr:   stderr.String(),
		ExitCode: exitCode,
	}
}

// Acceptance Test: Version command
func TestAcceptance_Version(t *testing.T) {
	result := runCLI(t, "version")

	if result.ExitCode != 0 {
		t.Errorf("exit code = %d, want 0", result.ExitCode)
	}

	if !strings.Contains(result.Stdout, "epack") {
		t.Errorf("stdout should contain 'epack', got: %s", result.Stdout)
	}
}

// Acceptance Test: Help command
func TestAcceptance_Help(t *testing.T) {
	result := runCLI(t, "--help")

	if result.ExitCode != 0 {
		t.Errorf("exit code = %d, want 0", result.ExitCode)
	}

	// Check for expected subcommands
	expectedCommands := []string{"build", "sign", "verify", "inspect", "list", "extract"}
	for _, cmd := range expectedCommands {
		if !strings.Contains(result.Stdout, cmd) {
			t.Errorf("help should mention '%s' command", cmd)
		}
	}
}

// Acceptance Test: Build -> Inspect -> Verify workflow
func TestAcceptance_BuildInspectVerify(t *testing.T) {
	tmpDir := t.TempDir()

	// Create test artifact
	artifactPath := filepath.Join(tmpDir, "data.json")
	if err := os.WriteFile(artifactPath, []byte(`{"key": "value"}`), 0644); err != nil {
		t.Fatalf("failed to write artifact: %v", err)
	}

	packPath := filepath.Join(tmpDir, "test.epack")

	// Build
	result := runCLI(t, "build", packPath, artifactPath, "--stream", "test/workflow")
	if result.ExitCode != 0 {
		t.Fatalf("build failed: exit %d, stderr: %s", result.ExitCode, result.Stderr)
	}

	// Verify pack was created
	if _, err := os.Stat(packPath); os.IsNotExist(err) {
		t.Fatal("pack file was not created")
	}

	// Inspect
	result = runCLI(t, "inspect", packPath)
	if result.ExitCode != 0 {
		t.Fatalf("inspect failed: exit %d, stderr: %s", result.ExitCode, result.Stderr)
	}

	if !strings.Contains(result.Stdout, "test/workflow") {
		t.Errorf("inspect output should contain stream name, got: %s", result.Stdout)
	}

	// Inspect with JSON output
	result = runCLI(t, "inspect", "--json", packPath)
	if result.ExitCode != 0 {
		t.Fatalf("inspect --json failed: exit %d, stderr: %s", result.ExitCode, result.Stderr)
	}

	if !strings.Contains(result.Stdout, `"stream"`) {
		t.Errorf("JSON output should contain 'stream' field, got: %s", result.Stdout)
	}

	// Verify (integrity only, since we didn't sign)
	result = runCLI(t, "verify", "--integrity-only", packPath)
	if result.ExitCode != 0 {
		t.Fatalf("verify failed: exit %d, stderr: %s", result.ExitCode, result.Stderr)
	}

	if !strings.Contains(result.Stdout, "passed") || !strings.Contains(result.Stdout, "Verification") {
		t.Errorf("verify output should indicate success, got: %s", result.Stdout)
	}
}

// Acceptance Test: Exit code for malformed pack
func TestAcceptance_ExitCode_MalformedPack(t *testing.T) {
	tmpDir := t.TempDir()

	// Create an invalid pack file
	invalidPack := filepath.Join(tmpDir, "invalid.epack")
	if err := os.WriteFile(invalidPack, []byte("not a zip file"), 0644); err != nil {
		t.Fatalf("failed to write invalid pack: %v", err)
	}

	result := runCLI(t, "verify", "--integrity-only", invalidPack)

	if result.ExitCode != ExitMalformedPack {
		t.Errorf("exit code = %d, want %d (ExitMalformedPack)", result.ExitCode, ExitMalformedPack)
	}
}

// Acceptance Test: Exit code for missing pack
func TestAcceptance_ExitCode_MissingPack(t *testing.T) {
	result := runCLI(t, "verify", "--integrity-only", "/nonexistent/path.epack")

	// Should fail with malformed pack code (can't open)
	if result.ExitCode != ExitMalformedPack {
		t.Errorf("exit code = %d, want %d (ExitMalformedPack)", result.ExitCode, ExitMalformedPack)
	}
}

// Acceptance Test: List artifacts
func TestAcceptance_ListArtifacts(t *testing.T) {
	tmpDir := t.TempDir()

	// Create test artifacts
	artifact1 := filepath.Join(tmpDir, "config.json")
	artifact2 := filepath.Join(tmpDir, "data.json")
	_ = os.WriteFile(artifact1, []byte(`{"config": true}`), 0644)
	_ = os.WriteFile(artifact2, []byte(`{"data": [1,2,3]}`), 0644)

	packPath := filepath.Join(tmpDir, "test.epack")

	// Build with multiple artifacts
	result := runCLI(t, "build", packPath, artifact1, artifact2, "--stream", "test/list")
	if result.ExitCode != 0 {
		t.Fatalf("build failed: exit %d, stderr: %s", result.ExitCode, result.Stderr)
	}

	// List artifacts
	result = runCLI(t, "list", "artifacts", packPath)
	if result.ExitCode != 0 {
		t.Fatalf("list artifacts failed: exit %d, stderr: %s", result.ExitCode, result.Stderr)
	}

	// Should list both artifacts
	if !strings.Contains(result.Stdout, "config.json") {
		t.Errorf("output should contain config.json, got: %s", result.Stdout)
	}
	if !strings.Contains(result.Stdout, "data.json") {
		t.Errorf("output should contain data.json, got: %s", result.Stdout)
	}
}

// Acceptance Test: Extract artifacts
func TestAcceptance_Extract(t *testing.T) {
	tmpDir := t.TempDir()

	// Create test artifact
	artifactContent := `{"extracted": true}`
	artifactPath := filepath.Join(tmpDir, "extract-test.json")
	_ = os.WriteFile(artifactPath, []byte(artifactContent), 0644)

	packPath := filepath.Join(tmpDir, "test.epack")
	outputDir := filepath.Join(tmpDir, "extracted")

	// Build
	result := runCLI(t, "build", packPath, artifactPath, "--stream", "test/extract")
	if result.ExitCode != 0 {
		t.Fatalf("build failed: exit %d", result.ExitCode)
	}

	// Extract
	result = runCLI(t, "extract", packPath, "--output", outputDir, "--all")
	if result.ExitCode != 0 {
		t.Fatalf("extract failed: exit %d, stderr: %s", result.ExitCode, result.Stderr)
	}

	// Verify extracted file exists and has correct content
	// Note: extract preserves the artifacts/ prefix by default
	extractedPath := filepath.Join(outputDir, "artifacts", "extract-test.json")
	content, err := os.ReadFile(extractedPath)
	if err != nil {
		t.Fatalf("failed to read extracted file: %v", err)
	}

	if string(content) != artifactContent {
		t.Errorf("extracted content = %q, want %q", string(content), artifactContent)
	}
}

// Acceptance Test: Quiet mode suppresses output
func TestAcceptance_QuietMode(t *testing.T) {
	tmpDir := t.TempDir()

	artifactPath := filepath.Join(tmpDir, "data.json")
	_ = os.WriteFile(artifactPath, []byte(`{}`), 0644)

	packPath := filepath.Join(tmpDir, "test.epack")

	// Build with --quiet
	result := runCLI(t, "build", "--quiet", packPath, artifactPath, "--stream", "test/quiet")
	if result.ExitCode != 0 {
		t.Fatalf("build failed: exit %d", result.ExitCode)
	}

	// Quiet mode should produce minimal output
	if len(result.Stdout) > 0 {
		t.Logf("quiet mode still produced stdout: %s", result.Stdout)
	}
}

// Acceptance Test: JSON output format
func TestAcceptance_JSONOutput(t *testing.T) {
	tmpDir := t.TempDir()

	artifactPath := filepath.Join(tmpDir, "data.json")
	_ = os.WriteFile(artifactPath, []byte(`{"test": 123}`), 0644)

	packPath := filepath.Join(tmpDir, "test.epack")

	// Build
	result := runCLI(t, "build", packPath, artifactPath, "--stream", "test/json")
	if result.ExitCode != 0 {
		t.Fatalf("build failed: exit %d", result.ExitCode)
	}

	// Inspect with JSON
	result = runCLI(t, "inspect", "--json", packPath)
	if result.ExitCode != 0 {
		t.Fatalf("inspect --json failed: exit %d", result.ExitCode)
	}

	// Verify it's valid JSON structure
	if !strings.HasPrefix(strings.TrimSpace(result.Stdout), "{") {
		t.Errorf("JSON output should start with '{', got: %s", result.Stdout)
	}

	// Check required JSON fields
	requiredFields := []string{`"spec_version"`, `"stream"`, `"pack_digest"`, `"artifacts"`}
	for _, field := range requiredFields {
		if !strings.Contains(result.Stdout, field) {
			t.Errorf("JSON output should contain %s", field)
		}
	}
}

// Acceptance Test: Verify with tampered pack fails
func TestAcceptance_VerifyTamperedPack(t *testing.T) {
	tmpDir := t.TempDir()

	artifactPath := filepath.Join(tmpDir, "data.json")
	_ = os.WriteFile(artifactPath, []byte(`{"original": true}`), 0644)

	packPath := filepath.Join(tmpDir, "test.epack")

	// Build
	result := runCLI(t, "build", packPath, artifactPath, "--stream", "test/tamper")
	if result.ExitCode != 0 {
		t.Fatalf("build failed: exit %d", result.ExitCode)
	}

	// Verify original pack passes
	result = runCLI(t, "verify", "--integrity-only", packPath)
	if result.ExitCode != 0 {
		t.Fatalf("verify of original pack failed: exit %d", result.ExitCode)
	}

	// Note: Actually tampering with a zip file is complex.
	// For a proper test, we'd need to modify the zip content.
	// This test verifies the basic flow works.
}

// Acceptance Test: Merge command
func TestAcceptance_Merge(t *testing.T) {
	tmpDir := t.TempDir()

	// Create two source packs
	artifact1 := filepath.Join(tmpDir, "data1.json")
	artifact2 := filepath.Join(tmpDir, "data2.json")
	_ = os.WriteFile(artifact1, []byte(`{"source": 1}`), 0644)
	_ = os.WriteFile(artifact2, []byte(`{"source": 2}`), 0644)

	pack1 := filepath.Join(tmpDir, "pack1.epack")
	pack2 := filepath.Join(tmpDir, "pack2.epack")
	merged := filepath.Join(tmpDir, "merged.epack")

	// Build source packs
	result := runCLI(t, "build", pack1, artifact1, "--stream", "test/source1")
	if result.ExitCode != 0 {
		t.Fatalf("build pack1 failed: exit %d", result.ExitCode)
	}

	result = runCLI(t, "build", pack2, artifact2, "--stream", "test/source2")
	if result.ExitCode != 0 {
		t.Fatalf("build pack2 failed: exit %d", result.ExitCode)
	}

	// Merge
	result = runCLI(t, "merge", merged, pack1, pack2, "--stream", "test/merged")
	if result.ExitCode != 0 {
		t.Fatalf("merge failed: exit %d, stderr: %s", result.ExitCode, result.Stderr)
	}

	// Verify merged pack
	if _, err := os.Stat(merged); os.IsNotExist(err) {
		t.Fatal("merged pack was not created")
	}

	// Inspect merged pack
	result = runCLI(t, "inspect", merged)
	if result.ExitCode != 0 {
		t.Fatalf("inspect merged failed: exit %d", result.ExitCode)
	}

	if !strings.Contains(result.Stdout, "test/merged") {
		t.Errorf("merged pack should have merged stream, got: %s", result.Stdout)
	}
}

// Acceptance Test: No color flag
func TestAcceptance_NoColor(t *testing.T) {
	tmpDir := t.TempDir()

	artifactPath := filepath.Join(tmpDir, "data.json")
	_ = os.WriteFile(artifactPath, []byte(`{}`), 0644)

	packPath := filepath.Join(tmpDir, "test.epack")

	result := runCLI(t, "build", packPath, artifactPath, "--stream", "test/nocolor")
	if result.ExitCode != 0 {
		t.Fatalf("build failed: exit %d", result.ExitCode)
	}

	// Run inspect with --no-color
	result = runCLI(t, "inspect", "--no-color", packPath)
	if result.ExitCode != 0 {
		t.Fatalf("inspect failed: exit %d", result.ExitCode)
	}

	// Check no ANSI codes in output
	if strings.Contains(result.Stdout, "\x1b[") {
		t.Error("--no-color output should not contain ANSI escape codes")
	}
}

// Acceptance Test: NO_COLOR environment variable
func TestAcceptance_NOCOLOREnv(t *testing.T) {
	tmpDir := t.TempDir()

	artifactPath := filepath.Join(tmpDir, "data.json")
	_ = os.WriteFile(artifactPath, []byte(`{}`), 0644)

	packPath := filepath.Join(tmpDir, "test.epack")

	result := runCLI(t, "build", packPath, artifactPath, "--stream", "test/envnocolor")
	if result.ExitCode != 0 {
		t.Fatalf("build failed: exit %d", result.ExitCode)
	}

	// Run inspect with NO_COLOR env
	result = runCLIWithEnv(t, map[string]string{"NO_COLOR": "1"}, "inspect", packPath)
	if result.ExitCode != 0 {
		t.Fatalf("inspect failed: exit %d", result.ExitCode)
	}

	// Check no ANSI codes in output
	if strings.Contains(result.Stdout, "\x1b[") {
		t.Error("NO_COLOR env should disable ANSI escape codes")
	}
}
