//go:build components

package remotecmd

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/locktivity/epack/internal/cli/output"
)

func TestRunWhoami_NoRemotes(t *testing.T) {
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

	// Run whoami with no args (all remotes)
	cmd := newWhoamiCommand()
	err := cmd.Execute()
	if err != nil {
		t.Fatalf("runWhoami() error = %v", err)
	}

	// Check output mentions no remotes
	outStr := stdout.String()
	if !strings.Contains(outStr, "No remotes configured") {
		t.Errorf("output should mention no remotes, got: %s", outStr)
	}
}

func TestRunWhoami_RemoteNotFound(t *testing.T) {
	// Create temp project with a remote
	projectDir := t.TempDir()
	configContent := `stream: test/stream
collectors:
  github:
    source: owner/repo@v1.0.0
remotes:
  locktivity:
    source: locktivity/epack-remote-locktivity@v1
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

	// Run whoami with nonexistent remote
	cmd := newWhoamiCommand()
	cmd.SetArgs([]string{"nonexistent"})
	err := cmd.Execute()
	if err == nil {
		t.Error("expected error for nonexistent remote")
	}
	if err != nil && !strings.Contains(err.Error(), "not found") {
		t.Errorf("error should mention 'not found', got: %v", err)
	}
}

func TestRunWhoami_NotInProject(t *testing.T) {
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

	// Run whoami - should error
	cmd := newWhoamiCommand()
	err := cmd.Execute()
	if err == nil {
		t.Error("expected error when not in project")
	}
}

func TestRunWhoami_JSONOutput_NoRemotes(t *testing.T) {
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

	// Run whoami
	cmd := newWhoamiCommand()
	err := cmd.Execute()
	if err != nil {
		t.Fatalf("runWhoami() error = %v", err)
	}

	// Parse JSON output
	var result struct {
		Identities []interface{} `json:"identities"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("parsing JSON output: %v", err)
	}

	if len(result.Identities) != 0 {
		t.Errorf("expected 0 identities, got %d", len(result.Identities))
	}
}

func TestRunWhoami_WithMockAdapter_Authenticated(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on Windows - no shell scripts")
	}

	projectDir := t.TempDir()

	// Create mock adapter that returns authenticated response
	adapterScript := `#!/bin/sh
case "$1" in
  --capabilities)
    echo '{"name":"mock","kind":"remote_adapter","deploy_protocol_version":1,"version":"1.0.0","features":{"prepare_finalize":true,"pull":true,"whoami":true}}'
    ;;
  auth.whoami)
    echo '{"ok":true,"type":"auth.whoami.result","identity":{"authenticated":true,"subject":"user@example.com","issuer":"https://accounts.example.com"}}'
    ;;
  *)
    echo '{"ok":false,"error":{"code":"unknown_command"}}' >&2
    exit 1
    ;;
esac
`
	adapterPath := filepath.Join(projectDir, "mock-adapter")
	if err := os.WriteFile(adapterPath, []byte(adapterScript), 0755); err != nil {
		t.Fatalf("writing adapter: %v", err)
	}

	// Compute digest for lockfile
	adapterData, _ := os.ReadFile(adapterPath)
	sum := sha256.Sum256(adapterData)
	digest := "sha256:" + hex.EncodeToString(sum[:])

	// Create config with binary remote
	configContent := fmt.Sprintf(`stream: test/stream
collectors:
  github:
    source: owner/repo@v1.0.0
remotes:
  mock:
    binary: %s
    adapter: mock
`, adapterPath)
	if err := os.WriteFile(filepath.Join(projectDir, "epack.yaml"), []byte(configContent), 0644); err != nil {
		t.Fatalf("writing config: %v", err)
	}

	// Create lockfile
	platform := runtime.GOOS + "/" + runtime.GOARCH
	lockContent := fmt.Sprintf(`schema_version: 1
remotes:
  mock:
    kind: external
    platforms:
      %s:
        digest: %s
`, platform, digest)
	if err := os.WriteFile(filepath.Join(projectDir, "epack.lock.yaml"), []byte(lockContent), 0644); err != nil {
		t.Fatalf("writing lockfile: %v", err)
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

	// Run whoami
	cmd := newWhoamiCommand()
	cmd.SetArgs([]string{"mock"})
	err := cmd.Execute()
	if err != nil {
		t.Fatalf("runWhoami() error = %v, stderr: %s", err, stderr.String())
	}

	// Parse JSON output
	var result struct {
		Identities []struct {
			Remote        string `json:"remote"`
			Authenticated bool   `json:"authenticated"`
			Subject       string `json:"subject"`
			Issuer        string `json:"issuer"`
			Supported     bool   `json:"supported"`
		} `json:"identities"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("parsing JSON output: %v\noutput: %s", err, stdout.String())
	}

	if len(result.Identities) != 1 {
		t.Fatalf("expected 1 identity, got %d", len(result.Identities))
	}

	id := result.Identities[0]
	if id.Remote != "mock" {
		t.Errorf("remote = %q, want %q", id.Remote, "mock")
	}
	if !id.Authenticated {
		t.Error("expected authenticated = true")
	}
	if id.Subject != "user@example.com" {
		t.Errorf("subject = %q, want %q", id.Subject, "user@example.com")
	}
	if !id.Supported {
		t.Error("expected supported = true")
	}
}

func TestRunWhoami_WithMockAdapter_NotAuthenticated(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on Windows - no shell scripts")
	}

	projectDir := t.TempDir()

	// Create mock adapter that returns unauthenticated response
	adapterScript := `#!/bin/sh
case "$1" in
  --capabilities)
    echo '{"name":"mock","kind":"remote_adapter","deploy_protocol_version":1,"version":"1.0.0","features":{"prepare_finalize":true,"pull":true,"whoami":true}}'
    ;;
  auth.whoami)
    echo '{"ok":true,"type":"auth.whoami.result","identity":{"authenticated":false}}'
    ;;
  *)
    echo '{"ok":false,"error":{"code":"unknown_command"}}' >&2
    exit 1
    ;;
esac
`
	adapterPath := filepath.Join(projectDir, "mock-adapter")
	if err := os.WriteFile(adapterPath, []byte(adapterScript), 0755); err != nil {
		t.Fatalf("writing adapter: %v", err)
	}

	// Compute digest for lockfile
	adapterData, _ := os.ReadFile(adapterPath)
	sum := sha256.Sum256(adapterData)
	digest := "sha256:" + hex.EncodeToString(sum[:])

	// Create config with binary remote
	configContent := fmt.Sprintf(`stream: test/stream
collectors:
  github:
    source: owner/repo@v1.0.0
remotes:
  mock:
    binary: %s
    adapter: mock
`, adapterPath)
	if err := os.WriteFile(filepath.Join(projectDir, "epack.yaml"), []byte(configContent), 0644); err != nil {
		t.Fatalf("writing config: %v", err)
	}

	// Create lockfile
	platform := runtime.GOOS + "/" + runtime.GOARCH
	lockContent := fmt.Sprintf(`schema_version: 1
remotes:
  mock:
    kind: external
    platforms:
      %s:
        digest: %s
`, platform, digest)
	if err := os.WriteFile(filepath.Join(projectDir, "epack.lock.yaml"), []byte(lockContent), 0644); err != nil {
		t.Fatalf("writing lockfile: %v", err)
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

	// Run whoami
	cmd := newWhoamiCommand()
	cmd.SetArgs([]string{"mock"})
	err := cmd.Execute()
	if err != nil {
		t.Fatalf("runWhoami() error = %v", err)
	}

	// Parse JSON output
	var result struct {
		Identities []struct {
			Authenticated bool `json:"authenticated"`
		} `json:"identities"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("parsing JSON output: %v", err)
	}

	if len(result.Identities) != 1 {
		t.Fatalf("expected 1 identity, got %d", len(result.Identities))
	}

	if result.Identities[0].Authenticated {
		t.Error("expected authenticated = false")
	}
}

func TestRunWhoami_AdapterDoesNotSupportWhoami(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on Windows - no shell scripts")
	}

	projectDir := t.TempDir()

	// Create mock adapter without whoami support
	adapterScript := `#!/bin/sh
case "$1" in
  --capabilities)
    echo '{"name":"mock","kind":"remote_adapter","deploy_protocol_version":1,"version":"1.0.0","features":{"prepare_finalize":true,"pull":true}}'
    ;;
  *)
    echo '{"ok":false,"error":{"code":"unknown_command"}}' >&2
    exit 1
    ;;
esac
`
	adapterPath := filepath.Join(projectDir, "mock-adapter")
	if err := os.WriteFile(adapterPath, []byte(adapterScript), 0755); err != nil {
		t.Fatalf("writing adapter: %v", err)
	}

	// Compute digest for lockfile
	adapterData, _ := os.ReadFile(adapterPath)
	sum := sha256.Sum256(adapterData)
	digest := "sha256:" + hex.EncodeToString(sum[:])

	// Create config with binary remote
	configContent := fmt.Sprintf(`stream: test/stream
collectors:
  github:
    source: owner/repo@v1.0.0
remotes:
  mock:
    binary: %s
    adapter: mock
`, adapterPath)
	if err := os.WriteFile(filepath.Join(projectDir, "epack.yaml"), []byte(configContent), 0644); err != nil {
		t.Fatalf("writing config: %v", err)
	}

	// Create lockfile
	platform := runtime.GOOS + "/" + runtime.GOARCH
	lockContent := fmt.Sprintf(`schema_version: 1
remotes:
  mock:
    kind: external
    platforms:
      %s:
        digest: %s
`, platform, digest)
	if err := os.WriteFile(filepath.Join(projectDir, "epack.lock.yaml"), []byte(lockContent), 0644); err != nil {
		t.Fatalf("writing lockfile: %v", err)
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

	// Run whoami
	cmd := newWhoamiCommand()
	cmd.SetArgs([]string{"mock"})
	err := cmd.Execute()
	if err != nil {
		t.Fatalf("runWhoami() error = %v", err)
	}

	// Parse JSON output
	var result struct {
		Identities []struct {
			Supported bool   `json:"supported"`
			Error     string `json:"error"`
		} `json:"identities"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("parsing JSON output: %v", err)
	}

	if len(result.Identities) != 1 {
		t.Fatalf("expected 1 identity, got %d", len(result.Identities))
	}

	if result.Identities[0].Supported {
		t.Error("expected supported = false")
	}
	if !strings.Contains(result.Identities[0].Error, "not support") {
		t.Errorf("error should mention not supported, got: %q", result.Identities[0].Error)
	}
}
