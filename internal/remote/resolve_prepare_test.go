package remote_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/locktivity/epack/internal/component/config"
	"github.com/locktivity/epack/internal/remote"
)

func TestPrepareAdapterExecutor_Success(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on Windows")
	}

	projectRoot := t.TempDir()
	adapter := writeAdapterScript(t, projectRoot, `{"name":"test","kind":"remote_adapter","deploy_protocol_version":1,"features":{"prepare_finalize":true,"pull":true}}`)
	digest := sha256Digest(t, adapter)
	writeLockfile(t, projectRoot, "origin", digest)

	cfg := &config.JobConfig{}
	remoteCfg := &config.RemoteConfig{
		Adapter: "test",
		Binary:  adapter,
	}

	exec, caps, err := remote.PrepareAdapterExecutor(context.Background(), projectRoot, "origin", cfg, remoteCfg, remote.AdapterExecutorOptions{
		Verification: remote.VerificationOptions{},
	})
	if err != nil {
		t.Fatalf("PrepareAdapterExecutor() error = %v", err)
	}
	defer exec.Close()

	if exec == nil {
		t.Fatal("PrepareAdapterExecutor() returned nil executor")
	}
	if caps == nil {
		t.Fatal("PrepareAdapterExecutor() returned nil capabilities")
	}
	if caps.Name != "test" {
		t.Fatalf("capabilities name = %q, want %q", caps.Name, "test")
	}
}

func TestPrepareAdapterExecutor_MissingDigest(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on Windows")
	}

	projectRoot := t.TempDir()
	adapter := writeAdapterScript(t, projectRoot, `{"name":"test","kind":"remote_adapter","deploy_protocol_version":1,"features":{"prepare_finalize":true}}`)
	writeLockfile(t, projectRoot, "origin", "")

	cfg := &config.JobConfig{}
	remoteCfg := &config.RemoteConfig{
		Adapter: "test",
		Binary:  adapter,
	}

	_, _, err := remote.PrepareAdapterExecutor(context.Background(), projectRoot, "origin", cfg, remoteCfg, remote.AdapterExecutorOptions{
		Verification: remote.VerificationOptions{},
	})
	if err == nil {
		t.Fatal("PrepareAdapterExecutor() expected error for missing digest")
	}
	if !strings.Contains(err.Error(), "not pinned in lockfile") {
		t.Fatalf("error = %q, want message containing %q", err.Error(), "not pinned in lockfile")
	}
}

func TestPrepareAdapterExecutor_UnsupportedProtocol(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on Windows")
	}

	projectRoot := t.TempDir()
	adapter := writeAdapterScript(t, projectRoot, `{"name":"test","kind":"remote_adapter","deploy_protocol_version":0,"features":{"prepare_finalize":true}}`)
	digest := sha256Digest(t, adapter)
	writeLockfile(t, projectRoot, "origin", digest)

	cfg := &config.JobConfig{}
	remoteCfg := &config.RemoteConfig{
		Adapter: "test",
		Binary:  adapter,
	}

	_, _, err := remote.PrepareAdapterExecutor(context.Background(), projectRoot, "origin", cfg, remoteCfg, remote.AdapterExecutorOptions{
		Verification: remote.VerificationOptions{},
	})
	if err == nil {
		t.Fatal("PrepareAdapterExecutor() expected protocol version error")
	}
	if !strings.Contains(err.Error(), "not supported") {
		t.Fatalf("error = %q, want message containing %q", err.Error(), "not supported")
	}
}

func writeAdapterScript(t *testing.T, dir, capabilitiesJSON string) string {
	t.Helper()

	path := filepath.Join(dir, "adapter")
	content := fmt.Sprintf("#!/bin/sh\necho '%s'\n", capabilitiesJSON)
	if err := os.WriteFile(path, []byte(content), 0755); err != nil {
		t.Fatalf("writing adapter script: %v", err)
	}
	return path
}

func sha256Digest(t *testing.T, path string) string {
	t.Helper()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading adapter script: %v", err)
	}
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func writeLockfile(t *testing.T, projectRoot, remoteName, digest string) {
	t.Helper()

	platform := runtime.GOOS + "/" + runtime.GOARCH
	content := fmt.Sprintf("schema_version: 1\nremotes:\n  %s:\n    kind: external\n    platforms:\n      %s:\n", remoteName, platform)
	if digest != "" {
		content += fmt.Sprintf("        digest: %s\n", digest)
	}

	path := filepath.Join(projectRoot, "epack.lock.yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("writing lockfile: %v", err)
	}
}

// TestResolveAdapterPath_BinaryRemoteSkipsLockfile verifies that binary-based remotes
// don't require a lockfile to exist. This enables local development with binary: paths.
func TestResolveAdapterPath_BinaryRemoteSkipsLockfile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on Windows")
	}

	projectRoot := t.TempDir()
	adapter := writeAdapterScript(t, projectRoot, `{"name":"test","kind":"remote_adapter","deploy_protocol_version":1,"features":{"prepare_finalize":true}}`)

	// Compute digest for verification
	digest := sha256Digest(t, adapter)

	// Create config WITHOUT a lockfile - this should work for binary remotes
	cfg := &config.RemoteConfig{
		Adapter: "test",
		Binary:  adapter,
	}

	// NO lockfile written - this would fail for source-based remotes

	// ResolveAdapterPath should succeed without lockfile for binary remotes
	// Note: We use AllowUnverifiedSource to skip digest verification since no lockfile
	opts := remote.AdapterExecutorOptions{
		Verification: remote.VerificationOptions{
			Unsafe: remote.VerificationUnsafeOverrides{
				AllowUnverifiedSource: true,
			},
		},
	}

	jobCfg := &config.JobConfig{}
	exec, caps, err := remote.PrepareAdapterExecutor(context.Background(), projectRoot, "origin", jobCfg, cfg, opts)
	if err != nil {
		t.Fatalf("PrepareAdapterExecutor() should succeed without lockfile for binary remote: %v", err)
	}
	defer exec.Close()

	if exec == nil {
		t.Fatal("PrepareAdapterExecutor() returned nil executor")
	}
	if caps == nil {
		t.Fatal("PrepareAdapterExecutor() returned nil capabilities")
	}

	// Verify it still works with lockfile present
	writeLockfile(t, projectRoot, "origin", digest)

	exec2, caps2, err := remote.PrepareAdapterExecutor(context.Background(), projectRoot, "origin", jobCfg, cfg, remote.AdapterExecutorOptions{})
	if err != nil {
		t.Fatalf("PrepareAdapterExecutor() with lockfile: %v", err)
	}
	defer exec2.Close()

	if caps2.Name != "test" {
		t.Errorf("caps.Name = %q, want %q", caps2.Name, "test")
	}
}

// TestResolveAdapterPath_SourceRemoteRequiresLockfile verifies that source-based remotes
// still require a lockfile for digest verification.
func TestResolveAdapterPath_SourceRemoteRequiresLockfile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on Windows")
	}

	projectRoot := t.TempDir()

	// Create config for source-based remote (no binary)
	cfg := &config.RemoteConfig{
		Adapter: "test",
		Source:  "owner/repo@v1.0.0",
		// No Binary set - this is a source-based remote
	}

	// NO lockfile written

	jobCfg := &config.JobConfig{}
	_, _, err := remote.PrepareAdapterExecutor(context.Background(), projectRoot, "origin", jobCfg, cfg, remote.AdapterExecutorOptions{})
	if err == nil {
		t.Fatal("PrepareAdapterExecutor() should fail without lockfile for source-based remote")
	}

	// Error should mention lockfile
	if !strings.Contains(err.Error(), "lockfile") {
		t.Errorf("error should mention lockfile, got: %v", err)
	}
}

// TestPrepareAdapterExecutor_SecretsPassedThrough verifies that the Secrets field
// from RemoteConfig is passed through to the Executor.
func TestPrepareAdapterExecutor_SecretsPassedThrough(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on Windows")
	}

	projectRoot := t.TempDir()
	adapter := writeAdapterScript(t, projectRoot, `{"name":"test","kind":"remote_adapter","deploy_protocol_version":1,"features":{"prepare_finalize":true}}`)
	digest := sha256Digest(t, adapter)
	writeLockfile(t, projectRoot, "origin", digest)

	cfg := &config.JobConfig{}
	remoteCfg := &config.RemoteConfig{
		Adapter: "test",
		Binary:  adapter,
		Secrets: []string{"MY_SECRET", "OTHER_TOKEN"},
	}

	exec, _, err := remote.PrepareAdapterExecutor(context.Background(), projectRoot, "origin", cfg, remoteCfg, remote.AdapterExecutorOptions{})
	if err != nil {
		t.Fatalf("PrepareAdapterExecutor() error = %v", err)
	}
	defer exec.Close()

	// Verify secrets were passed through
	if len(exec.Secrets) != 2 {
		t.Errorf("Secrets length = %d, want 2", len(exec.Secrets))
	}
	if exec.Secrets[0] != "MY_SECRET" || exec.Secrets[1] != "OTHER_TOKEN" {
		t.Errorf("Secrets = %v, want [MY_SECRET OTHER_TOKEN]", exec.Secrets)
	}
}
