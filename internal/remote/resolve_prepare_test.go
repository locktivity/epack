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
