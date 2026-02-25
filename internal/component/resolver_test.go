package component

import (
	"runtime"
	"strings"
	"testing"

	"github.com/locktivity/epack/internal/component/config"
	"github.com/locktivity/epack/internal/component/lockfile"
	"github.com/locktivity/epack/internal/component/sync"
	"github.com/locktivity/epack/internal/componenttypes"
	"github.com/locktivity/epack/internal/platform"
)

func TestInstallPath(t *testing.T) {
	path, err := sync.InstallPath("/base", componenttypes.KindCollector, "mycollector", "v1.2.3", "mycollector")
	if err != nil {
		t.Fatalf("InstallPath() error: %v", err)
	}

	// Path should include all components
	if !strings.Contains(path, "collectors") {
		t.Error("path should contain 'collectors'")
	}
	if !strings.Contains(path, "mycollector") {
		t.Error("path should contain collector name")
	}
	if !strings.Contains(path, "v1.2.3") {
		t.Error("path should contain version")
	}
	if !strings.Contains(path, runtime.GOOS+"-"+runtime.GOARCH) {
		t.Errorf("path should contain platform %s-%s", runtime.GOOS, runtime.GOARCH)
	}

	// Path should start with base
	if !strings.HasPrefix(path, "/base") {
		t.Errorf("path should start with /base, got %s", path)
	}
}

func TestInstallPath_ErrorOnInvalidCollectorName(t *testing.T) {
	_, err := sync.InstallPath("/base", componenttypes.KindCollector, "../traversal", "v1.0.0", "collector")
	if err == nil {
		t.Error("InstallPath should return error on invalid collector name")
	}
	if !strings.Contains(err.Error(), "invalid collector name") {
		t.Errorf("error should mention invalid collector name, got: %v", err)
	}
}

func TestInstallPath_ErrorOnEmptyVersion(t *testing.T) {
	_, err := sync.InstallPath("/base", componenttypes.KindCollector, "collector", "", "collector")
	if err == nil {
		t.Error("InstallPath should return error on empty version")
	}
	if !strings.Contains(err.Error(), "version cannot be empty") {
		t.Errorf("error should mention empty version, got: %v", err)
	}
}

func TestInstallPath_ErrorOnInvalidVersion(t *testing.T) {
	_, err := sync.InstallPath("/base", componenttypes.KindCollector, "collector", "../etc/passwd", "collector")
	if err == nil {
		t.Error("InstallPath should return error on invalid version")
	}
	if !strings.Contains(err.Error(), "invalid version") {
		t.Errorf("error should mention invalid version, got: %v", err)
	}
}

func TestInstallPath_ErrorOnInvalidBinaryName(t *testing.T) {
	_, err := sync.InstallPath("/base", componenttypes.KindCollector, "collector", "v1.0.0", "../bad")
	if err == nil {
		t.Error("InstallPath should return error on invalid binary name")
	}
	if !strings.Contains(err.Error(), "invalid binary name") {
		t.Errorf("error should mention invalid binary name, got: %v", err)
	}
}

func TestResolveBinaryPath_ExternalBinary(t *testing.T) {
	cfg := config.CollectorConfig{Binary: "/usr/local/bin/collector"}
	lf := lockfile.New()

	path, err := sync.ResolveBinaryPath("/base", "test", cfg, lf)
	if err != nil {
		t.Fatalf("sync.ResolveBinaryPath() error: %v", err)
	}
	if path != "/usr/local/bin/collector" {
		t.Errorf("path = %q, want %q", path, "/usr/local/bin/collector")
	}
}

func TestResolveBinaryPath_ExternalBinaryRelativePath(t *testing.T) {
	cfg := config.CollectorConfig{Binary: "relative/path/collector"}
	lf := lockfile.New()

	_, err := sync.ResolveBinaryPath("/base", "test", cfg, lf)
	if err == nil {
		t.Error("sync.ResolveBinaryPath() expected error for relative path, got nil")
	}
	if !strings.Contains(err.Error(), "absolute path") {
		t.Errorf("error should mention absolute path, got: %v", err)
	}
}

func TestResolveBinaryPath_SourceBased(t *testing.T) {
	cfg := config.CollectorConfig{Source: "owner/repo@v1.2.3"}
	lf := lockfile.New()
	lf.Collectors["mycollector"] = lockfile.LockedCollector{
		Version: "v1.2.3",
		Platforms: map[string]componenttypes.LockedPlatform{
			platform.Key(runtime.GOOS, runtime.GOARCH): {Digest: "sha256:abc123"},
		},
	}

	path, err := sync.ResolveBinaryPath("/base", "mycollector", cfg, lf)
	if err != nil {
		t.Fatalf("sync.ResolveBinaryPath() error: %v", err)
	}

	// Should return deterministic install path
	if !strings.Contains(path, "mycollector") {
		t.Errorf("path should contain collector name, got %s", path)
	}
	if !strings.Contains(path, "v1.2.3") {
		t.Errorf("path should contain version, got %s", path)
	}
}

func TestResolveBinaryPath_NoSourceOrBinary(t *testing.T) {
	cfg := config.CollectorConfig{}
	lf := lockfile.New()

	_, err := sync.ResolveBinaryPath("/base", "test", cfg, lf)
	if err == nil {
		t.Error("sync.ResolveBinaryPath() expected error for empty config, got nil")
	}
	if !strings.Contains(err.Error(), "no source or binary") {
		t.Errorf("error should mention no source or binary, got: %v", err)
	}
}

func TestResolveBinaryPath_NotInLockfile(t *testing.T) {
	cfg := config.CollectorConfig{Source: "owner/repo@v1.0.0"}
	lf := lockfile.New() // empty lockfile

	_, err := sync.ResolveBinaryPath("/base", "missing", cfg, lf)
	if err == nil {
		t.Error("sync.ResolveBinaryPath() expected error for missing lockfile entry, got nil")
	}
	if !strings.Contains(err.Error(), "not found in lockfile") {
		t.Errorf("error should mention not found in lockfile, got: %v", err)
	}
}

func TestResolveBinaryPath_MissingVersion(t *testing.T) {
	cfg := config.CollectorConfig{Source: "owner/repo@v1.0.0"}
	lf := lockfile.New()
	lf.Collectors["test"] = lockfile.LockedCollector{
		// Version is empty
		Platforms: map[string]componenttypes.LockedPlatform{
			platform.Key(runtime.GOOS, runtime.GOARCH): {Digest: "sha256:abc"},
		},
	}

	_, err := sync.ResolveBinaryPath("/base", "test", cfg, lf)
	if err == nil {
		t.Error("sync.ResolveBinaryPath() expected error for missing version, got nil")
	}
	if !strings.Contains(err.Error(), "missing version") {
		t.Errorf("error should mention missing version, got: %v", err)
	}
}

func TestResolveBinaryPath_MissingPlatform(t *testing.T) {
	cfg := config.CollectorConfig{Source: "owner/repo@v1.0.0"}
	lf := lockfile.New()
	lf.Collectors["test"] = lockfile.LockedCollector{
		Version: "v1.0.0",
		Platforms: map[string]componenttypes.LockedPlatform{
			// Different platform
			"other/arch": {Digest: "sha256:abc"},
		},
	}

	_, err := sync.ResolveBinaryPath("/base", "test", cfg, lf)
	if err == nil {
		t.Error("sync.ResolveBinaryPath() expected error for missing platform, got nil")
	}
	if !strings.Contains(err.Error(), "missing platform") {
		t.Errorf("error should mention missing platform, got: %v", err)
	}
}
