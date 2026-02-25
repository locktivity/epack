package collector

import (
	"bytes"
	"context"
	stderrors "errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/locktivity/epack/errors"
	"github.com/locktivity/epack/internal/component/config"
	"github.com/locktivity/epack/internal/component/lockfile"
	"github.com/locktivity/epack/internal/component/sync"
	"github.com/locktivity/epack/internal/componenttypes"
	"github.com/locktivity/epack/internal/execsafe"
	"github.com/locktivity/epack/internal/exitcode"
	"github.com/locktivity/epack/internal/limits"
	"github.com/locktivity/epack/internal/platform"
)

// runnerTestDirInCwd creates a temporary directory under the current working directory
// for tests that need to use LockFile.Save() (which requires paths under cwd).
// The directory is automatically cleaned up when the test ends.
// Returns an absolute path to ensure filepath.Rel works correctly.
func runnerTestDirInCwd(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp(".", "runner_test_*")
	if err != nil {
		t.Fatalf("creating test dir: %v", err)
	}
	// Convert to absolute path so filepath.Rel works correctly
	absDir, err := filepath.Abs(dir)
	if err != nil {
		_ = os.RemoveAll(dir)
		t.Fatalf("getting absolute path: %v", err)
	}
	t.Cleanup(func() {
		_ = os.RemoveAll(absDir)
	})
	return absDir
}

func TestRunnerResolveBinaryPath(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a fake installed binary
	installDir := filepath.Join(tmpDir, ".epack", "collectors", "github", "v1.0.0", runtime.GOOS+"-"+runtime.GOARCH)
	if err := os.MkdirAll(installDir, 0755); err != nil {
		t.Fatalf("creating install dir: %v", err)
	}
	binaryPath := filepath.Join(installDir, "github")
	if err := os.WriteFile(binaryPath, []byte("fake binary"), 0755); err != nil {
		t.Fatalf("creating binary: %v", err)
	}

	runner := &Runner{
		BaseDir: filepath.Join(tmpDir, ".epack"),
	}

	platform := platform.Key(runtime.GOOS, runtime.GOARCH)

	lf := lockfile.New()
	lf.Collectors["github"] = lockfile.LockedCollector{
		Version: "v1.0.0",
		Platforms: map[string]componenttypes.LockedPlatform{
			platform: {Digest: "sha256:abc"},
		},
	}

	// Source-based collector
	cfg := config.CollectorConfig{Source: "owner/repo@v1.0.0"}
	path, err := runner.resolveBinaryPath("github", cfg, lf)
	if err != nil {
		t.Fatalf("resolveBinaryPath() error: %v", err)
	}
	if path != binaryPath {
		t.Errorf("path = %q, want %q", path, binaryPath)
	}

	// External binary
	externalPath := filepath.Join(tmpDir, "external")
	if err := os.WriteFile(externalPath, []byte("external"), 0755); err != nil {
		t.Fatalf("creating external: %v", err)
	}
	cfg = config.CollectorConfig{Binary: externalPath}
	path, err = runner.resolveBinaryPath("external", cfg, lf)
	if err != nil {
		t.Fatalf("resolveBinaryPath() external error: %v", err)
	}
	if path != externalPath {
		t.Errorf("path = %q, want %q", path, externalPath)
	}

	// Relative path should fail
	cfg = config.CollectorConfig{Binary: "relative/path"}
	_, err = runner.resolveBinaryPath("bad", cfg, lf)
	if err == nil {
		t.Error("resolveBinaryPath() expected error for relative path")
	}
}

func TestVerifiedBinaryFD(t *testing.T) {
	tmpDir := t.TempDir()

	// Create binary with known content
	binaryPath := filepath.Join(tmpDir, "binary")
	binaryContent := []byte("test binary content")
	if err := os.WriteFile(binaryPath, binaryContent, 0755); err != nil {
		t.Fatalf("creating binary: %v", err)
	}

	// Compute correct digest
	correctDigest, err := sync.ComputeDigest(binaryPath)
	if err != nil {
		t.Fatalf("computing digest: %v", err)
	}

	// Should succeed with correct digest
	execPath, cleanup, err := execsafe.VerifiedBinaryFD(binaryPath, correctDigest)
	if err != nil {
		t.Errorf("VerifiedBinaryFD() unexpected error: %v", err)
	}
	if execPath == "" {
		t.Error("VerifiedBinaryFD() returned empty execPath")
	}
	if cleanup != nil {
		cleanup()
	}

	// Should fail with wrong digest
	_, _, err = execsafe.VerifiedBinaryFD(binaryPath, "sha256:wrongdigest")
	if err == nil {
		t.Error("verifiedBinaryFD() expected error for wrong digest")
	}
}

func TestCheckInsecureMarker(t *testing.T) {
	tmpDir := t.TempDir()

	// Create install directory with insecure marker
	installDir := filepath.Join(tmpDir, "install")
	if err := os.MkdirAll(installDir, 0755); err != nil {
		t.Fatalf("creating install dir: %v", err)
	}

	binaryPath := filepath.Join(installDir, "binary")
	if err := os.WriteFile(binaryPath, []byte("binary"), 0755); err != nil {
		t.Fatalf("creating binary: %v", err)
	}

	// Create insecure marker
	markerPath := filepath.Join(installDir, ".insecure-install")
	if err := os.WriteFile(markerPath, []byte("insecure"), 0644); err != nil {
		t.Fatalf("creating marker: %v", err)
	}

	runner := &Runner{
		BaseDir: tmpDir,
	}

	// Should fail in frozen mode with insecure marker
	err := runner.checkInsecureMarker("test", binaryPath, RunOptions{Frozen: true})
	if err == nil {
		t.Error("checkInsecureMarker() expected error for insecure install in frozen mode")
	}

	// Should also fail in non-frozen mode by default (security improvement)
	err = runner.checkInsecureMarker("test", binaryPath, RunOptions{Frozen: false})
	if err == nil {
		t.Error("checkInsecureMarker() expected error for insecure install in non-frozen mode by default")
	}

	// Should succeed only when explicitly allowed
	err = runner.checkInsecureMarker("test", binaryPath, RunOptions{
		Frozen:                  false,
		InsecureAllowUnverified: true,
	})
	if err != nil {
		t.Errorf("checkInsecureMarker() unexpected error when explicitly allowed: %v", err)
	}
}

func TestRunnerLoadLockfile(t *testing.T) {
	// Use runnerTestDirInCwd because LockFile.Save() requires paths under cwd
	tmpDir := runnerTestDirInCwd(t)

	runner := NewRunner(tmpDir)

	// All binary collectors, no lockfile - should work in non-frozen
	cfg := &config.JobConfig{
		Collectors: map[string]config.CollectorConfig{
			"external": {Binary: "/path/to/binary"},
		},
	}

	lf, err := runner.loadLockfile(cfg, RunOptions{Frozen: false})
	if err != nil {
		t.Errorf("loadLockfile() error for binary-only: %v", err)
	}
	if lf == nil {
		t.Error("loadLockfile() returned nil")
	}

	// Source collector without lockfile - should fail
	cfg = &config.JobConfig{
		Collectors: map[string]config.CollectorConfig{
			"github": {Source: "owner/repo@v1.0.0"},
		},
	}

	_, err = runner.loadLockfile(cfg, RunOptions{})
	if err == nil {
		t.Error("loadLockfile() expected error for source without lockfile")
	}

	// Create lockfile and retry
	lf = lockfile.New()
	lf.Collectors["github"] = lockfile.LockedCollector{Version: "v1.0.0"}
	if err := lf.Save(runner.LockfilePath); err != nil {
		t.Fatalf("saving lockfile: %v", err)
	}

	_, err = runner.loadLockfile(cfg, RunOptions{})
	if err != nil {
		t.Errorf("loadLockfile() error after creating lockfile: %v", err)
	}
}

func TestRunnerValidateFrozen(t *testing.T) {
	platform := platform.Key(runtime.GOOS, runtime.GOARCH)

	runner := &Runner{}

	// Config and lockfile aligned
	cfg := &config.JobConfig{
		Collectors: map[string]config.CollectorConfig{
			"github": {Source: "owner/repo@v1.0.0"},
		},
	}

	lf := lockfile.New()
	lf.Collectors["github"] = lockfile.LockedCollector{
		Source:  "github.com/owner/repo",
		Version: "v1.0.0",
		Platforms: map[string]componenttypes.LockedPlatform{
			platform: {Digest: "sha256:abc"},
		},
	}

	err := runner.validateFrozen(cfg, lf, platform)
	if err != nil {
		t.Errorf("validateFrozen() unexpected error: %v", err)
	}

	// Config has collector not in lockfile
	cfg.Collectors["missing"] = config.CollectorConfig{Source: "other/repo@v1.0.0"}
	err = runner.validateFrozen(cfg, lf, platform)
	if err == nil {
		t.Error("validateFrozen() expected error for missing collector")
	}
	delete(cfg.Collectors, "missing")

	// Lockfile has collector not in config
	lf.Collectors["stale"] = lockfile.LockedCollector{Source: "github.com/stale/repo"}
	err = runner.validateFrozen(cfg, lf, platform)
	if err == nil {
		t.Error("validateFrozen() expected error for stale lockfile entry")
	}
}

func TestRunnerValidateFrozenKindMismatch(t *testing.T) {
	platform := platform.Key(runtime.GOOS, runtime.GOARCH)

	runner := &Runner{}

	// Test: Config has source but lockfile has external
	lf := lockfile.New()
	lf.Collectors["github"] = lockfile.LockedCollector{
		Kind: "external", // Locked as external
		Platforms: map[string]componenttypes.LockedPlatform{
			platform: {Digest: "sha256:abc123"},
		},
	}

	cfg := &config.JobConfig{
		Collectors: map[string]config.CollectorConfig{
			"github": {Source: "owner/repo@^1.0.0"}, // Config declares as source
		},
	}

	err := runner.validateFrozen(cfg, lf, platform)
	if err == nil {
		t.Error("validateFrozen() expected error for source-vs-external mismatch")
	}
	var e *errors.Error
	if !stderrors.As(err, &e) {
		t.Errorf("expected *errors.Error, got %T", err)
	} else if e.ExitCode() != exitcode.LockInvalid {
		t.Errorf("ExitCode = %d, want %d", e.ExitCode(), exitcode.LockInvalid)
	}

	// Test: Config has binary but lockfile has source
	lf2 := lockfile.New()
	lf2.Collectors["github"] = lockfile.LockedCollector{
		Source:  "github.com/owner/repo", // Locked as source (no Kind = source-based)
		Version: "v1.0.0",
		Platforms: map[string]componenttypes.LockedPlatform{
			platform: {Digest: "sha256:abc123"},
		},
	}

	cfg2 := &config.JobConfig{
		Collectors: map[string]config.CollectorConfig{
			"github": {Binary: "/path/to/binary"}, // Config declares as external
		},
	}

	err = runner.validateFrozen(cfg2, lf2, platform)
	if err == nil {
		t.Error("validateFrozen() expected error for binary-vs-source mismatch")
	}
	if !stderrors.As(err, &e) {
		t.Errorf("expected *errors.Error, got %T", err)
	} else if e.ExitCode() != exitcode.LockInvalid {
		t.Errorf("ExitCode = %d, want %d", e.ExitCode(), exitcode.LockInvalid)
	}

	// Test: Lockfile has source-based but config declares as external (reverse check)
	lf3 := lockfile.New()
	lf3.Collectors["github"] = lockfile.LockedCollector{
		Source:  "github.com/owner/repo",
		Version: "v1.0.0",
		Platforms: map[string]componenttypes.LockedPlatform{
			platform: {Digest: "sha256:abc123"},
		},
	}

	cfg3 := &config.JobConfig{
		Collectors: map[string]config.CollectorConfig{
			"github": {Binary: "/path/to/binary"}, // Config declares as external
		},
	}

	err = runner.validateFrozen(cfg3, lf3, platform)
	if err == nil {
		t.Error("validateFrozen() expected error when lockfile source-based but config external")
	}
}

func TestRunnerSelectCollectors(t *testing.T) {
	runner := &Runner{}

	cfg := &config.JobConfig{
		Collectors: map[string]config.CollectorConfig{
			"github": {Source: "owner/repo@v1.0.0"},
			"aws":    {Source: "other/repo@v2.0.0"},
			"gcp":    {Source: "gcp/repo@v3.0.0"},
		},
	}

	// No filter - returns all
	selected := runner.selectCollectors(cfg, RunOptions{})
	if len(selected) != 3 {
		t.Errorf("len(selected) = %d, want 3", len(selected))
	}

	// Filter to specific collectors
	selected = runner.selectCollectors(cfg, RunOptions{Only: []string{"github", "aws"}})
	if len(selected) != 2 {
		t.Errorf("len(selected) = %d, want 2", len(selected))
	}
	if _, ok := selected["github"]; !ok {
		t.Error("missing 'github' in selected")
	}
	if _, ok := selected["aws"]; !ok {
		t.Error("missing 'aws' in selected")
	}

	// Filter to non-existent collector
	selected = runner.selectCollectors(cfg, RunOptions{Only: []string{"nonexistent"}})
	if len(selected) != 0 {
		t.Errorf("len(selected) = %d, want 0", len(selected))
	}
}

func TestRunnerRunOne(t *testing.T) {
	// This test requires an actual executable, so we'll use a simple shell command
	// Skip on Windows for simplicity
	if runtime.GOOS == "windows" {
		t.Skip("skipping on Windows")
	}

	tmpDir := t.TempDir()

	// Create a simple collector script
	scriptPath := filepath.Join(tmpDir, "collector")
	script := `#!/bin/sh
cat -
echo '{"status": "ok"}'
`
	if err := os.WriteFile(scriptPath, []byte(script), 0755); err != nil {
		t.Fatalf("creating script: %v", err)
	}

	platform := platform.Key(runtime.GOOS, runtime.GOARCH)
	digest, _ := sync.ComputeDigest(scriptPath)

	runner := &Runner{
		BaseDir: tmpDir,
	}

	lf := lockfile.New()
	lf.Collectors["test"] = lockfile.LockedCollector{
		Kind: "external",
		Platforms: map[string]componenttypes.LockedPlatform{
			platform: {Digest: digest},
		},
	}

	cfg := config.CollectorConfig{
		Binary: scriptPath,
		Config: map[string]any{"key": "value"},
	}

	result := runner.runOne(context.Background(), "test", cfg, lf, platform, RunOptions{})
	if !result.Success {
		t.Errorf("runOne() failed: %v", result.Error)
	}
	if len(result.Output) == 0 {
		t.Error("runOne() returned empty output")
	}
}

// TestRunnerRejectsSourceCollectorWithEmptyDigest is a SECURITY REGRESSION TEST.
// It verifies that source-based collectors with empty/missing digests are REJECTED
// by default, preventing the RCE vulnerability where an attacker can:
// 1. Modify the lockfile to remove the digest
// 2. Drop a trojan binary at the predictable install path
// 3. Have it executed without any verification
func TestRunnerRejectsSourceCollectorWithEmptyDigest(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on Windows")
	}

	tmpDir := t.TempDir()
	platform := platform.Key(runtime.GOOS, runtime.GOARCH)

	// Create install directory structure matching what Syncer creates
	// This simulates the attack: binary exists at predictable path
	installDir := filepath.Join(tmpDir, "collectors", "malicious", "v1.0.0", runtime.GOOS+"-"+runtime.GOARCH)
	if err := os.MkdirAll(installDir, 0755); err != nil {
		t.Fatalf("creating install dir: %v", err)
	}

	// Create a trojan script at the deterministic path
	scriptPath := filepath.Join(installDir, "malicious")
	script := `#!/bin/sh
echo '{"pwned": true}'
`
	if err := os.WriteFile(scriptPath, []byte(script), 0755); err != nil {
		t.Fatalf("creating script: %v", err)
	}

	runner := &Runner{
		BaseDir: tmpDir,
	}

	// Create lockfile with a SOURCE-BASED collector that has an EMPTY digest
	// This is the attack scenario - attacker modified lockfile to remove digest
	lf := lockfile.New()
	lf.Collectors["malicious"] = lockfile.LockedCollector{
		Source:  "github.com/attacker/pwned", // Source-based collector
		Version: "v1.0.0",
		Platforms: map[string]componenttypes.LockedPlatform{
			platform: {Digest: ""}, // Empty digest - should be rejected
		},
	}

	cfg := config.CollectorConfig{
		Source: "github.com/attacker/pwned",
		Config: map[string]any{},
	}

	// Run WITHOUT the insecure flag - this MUST fail
	result := runner.runOne(context.Background(), "malicious", cfg, lf, platform, RunOptions{
		AllowUnverifiedSourceCollectors: false, // Default - secure mode
	})

	// MUST fail - if it succeeds, we have an RCE vulnerability
	if result.Success {
		t.Errorf("SECURITY REGRESSION: Source collector with empty digest was executed! Output: %s", result.Output)
	}
	if result.Error == nil {
		t.Error("SECURITY REGRESSION: Expected error for source collector with empty digest")
	}

	// Verify the error mentions the security requirement
	if result.Error != nil {
		errMsg := result.Error.Error()
		if !strings.Contains(errMsg, "missing digest") && !strings.Contains(errMsg, "verification required") {
			t.Errorf("Error should mention missing digest requirement, got: %v", result.Error)
		}
	}
}

// TestRunnerAllowsSourceCollectorWithExplicitInsecureOpt verifies that the insecure
// opt-out flag works (for backwards compatibility), but documents the risk.
func TestRunnerAllowsSourceCollectorWithExplicitInsecureOpt(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on Windows")
	}

	tmpDir := t.TempDir()
	platform := platform.Key(runtime.GOOS, runtime.GOARCH)

	// Create install directory structure that matches what Syncer would create
	installDir := filepath.Join(tmpDir, "collectors", "test", "v1.0.0", runtime.GOOS+"-"+runtime.GOARCH)
	if err := os.MkdirAll(installDir, 0755); err != nil {
		t.Fatalf("creating install dir: %v", err)
	}

	scriptPath := filepath.Join(installDir, "test")
	script := `#!/bin/sh
echo '{"status": "ok"}'
`
	if err := os.WriteFile(scriptPath, []byte(script), 0755); err != nil {
		t.Fatalf("creating script: %v", err)
	}

	runner := &Runner{
		BaseDir: tmpDir,
	}

	lf := lockfile.New()
	lf.Collectors["test"] = lockfile.LockedCollector{
		Source:  "github.com/owner/test",
		Version: "v1.0.0",
		Platforms: map[string]componenttypes.LockedPlatform{
			platform: {Digest: ""}, // Empty digest
		},
	}

	cfg := config.CollectorConfig{
		Source: "github.com/owner/test",
		Config: map[string]any{},
	}

	// With explicit insecure flag, this should work (but is dangerous)
	result := runner.runOne(context.Background(), "test", cfg, lf, platform, RunOptions{
		AllowUnverifiedSourceCollectors: true, // INSECURE - explicit opt-in
	})

	// Should succeed when explicitly opted in
	if !result.Success {
		t.Errorf("Expected success with AllowUnverifiedSourceCollectors=true, got error: %v", result.Error)
	}
}

func TestBuildCollectorEnv(t *testing.T) {
	// Set up environment with sensitive variables that should be filtered
	originalEnv := os.Environ()

	tests := []struct {
		name                string
		insecureInheritPath bool
		wantSafePath        bool
	}{
		{
			name:                "default uses safe PATH",
			insecureInheritPath: false,
			wantSafePath:        true,
		},
		{
			name:                "insecure inherits PATH",
			insecureInheritPath: true,
			wantSafePath:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := execsafe.BuildRestrictedEnv(originalEnv, tt.insecureInheritPath)

			// Check that PATH is present
			var foundPath string
			for _, e := range env {
				if len(e) > 5 && e[:5] == "PATH=" {
					foundPath = e[5:]
					break
				}
			}
			if foundPath == "" {
				t.Fatal("PATH not found in environment")
			}

			expectedSafe := execsafe.SafePATH()
			if tt.wantSafePath {
				if foundPath != expectedSafe {
					t.Errorf("PATH = %q, want safe PATH %q", foundPath, expectedSafe)
				}
			} else {
				// Should contain the original PATH (which typically has more entries)
				if foundPath == expectedSafe {
					t.Errorf("PATH = %q, should inherit from environment not safe PATH", foundPath)
				}
			}

			// Check that sensitive environment variables are NOT included
			sensitiveVars := []string{"GITHUB_TOKEN", "AWS_SECRET_ACCESS_KEY", "API_KEY"}
			for _, sensitive := range sensitiveVars {
				for _, e := range env {
					if len(e) > len(sensitive)+1 && e[:len(sensitive)+1] == sensitive+"=" {
						t.Errorf("sensitive variable %s should not be in environment", sensitive)
					}
				}
			}
		})
	}
}

func TestSafePATH(t *testing.T) {
	path := execsafe.SafePATH()
	if path == "" {
		t.Fatal("safePATH() returned empty string")
	}

	// On Unix, should start with /usr/bin
	if runtime.GOOS != "windows" {
		if len(path) < 8 || path[:8] != "/usr/bin" {
			t.Errorf("safePATH() on Unix should start with /usr/bin, got %q", path)
		}
	}
}

// Regression test: safePATH must use hardcoded paths, not environment variables.
// SECURITY: On Windows, the SystemRoot environment variable can be controlled by
// attackers. Using os.Getenv("SystemRoot") allows an attacker to set
// SystemRoot=C:\attacker and hijack all commands.
//
// This test verifies that safePATH() returns a static, deterministic path
// regardless of environment variables.
func TestSafePATH_HardcodedNotEnvVar(t *testing.T) {
	// SECURITY REGRESSION TEST: safePATH() must NOT read from environment variables.
	// The fix for this vulnerability was to hardcode Windows paths as:
	//   return `C:\Windows\System32;C:\Windows`
	// instead of using os.Getenv("SystemRoot").
	//
	// This test documents the fix for: safePATH trusts hostile SystemRoot env
	// which could allow RCE by placing malicious binaries in C:\attacker\System32\

	// Set a malicious SystemRoot value
	t.Setenv("SystemRoot", `C:\attacker\malicious`)

	// SafePATH should return the same value regardless of SystemRoot
	path := execsafe.SafePATH()

	// The path should NOT contain the attacker-controlled value
	if containsPath(path, "attacker") || containsPath(path, "malicious") {
		t.Errorf("SECURITY REGRESSION: safePATH() is reading from SystemRoot env var! path=%q", path)
	}

	// On Windows, should be the hardcoded Windows path
	if runtime.GOOS == "windows" {
		expected := `C:\Windows\System32;C:\Windows`
		if path != expected {
			t.Errorf("SECURITY REGRESSION: safePATH() on Windows should return hardcoded path %q, got %q", expected, path)
		}
	}

	// On Unix, should be the standard safe PATH
	if runtime.GOOS != "windows" {
		expected := "/usr/bin:/bin:/usr/sbin:/sbin"
		if path != expected {
			t.Errorf("safePATH() on Unix should return %q, got %q", expected, path)
		}
	}
}

// containsPath checks if a PATH-like string contains a specific substring
func containsPath(path, substr string) bool {
	lowerPath := path
	lowerSubstr := substr
	// Case-insensitive check for Windows
	if runtime.GOOS == "windows" {
		lowerPath = strings.ToLower(path)
		lowerSubstr = strings.ToLower(substr)
	}
	return strings.Contains(lowerPath, lowerSubstr)
}

func TestFilterEnv_AllowList(t *testing.T) {
	environ := []string{
		"HOME=/home/user",
		"USER=testuser",
		"GITHUB_TOKEN=secret",
		"AWS_SECRET_ACCESS_KEY=supersecret",
		"LANG=en_US.UTF-8",
		"TMPDIR=/tmp",
	}

	allowed := []string{"HOME", "USER", "LANG", "TMPDIR"}
	filtered := execsafe.FilterEnv(environ, allowed)

	// Should include allowed variables
	wantIncluded := map[string]bool{
		"HOME=":   true,
		"USER=":   true,
		"LANG=":   true,
		"TMPDIR=": true,
	}

	for _, env := range filtered {
		for prefix := range wantIncluded {
			if len(env) >= len(prefix) && env[:len(prefix)] == prefix {
				delete(wantIncluded, prefix)
			}
		}
	}

	if len(wantIncluded) > 0 {
		t.Errorf("missing expected env vars: %v", wantIncluded)
	}

	// Should NOT include sensitive variables
	for _, env := range filtered {
		if len(env) > 13 && env[:13] == "GITHUB_TOKEN=" {
			t.Error("GITHUB_TOKEN should be filtered out")
		}
		if len(env) > 21 && env[:21] == "AWS_SECRET_ACCESS_KEY=" {
			t.Error("AWS_SECRET_ACCESS_KEY should be filtered out")
		}
	}
}

// TestAggregateBudgetPreventsOOM verifies that when the aggregate budget is exceeded,
// the runner correctly prevents OOM by skipping remaining collectors and returning an error.
func TestAggregateBudgetPreventsOOM(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on Windows")
	}

	// Use runnerTestDirInCwd because LockFile.Save() requires paths under cwd
	tmpDir := runnerTestDirInCwd(t)
	platform := platform.Key(runtime.GOOS, runtime.GOARCH)

	// Create a collector script that outputs a fixed-size JSON blob
	// Uses only POSIX shell to avoid external dependencies like python
	scriptPath := filepath.Join(tmpDir, "big-output")
	script := `#!/bin/sh
# Output a ~1KB JSON blob using only shell builtins
printf '{"data":"'
i=0
while [ $i -lt 100 ]; do
    printf 'xxxxxxxxxx'
    i=$((i + 1))
done
printf '"}\n'
`
	if err := os.WriteFile(scriptPath, []byte(script), 0755); err != nil {
		t.Fatalf("creating script: %v", err)
	}

	digest, _ := sync.ComputeDigest(scriptPath)

	runner := &Runner{
		BaseDir:      tmpDir,
		LockfilePath: filepath.Join(tmpDir, "epack.lock.yaml"),
	}

	// Create lockfile with many collectors
	lf := lockfile.New()
	cfg := &config.JobConfig{
		Stream:     "test/stream",
		Collectors: make(map[string]config.CollectorConfig),
	}

	// Add 10 collectors
	for i := 0; i < 10; i++ {
		name := fmt.Sprintf("collector%d", i)
		lf.Collectors[name] = lockfile.LockedCollector{
			Kind: "external",
			Platforms: map[string]componenttypes.LockedPlatform{
				platform: {Digest: digest},
			},
		}
		cfg.Collectors[name] = config.CollectorConfig{
			Binary: scriptPath,
			Config: map[string]any{},
		}
	}

	if err := lf.Save(runner.LockfilePath); err != nil {
		t.Fatalf("saving lockfile: %v", err)
	}

	// Run with a very small aggregate budget (1KB)
	// This should cause some collectors to be skipped
	result, err := runner.Run(context.Background(), cfg, RunOptions{
		MaxAggregateBudget: 1024, // 1 KB - very small
	})
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}

	// Some collectors should have succeeded
	successCount := 0
	budgetExceededCount := 0
	for _, r := range result.Results {
		if r.Success {
			successCount++
		} else if r.Error != nil && (strings.Contains(r.Error.Error(), "budget exceeded") ||
			strings.Contains(r.Error.Error(), "aggregate budget")) {
			budgetExceededCount++
		}
	}

	// At least one should succeed (first collector)
	if successCount == 0 {
		t.Error("expected at least one collector to succeed")
	}

	// Some should fail due to budget (either skipped or output discarded)
	if budgetExceededCount == 0 {
		t.Error("expected some collectors to fail due to budget")
	}

	t.Logf("succeeded: %d, budget exceeded: %d, total failures: %d",
		successCount, budgetExceededCount, result.Failures)
}

// TestAggregateBudgetDefault verifies the default aggregate budget is applied
func TestAggregateBudgetDefault(t *testing.T) {
	// Just verify the constant is set to a reasonable value
	if limits.MaxAggregateOutputBytes < limits.CollectorOutput.Bytes() {
		t.Errorf("MaxAggregateOutputBytes (%d) should be >= CollectorOutput (%d)",
			limits.MaxAggregateOutputBytes, limits.CollectorOutput.Bytes())
	}

	// Should allow at least 4 collectors at max output
	if limits.MaxAggregateOutputBytes < 4*limits.CollectorOutput.Bytes() {
		t.Errorf("MaxAggregateOutputBytes (%d) should allow at least 4 max-size collectors",
			limits.MaxAggregateOutputBytes)
	}
}

func TestLimitedWriter(t *testing.T) {
	var buf strings.Builder
	lw := limits.NewLimitedWriter(&buf, 10)

	// Write within limit
	n, err := lw.Write([]byte("hello"))
	if err != nil {
		t.Fatalf("Write error: %v", err)
	}
	if n != 5 {
		t.Errorf("Write returned %d, want 5", n)
	}
	if buf.String() != "hello" {
		t.Errorf("buffer = %q, want %q", buf.String(), "hello")
	}

	// Write at limit boundary - reports original length to avoid breaking subprocess
	n, err = lw.Write([]byte("world!"))
	if err != nil {
		t.Fatalf("Write error: %v", err)
	}
	// Reports original length (6) even though only 5 bytes were written
	if n != 6 {
		t.Errorf("Write returned %d, want 6", n)
	}
	// But buffer only gets up to limit
	if buf.String() != "helloworld" {
		t.Errorf("buffer = %q, want %q", buf.String(), "helloworld")
	}

	// Write past limit - should silently discard and report full length
	n, err = lw.Write([]byte("extra"))
	if err != nil {
		t.Fatalf("Write error: %v", err)
	}
	// Reports full length to avoid breaking subprocess
	if n != 5 {
		t.Errorf("Write returned %d, want 5", n)
	}
	// Buffer should not grow past limit
	if buf.String() != "helloworld" {
		t.Errorf("buffer = %q, want %q", buf.String(), "helloworld")
	}
}

// TestParseCollectorOutput_PreservesLargeIntegers verifies that JSON number precision
// is preserved for integers above 2^53-1. This is a CORRECTNESS TEST.
//
// Standard json.Unmarshal decodes numbers as float64, which loses precision for
// integers > 9007199254740992 (2^53). By using json.RawMessage, we preserve the
// exact bytes and avoid this precision loss.
func TestParseCollectorOutput_PreservesLargeIntegers(t *testing.T) {
	// 9007199254740993 is 2^53 + 1, which cannot be exactly represented in float64
	// If decoded as float64 and re-encoded, it becomes 9007199254740992
	largeInt := "9007199254740993"

	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "envelope with large integer in data",
			input: `{"protocol_version":1,"data":{"id":` + largeInt + `}}`,
		},
		{
			name:  "plain JSON with large integer",
			input: `{"id":` + largeInt + `}`,
		},
		{
			name:  "nested large integer",
			input: `{"protocol_version":1,"data":{"nested":{"deep":{"id":` + largeInt + `}}}}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output, err := ParseCollectorOutput([]byte(tt.input))
			if err != nil {
				t.Fatalf("ParseCollectorOutput() error: %v", err)
			}

			// The RawData should contain the exact original bytes for the data field
			// This means the large integer should be preserved exactly
			if !bytes.Contains(output.RawData, []byte(largeInt)) {
				t.Errorf("RawData does not contain exact large integer %s\nRawData: %s",
					largeInt, string(output.RawData))
			}
		})
	}
}

// TestParseCollectorOutput_EnvelopeExtraction verifies envelope parsing extracts data correctly.
func TestParseCollectorOutput_EnvelopeExtraction(t *testing.T) {
	tests := []struct {
		name            string
		input           string
		wantVersion     int
		wantDataContain string
	}{
		{
			name:            "valid envelope",
			input:           `{"protocol_version":1,"data":{"key":"value"}}`,
			wantVersion:     1,
			wantDataContain: `"key":"value"`,
		},
		{
			name:            "plain JSON (no envelope)",
			input:           `{"key":"value"}`,
			wantVersion:     0,
			wantDataContain: `"key":"value"`,
		},
		{
			name:            "non-JSON text",
			input:           "plain text output",
			wantVersion:     0,
			wantDataContain: "plain text output",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output, err := ParseCollectorOutput([]byte(tt.input))
			if err != nil {
				t.Fatalf("ParseCollectorOutput() error: %v", err)
			}

			if output.ProtocolVersion != tt.wantVersion {
				t.Errorf("ProtocolVersion = %d, want %d", output.ProtocolVersion, tt.wantVersion)
			}

			if !bytes.Contains(output.RawData, []byte(tt.wantDataContain)) {
				t.Errorf("RawData does not contain %q\nRawData: %s",
					tt.wantDataContain, string(output.RawData))
			}
		})
	}
}

// TestValidateFrozen_DeterministicErrors verifies that validateFrozen returns deterministic
// error messages regardless of Go's map iteration order. This is a CORRECTNESS TEST.
//
// Without sorting, iterating over cfg.Collectors and lf.Collectors maps can produce
// different error messages across runs when multiple collectors are invalid.
func TestValidateFrozen_DeterministicErrors(t *testing.T) {
	platform := platform.Key(runtime.GOOS, runtime.GOARCH)
	runner := &Runner{}

	// Create config with multiple source collectors that are missing from lockfile
	cfg := &config.JobConfig{
		Collectors: map[string]config.CollectorConfig{
			"zebra":   {Source: "github.com/x/zebra@v1.0.0"},
			"alpha":   {Source: "github.com/x/alpha@v1.0.0"},
			"middle":  {Source: "github.com/x/middle@v1.0.0"},
			"beta":    {Source: "github.com/x/beta@v1.0.0"},
			"gamma":   {Source: "github.com/x/gamma@v1.0.0"},
			"delta":   {Source: "github.com/x/delta@v1.0.0"},
			"epsilon": {Source: "github.com/x/epsilon@v1.0.0"},
			"omega":   {Source: "github.com/x/omega@v1.0.0"},
		},
	}

	// Empty lockfile - all collectors will fail validation
	lf := lockfile.New()

	// Run validation 50 times and collect all error messages
	var errorMsgs []string
	for i := 0; i < 50; i++ {
		err := runner.validateFrozen(cfg, lf, platform)
		if err == nil {
			t.Fatal("expected validation error for missing collectors")
		}
		errorMsgs = append(errorMsgs, err.Error())
	}

	// All error messages must be identical (deterministic)
	for i := 1; i < len(errorMsgs); i++ {
		if errorMsgs[i] != errorMsgs[0] {
			t.Errorf("non-deterministic error messages:\n  iteration 0: %s\n  iteration %d: %s",
				errorMsgs[0], i, errorMsgs[i])
		}
	}

	// The first error should be for "alpha" (alphabetically first)
	if !strings.Contains(errorMsgs[0], `"alpha"`) {
		t.Errorf("expected first error to mention 'alpha' (alphabetically first), got: %s", errorMsgs[0])
	}
}

// TestValidateFrozen_LockfileIterationDeterministic verifies that the lockfile
// iteration in validateFrozen is also deterministic.
func TestValidateFrozen_LockfileIterationDeterministic(t *testing.T) {
	platform := platform.Key(runtime.GOOS, runtime.GOARCH)
	runner := &Runner{}

	// Create config with one valid collector
	cfg := &config.JobConfig{
		Collectors: map[string]config.CollectorConfig{
			"valid": {Source: "github.com/x/valid@v1.0.0"},
		},
	}

	// Create lockfile with multiple source collectors not in config
	// This tests the second loop in validateFrozen
	lf := lockfile.New()
	lf.Collectors["valid"] = lockfile.LockedCollector{
		Source:  "github.com/x/valid",
		Version: "v1.0.0",
		Platforms: map[string]componenttypes.LockedPlatform{
			platform: {Digest: "sha256:abc"},
		},
	}
	// Add stale collectors that aren't in config
	lf.Collectors["stale-zebra"] = lockfile.LockedCollector{Source: "github.com/x/zebra", Version: "v1.0.0"}
	lf.Collectors["stale-alpha"] = lockfile.LockedCollector{Source: "github.com/x/alpha", Version: "v1.0.0"}
	lf.Collectors["stale-middle"] = lockfile.LockedCollector{Source: "github.com/x/middle", Version: "v1.0.0"}
	lf.Collectors["stale-beta"] = lockfile.LockedCollector{Source: "github.com/x/beta", Version: "v1.0.0"}

	// Run validation 50 times
	var errorMsgs []string
	for i := 0; i < 50; i++ {
		err := runner.validateFrozen(cfg, lf, platform)
		if err == nil {
			t.Fatal("expected validation error for stale lockfile entries")
		}
		errorMsgs = append(errorMsgs, err.Error())
	}

	// All error messages must be identical
	for i := 1; i < len(errorMsgs); i++ {
		if errorMsgs[i] != errorMsgs[0] {
			t.Errorf("non-deterministic lockfile iteration:\n  iteration 0: %s\n  iteration %d: %s",
				errorMsgs[0], i, errorMsgs[i])
		}
	}

	// The first error should be for "stale-alpha" (alphabetically first)
	if !strings.Contains(errorMsgs[0], `"stale-alpha"`) {
		t.Errorf("expected first error to mention 'stale-alpha' (alphabetically first), got: %s", errorMsgs[0])
	}
}
