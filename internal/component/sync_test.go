package component

import (
	"context"
	stderrors "errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/locktivity/epack/errors"
	"github.com/locktivity/epack/internal/component/config"
	"github.com/locktivity/epack/internal/component/lockfile"
	"github.com/locktivity/epack/internal/component/sync"
	"github.com/locktivity/epack/internal/componenttypes"
	"github.com/locktivity/epack/internal/exitcode"
	"github.com/locktivity/epack/internal/platform"
)

// syncTestDirInCwd creates a temporary directory under the current working directory
// for tests that need to use LockFile.Save() (which requires paths under cwd).
// The directory is automatically cleaned up when the test ends.
// Returns an absolute path to ensure filepath.Rel works correctly.
func syncTestDirInCwd(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp(".", "sync_test_*")
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

func TestSyncerValidateAlignment(t *testing.T) {
	tmpDir := t.TempDir()

	syncer := &sync.Syncer{
		LockfilePath: filepath.Join(tmpDir, lockfile.FileName),
		BaseDir:      filepath.Join(tmpDir, ".epack"),
	}

	// Create lockfile with one collector
	lf := lockfile.New()
	lf.Collectors["github"] = lockfile.LockedCollector{
		Source:  "github.com/owner/repo",
		Version: "v1.0.0",
		Platforms: map[string]componenttypes.LockedPlatform{
			"linux/amd64": {Digest: "sha256:abc123"},
		},
	}

	// Config matches lockfile
	cfg := &config.JobConfig{
		Collectors: map[string]config.CollectorConfig{
			"github": {Source: "owner/repo@^1.0.0"},
		},
	}

	if err := syncer.ValidateAlignment(cfg, lf); err != nil {
		t.Errorf("validateAlignment() unexpected error: %v", err)
	}

	// Config has collector not in lockfile
	cfg2 := &config.JobConfig{
		Collectors: map[string]config.CollectorConfig{
			"github":  {Source: "owner/repo@^1.0.0"},
			"missing": {Source: "other/repo@^1.0.0"},
		},
	}

	err := syncer.ValidateAlignment(cfg2, lf)
	if err == nil {
		t.Error("validateAlignment() expected error for missing collector")
	}
	var e *errors.Error
	if !stderrors.As(err, &e) {
		t.Errorf("expected *errors.Error, got %T", err)
	} else if e.ExitCode() != exitcode.LockInvalid {
		t.Errorf("ExitCode = %d, want %d", e.ExitCode(), exitcode.LockInvalid)
	}

	// Lockfile has collector not in config
	lf.Collectors["stale"] = lockfile.LockedCollector{
		Source:  "github.com/stale/repo",
		Version: "v2.0.0",
	}

	err = syncer.ValidateAlignment(cfg, lf)
	if err == nil {
		t.Error("validateAlignment() expected error for stale lockfile entry")
	}
}

func TestSyncerValidateAlignmentKindMismatch(t *testing.T) {
	tmpDir := t.TempDir()

	syncer := &sync.Syncer{
		LockfilePath: filepath.Join(tmpDir, lockfile.FileName),
		BaseDir:      filepath.Join(tmpDir, ".epack"),
	}

	// Test: Config has source but lockfile has external
	lf := lockfile.New()
	lf.Collectors["github"] = lockfile.LockedCollector{
		Kind: "external", // Locked as external
		Platforms: map[string]componenttypes.LockedPlatform{
			"linux/amd64": {Digest: "sha256:abc123"},
		},
	}

	cfg := &config.JobConfig{
		Collectors: map[string]config.CollectorConfig{
			"github": {Source: "owner/repo@^1.0.0"}, // Config declares as source
		},
	}

	err := syncer.ValidateAlignment(cfg, lf)
	if err == nil {
		t.Error("validateAlignment() expected error for source-vs-external mismatch")
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
			"linux/amd64": {Digest: "sha256:abc123"},
		},
	}

	cfg2 := &config.JobConfig{
		Collectors: map[string]config.CollectorConfig{
			"github": {Binary: "/path/to/binary"}, // Config declares as external
		},
	}

	err = syncer.ValidateAlignment(cfg2, lf2)
	if err == nil {
		t.Error("validateAlignment() expected error for binary-vs-source mismatch")
	}
	if !stderrors.As(err, &e) {
		t.Errorf("expected *errors.Error, got %T", err)
	} else if e.ExitCode() != exitcode.LockInvalid {
		t.Errorf("ExitCode = %d, want %d", e.ExitCode(), exitcode.LockInvalid)
	}

	// Test: Lockfile has source-based but config declares as external
	lf3 := lockfile.New()
	lf3.Collectors["github"] = lockfile.LockedCollector{
		Source:  "github.com/owner/repo",
		Version: "v1.0.0",
		Platforms: map[string]componenttypes.LockedPlatform{
			"linux/amd64": {Digest: "sha256:abc123"},
		},
	}

	cfg3 := &config.JobConfig{
		Collectors: map[string]config.CollectorConfig{
			"github": {Binary: "/path/to/binary"}, // Config declares as external
		},
	}

	err = syncer.ValidateAlignment(cfg3, lf3)
	if err == nil {
		t.Error("validateAlignment() expected error when lockfile source-based but config external")
	}
}

func TestSyncerValidateAlignmentSourceMismatch(t *testing.T) {
	tmpDir := t.TempDir()

	syncer := &sync.Syncer{
		LockfilePath: filepath.Join(tmpDir, lockfile.FileName),
		BaseDir:      filepath.Join(tmpDir, ".epack"),
	}

	// Test: Config source doesn't match lockfile source (lockfile retargeting attack)
	lf := lockfile.New()
	lf.Collectors["github"] = lockfile.LockedCollector{
		Source:  "github.com/legit-owner/legit-repo", // Locked from legit source
		Version: "v1.0.0",
		Signer: &componenttypes.LockedSigner{
			Issuer:              "https://token.actions.githubusercontent.com",
			SourceRepositoryURI: "https://github.com/legit-owner/legit-repo",
			SourceRepositoryRef: "refs/tags/v1.0.0",
		},
		Platforms: map[string]componenttypes.LockedPlatform{
			"linux/amd64": {Digest: "sha256:abc123"},
		},
	}

	// Config points to different repository (attack scenario)
	cfg := &config.JobConfig{
		Collectors: map[string]config.CollectorConfig{
			"github": {Source: "attacker/evil-repo@^1.0.0"}, // Different from lockfile!
		},
	}

	err := syncer.ValidateAlignment(cfg, lf)
	if err == nil {
		t.Error("validateAlignment() expected error for source mismatch")
	}
	var e *errors.Error
	if !stderrors.As(err, &e) {
		t.Errorf("expected *errors.Error, got %T", err)
	} else if e.ExitCode() != exitcode.LockInvalid {
		t.Errorf("ExitCode = %d, want %d", e.ExitCode(), exitcode.LockInvalid)
	}
	// Check error message mentions the mismatch
	if e != nil && !contains(e.Message, "mismatch") && !contains(e.Message, "source") {
		t.Errorf("expected error message to mention source mismatch, got: %s", e.Message)
	}

	// Test: Signer source doesn't match config source
	lf2 := lockfile.New()
	lf2.Collectors["github"] = lockfile.LockedCollector{
		Source:  "github.com/owner/repo", // Source matches config
		Version: "v1.0.0",
		Signer: &componenttypes.LockedSigner{
			Issuer:              "https://token.actions.githubusercontent.com",
			SourceRepositoryURI: "https://github.com/different-owner/different-repo", // But signer is from different repo!
			SourceRepositoryRef: "refs/tags/v1.0.0",
		},
		Platforms: map[string]componenttypes.LockedPlatform{
			"linux/amd64": {Digest: "sha256:abc123"},
		},
	}

	cfg2 := &config.JobConfig{
		Collectors: map[string]config.CollectorConfig{
			"github": {Source: "owner/repo@^1.0.0"},
		},
	}

	err = syncer.ValidateAlignment(cfg2, lf2)
	if err == nil {
		t.Error("validateAlignment() expected error for signer source mismatch")
	}
	if !stderrors.As(err, &e) {
		t.Errorf("expected *errors.Error, got %T", err)
	} else if e.ExitCode() != exitcode.LockInvalid {
		t.Errorf("ExitCode = %d, want %d", e.ExitCode(), exitcode.LockInvalid)
	}
}

// contains is a simple helper for checking substrings in tests
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsImpl(s, substr))
}

func containsImpl(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestSyncerVerifyExternal(t *testing.T) {
	tmpDir := t.TempDir()

	// Create external binary
	binaryPath := filepath.Join(tmpDir, "external-binary")
	binaryContent := []byte("external binary content")
	if err := os.WriteFile(binaryPath, binaryContent, 0755); err != nil {
		t.Fatalf("writing binary: %v", err)
	}

	// Compute its digest
	digest, err := sync.ComputeDigest(binaryPath)
	if err != nil {
		t.Fatalf("computing digest: %v", err)
	}

	platform := platform.Key(runtime.GOOS, runtime.GOARCH)

	// Create lockfile with matching digest
	lf := lockfile.New()
	lf.Collectors["external"] = lockfile.LockedCollector{
		Kind: "external",
		Platforms: map[string]componenttypes.LockedPlatform{
			platform: {Digest: digest},
		},
	}

	syncer := &sync.Syncer{
		BaseDir: filepath.Join(tmpDir, ".epack"),
	}

	cfg := config.CollectorConfig{Binary: binaryPath}

	// Should succeed with matching digest
	result, err := syncer.VerifyExternalCollector("external", cfg, lf, platform, sync.SyncOpts{})
	if err != nil {
		t.Fatalf("verifyExternal() error: %v", err)
	}
	if !result.Verified {
		t.Error("expected Verified = true")
	}
	if !result.Skipped {
		t.Error("expected Skipped = true for external")
	}

	// Should fail with wrong digest
	lf.Collectors["external"] = lockfile.LockedCollector{
		Kind: "external",
		Platforms: map[string]componenttypes.LockedPlatform{
			platform: {Digest: "sha256:wrongdigest"},
		},
	}

	_, err = syncer.VerifyExternalCollector("external", cfg, lf, platform, sync.SyncOpts{})
	if err == nil {
		t.Error("verifyExternal() expected error for wrong digest")
	}
	var e *errors.Error
	if !stderrors.As(err, &e) {
		t.Errorf("expected *errors.Error, got %T", err)
	} else if e.ExitCode() != exitcode.DigestMismatch {
		t.Errorf("ExitCode = %d, want %d", e.ExitCode(), exitcode.DigestMismatch)
	}

	// Should skip verification with InsecureSkipVerify
	// SECURITY: Verified MUST be false when verification was skipped
	result, err = syncer.VerifyExternalCollector("external", cfg, lf, platform, sync.SyncOpts{InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("verifyExternal() with InsecureSkipVerify error: %v", err)
	}
	if result.Verified {
		t.Error("SECURITY: Verified should be false when InsecureSkipVerify is set")
	}
}

func TestSyncerVerifyExternalFrozenMissingPlatform(t *testing.T) {
	tmpDir := t.TempDir()
	platform := platform.Key(runtime.GOOS, runtime.GOARCH)

	// Create external binary
	binaryPath := filepath.Join(tmpDir, "external-binary")
	if err := os.WriteFile(binaryPath, []byte("content"), 0755); err != nil {
		t.Fatalf("writing binary: %v", err)
	}

	syncer := &sync.Syncer{
		BaseDir: filepath.Join(tmpDir, ".epack"),
	}

	cfg := config.CollectorConfig{Binary: binaryPath}

	// Lockfile has external but missing current platform
	lf := lockfile.New()
	lf.Collectors["external"] = lockfile.LockedCollector{
		Kind: "external",
		Platforms: map[string]componenttypes.LockedPlatform{
			"other/platform": {Digest: "sha256:abc"},
		},
	}

	// Non-frozen: should succeed (skipped, unverified)
	result, err := syncer.VerifyExternalCollector("external", cfg, lf, platform, sync.SyncOpts{Frozen: false})
	if err != nil {
		t.Errorf("verifyExternal() non-frozen unexpected error: %v", err)
	}
	if result != nil && !result.Skipped {
		t.Error("expected Skipped = true for non-frozen missing platform")
	}

	// Frozen: should fail - platform not locked
	_, err = syncer.VerifyExternalCollector("external", cfg, lf, platform, sync.SyncOpts{Frozen: true})
	if err == nil {
		t.Error("verifyExternal() frozen expected error for missing platform")
	}
	var e *errors.Error
	if !stderrors.As(err, &e) {
		t.Errorf("expected *errors.Error, got %T", err)
	} else if e.ExitCode() != exitcode.MissingBinary {
		t.Errorf("ExitCode = %d, want %d", e.ExitCode(), exitcode.MissingBinary)
	}

	// Also test empty digest
	lf.Collectors["external"] = lockfile.LockedCollector{
		Kind: "external",
		Platforms: map[string]componenttypes.LockedPlatform{
			platform: {Digest: ""}, // Empty digest
		},
	}

	_, err = syncer.VerifyExternalCollector("external", cfg, lf, platform, sync.SyncOpts{Frozen: true})
	if err == nil {
		t.Error("verifyExternal() frozen expected error for empty digest")
	}
}

func TestSyncerFrozenInsecureCombination(t *testing.T) {
	// Use syncTestDirInCwd because LockFile.Save() requires paths under cwd
	tmpDir := syncTestDirInCwd(t)

	syncer := sync.NewSyncer(tmpDir)

	// Create minimal lockfile
	lf := lockfile.New()
	if err := lf.Save(syncer.LockfilePath); err != nil {
		t.Fatalf("saving lockfile: %v", err)
	}

	cfg := &config.JobConfig{
		Collectors: map[string]config.CollectorConfig{},
	}

	// Should fail with frozen + insecure
	_, err := syncer.Sync(context.Background(), cfg, sync.SyncOpts{
		Frozen:             true,
		InsecureSkipVerify: true,
	})
	if err == nil {
		t.Error("Sync() expected error for frozen + insecure combination")
	}
}

func TestSyncerMissingLockfile(t *testing.T) {
	tmpDir := t.TempDir()

	syncer := sync.NewSyncer(tmpDir)

	cfg := &config.JobConfig{
		Collectors: map[string]config.CollectorConfig{
			"test": {Source: "owner/repo@v1.0.0"},
		},
	}

	_, err := syncer.Sync(context.Background(), cfg, sync.SyncOpts{})
	if err == nil {
		t.Error("Sync() expected error for missing lockfile")
	}

	var e *errors.Error
	if !stderrors.As(err, &e) {
		t.Errorf("expected *errors.Error, got %T", err)
	} else if e.ExitCode() != exitcode.LockInvalid {
		t.Errorf("ExitCode = %d, want %d", e.ExitCode(), exitcode.LockInvalid)
	}
}

func TestSyncParseSourceURI(t *testing.T) {
	tests := []struct {
		source    string
		wantOwner string
		wantRepo  string
		wantErr   bool
	}{
		{"github.com/owner/repo", "owner", "repo", false},
		{"github.com/my-org/my-repo", "my-org", "my-repo", false},
		{"gitlab.com/owner/repo", "", "", true},
		{"github.com/", "", "", true},
		{"invalid", "", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.source, func(t *testing.T) {
			owner, repo, err := sync.ParseSourceURI(tt.source)
			if tt.wantErr {
				if err == nil {
					t.Error("sync.ParseSourceURI() expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("sync.ParseSourceURI() error: %v", err)
			}
			if owner != tt.wantOwner {
				t.Errorf("owner = %q, want %q", owner, tt.wantOwner)
			}
			if repo != tt.wantRepo {
				t.Errorf("repo = %q, want %q", repo, tt.wantRepo)
			}
		})
	}
}

func TestSyncerFrozenNoNetwork(t *testing.T) {
	// Use syncTestDirInCwd because LockFile.Save() requires paths under cwd
	tmpDir := syncTestDirInCwd(t)
	platform := platform.Key(runtime.GOOS, runtime.GOARCH)

	syncer := sync.NewSyncer(tmpDir)

	// Create lockfile with a collector entry but no installed binary
	lf := lockfile.New()
	lf.Collectors["github"] = lockfile.LockedCollector{
		Source:  "github.com/owner/repo",
		Version: "v1.0.0",
		Platforms: map[string]componenttypes.LockedPlatform{
			platform: {Digest: "sha256:abc123"},
		},
	}
	if err := lf.Save(syncer.LockfilePath); err != nil {
		t.Fatalf("saving lockfile: %v", err)
	}

	cfg := &config.JobConfig{
		Collectors: map[string]config.CollectorConfig{
			"github": {Source: "owner/repo@v1.0.0"},
		},
	}

	// Frozen mode should fail when binary not installed (no network allowed)
	_, err := syncer.Sync(context.Background(), cfg, sync.SyncOpts{Frozen: true})
	if err == nil {
		t.Error("Sync() with --frozen expected error when binary not installed")
	}
	var e *errors.Error
	if !stderrors.As(err, &e) {
		t.Errorf("expected *errors.Error, got %T", err)
	} else if e.ExitCode() != exitcode.MissingBinary {
		t.Errorf("ExitCode = %d, want %d", e.ExitCode(), exitcode.MissingBinary)
	}
}

func TestSyncerFrozenVerifiesInstalled(t *testing.T) {
	// Use syncTestDirInCwd because LockFile.Save() requires paths under cwd
	tmpDir := syncTestDirInCwd(t)
	platformKey := platform.Key(runtime.GOOS, runtime.GOARCH)

	syncer := sync.NewSyncer(tmpDir)

	// Create an installed binary
	goos, goarch := platform.Split(platformKey)
	_ = goarch // unused but needed for install path
	installDir := filepath.Join(tmpDir, ".epack", "collectors", "github", "v1.0.0", goos+"-"+goarch)
	if err := os.MkdirAll(installDir, 0755); err != nil {
		t.Fatalf("creating install dir: %v", err)
	}
	binaryPath := filepath.Join(installDir, "github")
	binaryContent := []byte("fake binary content")
	if err := os.WriteFile(binaryPath, binaryContent, 0755); err != nil {
		t.Fatalf("creating binary: %v", err)
	}

	// Compute correct digest
	digest, _ := sync.ComputeDigest(binaryPath)

	// Create lockfile with matching digest
	lf := lockfile.New()
	lf.Collectors["github"] = lockfile.LockedCollector{
		Source:  "github.com/owner/repo",
		Version: "v1.0.0",
		Platforms: map[string]componenttypes.LockedPlatform{
			platformKey: {Digest: digest},
		},
	}
	if err := lf.Save(syncer.LockfilePath); err != nil {
		t.Fatalf("saving lockfile: %v", err)
	}

	cfg := &config.JobConfig{
		Collectors: map[string]config.CollectorConfig{
			"github": {Source: "owner/repo@v1.0.0"},
		},
	}

	// Frozen mode should succeed when binary is installed and digest matches
	results, err := syncer.Sync(context.Background(), cfg, sync.SyncOpts{Frozen: true})
	if err != nil {
		t.Fatalf("Sync() with --frozen error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if !results[0].Verified {
		t.Error("expected Verified = true")
	}
	if results[0].Installed {
		t.Error("expected Installed = false (already installed)")
	}
}

func TestSyncerClearsInsecureMarker(t *testing.T) {
	// Use syncTestDirInCwd because LockFile.Save() requires paths under cwd
	tmpDir := syncTestDirInCwd(t)
	platformKey := platform.Key(runtime.GOOS, runtime.GOARCH)

	syncer := sync.NewSyncer(tmpDir)

	// Create an installed binary with insecure marker
	goos, goarch := platform.Split(platformKey)
	installDir := filepath.Join(tmpDir, ".epack", "collectors", "github", "v1.0.0", goos+"-"+goarch)
	if err := os.MkdirAll(installDir, 0755); err != nil {
		t.Fatalf("creating install dir: %v", err)
	}
	binaryPath := filepath.Join(installDir, "github")
	binaryContent := []byte("fake binary content")
	if err := os.WriteFile(binaryPath, binaryContent, 0755); err != nil {
		t.Fatalf("creating binary: %v", err)
	}

	// Create insecure marker (simulating previous --insecure-skip-verify)
	markerPath := filepath.Join(installDir, ".insecure-install")
	if err := os.WriteFile(markerPath, []byte("insecure"), 0644); err != nil {
		t.Fatalf("creating marker: %v", err)
	}

	// Compute correct digest
	digest, _ := sync.ComputeDigest(binaryPath)

	// Create lockfile with matching digest
	lf := lockfile.New()
	lf.Collectors["github"] = lockfile.LockedCollector{
		Source:  "github.com/owner/repo",
		Version: "v1.0.0",
		Platforms: map[string]componenttypes.LockedPlatform{
			platformKey: {Digest: digest},
		},
	}
	if err := lf.Save(syncer.LockfilePath); err != nil {
		t.Fatalf("saving lockfile: %v", err)
	}

	cfg := &config.JobConfig{
		Collectors: map[string]config.CollectorConfig{
			"github": {Source: "owner/repo@v1.0.0"},
		},
	}

	// Run sync WITHOUT --insecure-skip-verify
	_, err := syncer.Sync(context.Background(), cfg, sync.SyncOpts{})
	if err != nil {
		t.Fatalf("Sync() error: %v", err)
	}

	// Marker should be removed
	if _, err := os.Stat(markerPath); !os.IsNotExist(err) {
		t.Error("expected .insecure-install marker to be removed after secure sync")
	}
}

func TestErrorTypes(t *testing.T) {
	// Test unified error type formatting
	err := &errors.Error{
		Code:    errors.LockfileInvalid,
		Exit:    exitcode.LockInvalid,
		Message: "lockfile missing",
		Hint:    "Run 'epack collector lock'",
	}
	s := err.Error()
	if s == "" {
		t.Error("Error.Error() returned empty string")
	}
	if err.ExitCode() != exitcode.LockInvalid {
		t.Errorf("ExitCode() = %d, want %d", err.ExitCode(), exitcode.LockInvalid)
	}

	// Test error with cause
	cause := stderrors.New("underlying error")
	errWithCause := &errors.Error{
		Code:    errors.DigestMismatch,
		Message: "digest mismatch",
		Hint:    "reinstall",
		Cause:   cause,
	}
	s = errWithCause.Error()
	if s == "" {
		t.Error("Error.Error() with cause returned empty string")
	}
	if errWithCause.Unwrap() != cause {
		t.Error("Unwrap() did not return cause")
	}
}
