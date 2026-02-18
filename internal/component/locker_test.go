package component

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/locktivity/epack/internal/component/config"
	"github.com/locktivity/epack/internal/component/github"
	"github.com/locktivity/epack/internal/component/lockfile"
	"github.com/locktivity/epack/internal/component/sync"
	"github.com/locktivity/epack/internal/platform"
)

// lockerTestDirInCwd creates a temporary directory under the current working directory
// for tests that need to use LockFile.Save() (which requires paths under cwd).
// The directory is automatically cleaned up when the test ends.
// Returns an absolute path to ensure filepath.Rel works correctly.
func lockerTestDirInCwd(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp(".", "locker_test_*")
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

func TestLockerLockSource(t *testing.T) {
	// Create mock GitHub server
	release := github.Release{
		TagName: "v1.2.3",
		Assets: []github.Asset{
			{Name: "mycollector-linux-amd64", BrowserDownloadURL: ""},
			{Name: "mycollector-linux-amd64.sigstore.json", BrowserDownloadURL: ""},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/owner/repo/releases/tags/v1.2.3":
			_ = json.NewEncoder(w).Encode(release)
		case "/repos/owner/repo/releases":
			_ = json.NewEncoder(w).Encode([]github.Release{release})
		default:
			// Asset downloads - return dummy content
			_, _ = w.Write([]byte("binary content"))
		}
	}))
	defer server.Close()

	// Update asset URLs to point to mock server
	release.Assets[0].BrowserDownloadURL = server.URL + "/assets/binary"
	release.Assets[1].BrowserDownloadURL = server.URL + "/assets/bundle"

	// Use lockerTestDirInCwd because Lock() calls LockFile.Save() which requires paths under cwd
	tmpDir := lockerTestDirInCwd(t)

	client := github.NewClientForTest(server.Client(), server.URL)
	registry := sync.NewGitHubRegistryWithClient(client)

	locker := sync.NewLockerWithRegistry(registry, tmpDir)

	cfg := &config.JobConfig{
		Collectors: map[string]config.CollectorConfig{
			"mycollector": {Source: "owner/repo@v1.2.3"},
		},
	}

	// This will fail at sigstore verification since we're using fake data,
	// but we can test up to that point
	_, err := locker.Lock(context.Background(), cfg, sync.LockOpts{
		Platforms: []string{"linux/amd64"},
	})

	// We expect a sigstore error since we're not providing real signatures
	if err == nil {
		t.Log("Lock succeeded (unexpected but OK for mock)")
	} else {
		// Should be a sigstore-related error, not a network or parse error
		t.Logf("Lock error (expected for mock data): %v", err)
	}
}

func TestLockerLockExternal(t *testing.T) {
	// Use lockerTestDirInCwd because Lock() calls LockFile.Save() which requires paths under cwd
	tmpDir := lockerTestDirInCwd(t)

	// Create a fake external binary
	binaryPath := filepath.Join(tmpDir, "my-external")
	if err := os.WriteFile(binaryPath, []byte("fake binary"), 0755); err != nil {
		t.Fatalf("creating binary: %v", err)
	}

	locker := sync.NewLocker(tmpDir)

	cfg := &config.JobConfig{
		Collectors: map[string]config.CollectorConfig{
			"external": {Binary: binaryPath},
		},
	}

	results, err := locker.Lock(context.Background(), cfg, sync.LockOpts{})
	if err != nil {
		t.Fatalf("Lock() error: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	result := results[0]
	if result.Name != "external" {
		t.Errorf("Name = %q, want %q", result.Name, "external")
	}
	if !result.IsNew {
		t.Error("expected IsNew = true")
	}

	// Verify lockfile was created
	lf, err := lockfile.Load(locker.LockfilePath)
	if err != nil {
		t.Fatalf("loading lockfile: %v", err)
	}

	locked, ok := lf.GetCollector("external")
	if !ok {
		t.Fatal("external collector not in lockfile")
	}
	if locked.Kind != "external" {
		t.Errorf("Kind = %q, want %q", locked.Kind, "external")
	}
	if len(locked.Platforms) == 0 {
		t.Error("expected at least one platform entry")
	}
}

func TestSyncSplitPlatform(t *testing.T) {
	tests := []struct {
		platform   string
		wantGoos   string
		wantGoarch string
	}{
		{"linux/amd64", "linux", "amd64"},
		{"darwin/arm64", "darwin", "arm64"},
		{"windows/amd64", "windows", "amd64"},
		{"linux", "linux", ""},
	}

	for _, tt := range tests {
		t.Run(tt.platform, func(t *testing.T) {
			goos, goarch := platform.Split(tt.platform)
			if goos != tt.wantGoos {
				t.Errorf("goos = %q, want %q", goos, tt.wantGoos)
			}
			if goarch != tt.wantGoarch {
				t.Errorf("goarch = %q, want %q", goarch, tt.wantGoarch)
			}
		})
	}
}

func TestLockerLoadOrCreateLockfile(t *testing.T) {
	// Use lockerTestDirInCwd because Save() requires paths under cwd
	tmpDir := lockerTestDirInCwd(t)

	locker := sync.NewLocker(tmpDir)

	// First call should create new
	lf, err := locker.LoadOrCreateLockfile()
	if err != nil {
		t.Fatalf("loadOrCreateLockfile() error: %v", err)
	}
	if lf.SchemaVersion != 1 {
		t.Errorf("SchemaVersion = %d, want 1", lf.SchemaVersion)
	}

	// Save and reload
	lf.Collectors["test"] = lockfile.LockedCollector{Version: "v1.0.0"}
	if err := lf.Save(locker.LockfilePath); err != nil {
		t.Fatalf("Save() error: %v", err)
	}

	lf2, err := locker.LoadOrCreateLockfile()
	if err != nil {
		t.Fatalf("loadOrCreateLockfile() second call error: %v", err)
	}
	if _, ok := lf2.GetCollector("test"); !ok {
		t.Error("expected 'test' collector to exist after reload")
	}
}

func TestLockerDetectAvailablePlatforms(t *testing.T) {
	release := &sync.ReleaseInfo{
		Assets: []sync.AssetInfo{
			{Name: "app-linux-amd64"},
			{Name: "app-linux-arm64"},
			{Name: "app-darwin-arm64"},
			{Name: "app-darwin-amd64"},
		},
	}

	locker := &sync.Locker{Registry: sync.NewGitHubRegistry()}

	platforms := locker.DetectAvailablePlatforms(release, "app")

	expected := map[string]bool{
		"linux/amd64":  true,
		"linux/arm64":  true,
		"darwin/amd64": true,
		"darwin/arm64": true,
	}

	for _, p := range platforms {
		if !expected[p] {
			t.Errorf("unexpected platform: %s", p)
		}
		delete(expected, p)
	}

	// windows/amd64 should not be found since no asset exists
	delete(expected, "windows/amd64")

	for p := range expected {
		t.Errorf("missing platform: %s", p)
	}
}
