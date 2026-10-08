package userremote

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/locktivity/epack/internal/component/lockfile"
	"github.com/locktivity/epack/internal/component/sync"
	"github.com/locktivity/epack/internal/componenttypes"
	"github.com/locktivity/epack/internal/platform"
	"github.com/locktivity/epack/internal/userconfig"
)

const fakeAdapter = `#!/bin/sh
case "$1" in
  --capabilities)
    echo '{"name":"mock","kind":"remote_adapter","deploy_protocol_version":1,"version":"1.0.0","features":{"auth_login":true,"auth_browser":true,"whoami":true,"config_pull":true}}'
    ;;
  *)
    echo '{"ok":false,"error":{"code":"unknown_command","message":"unknown command"}}'
    exit 1
    ;;
esac
`

func installFakeAdapter(t *testing.T, dir string) {
	t.Helper()
	installPath, err := sync.InstallPath(dir, componenttypes.KindRemote, "mock", "v1.0.0", "mock")
	if err != nil {
		t.Fatalf("install path: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(installPath), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(installPath, []byte(fakeAdapter), 0o755); err != nil {
		t.Fatalf("writing adapter: %v", err)
	}
	sum := sha256.Sum256([]byte(fakeAdapter))
	lf := lockfile.New()
	lf.Remotes["mock"] = lockfile.LockedRemote{
		Source:  "github.com/owner/epack-remote-mock",
		Version: "v1.0.0",
		Platforms: map[string]componenttypes.LockedPlatform{
			platform.Key(runtime.GOOS, runtime.GOARCH): {Digest: "sha256:" + hex.EncodeToString(sum[:])},
		},
	}
	if err := userconfig.SaveRemotesLockToPath(filepath.Join(dir, userconfig.RemotesLockFile), lf); err != nil {
		t.Fatalf("saving lock: %v", err)
	}
}

func tempDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("resolving temp dir: %v", err)
	}
	return dir
}

func newTestResolver(dir string, lookup LookupFunc) *Resolver {
	return &Resolver{
		Dir:      dir,
		LockPath: filepath.Join(dir, userconfig.RemotesLockFile),
		Lookup:   lookup,
	}
}

func TestPrepare_UsesInstalledAdapterWithoutLookup(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell script adapters are not available on Windows")
	}
	dir := tempDir(t)
	installFakeAdapter(t, dir)
	lookupCalled := false
	resolver := newTestResolver(dir, func(context.Context, string) (string, error) {
		lookupCalled = true
		return "", errors.New("lookup must not run for a locked adapter")
	})

	var steps []string
	resolver.Step = func(message string, started bool) { steps = append(steps, message) }

	exec, caps, err := resolver.Prepare(context.Background(), "mock")
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	defer exec.Close()

	if lookupCalled {
		t.Error("lookup ran although the adapter was locked")
	}
	if !caps.SupportsAuthLogin() || !caps.SupportsAuthBrowser() || !caps.SupportsConfigPull() {
		t.Errorf("capabilities not read from the adapter: %+v", caps.Features)
	}
	if exec.AdapterName != "mock" {
		t.Errorf("AdapterName = %q, want mock", exec.AdapterName)
	}
	if len(steps) != 0 {
		t.Errorf("no install steps expected for an installed adapter, got %v", steps)
	}
}

func TestPrepare_LooksUpSourceWhenNotLocked(t *testing.T) {
	dir := tempDir(t)
	var asked string
	resolver := newTestResolver(dir, func(_ context.Context, name string) (string, error) {
		asked = name
		return "", errors.New("no catalog in this test")
	})

	_, _, err := resolver.Prepare(context.Background(), "locktivity")
	if err == nil {
		t.Fatal("expected the lookup error")
	}
	if asked != "locktivity" {
		t.Errorf("lookup asked for %q, want locktivity", asked)
	}
	if err.Error() != "no catalog in this test" {
		t.Errorf("error = %v", err)
	}
}

func TestPrepare_RejectsInvalidName(t *testing.T) {
	resolver := newTestResolver(tempDir(t), nil)
	if _, _, err := resolver.Prepare(context.Background(), "../etc"); err == nil {
		t.Fatal("expected an error for an invalid name")
	}
}

func TestSourceDescriptor_PinsLockedVersion(t *testing.T) {
	got := sourceDescriptor(lockfile.LockedRemote{Source: "github.com/locktivity/epack-remote-locktivity", Version: "v0.3.0"})
	if got != "locktivity/epack-remote-locktivity@v0.3.0" {
		t.Errorf("sourceDescriptor = %q", got)
	}
}

const brokenAdapter = `#!/bin/sh
case "$1" in
  --capabilities)
    echo '{"name":"mock","kind":"remote_adapter","deploy_protocol_version":0,"version":"1.2.0","features":{}}'
    ;;
  *)
    exit 1
    ;;
esac
`

// installFakeRelease puts a release of the mock adapter where an install
// would, and returns its lock entry.
func installFakeRelease(t *testing.T, dir, version, script string) lockfile.LockedRemote {
	t.Helper()
	installPath, err := sync.InstallPath(dir, componenttypes.KindRemote, "mock", version, "mock")
	if err != nil {
		t.Fatalf("install path: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(installPath), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(installPath, []byte(script), 0o755); err != nil {
		t.Fatalf("writing adapter: %v", err)
	}
	sum := sha256.Sum256([]byte(script))
	return lockfile.LockedRemote{
		Source:  "github.com/owner/epack-remote-mock",
		Version: version,
		Platforms: map[string]componenttypes.LockedPlatform{
			platform.Key(runtime.GOOS, runtime.GOARCH): {Digest: "sha256:" + hex.EncodeToString(sum[:])},
		},
	}
}

func lockedVersion(t *testing.T, dir string) string {
	t.Helper()
	lf, err := userconfig.LoadRemotesLockFromPath(filepath.Join(dir, userconfig.RemotesLockFile))
	if err != nil {
		t.Fatal(err)
	}
	return lf.Remotes["mock"].Version
}

func TestUpdate_NeedsAnInstalledAdapter(t *testing.T) {
	dir := tempDir(t)
	resolver := newTestResolver(dir, nil)
	resolver.Latest = func(context.Context, string) (string, error) {
		t.Fatal("the catalog must not be asked for an adapter that is not installed")
		return "", nil
	}

	_, err := resolver.Update(context.Background(), "mock")
	if err == nil || !strings.Contains(err.Error(), "epack remote login mock") {
		t.Fatalf("want the sign-in hint, got %v", err)
	}
}

func TestUpdate_StaysWithinTheInstalledRepository(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell script adapters are not available on Windows")
	}
	dir := tempDir(t)
	installFakeAdapter(t, dir)
	resolver := newTestResolver(dir, nil)
	resolver.Latest = func(context.Context, string) (string, error) {
		return "someone-else/epack-remote-mock@^1.0", nil
	}

	_, err := resolver.Update(context.Background(), "mock")
	if err == nil || !strings.Contains(err.Error(), "only updates an adapter within its own repository") {
		t.Fatalf("want a refusal to move repositories, got %v", err)
	}
	if got := lockedVersion(t, dir); got != "v1.0.0" {
		t.Fatalf("lock moved to %s", got)
	}

	resolver.Latest = func(context.Context, string) (string, error) { return "", errors.New("catalog unreachable") }
	if _, err := resolver.Update(context.Background(), "mock"); err == nil || err.Error() != "catalog unreachable" {
		t.Fatalf("want the catalog error, got %v", err)
	}
}

func TestAdopt_MovesThePinOnlyOnceTheNewReleaseRuns(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell script adapters are not available on Windows")
	}
	dir := tempDir(t)
	installFakeAdapter(t, dir)
	resolver := newTestResolver(dir, nil)
	load := func() *lockfile.LockFile {
		lf, err := userconfig.LoadRemotesLockFromPath(filepath.Join(dir, userconfig.RemotesLockFile))
		if err != nil {
			t.Fatal(err)
		}
		return lf
	}

	lf := load()
	next := installFakeRelease(t, dir, "v1.1.0", fakeAdapter)
	result, err := resolver.adopt(context.Background(), "mock", lf, lf.Remotes["mock"], next)
	if err != nil {
		t.Fatalf("adopt: %v", err)
	}
	if !result.Updated || result.Previous != "v1.0.0" || result.Version != "v1.1.0" {
		t.Fatalf("result = %+v", result)
	}
	if got := lockedVersion(t, dir); got != "v1.1.0" {
		t.Fatalf("lock = %s, want v1.1.0", got)
	}

	lf = load()
	broken := installFakeRelease(t, dir, "v1.2.0", brokenAdapter)
	_, err = resolver.adopt(context.Background(), "mock", lf, lf.Remotes["mock"], broken)
	if err == nil || !strings.Contains(err.Error(), "mock v1.2.0 did not start, so mock stays on v1.1.0") {
		t.Fatalf("want the release that does not start to be refused, got %v", err)
	}
	if got := lockedVersion(t, dir); got != "v1.1.0" {
		t.Fatalf("lock moved to %s after a failed start", got)
	}
}

func TestNewerRelease(t *testing.T) {
	cases := []struct {
		next, current string
		want          bool
	}{
		{"v0.1.6", "v0.1.5", true},
		{"v0.2.0", "v0.1.9", true},
		{"v1.0.0", "v0.9.9", true},
		{"v0.1.5", "v0.1.5", false},
		{"v0.1.4", "v0.1.5", false},
		{"v0.1.5", "v0.1.5-rc.1", true},
		{"v0.1.5-rc.2", "v0.1.5-rc.1", true},
		{"v0.1.5-rc.1", "v0.1.5", false},
		{"not-a-version", "v0.1.5", false},
	}
	for _, c := range cases {
		if got := newerRelease(c.next, c.current); got != c.want {
			t.Errorf("newerRelease(%q, %q) = %v, want %v", c.next, c.current, got, c.want)
		}
	}
}
