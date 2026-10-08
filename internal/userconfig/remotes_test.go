package userconfig

import (
	"path/filepath"
	"testing"

	"github.com/locktivity/epack/internal/component/lockfile"
	"github.com/locktivity/epack/internal/componenttypes"
	"github.com/locktivity/epack/internal/testutil/testhome"
)

func TestLoadRemotesLockFromPath_MissingIsEmpty(t *testing.T) {
	lf, err := LoadRemotesLockFromPath(filepath.Join(t.TempDir(), RemotesLockFile))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(lf.Remotes) != 0 {
		t.Errorf("len(Remotes) = %d, want 0", len(lf.Remotes))
	}
}

func TestSaveRemotesLockToPath_RoundTrip(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("resolving temp dir: %v", err)
	}
	path := filepath.Join(base, "nested", RemotesLockFile)
	lf := lockfile.New()
	lf.Remotes["locktivity"] = lockfile.LockedRemote{
		Source:  "github.com/locktivity/epack-remote-locktivity",
		Version: "v0.3.0",
		Platforms: map[string]componenttypes.LockedPlatform{
			"darwin/arm64": {Digest: "sha256:abc"},
		},
	}
	if err := SaveRemotesLockToPath(path, lf); err != nil {
		t.Fatalf("SaveRemotesLockToPath: %v", err)
	}

	loaded, err := LoadRemotesLockFromPath(path)
	if err != nil {
		t.Fatalf("LoadRemotesLockFromPath: %v", err)
	}
	locked, ok := loaded.GetRemote("locktivity")
	if !ok {
		t.Fatal("remote missing after round trip")
	}
	if locked.Version != "v0.3.0" || locked.Source != "github.com/locktivity/epack-remote-locktivity" {
		t.Errorf("unexpected entry: %+v", locked)
	}
	if locked.Platforms["darwin/arm64"].Digest != "sha256:abc" {
		t.Errorf("digest = %q", locked.Platforms["darwin/arm64"].Digest)
	}
}

func TestSaveRemotesLockToPath_RejectsBadName(t *testing.T) {
	lf := lockfile.New()
	lf.Remotes["../escape"] = lockfile.LockedRemote{Version: "v1.0.0"}
	if err := SaveRemotesLockToPath(filepath.Join(t.TempDir(), RemotesLockFile), lf); err == nil {
		t.Fatal("expected an error for an invalid remote name")
	}
}

func TestDefaultRemote_RoundTrip(t *testing.T) {
	testhome.Isolate(t)

	if name, err := DefaultRemote(); err != nil || name != "" {
		t.Fatalf("DefaultRemote before login = %q, %v", name, err)
	}
	if err := SetDefaultRemote("locktivity"); err != nil {
		t.Fatalf("SetDefaultRemote: %v", err)
	}
	if name, err := DefaultRemote(); err != nil || name != "locktivity" {
		t.Fatalf("DefaultRemote = %q, %v; want locktivity", name, err)
	}
	if err := SetDefaultRemote("../nope"); err == nil {
		t.Fatal("expected an invalid remote name to be rejected")
	}
}
