package sync

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/locktivity/epack/internal/componenttypes"
)

// lookupFreeRegistry fails every release lookup and records downloads.
type lookupFreeRegistry struct {
	*GitHubRegistry
	lookups   int
	downloads []string
}

func (r *lookupFreeRegistry) FetchRelease(context.Context, string, string) (*ReleaseInfo, error) {
	r.lookups++
	return nil, errors.New("unexpected status 403 fetching release")
}

func (r *lookupFreeRegistry) DownloadAsset(_ context.Context, url, destPath string) error {
	r.downloads = append(r.downloads, url)
	return os.WriteFile(destPath, []byte("adapter binary"), 0o600)
}

const lockedAdapterURL = "https://github.com/locktivity/epack-remote-locktivity/releases/download/v0.2.1/epack-remote-locktivity-linux-amd64"

func lockedAdapter() *lockedComponent {
	return &lockedComponent{Source: "github.com/locktivity/epack-remote-locktivity", Version: "v0.2.1"}
}

func TestResolveReleaseAsset_DownloadsTheLockedAssetWithoutALookup(t *testing.T) {
	registry := &lookupFreeRegistry{GitHubRegistry: NewGitHubRegistry()}
	syncer := NewSyncerWithRegistry(registry, t.TempDir())
	entry := componenttypes.LockedPlatform{Asset: "epack-remote-locktivity-linux-amd64"}

	owner, repo, release, asset, err := syncer.resolveReleaseAsset(context.Background(), "locktivity", lockedAdapter(), entry)
	if err != nil {
		t.Fatalf("resolveReleaseAsset: %v", err)
	}
	if registry.lookups != 0 {
		t.Fatalf("looked the release up %d times", registry.lookups)
	}
	if owner != "locktivity" || repo != "epack-remote-locktivity" || asset.URL != lockedAdapterURL {
		t.Fatalf("got %s/%s from %s, want the release download link %s", owner, repo, asset.URL, lockedAdapterURL)
	}
	bundle, err := registry.FindSigstoreBundle(release, asset.Name)
	if err != nil || bundle.URL != lockedAdapterURL+".sigstore.json" {
		t.Fatalf("bundle = %+v, err %v; want the asset's .sigstore.json download link", bundle, err)
	}
}

func TestResolveReleaseAsset_LooksTheReleaseUpWhenTheLockNamesNoUsableAsset(t *testing.T) {
	for _, assetName := range []string{"", "../epack-remote-locktivity-linux-amd64"} {
		registry := &lookupFreeRegistry{GitHubRegistry: NewGitHubRegistry()}
		syncer := NewSyncerWithRegistry(registry, t.TempDir())

		_, _, _, _, err := syncer.resolveReleaseAsset(context.Background(), "locktivity", lockedAdapter(), componenttypes.LockedPlatform{Asset: assetName})
		if registry.lookups != 1 || err == nil {
			t.Errorf("asset %q: %d lookups, err %v; want the release lookup and its error", assetName, registry.lookups, err)
		}
	}
}

func TestDownloadAndInstallComponent_FetchesTheLockedAssetsDownloadLink(t *testing.T) {
	registry := &lookupFreeRegistry{GitHubRegistry: NewGitHubRegistry()}
	workDir := t.TempDir()
	syncer := NewSyncerWithRegistry(registry, workDir)
	sum := sha256.Sum256([]byte("adapter binary"))
	entry := componenttypes.LockedPlatform{Asset: "epack-remote-locktivity-linux-amd64", Digest: "sha256:" + hex.EncodeToString(sum[:])}
	installDir := filepath.Join(workDir, ".epack", "remotes", "locktivity", "v0.2.1")
	if err := os.MkdirAll(filepath.Join(workDir, ".epack"), 0o700); err != nil {
		t.Fatal(err)
	}

	err := syncer.downloadAndInstallComponent(context.Background(), "locktivity", "remote", lockedAdapter(), entry,
		filepath.Join(installDir, "epack-remote-locktivity"), installDir, SyncOpts{Unsafe: SyncUnsafeOverrides{SkipVerify: true}})
	if err != nil {
		t.Fatalf("downloadAndInstallComponent: %v", err)
	}
	if registry.lookups != 0 || len(registry.downloads) != 1 || registry.downloads[0] != lockedAdapterURL {
		t.Fatalf("lookups %d, downloads %v; want only %s", registry.lookups, registry.downloads, lockedAdapterURL)
	}
}
