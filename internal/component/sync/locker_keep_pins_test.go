package sync

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/locktivity/epack/internal/component/config"
	"github.com/locktivity/epack/internal/component/lockfile"
	"github.com/locktivity/epack/internal/componenttypes"
)

// pinRegistry serves one newest release per repository and records which
// ranges were resolved and which releases were fetched.
type pinRegistry struct {
	newest   map[string]string
	resolved []string
	fetched  []string
}

func (r *pinRegistry) Name() string { return "test" }

func (r *pinRegistry) ResolveVersion(_ context.Context, source, _ string) (string, error) {
	r.resolved = append(r.resolved, source)
	return r.newest[source], nil
}

func (r *pinRegistry) FetchRelease(_ context.Context, source, version string) (*ReleaseInfo, error) {
	r.fetched = append(r.fetched, source+"@"+version)
	return &ReleaseInfo{Version: version, Commit: "commit-" + version}, nil
}

func (r *pinRegistry) DownloadAsset(_ context.Context, url, destPath string) error {
	return os.WriteFile(destPath, []byte(url), 0o600)
}

func (r *pinRegistry) FindBinaryAsset(release *ReleaseInfo, componentName, goos, goarch string) (*AssetInfo, error) {
	name := fmt.Sprintf("%s-%s-%s", componentName, goos, goarch)
	return &AssetInfo{Name: name, URL: "https://releases.test/" + release.Version + "/" + name}, nil
}

func (r *pinRegistry) FindSigstoreBundle(release *ReleaseInfo, binaryAssetName string) (*AssetInfo, error) {
	name := binaryAssetName + ".sigstore.json"
	return &AssetInfo{Name: name, URL: "https://releases.test/" + release.Version + "/" + name}, nil
}

type acceptingVerifier struct{}

func (acceptingVerifier) Verify(_, _ string, expected *ExpectedIdentity) (*SigstoreResult, error) {
	return &SigstoreResult{
		Issuer:              "https://token.actions.githubusercontent.com",
		SourceRepositoryURI: expected.SourceRepositoryURI,
		SourceRepositoryRef: expected.SourceRepositoryRef,
	}, nil
}

func keepPinsLocker(t *testing.T, registry *pinRegistry, pinned map[string]lockfile.LockedCollector) *Locker {
	t.Helper()
	dir, err := os.MkdirTemp(".", "keep_pins_test_*")
	if err != nil {
		t.Fatalf("creating test dir: %v", err)
	}
	dir, err = filepath.Abs(dir)
	if err != nil {
		t.Fatalf("resolving test dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	locker := NewLockerWithRegistry(registry, dir)
	locker.Verifier = acceptingVerifier{}
	lf := lockfile.New()
	for name, entry := range pinned {
		lf.Collectors[name] = entry
	}
	if err := lf.Save(locker.LockfilePath); err != nil {
		t.Fatalf("saving lockfile: %v", err)
	}
	return locker
}

func pinnedCollector(repo, version string, platforms ...string) lockfile.LockedCollector {
	locked := make(map[string]componenttypes.LockedPlatform)
	for _, plat := range platforms {
		locked[plat] = componenttypes.LockedPlatform{Digest: "sha256:" + version + "-" + plat}
	}
	return lockfile.LockedCollector{
		Source:  "github.com/" + repo,
		Version: version,
		Commit:  "commit-" + version,
		Signer: &componenttypes.LockedSigner{
			Issuer:              "https://token.actions.githubusercontent.com",
			SourceRepositoryURI: "https://github.com/" + repo,
			SourceRepositoryRef: "refs/tags/" + version,
		},
		Platforms: locked,
	}
}

func lockedVersions(t *testing.T, locker *Locker) map[string]string {
	t.Helper()
	lf, err := lockfile.Load(locker.LockfilePath)
	if err != nil {
		t.Fatalf("loading lockfile: %v", err)
	}
	versions := make(map[string]string)
	for name, entry := range lf.Collectors {
		versions[name] = entry.Version
	}
	return versions
}

func summaries(results []LockResult) []string {
	lines := make([]string, 0, len(results))
	for _, r := range results {
		lines = append(lines, r.Summary())
	}
	return lines
}

func TestLockKeepPinsResolvesOnlyAnAddedComponent(t *testing.T) {
	registry := &pinRegistry{newest: map[string]string{
		"locktivity/epack-collector-okta":   "v0.6.5",
		"locktivity/epack-collector-sentry": "v0.3.1",
	}}
	locker := keepPinsLocker(t, registry, map[string]lockfile.LockedCollector{
		"okta": pinnedCollector("locktivity/epack-collector-okta", "v0.6.2", "linux/amd64"),
	})
	cfg := &config.JobConfig{Collectors: map[string]config.CollectorConfig{
		"okta":   {Source: "locktivity/epack-collector-okta@^0.6.0"},
		"sentry": {Source: "locktivity/epack-collector-sentry@^0.3.0"},
	}}

	results, err := locker.Lock(context.Background(), cfg, LockOpts{Platforms: []string{"linux/amd64"}, KeepPins: true})
	if err != nil {
		t.Fatalf("Lock() error: %v", err)
	}

	want := map[string]string{"okta": "v0.6.2", "sentry": "v0.3.1"}
	if got := lockedVersions(t, locker); !mapsEqual(got, want) {
		t.Errorf("locked versions = %v, want %v", got, want)
	}
	if !slices.Equal(registry.resolved, []string{"locktivity/epack-collector-sentry"}) {
		t.Errorf("resolved ranges = %v, want only sentry's", registry.resolved)
	}
	wantSummaries := []string{"kept okta@v0.6.2 (linux/amd64)", "added sentry@v0.3.1 (linux/amd64)"}
	if got := summaries(results); !slices.Equal(got, wantSummaries) {
		t.Errorf("summaries = %q, want %q", got, wantSummaries)
	}
}

func TestLockKeepPinsKeepsEveryPinWhenNothingWasAdded(t *testing.T) {
	registry := &pinRegistry{newest: map[string]string{"locktivity/epack-collector-okta": "v0.6.5"}}
	pinned := pinnedCollector("locktivity/epack-collector-okta", "v0.6.2", "darwin/arm64", "linux/amd64")
	locker := keepPinsLocker(t, registry, map[string]lockfile.LockedCollector{"okta": pinned})
	cfg := &config.JobConfig{Collectors: map[string]config.CollectorConfig{
		"okta": {Source: "locktivity/epack-collector-okta@^0.6.0", Config: map[string]any{"group_filter": "engineering"}},
	}}

	if _, err := locker.Lock(context.Background(), cfg, LockOpts{AllPlatforms: true, KeepPins: true}); err != nil {
		t.Fatalf("Lock() error: %v", err)
	}

	lf, err := lockfile.Load(locker.LockfilePath)
	if err != nil {
		t.Fatalf("loading lockfile: %v", err)
	}
	got := lf.Collectors["okta"]
	if got.Version != "v0.6.2" || len(got.Platforms) != 2 || got.Platforms["linux/amd64"].Digest != pinned.Platforms["linux/amd64"].Digest {
		t.Errorf("okta entry = %+v, want the pinned entry unchanged", got)
	}
	if len(registry.resolved) != 0 || len(registry.fetched) != 0 {
		t.Errorf("a kept pin reached the registry: resolved %v, fetched %v", registry.resolved, registry.fetched)
	}
}

func TestLockKeepPinsMovesAPinItsRangeNoLongerAdmits(t *testing.T) {
	registry := &pinRegistry{newest: map[string]string{"locktivity/epack-collector-okta": "v0.6.5"}}
	locker := keepPinsLocker(t, registry, map[string]lockfile.LockedCollector{
		"okta": pinnedCollector("locktivity/epack-collector-okta", "v0.5.9", "linux/amd64"),
	})
	cfg := &config.JobConfig{Collectors: map[string]config.CollectorConfig{
		"okta": {Source: "locktivity/epack-collector-okta@^0.6.0"},
	}}

	results, err := locker.Lock(context.Background(), cfg, LockOpts{Platforms: []string{"linux/amd64"}, KeepPins: true})
	if err != nil {
		t.Fatalf("Lock() error: %v", err)
	}

	if got := lockedVersions(t, locker)["okta"]; got != "v0.6.5" {
		t.Errorf("okta = %s, want v0.6.5", got)
	}
	if got := summaries(results); !slices.Equal(got, []string{"updated okta@v0.6.5 (linux/amd64)"}) {
		t.Errorf("summaries = %q", got)
	}
}

func TestLockKeepPinsResolvesAPinFromAnotherSource(t *testing.T) {
	registry := &pinRegistry{newest: map[string]string{"locktivity/epack-collector-okta": "v0.6.5"}}
	locker := keepPinsLocker(t, registry, map[string]lockfile.LockedCollector{
		"okta": pinnedCollector("someone-else/epack-collector-okta", "v0.6.2", "linux/amd64"),
	})
	cfg := &config.JobConfig{Collectors: map[string]config.CollectorConfig{
		"okta": {Source: "locktivity/epack-collector-okta@^0.6.0"},
	}}

	if _, err := locker.Lock(context.Background(), cfg, LockOpts{Platforms: []string{"linux/amd64"}, KeepPins: true}); err != nil {
		t.Fatalf("Lock() error: %v", err)
	}

	lf, err := lockfile.Load(locker.LockfilePath)
	if err != nil {
		t.Fatalf("loading lockfile: %v", err)
	}
	if got := lf.Collectors["okta"]; got.Version != "v0.6.5" || got.Source != "github.com/locktivity/epack-collector-okta" {
		t.Errorf("okta entry = %s from %s, want v0.6.5 from the configured repository", got.Version, got.Source)
	}
}

func TestLockKeepPinsLocksAMissingPlatformAtThePinnedVersion(t *testing.T) {
	registry := &pinRegistry{newest: map[string]string{"locktivity/epack-collector-okta": "v0.6.5"}}
	locker := keepPinsLocker(t, registry, map[string]lockfile.LockedCollector{
		"okta": pinnedCollector("locktivity/epack-collector-okta", "v0.6.2", "linux/amd64"),
	})
	cfg := &config.JobConfig{Collectors: map[string]config.CollectorConfig{
		"okta": {Source: "locktivity/epack-collector-okta@^0.6.0"},
	}}

	if _, err := locker.Lock(context.Background(), cfg, LockOpts{Platforms: []string{"linux/amd64", "darwin/arm64"}, KeepPins: true}); err != nil {
		t.Fatalf("Lock() error: %v", err)
	}

	lf, err := lockfile.Load(locker.LockfilePath)
	if err != nil {
		t.Fatalf("loading lockfile: %v", err)
	}
	got := lf.Collectors["okta"]
	if got.Version != "v0.6.2" {
		t.Errorf("okta = %s, want the pin kept at v0.6.2", got.Version)
	}
	if _, ok := got.Platforms["darwin/arm64"]; !ok {
		t.Errorf("platforms = %v, want darwin/arm64 locked too", got.Platforms)
	}
	if len(registry.resolved) != 0 || !slices.Equal(registry.fetched, []string{"locktivity/epack-collector-okta@v0.6.2"}) {
		t.Errorf("resolved %v and fetched %v, want only the pinned release fetched", registry.resolved, registry.fetched)
	}
}

func TestLockWithoutKeepPinsMovesEveryPinToTheNewestRelease(t *testing.T) {
	registry := &pinRegistry{newest: map[string]string{"locktivity/epack-collector-okta": "v0.6.5"}}
	locker := keepPinsLocker(t, registry, map[string]lockfile.LockedCollector{
		"okta": pinnedCollector("locktivity/epack-collector-okta", "v0.6.2", "linux/amd64"),
	})
	cfg := &config.JobConfig{Collectors: map[string]config.CollectorConfig{
		"okta": {Source: "locktivity/epack-collector-okta@^0.6.0"},
	}}

	if _, err := locker.Lock(context.Background(), cfg, LockOpts{Platforms: []string{"linux/amd64"}}); err != nil {
		t.Fatalf("Lock() error: %v", err)
	}

	if got := lockedVersions(t, locker)["okta"]; got != "v0.6.5" {
		t.Errorf("okta = %s, want v0.6.5", got)
	}
}

func mapsEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for key, value := range a {
		if b[key] != value {
			return false
		}
	}
	return true
}
