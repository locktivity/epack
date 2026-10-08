// Package userremote reaches a remote adapter by name when no project names
// it. The catalog says where the adapter comes from, the adapter is locked and
// installed under the user's epack directory, and every later use verifies
// the installed binary against that lock before running it.
package userremote

import (
	"context"
	stderrors "errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"

	"github.com/locktivity/epack/errors"
	"github.com/locktivity/epack/internal/catalog"
	"github.com/locktivity/epack/internal/component/config"
	"github.com/locktivity/epack/internal/component/lockfile"
	"github.com/locktivity/epack/internal/component/semver"
	"github.com/locktivity/epack/internal/component/sync"
	"github.com/locktivity/epack/internal/componenttypes"
	"github.com/locktivity/epack/internal/exitcode"
	"github.com/locktivity/epack/internal/platform"
	"github.com/locktivity/epack/internal/remote"
	"github.com/locktivity/epack/internal/safefile"
	"github.com/locktivity/epack/internal/userconfig"
)

// LookupFunc names the source an adapter is installed from, as a config
// source such as "locktivity/epack-remote-locktivity@v0.3.0".
type LookupFunc func(ctx context.Context, name string) (string, error)

// Resolver installs and verifies remote adapters for the user.
type Resolver struct {
	// Dir is the user epack directory the adapters are installed under.
	Dir string
	// LockPath is the user-level remotes lockfile.
	LockPath string
	Registry sync.RegistryClient
	Lookup   LookupFunc
	// Latest names the newest source the catalog lists for an adapter,
	// against a freshly fetched catalog. Update uses it.
	Latest LookupFunc
	// Stderr receives the adapter's stderr.
	Stderr io.Writer
	// Step receives progress events while locking and installing.
	Step         remote.StepCallback
	Verification remote.VerificationOptions
}

// New returns a resolver over the user's epack directory, the GitHub
// registry, and the catalog.
func New() (*Resolver, error) {
	dir, err := userconfig.Dir()
	if err != nil {
		return nil, err
	}
	lockPath, err := userconfig.RemotesLockPath()
	if err != nil {
		return nil, err
	}
	return &Resolver{
		Dir:      dir,
		LockPath: lockPath,
		Registry: sync.NewGitHubRegistry(),
		Lookup:   CatalogLookup,
		Latest:   CatalogLatest,
	}, nil
}

// Prepare returns a verified executor for the named adapter, locking and
// installing it first when needed. Callers must Close the executor.
func (r *Resolver) Prepare(ctx context.Context, name string) (*remote.Executor, *remote.Capabilities, error) {
	if err := config.ValidateRemoteName(name); err != nil {
		return nil, nil, err
	}
	lf, err := userconfig.LoadRemotesLockFromPath(r.LockPath)
	if err != nil {
		return nil, nil, err
	}
	platformKey := platform.Key(runtime.GOOS, runtime.GOARCH)
	if err := r.ensureLocked(ctx, name, lf, platformKey); err != nil {
		return nil, nil, err
	}
	locked, _ := lf.GetRemote(name)
	remoteCfg := config.RemoteConfig{Source: sourceDescriptor(locked)}
	if err := r.ensureInstalled(ctx, name, remoteCfg, lf, platformKey); err != nil {
		return nil, nil, err
	}
	return r.start(ctx, name, remoteCfg, lf, platformKey)
}

// start verifies an installed adapter against its lock, runs it, and checks
// that it speaks this epack's protocol.
func (r *Resolver) start(ctx context.Context, name string, remoteCfg config.RemoteConfig, lf *lockfile.LockFile, platformKey string) (*remote.Executor, *remote.Capabilities, error) {
	binaryPath, err := sync.ResolveRemoteBinaryPath(r.Dir, name, remoteCfg, lf)
	if err != nil {
		return nil, nil, fmt.Errorf("resolving adapter path: %w", err)
	}
	digestInfo := remote.GetAdapterDigestInfo(name, &remoteCfg, lf, platformKey)
	if err := remote.CheckAdapterSecurity(name, binaryPath, digestInfo, r.Verification); err != nil {
		return nil, nil, err
	}
	exec, err := newExecutor(binaryPath, digestInfo, remoteCfg.EffectiveAdapter())
	if err != nil {
		return nil, nil, err
	}
	exec.Stderr = r.Stderr
	caps, err := remote.QueryCapabilities(ctx, exec.BinaryPath)
	if err != nil {
		exec.Close()
		return nil, nil, fmt.Errorf("querying adapter capabilities: %w", err)
	}
	if !caps.SupportsProtocolVersion(remote.ProtocolVersion) {
		exec.Close()
		return nil, nil, fmt.Errorf("adapter protocol version %d not supported (need %d)",
			caps.DeployProtocolVersion, remote.ProtocolVersion)
	}
	return exec, caps, nil
}

// UpdateResult says what an update did.
type UpdateResult struct {
	// Previous is the release that was installed.
	Previous string
	// Version is the release installed now.
	Version string
	// Updated is false when the installed release was already the newest.
	Updated bool
}

// Update moves an adapter installed for the user to the newest release the
// catalog lists for the same repository; the pin in the user lock never
// moves on its own. The new release is locked, installed, and started before
// the pin moves, so a release that fails any of those leaves the working
// adapter in place.
func (r *Resolver) Update(ctx context.Context, name string) (*UpdateResult, error) {
	if err := config.ValidateRemoteName(name); err != nil {
		return nil, err
	}
	lf, err := userconfig.LoadRemotesLockFromPath(r.LockPath)
	if err != nil {
		return nil, err
	}
	installed, ok := lf.GetRemote(name)
	if !ok {
		return nil, errors.WithHint(errors.RemoteNotFound, exitcode.General,
			fmt.Sprintf("no %s adapter is installed for you yet", name),
			fmt.Sprintf("Sign in with 'epack remote login %s'; it installs the newest release", name), nil)
	}
	latest := r.Latest
	if latest == nil {
		latest = CatalogLatest
	}
	source, err := latest(ctx, name)
	if err != nil {
		return nil, err
	}
	repo := strings.SplitN(source, "@", 2)[0]
	installedRepo := strings.TrimPrefix(installed.Source, "github.com/")
	if !strings.EqualFold(repo, installedRepo) {
		return nil, fmt.Errorf("the catalog now lists github.com/%s for %s, not github.com/%s; epack only updates an adapter within its own repository", repo, name, installedRepo)
	}

	r.step(fmt.Sprintf("Checking github.com/%s for a newer release", repo), true)
	candidate := lockfile.New()
	locker := &sync.Locker{Registry: r.Registry, LockfilePath: r.LockPath, BaseDir: r.Dir}
	if _, err := locker.LockRemote(ctx, name, config.RemoteConfig{Source: source}, candidate, sync.LockOpts{}); err != nil {
		return nil, fmt.Errorf("locking remote %q: %w", name, err)
	}
	next, _ := candidate.GetRemote(name)
	r.step(fmt.Sprintf("Newest %s release is %s", name, next.Version), false)
	if !newerRelease(next.Version, installed.Version) {
		return &UpdateResult{Previous: installed.Version, Version: installed.Version}, nil
	}
	next.ResolvedFrom = &componenttypes.ResolvedFrom{Registry: "catalog", Descriptor: source}
	return r.adopt(ctx, name, lf, installed, next)
}

// adopt installs and starts a newly locked release, and moves the user's
// pin to it only once it runs.
func (r *Resolver) adopt(ctx context.Context, name string, lf *lockfile.LockFile, installed, next lockfile.LockedRemote) (*UpdateResult, error) {
	platformKey := platform.Key(runtime.GOOS, runtime.GOARCH)
	candidate := lockfile.New()
	candidate.Remotes[name] = next
	remoteCfg := config.RemoteConfig{Source: sourceDescriptor(next)}
	if err := r.ensureInstalled(ctx, name, remoteCfg, candidate, platformKey); err != nil {
		return nil, fmt.Errorf("%s %s did not install, so %s stays on %s: %w", name, next.Version, name, installed.Version, err)
	}
	exec, _, err := r.start(ctx, name, remoteCfg, candidate, platformKey)
	if err != nil {
		return nil, fmt.Errorf("%s %s did not start, so %s stays on %s: %w", name, next.Version, name, installed.Version, err)
	}
	exec.Close()
	lf.Remotes[name] = next
	if err := userconfig.SaveRemotesLockToPath(r.LockPath, lf); err != nil {
		return nil, err
	}
	return &UpdateResult{Previous: installed.Version, Version: next.Version, Updated: true}, nil
}

// newerRelease reports whether next is a later release than current. A
// release that does not parse is never treated as newer.
func newerRelease(next, current string) bool {
	n, err := semver.ParseVersion(next)
	if err != nil {
		return false
	}
	c, err := semver.ParseVersion(current)
	if err != nil {
		return false
	}
	switch {
	case n.Major != c.Major:
		return n.Major > c.Major
	case n.Minor != c.Minor:
		return n.Minor > c.Minor
	case n.Patch != c.Patch:
		return n.Patch > c.Patch
	default:
		return c.Prerelease != "" && (n.Prerelease == "" || n.Prerelease > c.Prerelease)
	}
}

func newExecutor(binaryPath string, digestInfo remote.AdapterDigestInfo, adapterName string) (*remote.Executor, error) {
	if digestInfo.Digest == "" {
		return remote.NewExecutor(binaryPath, adapterName), nil
	}
	exec, err := remote.NewVerifiedExecutor(binaryPath, digestInfo.Digest, adapterName)
	if err != nil {
		return nil, fmt.Errorf("verifying adapter: %w", err)
	}
	return exec, nil
}

func (r *Resolver) ensureLocked(ctx context.Context, name string, lf *lockfile.LockFile, platformKey string) error {
	locked, exists := lf.GetRemote(name)
	if exists {
		if entry, ok := locked.Platforms[platformKey]; ok && entry.Digest != "" {
			return nil
		}
	}
	source := ""
	if exists {
		source = sourceDescriptor(locked)
	} else {
		var err error
		source, err = r.Lookup(ctx, name)
		if err != nil {
			return err
		}
	}
	repo := strings.SplitN(source, "@", 2)[0]
	r.step(fmt.Sprintf("Locking %s from github.com/%s", name, repo), true)
	locker := &sync.Locker{Registry: r.Registry, LockfilePath: r.LockPath, BaseDir: r.Dir}
	result, err := locker.LockRemote(ctx, name, config.RemoteConfig{Source: source}, lf, sync.LockOpts{})
	if err != nil {
		return fmt.Errorf("locking remote %q: %w", name, err)
	}
	if !exists {
		entry := lf.Remotes[name]
		entry.ResolvedFrom = &componenttypes.ResolvedFrom{Registry: "catalog", Descriptor: source}
		lf.Remotes[name] = entry
	}
	if err := userconfig.SaveRemotesLockToPath(r.LockPath, lf); err != nil {
		return err
	}
	r.step(fmt.Sprintf("Locked %s %s from github.com/%s", name, result.Version, repo), false)
	return nil
}

func (r *Resolver) ensureInstalled(ctx context.Context, name string, remoteCfg config.RemoteConfig, lf *lockfile.LockFile, platformKey string) error {
	if err := safefile.EnsureBaseDir(r.Dir); err != nil {
		return fmt.Errorf("creating %s: %w", r.Dir, err)
	}
	installed := false
	if path, err := sync.ResolveRemoteBinaryPath(r.Dir, name, remoteCfg, lf); err == nil {
		_, statErr := os.Stat(path)
		installed = statErr == nil
	}
	if !installed {
		r.step(fmt.Sprintf("Installing %s", name), true)
	}
	syncer := &sync.Syncer{Registry: r.Registry, LockfilePath: r.LockPath, BaseDir: r.Dir, WorkDir: r.Dir}
	result, err := syncer.SyncRemote(ctx, name, remoteCfg, lf, platformKey, sync.SyncOpts{})
	if err != nil {
		return fmt.Errorf("installing remote %q: %w", name, err)
	}
	if !installed && result != nil {
		r.step(fmt.Sprintf("Installed %s %s", name, result.Version), false)
	}
	return nil
}

func (r *Resolver) step(message string, started bool) {
	if r.Step != nil {
		r.Step(message, started)
	}
}

// Source returns the locked source of an adapter installed for the user,
// as owner/repo@version, or an empty string when it is not locked.
func (r *Resolver) Source(name string) (string, error) {
	lf, err := userconfig.LoadRemotesLockFromPath(r.LockPath)
	if err != nil {
		return "", err
	}
	locked, ok := lf.GetRemote(name)
	if !ok {
		return "", nil
	}
	return sourceDescriptor(locked), nil
}

// sourceDescriptor rebuilds the config source for a locked remote, pinned to
// the locked version so a later lock never moves it on its own.
func sourceDescriptor(locked lockfile.LockedRemote) string {
	return strings.TrimPrefix(locked.Source, "github.com/") + "@" + locked.Version
}

// CatalogLookup finds the adapter in the cached catalog, refreshing the
// catalog once when it is missing or does not list the name.
func CatalogLookup(ctx context.Context, name string) (string, error) {
	source, err := lookupCatalog(name)
	if err == nil {
		return source, nil
	}
	if !stderrors.Is(err, catalog.ErrNoCatalog) && !stderrors.Is(err, catalog.ErrNotFound) {
		return "", err
	}
	if err := refreshCatalog(ctx); err != nil {
		return "", err
	}
	source, err = lookupCatalog(name)
	if err == nil {
		return source, nil
	}
	if stderrors.Is(err, catalog.ErrNoCatalog) || stderrors.Is(err, catalog.ErrNotFound) {
		return "", errors.WithHint(errors.RemoteNotFound, exitcode.General,
			fmt.Sprintf("no remote named %q in the catalog", name),
			"Inside a project, add the remote to epack.yaml with its source", nil)
	}
	return "", err
}

// CatalogLatest is CatalogLookup against a freshly fetched catalog, so an
// update sees releases listed since the cached copy was taken.
func CatalogLatest(ctx context.Context, name string) (string, error) {
	if err := refreshCatalog(ctx); err != nil {
		return "", err
	}
	return CatalogLookup(ctx, name)
}

func lookupCatalog(name string) (string, error) {
	result, err := catalog.LookupComponent(name, componenttypes.KindRemote, "latest")
	if err != nil {
		return "", err
	}
	return result.Source, nil
}

func refreshCatalog(ctx context.Context) error {
	opts := catalog.FetchOptions{}
	if meta := catalog.GetCachedMeta(); meta != nil {
		opts.ETag = meta.ETag
		opts.LastModified = meta.LastModified
	}
	if _, err := catalog.FetchCatalog(ctx, opts); err != nil {
		return fmt.Errorf("fetching catalog: %w", err)
	}
	return nil
}
