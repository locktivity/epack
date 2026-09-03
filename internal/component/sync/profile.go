package sync

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"time"

	"github.com/locktivity/epack/errors"
	"github.com/locktivity/epack/internal/component/config"
	"github.com/locktivity/epack/internal/component/lockfile"
	"github.com/locktivity/epack/internal/exitcode"
	"github.com/locktivity/epack/internal/limits"
	"github.com/locktivity/epack/internal/safefile"
)

// LocalFileSyncResult contains the result of syncing a profile, overlay, or mapping.
type LocalFileSyncResult struct {
	Source   string // Profile source reference or path
	Kind     string // "profile", "overlay", or "mapping"
	Digest   string // SHA256 digest of the profile file
	Cached   bool   // Whether the profile was already cached
	IsLocal  bool   // Whether this is a local path (not remote source)
	Verified bool   // Whether the digest was verified against lockfile
}

// LocalFileLockResult contains the result of locking a profile, overlay, or mapping.
type LocalFileLockResult struct {
	Source  string // Profile source reference or path
	Kind    string // "profile", "overlay", or "mapping"
	Digest  string // SHA256 digest of the profile file
	IsNew   bool   // Whether this is a newly locked profile
	Updated bool   // Whether the digest was updated
}

// localFileKind describes one kind of digest-locked local file (profile,
// overlay, mapping) so sync, lock, alignment, gap, and drift logic iterate
// kinds instead of carrying a hand-written copy per kind. The lockfile
// structs stay distinct because they serialize into epack.lock.yaml, which
// is a committed contract. lockedEntry and lockedDigest differ on entries
// with an empty digest: alignment accepts them, verification does not.
type localFileKind struct {
	name         string
	configKeys   func(*config.JobConfig) []string
	localFiles   func(*config.JobConfig) []localFileRef
	lockedEntry  func(*lockfile.LockFile, string) bool
	lockedDigest func(*lockfile.LockFile, string) (string, bool)
	lockedKeys   func(*lockfile.LockFile) []string
	setLocked    func(lf *lockfile.LockFile, key, digest, lockedAt string) (existed bool, prevDigest string)
}

type localFileRef struct {
	key      string
	filePath string
}

func mapKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	return keys
}

var profileKind = &localFileKind{
	name: "profile",
	configKeys: func(cfg *config.JobConfig) []string {
		keys := make([]string, 0, len(cfg.Profiles))
		for _, p := range cfg.Profiles {
			keys = append(keys, p.Key())
		}
		return keys
	},
	localFiles: func(cfg *config.JobConfig) []localFileRef {
		refs := make([]localFileRef, 0, len(cfg.Profiles))
		for _, p := range cfg.Profiles {
			if p.Path != "" {
				refs = append(refs, localFileRef{key: p.Key(), filePath: p.FilePath()})
			}
		}
		return refs
	},
	lockedEntry: func(lf *lockfile.LockFile, key string) bool {
		_, ok := lf.Profiles[key]
		return ok
	},
	lockedDigest: (*lockfile.LockFile).GetProfileDigest,
	lockedKeys:   func(lf *lockfile.LockFile) []string { return mapKeys(lf.Profiles) },
	setLocked: func(lf *lockfile.LockFile, key, digest, lockedAt string) (bool, string) {
		existing, exists := lf.Profiles[key]
		lf.Profiles[key] = lockfile.LockedProfile{
			Source:   key,
			Digest:   digest,
			LockedAt: lockedAt,
		}
		return exists, existing.Digest
	},
}

var overlayKind = &localFileKind{
	name: "overlay",
	configKeys: func(cfg *config.JobConfig) []string {
		keys := make([]string, 0, len(cfg.Overlays))
		for _, o := range cfg.Overlays {
			keys = append(keys, o.Key())
		}
		return keys
	},
	localFiles: func(cfg *config.JobConfig) []localFileRef {
		refs := make([]localFileRef, 0, len(cfg.Overlays))
		for _, o := range cfg.Overlays {
			if o.Path != "" {
				refs = append(refs, localFileRef{key: o.Key(), filePath: o.FilePath()})
			}
		}
		return refs
	},
	lockedEntry: func(lf *lockfile.LockFile, key string) bool {
		_, ok := lf.Overlays[key]
		return ok
	},
	lockedDigest: (*lockfile.LockFile).GetOverlayDigest,
	lockedKeys:   func(lf *lockfile.LockFile) []string { return mapKeys(lf.Overlays) },
	setLocked: func(lf *lockfile.LockFile, key, digest, lockedAt string) (bool, string) {
		existing, exists := lf.Overlays[key]
		lf.Overlays[key] = lockfile.LockedOverlay{
			Source:   key,
			Digest:   digest,
			LockedAt: lockedAt,
		}
		return exists, existing.Digest
	},
}

var mappingKind = &localFileKind{
	name: "mapping",
	configKeys: func(cfg *config.JobConfig) []string {
		keys := make([]string, 0, len(cfg.Mappings))
		for _, m := range cfg.Mappings {
			keys = append(keys, m.Key())
		}
		return keys
	},
	localFiles: func(cfg *config.JobConfig) []localFileRef {
		refs := make([]localFileRef, 0, len(cfg.Mappings))
		for _, m := range cfg.Mappings {
			refs = append(refs, localFileRef{key: m.Key(), filePath: m.FilePath()})
		}
		return refs
	},
	lockedEntry: func(lf *lockfile.LockFile, key string) bool {
		_, ok := lf.Mappings[key]
		return ok
	},
	lockedDigest: (*lockfile.LockFile).GetMappingDigest,
	lockedKeys:   func(lf *lockfile.LockFile) []string { return mapKeys(lf.Mappings) },
	setLocked: func(lf *lockfile.LockFile, key, digest, lockedAt string) (bool, string) {
		existing, exists := lf.Mappings[key]
		lf.Mappings[key] = lockfile.LockedMapping{
			Source:   key,
			Digest:   digest,
			LockedAt: lockedAt,
		}
		return exists, existing.Digest
	},
}

var localFileKinds = []*localFileKind{profileKind, overlayKind, mappingKind}

// SyncProfiles syncs all profiles from the config.
// For local profiles (path), it computes the digest and caches it.
// For remote profiles (source), it fetches from the registry and caches.
func (s *Syncer) SyncProfiles(ctx context.Context, cfg *config.JobConfig, lf *lockfile.LockFile, opts SyncOpts) ([]LocalFileSyncResult, error) {
	var results []LocalFileSyncResult

	for _, profile := range cfg.Profiles {
		result, err := s.syncProfile(ctx, profile, lf, opts)
		if err != nil {
			return nil, err
		}
		results = append(results, *result)
	}

	return results, nil
}

// SyncOverlays syncs all overlays from the config.
func (s *Syncer) SyncOverlays(ctx context.Context, cfg *config.JobConfig, lf *lockfile.LockFile, opts SyncOpts) ([]LocalFileSyncResult, error) {
	var results []LocalFileSyncResult

	for _, overlay := range cfg.Overlays {
		result, err := s.syncOverlay(ctx, overlay, lf, opts)
		if err != nil {
			return nil, err
		}
		results = append(results, *result)
	}

	return results, nil
}

// SyncMappings syncs all control mappings from the config.
// Mappings are always local files, so this only computes and verifies digests.
func (s *Syncer) SyncMappings(cfg *config.JobConfig, lf *lockfile.LockFile, opts SyncOpts) ([]LocalFileSyncResult, error) {
	var results []LocalFileSyncResult

	for _, mapping := range cfg.Mappings {
		result, err := s.syncLocalFile(mappingKind, mapping.Key(), mapping.FilePath(), lf, opts)
		if err != nil {
			return nil, err
		}
		results = append(results, *result)
	}

	return results, nil
}

func (s *Syncer) syncProfile(ctx context.Context, profile config.ProfileConfig, lf *lockfile.LockFile, opts SyncOpts) (*LocalFileSyncResult, error) {
	if profile.Path != "" {
		return s.syncLocalFile(profileKind, profile.Key(), profile.FilePath(), lf, opts)
	}
	return s.syncRemoteFile(ctx, profileKind, profile.Source, lf, opts)
}

func (s *Syncer) syncOverlay(ctx context.Context, overlay config.OverlayConfig, lf *lockfile.LockFile, opts SyncOpts) (*LocalFileSyncResult, error) {
	if overlay.Path != "" {
		return s.syncLocalFile(overlayKind, overlay.Key(), overlay.FilePath(), lf, opts)
	}
	return s.syncRemoteFile(ctx, overlayKind, overlay.Source, lf, opts)
}

// resolveLocalFilePath determines the validated absolute path for file I/O.
// If filePath is absolute (from ResolvedPath), validates containment and symlinks.
// Otherwise, validates key relative to workDir using standard path resolution.
//
// SECURITY: Both code paths enforce containment within workDir and symlink rejection
// via safefile primitives. The containment check for absolute paths is defense-in-depth:
// even if config was normalized against a different base directory, the path must still
// be within workDir.
func resolveLocalFilePath(workDir, key, filePath string) (string, error) {
	// If filePath is not absolute, use standard path resolution with key
	if !filepath.IsAbs(filePath) {
		return safefile.ValidateRegularFile(workDir, key)
	}

	// filePath is absolute - validate containment, symlinks, and file type
	return safefile.ValidateAbsoluteFile(workDir, filePath)
}

// syncLocalFile handles local profile/overlay/mapping files.
// key is the lockfile key (project-relative path), filePath is for file I/O (absolute if normalized).
// It computes the digest and optionally verifies against lockfile in frozen mode.
//
// SECURITY: Uses safefile.ValidateRegularFile for full path-component symlink rejection,
// and safefile.ReadFile for bounded, race-safe reads with O_NOFOLLOW.
func (s *Syncer) syncLocalFile(kind *localFileKind, key, filePath string, lf *lockfile.LockFile, opts SyncOpts) (*LocalFileSyncResult, error) {
	// Determine which path to use for file I/O
	// If filePath is absolute (from ResolvedPath), use it after symlink validation
	// Otherwise, validate key relative to WorkDir
	validatedPath, err := resolveLocalFilePath(s.WorkDir, key, filePath)
	if err != nil {
		code := errors.CodeOf(err)
		if code == errors.SymlinkNotAllowed || code == errors.InvalidPath || code == errors.PathTraversal {
			return nil, errors.WithHint(code, exitcode.FileNotFound,
				fmt.Sprintf("local %s path invalid: %s", kind.name, key),
				"Profile paths cannot contain symlinks or escape the project directory", err)
		}
		return nil, errors.WithHint(errors.FileNotFound, exitcode.FileNotFound,
			fmt.Sprintf("local %s not found: %s", kind.name, key),
			fmt.Sprintf("Create the %s file or update epack.yaml", kind.name), err)
	}

	// Read file with bounded size and O_NOFOLLOW protection on leaf
	data, err := safefile.ReadFile(validatedPath, limits.ProfileFile)
	if err != nil {
		return nil, errors.WithHint(errors.FileNotFound, exitcode.FileNotFound,
			fmt.Sprintf("reading local %s: %s", kind.name, key),
			fmt.Sprintf("Create the %s file or update epack.yaml", kind.name), err)
	}

	// Compute digest from bounded bytes (same bytes that would be parsed)
	digest := computeDigestFromBytes(data)

	// Check if digest matches lockfile
	lockedDigest, hasLocked := kind.lockedDigest(lf, key)

	// In strict mode, require lockfile entry and matching digest
	if opts.Secure.strict() {
		if !hasLocked {
			return nil, errors.WithHint(errors.LockConfigMismatch, exitcode.LockInvalid,
				fmt.Sprintf("local %s %q not in lockfile", kind.name, key),
				"Run 'epack lock' to add the profile", nil)
		}
		if lockedDigest != digest {
			return nil, errors.WithHint(errors.DigestMismatch, exitcode.DigestMismatch,
				fmt.Sprintf("local %s %q digest mismatch", kind.name, key),
				fmt.Sprintf("File was modified. Run 'epack lock' to update, expected %s got %s", lockedDigest, digest), nil)
		}
	}

	// Only report as verified if we actually verified against lockfile
	verified := hasLocked && lockedDigest == digest

	return &LocalFileSyncResult{
		Source:   key,
		Kind:     kind.name,
		Digest:   digest,
		Cached:   false,
		IsLocal:  true,
		Verified: verified,
	}, nil
}

// syncRemoteFile handles remote profile/overlay sources.
// TODO: Implement fetching from registry. For now, returns an error.
func (s *Syncer) syncRemoteFile(ctx context.Context, kind *localFileKind, source string, lf *lockfile.LockFile, opts SyncOpts) (*LocalFileSyncResult, error) {
	// Check if already in lockfile
	lockedDigest, ok := kind.lockedDigest(lf, source)

	// Check cache directory
	cacheDir := filepath.Join(s.BaseDir, kind.name+"s")
	cachePath := filepath.Join(cacheDir, sanitizeSourceForPath(source)+".yaml")

	// If cached file exists and matches lockfile digest, use it
	if ok && lockedDigest != "" {
		if digest, err := computeFileDigest(cachePath); err == nil && digest == lockedDigest {
			return &LocalFileSyncResult{
				Source:   source,
				Kind:     kind.name,
				Digest:   digest,
				Cached:   true,
				IsLocal:  false,
				Verified: true, // Cache matches lockfile digest
			}, nil
		}
	}

	// In frozen mode, fail if not cached
	if opts.Secure.Frozen {
		return nil, errors.WithHint(errors.BinaryNotFound, exitcode.MissingBinary,
			fmt.Sprintf("remote %s %q not cached", kind.name, source),
			"Run 'epack sync' to fetch profiles", nil)
	}

	// TODO: Implement remote profile fetching
	// For now, return an error indicating this isn't implemented yet
	return nil, errors.WithHint(errors.NotImplemented, exitcode.NotImplemented,
		fmt.Sprintf("remote %s sources not yet supported: %s", kind.name, source),
		"Use path: instead of source: for local profiles", nil)
}

// computeDigestFromBytes computes SHA256 digest from byte slice.
// This ensures the digest is computed from the same bounded bytes used for parsing.
func computeDigestFromBytes(data []byte) string {
	h := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(h[:])
}

// computeFileDigest reads a cache file and computes its digest.
// Used for system-managed cache paths (not user-provided paths).
// Uses bounded reads but not full path validation since the path is constructed internally.
func computeFileDigest(absPath string) (string, error) {
	data, err := safefile.ReadFile(absPath, limits.ProfileFile)
	if err != nil {
		return "", err
	}
	return computeDigestFromBytes(data), nil
}

// sanitizeSourceForPath converts a source reference to a safe filename.
// e.g., "evidencepack/soc2-basic@v1" -> "evidencepack_soc2-basic_v1"
func sanitizeSourceForPath(source string) string {
	result := make([]byte, 0, len(source))
	for i := 0; i < len(source); i++ {
		c := source[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' {
			result = append(result, c)
		} else {
			result = append(result, '_')
		}
	}
	return string(result)
}

// LockLocalFiles updates the lockfile with digests for every local file kind.
// This is called by 'epack lock' to pin profile, overlay, and mapping versions.
func LockLocalFiles(cfg *config.JobConfig, lf *lockfile.LockFile, workDir string) ([]LocalFileLockResult, error) {
	var results []LocalFileLockResult

	for _, kind := range localFileKinds {
		for _, ref := range kind.localFiles(cfg) {
			result, err := lockLocalFile(kind, ref.key, ref.filePath, lf, workDir)
			if err != nil {
				return nil, err
			}
			results = append(results, *result)
		}
		// TODO: Handle remote profile/overlay sources when implemented
	}

	return results, nil
}

func lockLocalFile(kind *localFileKind, key, filePath string, lf *lockfile.LockFile, workDir string) (*LocalFileLockResult, error) {
	// Resolve the path to use for file I/O
	// If filePath is absolute (from ResolvedPath), use it after validation
	// Otherwise, use key relative to workDir
	resolvedPath, err := resolveLocalFilePath(workDir, key, filePath)
	if err != nil {
		return nil, fmt.Errorf("computing digest for %s %s: %w", kind.name, key, err)
	}
	digest, err := computeFileDigest(resolvedPath)
	if err != nil {
		return nil, fmt.Errorf("computing digest for %s %s: %w", kind.name, key, err)
	}

	existed, prevDigest := kind.setLocked(lf, key, digest, time.Now().UTC().Format(time.RFC3339))

	return &LocalFileLockResult{
		Source:  key,
		Kind:    kind.name,
		Digest:  digest,
		IsNew:   !existed,
		Updated: existed && prevDigest != digest,
	}, nil
}

// ValidateLocalFileAlignment checks that configured local files match lockfile entries.
func ValidateLocalFileAlignment(cfg *config.JobConfig, lf *lockfile.LockFile, skipStaleCheck bool) error {
	// Validate configured entries exist in the lockfile
	for _, kind := range localFileKinds {
		for i, key := range kind.configKeys(cfg) {
			if kind.lockedEntry(lf, key) {
				continue
			}
			return errors.WithHint(errors.LockfileInvalid, exitcode.LockInvalid,
				fmt.Sprintf("%s[%d] %q not in lockfile", kind.name, i, key),
				fmt.Sprintf("Run 'epack lock' to add the %s", kind.name), nil)
		}
	}

	// Skip reverse check (lockfile -> config) if requested
	if skipStaleCheck {
		return nil
	}

	// Check for stale lockfile entries
	for _, kind := range localFileKinds {
		configured := make(map[string]bool)
		for _, key := range kind.configKeys(cfg) {
			configured[key] = true
		}
		for _, key := range kind.lockedKeys(lf) {
			if !configured[key] {
				return errors.WithHint(errors.LockfileInvalid, exitcode.LockInvalid,
					fmt.Sprintf("lockfile has %s %q not in config", kind.name, key),
					fmt.Sprintf("Remove stale entries or add %s to config", kind.name), nil)
			}
		}
	}

	return nil
}

// HasLocalFileLockfileGap checks if any configured local file is missing from the lockfile.
// Returns true if any entry is missing, false if all are present.
func HasLocalFileLockfileGap(cfg *config.JobConfig, lf *lockfile.LockFile) bool {
	for _, kind := range localFileKinds {
		for _, key := range kind.configKeys(cfg) {
			if !kind.lockedEntry(lf, key) {
				return true
			}
		}
	}
	return false
}

// HasLocalFileDigestDrift checks if any local file has content that differs from the lockfile.
// This detects the case where a file was modified after locking but before collection.
// Returns true if any digest has drifted, false if all match or on any error.
// Errors are silently ignored to allow the workflow to proceed (the actual sync will catch issues).
func HasLocalFileDigestDrift(cfg *config.JobConfig, lf *lockfile.LockFile, workDir string) bool {
	for _, kind := range localFileKinds {
		for _, ref := range kind.localFiles(cfg) {
			lockedDigest, ok := kind.lockedDigest(lf, ref.key)
			if !ok {
				continue // Entry missing - handled elsewhere
			}
			resolvedPath, err := resolveLocalFilePath(workDir, ref.key, ref.filePath)
			if err != nil {
				continue // File issues handled during actual sync
			}
			currentDigest, err := computeFileDigest(resolvedPath)
			if err != nil {
				continue // File issues handled during actual sync
			}
			if currentDigest != lockedDigest {
				return true // Digest drifted
			}
		}
	}
	return false
}

// ProfilePaths returns the paths to all profile files for loading.
// For local profiles, returns the path directly.
// For remote profiles, returns the cached path.
func ProfilePaths(cfg *config.JobConfig, baseDir string) []string {
	paths := make([]string, 0, len(cfg.Profiles))
	for _, profile := range cfg.Profiles {
		if profile.Path != "" {
			paths = append(paths, profile.FilePath())
		} else {
			// Remote profile - use cache path
			cacheDir := filepath.Join(baseDir, "profiles")
			cachePath := filepath.Join(cacheDir, sanitizeSourceForPath(profile.Source)+".yaml")
			paths = append(paths, cachePath)
		}
	}
	return paths
}

// OverlayPaths returns the paths to all overlay files for loading.
func OverlayPaths(cfg *config.JobConfig, baseDir string) []string {
	paths := make([]string, 0, len(cfg.Overlays))
	for _, overlay := range cfg.Overlays {
		if overlay.Path != "" {
			paths = append(paths, overlay.FilePath())
		} else {
			// Remote overlay - use cache path
			cacheDir := filepath.Join(baseDir, "overlays")
			cachePath := filepath.Join(cacheDir, sanitizeSourceForPath(overlay.Source)+".yaml")
			paths = append(paths, cachePath)
		}
	}
	return paths
}

// EnsureProfileCacheDir creates the profile cache directory if it doesn't exist.
func EnsureProfileCacheDir(baseDir string) error {
	cacheDir := filepath.Join(baseDir, "profiles")
	return safefile.EnsureBaseDir(cacheDir)
}
