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

// ProfileSyncResult contains the result of syncing a profile or overlay.
type ProfileSyncResult struct {
	Source   string // Profile source reference or path
	Kind     string // "profile" or "overlay"
	Digest   string // SHA256 digest of the profile file
	Cached   bool   // Whether the profile was already cached
	IsLocal  bool   // Whether this is a local path (not remote source)
	Verified bool   // Whether the digest was verified against lockfile
}

// ProfileLockResult contains the result of locking a profile or overlay.
type ProfileLockResult struct {
	Source  string // Profile source reference or path
	Kind    string // "profile" or "overlay"
	Digest  string // SHA256 digest of the profile file
	IsNew   bool   // Whether this is a newly locked profile
	Updated bool   // Whether the digest was updated
}

// SyncProfiles syncs all profiles from the config.
// For local profiles (path), it computes the digest and caches it.
// For remote profiles (source), it fetches from the registry and caches.
func (s *Syncer) SyncProfiles(ctx context.Context, cfg *config.JobConfig, lf *lockfile.LockFile, opts SyncOpts) ([]ProfileSyncResult, error) {
	var results []ProfileSyncResult

	for i, profile := range cfg.Profiles {
		result, err := s.syncProfile(ctx, i, profile, lf, opts)
		if err != nil {
			return nil, err
		}
		results = append(results, *result)
	}

	return results, nil
}

// SyncOverlays syncs all overlays from the config.
func (s *Syncer) SyncOverlays(ctx context.Context, cfg *config.JobConfig, lf *lockfile.LockFile, opts SyncOpts) ([]ProfileSyncResult, error) {
	var results []ProfileSyncResult

	for i, overlay := range cfg.Overlays {
		result, err := s.syncOverlay(ctx, i, overlay, lf, opts)
		if err != nil {
			return nil, err
		}
		results = append(results, *result)
	}

	return results, nil
}

func (s *Syncer) syncProfile(ctx context.Context, index int, profile config.ProfileConfig, lf *lockfile.LockFile, opts SyncOpts) (*ProfileSyncResult, error) {
	if profile.Path != "" {
		return s.syncLocalProfile(profile.Key(), profile.FilePath(), "profile", index, lf, opts)
	}
	return s.syncRemoteProfile(ctx, profile.Source, "profile", lf, opts)
}

func (s *Syncer) syncOverlay(ctx context.Context, index int, overlay config.OverlayConfig, lf *lockfile.LockFile, opts SyncOpts) (*ProfileSyncResult, error) {
	if overlay.Path != "" {
		return s.syncLocalProfile(overlay.Key(), overlay.FilePath(), "overlay", index, lf, opts)
	}
	return s.syncRemoteProfile(ctx, overlay.Source, "overlay", lf, opts)
}

// resolveProfilePath determines the validated absolute path for file I/O.
// If filePath is absolute (from ResolvedPath), validates containment and symlinks.
// Otherwise, validates key relative to workDir using standard path resolution.
//
// SECURITY: Both code paths enforce containment within workDir and symlink rejection
// via safefile primitives. The containment check for absolute paths is defense-in-depth:
// even if config was normalized against a different base directory, the path must still
// be within workDir.
func resolveProfilePath(workDir, key, filePath string) (string, error) {
	// If filePath is not absolute, use standard path resolution with key
	if !filepath.IsAbs(filePath) {
		return safefile.ValidateRegularFile(workDir, key)
	}

	// filePath is absolute - validate containment, symlinks, and file type
	return safefile.ValidateAbsoluteFile(workDir, filePath)
}

// syncLocalProfile handles local profile/overlay files.
// key is the lockfile key (project-relative path), filePath is for file I/O (absolute if normalized).
// It computes the digest and optionally verifies against lockfile in frozen mode.
//
// SECURITY: Uses safefile.ValidateRegularFile for full path-component symlink rejection,
// and safefile.ReadFile for bounded, race-safe reads with O_NOFOLLOW.
func (s *Syncer) syncLocalProfile(key, filePath, kind string, index int, lf *lockfile.LockFile, opts SyncOpts) (*ProfileSyncResult, error) {
	// Determine which path to use for file I/O
	// If filePath is absolute (from ResolvedPath), use it after symlink validation
	// Otherwise, validate key relative to WorkDir
	validatedPath, err := resolveProfilePath(s.WorkDir, key, filePath)
	if err != nil {
		code := errors.CodeOf(err)
		if code == errors.SymlinkNotAllowed || code == errors.InvalidPath || code == errors.PathTraversal {
			return nil, errors.WithHint(code, exitcode.FileNotFound,
				fmt.Sprintf("local %s path invalid: %s", kind, key),
				"Profile paths cannot contain symlinks or escape the project directory", err)
		}
		return nil, errors.WithHint(errors.FileNotFound, exitcode.FileNotFound,
			fmt.Sprintf("local %s not found: %s", kind, key),
			fmt.Sprintf("Create the %s file or update epack.yaml", kind), err)
	}

	// Read file with bounded size and O_NOFOLLOW protection on leaf
	data, err := safefile.ReadFile(validatedPath, limits.ProfileFile)
	if err != nil {
		return nil, errors.WithHint(errors.FileNotFound, exitcode.FileNotFound,
			fmt.Sprintf("reading local %s: %s", kind, key),
			fmt.Sprintf("Create the %s file or update epack.yaml", kind), err)
	}

	// Compute digest from bounded bytes (same bytes that would be parsed)
	digest := computeDigestFromBytes(data)

	// Check if digest matches lockfile
	var lockedDigest string
	var hasLocked bool
	if kind == "profile" {
		lockedDigest, hasLocked = lf.GetProfileDigest(key)
	} else {
		lockedDigest, hasLocked = lf.GetOverlayDigest(key)
	}

	// In frozen mode, require lockfile entry and matching digest
	if opts.Secure.Frozen {
		if !hasLocked {
			return nil, errors.WithHint(errors.LockfileInvalid, exitcode.LockInvalid,
				fmt.Sprintf("local %s %q not in lockfile", kind, key),
				"Run 'epack lock' to add the profile", nil)
		}
		if lockedDigest != digest {
			return nil, errors.WithHint(errors.DigestMismatch, exitcode.DigestMismatch,
				fmt.Sprintf("local %s %q digest mismatch", kind, key),
				fmt.Sprintf("File was modified. Run 'epack lock' to update, expected %s got %s", lockedDigest, digest), nil)
		}
	}

	// Only report as verified if we actually verified against lockfile
	verified := hasLocked && lockedDigest == digest

	return &ProfileSyncResult{
		Source:   key,
		Kind:     kind,
		Digest:   digest,
		Cached:   false,
		IsLocal:  true,
		Verified: verified,
	}, nil
}

// syncRemoteProfile handles remote profile/overlay sources.
// TODO: Implement fetching from registry. For now, returns an error.
func (s *Syncer) syncRemoteProfile(ctx context.Context, source, kind string, lf *lockfile.LockFile, opts SyncOpts) (*ProfileSyncResult, error) {
	// Check if already in lockfile
	var lockedDigest string
	var ok bool
	if kind == "profile" {
		lockedDigest, ok = lf.GetProfileDigest(source)
	} else {
		lockedDigest, ok = lf.GetOverlayDigest(source)
	}

	// Check cache directory
	cacheDir := filepath.Join(s.BaseDir, kind+"s")
	cachePath := filepath.Join(cacheDir, sanitizeSourceForPath(source)+".yaml")

	// If cached file exists and matches lockfile digest, use it
	if ok && lockedDigest != "" {
		if digest, err := computeFileDigest(cachePath); err == nil && digest == lockedDigest {
			return &ProfileSyncResult{
				Source:   source,
				Kind:     kind,
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
			fmt.Sprintf("remote %s %q not cached", kind, source),
			"Run 'epack sync' to fetch profiles", nil)
	}

	// TODO: Implement remote profile fetching
	// For now, return an error indicating this isn't implemented yet
	return nil, errors.WithHint(errors.NotImplemented, exitcode.NotImplemented,
		fmt.Sprintf("remote %s sources not yet supported: %s", kind, source),
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

// LockProfiles updates the lockfile with profile digests.
// This is called by 'epack lock' to pin profile versions.
func LockProfiles(cfg *config.JobConfig, lf *lockfile.LockFile, workDir string) ([]ProfileLockResult, error) {
	var results []ProfileLockResult

	for _, profile := range cfg.Profiles {
		if profile.Path != "" {
			result, err := lockLocalProfile(profile.Key(), profile.FilePath(), lf, workDir)
			if err != nil {
				return nil, err
			}
			results = append(results, *result)
		}
		// TODO: Handle remote sources when implemented
	}

	for _, overlay := range cfg.Overlays {
		if overlay.Path != "" {
			result, err := lockLocalOverlay(overlay.Key(), overlay.FilePath(), lf, workDir)
			if err != nil {
				return nil, err
			}
			results = append(results, *result)
		}
		// TODO: Handle remote sources when implemented
	}

	return results, nil
}

func lockLocalProfile(key, filePath string, lf *lockfile.LockFile, workDir string) (*ProfileLockResult, error) {
	// Resolve the path to use for file I/O
	// If filePath is absolute (from ResolvedPath), use it after validation
	// Otherwise, use key relative to workDir
	resolvedPath, err := resolveProfilePath(workDir, key, filePath)
	if err != nil {
		return nil, fmt.Errorf("computing digest for profile %s: %w", key, err)
	}
	digest, err := computeFileDigest(resolvedPath)
	if err != nil {
		return nil, fmt.Errorf("computing digest for profile %s: %w", key, err)
	}

	// Check if this is new or updated
	existing, exists := lf.Profiles[key]
	isNew := !exists
	updated := exists && existing.Digest != digest

	lf.Profiles[key] = lockfile.LockedProfile{
		Source:   key,
		Digest:   digest,
		LockedAt: time.Now().UTC().Format(time.RFC3339),
	}

	return &ProfileLockResult{
		Source:  key,
		Kind:    "profile",
		Digest:  digest,
		IsNew:   isNew,
		Updated: updated,
	}, nil
}

func lockLocalOverlay(key, filePath string, lf *lockfile.LockFile, workDir string) (*ProfileLockResult, error) {
	// Resolve the path to use for file I/O
	// If filePath is absolute (from ResolvedPath), use it after validation
	// Otherwise, use key relative to workDir
	resolvedPath, err := resolveProfilePath(workDir, key, filePath)
	if err != nil {
		return nil, fmt.Errorf("computing digest for overlay %s: %w", key, err)
	}
	digest, err := computeFileDigest(resolvedPath)
	if err != nil {
		return nil, fmt.Errorf("computing digest for overlay %s: %w", key, err)
	}

	// Check if this is new or updated
	existing, exists := lf.Overlays[key]
	isNew := !exists
	updated := exists && existing.Digest != digest

	lf.Overlays[key] = lockfile.LockedOverlay{
		Source:   key,
		Digest:   digest,
		LockedAt: time.Now().UTC().Format(time.RFC3339),
	}

	return &ProfileLockResult{
		Source:  key,
		Kind:    "overlay",
		Digest:  digest,
		IsNew:   isNew,
		Updated: updated,
	}, nil
}

// ValidateProfileAlignment checks that config profiles match lockfile entries.
func ValidateProfileAlignment(cfg *config.JobConfig, lf *lockfile.LockFile, skipStaleCheck bool) error {
	// Validate profiles in config exist in lockfile
	for i, profile := range cfg.Profiles {
		key := profile.Key()
		if _, ok := lf.Profiles[key]; !ok {
			return errors.WithHint(errors.LockfileInvalid, exitcode.LockInvalid,
				fmt.Sprintf("profile[%d] %q not in lockfile", i, key),
				"Run 'epack lock' to add the profile", nil)
		}
	}

	// Validate overlays in config exist in lockfile
	for i, overlay := range cfg.Overlays {
		key := overlay.Key()
		if _, ok := lf.Overlays[key]; !ok {
			return errors.WithHint(errors.LockfileInvalid, exitcode.LockInvalid,
				fmt.Sprintf("overlay[%d] %q not in lockfile", i, key),
				"Run 'epack lock' to add the overlay", nil)
		}
	}

	// Skip reverse check (lockfile -> config) if requested
	if skipStaleCheck {
		return nil
	}

	// Check for stale lockfile entries
	profileKeys := make(map[string]bool)
	for _, p := range cfg.Profiles {
		profileKeys[p.Key()] = true
	}
	for key := range lf.Profiles {
		if !profileKeys[key] {
			return errors.WithHint(errors.LockfileInvalid, exitcode.LockInvalid,
				fmt.Sprintf("lockfile has profile %q not in config", key),
				"Remove stale entries or add profile to config", nil)
		}
	}

	overlayKeys := make(map[string]bool)
	for _, o := range cfg.Overlays {
		overlayKeys[o.Key()] = true
	}
	for key := range lf.Overlays {
		if !overlayKeys[key] {
			return errors.WithHint(errors.LockfileInvalid, exitcode.LockInvalid,
				fmt.Sprintf("lockfile has overlay %q not in config", key),
				"Remove stale entries or add overlay to config", nil)
		}
	}

	return nil
}

// HasProfileLockfileGap checks if any profile or overlay in the config is missing from the lockfile.
// Returns true if any entry is missing, false if all are present.
func HasProfileLockfileGap(cfg *config.JobConfig, lf *lockfile.LockFile) bool {
	for _, p := range cfg.Profiles {
		if _, ok := lf.Profiles[p.Key()]; !ok {
			return true
		}
	}
	for _, o := range cfg.Overlays {
		if _, ok := lf.Overlays[o.Key()]; !ok {
			return true
		}
	}
	return false
}

// HasProfileDigestDrift checks if any local profile or overlay has content that differs from the lockfile.
// This detects the case where a file was modified after locking but before collection.
// Returns true if any digest has drifted, false if all match or on any error.
// Errors are silently ignored to allow the workflow to proceed (the actual sync will catch issues).
func HasProfileDigestDrift(cfg *config.JobConfig, lf *lockfile.LockFile, workDir string) bool {
	// Check profiles
	for _, profile := range cfg.Profiles {
		if profile.Path == "" {
			continue // Skip remote profiles
		}
		key := profile.Key()
		lockedDigest, ok := lf.GetProfileDigest(key)
		if !ok {
			continue // Entry missing - handled elsewhere
		}
		// Resolve the path and compute current digest
		resolvedPath, err := resolveProfilePath(workDir, key, profile.FilePath())
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

	// Check overlays
	for _, overlay := range cfg.Overlays {
		if overlay.Path == "" {
			continue // Skip remote overlays
		}
		key := overlay.Key()
		lockedDigest, ok := lf.GetOverlayDigest(key)
		if !ok {
			continue // Entry missing - handled elsewhere
		}
		// Resolve the path and compute current digest
		resolvedPath, err := resolveProfilePath(workDir, key, overlay.FilePath())
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
