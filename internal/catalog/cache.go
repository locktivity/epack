package catalog

import (
	"encoding/json"
	stderrors "errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/locktivity/epack/errors"
	"github.com/locktivity/epack/internal/limits"
	"github.com/locktivity/epack/internal/platformpath"
	"github.com/locktivity/epack/internal/safefile"
)

const (
	// CatalogFileName is the name of the cached catalog file.
	CatalogFileName = "catalog.json"

	// MetaFileName is the name of the catalog metadata file.
	MetaFileName = "catalog.json.meta"

	// CacheDirName is the epack cache directory name.
	CacheDirName = "epack"
)

// ErrNoCatalog is returned when no cached catalog exists.
var ErrNoCatalog = errors.E(errors.CatalogNotFound, "no cached catalog found; run 'epack tool catalog refresh'", nil)

// ErrNoMeta is returned when no catalog metadata exists.
var ErrNoMeta = errors.E(errors.CatalogMetaNotFound, "no catalog metadata found", nil)

// Dir returns the epack cache directory path.
// Uses XDG_CACHE_HOME on Unix, or platform-appropriate defaults.
//
// Precedence:
//  1. $XDG_CACHE_HOME/epack (if XDG_CACHE_HOME set)
//  2. ~/.cache/epack (Unix)
//  3. %LOCALAPPDATA%\epack\cache (Windows)
func Dir() (string, error) {
	// Check XDG_CACHE_HOME first (works on all platforms)
	if xdgCache := os.Getenv("XDG_CACHE_HOME"); xdgCache != "" {
		return filepath.Join(xdgCache, CacheDirName), nil
	}

	// Platform-specific defaults
	if runtime.GOOS == "windows" {
		// Windows: use %LOCALAPPDATA%\epack\cache
		localAppData := os.Getenv("LOCALAPPDATA")
		// SECURITY: Validate LOCALAPPDATA is a safe local path.
		// Reject UNC paths (\\server\share) which could cause file operations on remote shares.
		// An attacker controlling LOCALAPPDATA could redirect reads/writes to a malicious server.
		if localAppData == "" || !isLocalWindowsPath(localAppData) {
			return "", fmt.Errorf("LOCALAPPDATA not set or invalid (UNC paths not allowed)")
		}
		return filepath.Join(localAppData, CacheDirName, "cache"), nil
	}

	// Unix: ~/.cache/epack
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("getting home directory: %w", err)
	}
	return filepath.Join(home, ".cache", CacheDirName), nil
}

// isLocalWindowsPath checks if a path is a local Windows path (not UNC or otherwise unsafe).
// Returns true for paths like "C:\Users\..." and false for UNC paths like "\\server\share".
func isLocalWindowsPath(path string) bool {
	return platformpath.IsLocalWindowsPath(path)
}

// CatalogPath returns the full path to the cached catalog file.
func CatalogPath() (string, error) {
	cacheDir, err := Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(cacheDir, CatalogFileName), nil
}

// MetaPath returns the full path to the catalog metadata file.
func MetaPath() (string, error) {
	cacheDir, err := Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(cacheDir, MetaFileName), nil
}

// ReadCatalog reads the cached catalog, enforcing size limits.
// Returns ErrNoCatalog if no cached catalog exists.
//
// SECURITY: Uses safefile.ReadFile to refuse symlinks, preventing
// an attacker from swapping the cache file with a symlink to read arbitrary files
// or cause the application to process attacker-controlled data.
func ReadCatalog() (*Catalog, []string, error) {
	path, err := CatalogPath()
	if err != nil {
		return nil, nil, err
	}

	// SECURITY: Use safefile to refuse symlinks when reading
	data, err := safefile.ReadFile(path, limits.Catalog)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil, ErrNoCatalog
		}
		return nil, nil, fmt.Errorf("reading catalog: %w", err)
	}

	catalog, err := ParseCatalog(data)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing catalog: %w", err)
	}

	// Validate and sanitize
	warnings := catalog.Validate()

	// Check component count limit
	if len(catalog.Tools) > limits.MaxCatalogComponentCount {
		return nil, nil, fmt.Errorf("catalog has %d components, exceeds limit of %d",
			len(catalog.Tools), limits.MaxCatalogComponentCount)
	}

	return catalog, warnings, nil
}

// WriteCatalog writes the catalog to the cache directory.
// Creates the cache directory if it doesn't exist.
//
// SECURITY: Uses safefile.OpenForWrite to prevent symlink attacks.
// O_NOFOLLOW atomically refuses to follow symlinks at file creation time,
// preventing attackers from swapping files with symlinks.
//
// Note: We don't validate the entire cache path for symlinks because
// system symlinks (e.g., /var -> /private/var on macOS) are legitimate.
func WriteCatalog(catalog *Catalog) error {
	path, err := CatalogPath()
	if err != nil {
		return err
	}

	// Ensure cache directory exists
	cacheDir := filepath.Dir(path)
	if err := os.MkdirAll(cacheDir, 0700); err != nil {
		return fmt.Errorf("creating cache directory: %w", err)
	}

	data, err := json.MarshalIndent(catalog, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling catalog: %w", err)
	}

	// Check size before writing
	if int64(len(data)) > limits.Catalog.Bytes() {
		return fmt.Errorf("catalog too large to write: %d bytes exceeds %d limit",
			len(data), limits.Catalog.Bytes())
	}

	// Write atomically: write to temp file, then rename
	// This prevents partial writes from corrupting the cache
	// SECURITY: Use OpenForWrite to refuse symlinks (prevents symlink attacks)
	tmpPath := path + ".tmp"
	f, err := safefile.OpenForWrite(tmpPath)
	if err != nil {
		return fmt.Errorf("creating temp catalog: %w", err)
	}

	_, writeErr := f.Write(data)
	syncErr := f.Sync()
	closeErr := f.Close()

	if writeErr != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("writing temp catalog: %w", writeErr)
	}
	if syncErr != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("syncing temp catalog: %w", syncErr)
	}
	if closeErr != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("closing temp catalog: %w", closeErr)
	}

	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath) // Clean up on failure
		return fmt.Errorf("renaming catalog: %w", err)
	}

	return nil
}

// ReadMeta reads the catalog metadata file.
// Returns ErrNoMeta if no metadata exists.
//
// SECURITY: Uses safefile.ReadFile to refuse symlinks.
func ReadMeta() (*CatalogMeta, error) {
	path, err := MetaPath()
	if err != nil {
		return nil, err
	}

	// SECURITY: Use safefile to refuse symlinks when reading
	data, err := safefile.ReadFile(path, limits.CatalogMeta)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNoMeta
		}
		return nil, fmt.Errorf("reading meta: %w", err)
	}

	meta, err := ParseMeta(data)
	if err != nil {
		return nil, fmt.Errorf("parsing meta: %w", err)
	}

	return meta, nil
}

// WriteMeta writes the catalog metadata file.
// Creates the cache directory if it doesn't exist.
//
// SECURITY: Uses safefile.OpenForWrite to prevent symlink attacks.
// O_NOFOLLOW atomically refuses to follow symlinks at file creation time,
// preventing attackers from swapping files with symlinks.
func WriteMeta(meta *CatalogMeta) error {
	path, err := MetaPath()
	if err != nil {
		return err
	}

	// Ensure cache directory exists
	cacheDir := filepath.Dir(path)
	if err := os.MkdirAll(cacheDir, 0700); err != nil {
		return fmt.Errorf("creating cache directory: %w", err)
	}

	data, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling meta: %w", err)
	}

	// Check size before writing
	if int64(len(data)) > limits.CatalogMeta.Bytes() {
		return fmt.Errorf("meta too large to write: %d bytes exceeds %d limit",
			len(data), limits.CatalogMeta.Bytes())
	}

	// Write atomically
	// SECURITY: Use OpenForWrite to refuse symlinks (prevents symlink attacks)
	tmpPath := path + ".tmp"
	f, err := safefile.OpenForWrite(tmpPath)
	if err != nil {
		return fmt.Errorf("creating temp meta: %w", err)
	}

	_, writeErr := f.Write(data)
	syncErr := f.Sync()
	closeErr := f.Close()

	if writeErr != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("writing temp meta: %w", writeErr)
	}
	if syncErr != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("syncing temp meta: %w", syncErr)
	}
	if closeErr != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("closing temp meta: %w", closeErr)
	}

	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("renaming meta: %w", err)
	}

	return nil
}

// ClearCache removes the cached catalog and metadata.
func ClearCache() error {
	catalogPath, err := CatalogPath()
	if err != nil {
		return err
	}
	metaPath, err := MetaPath()
	if err != nil {
		return err
	}

	var errs []error
	if err := os.Remove(catalogPath); err != nil && !os.IsNotExist(err) {
		errs = append(errs, fmt.Errorf("removing catalog: %w", err))
	}
	if err := os.Remove(metaPath); err != nil && !os.IsNotExist(err) {
		errs = append(errs, fmt.Errorf("removing meta: %w", err))
	}

	if len(errs) > 0 {
		return stderrors.Join(errs...)
	}
	return nil
}

// Exists returns true if a cached catalog exists.
func Exists() bool {
	path, err := CatalogPath()
	if err != nil {
		return false
	}
	_, err = os.Stat(path)
	return err == nil
}

