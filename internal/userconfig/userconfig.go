// Package userconfig manages user-level epack configuration and utilities.
// User configuration is stored in ~/.epack/ and is separate from project-level
// configuration (epack.yaml/epack.lock.yaml).
//
// Directory structure:
//
//	~/.epack/
//	  utilities.lock       # Pinned utility versions and digests
//	  bin/                 # Installed utility binaries
//	    {name}/
//	      {version}/
//	        {os}-{arch}/
//	          epack-util-{name}
package userconfig

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"

	"github.com/locktivity/epack/internal/component/config"
	"github.com/locktivity/epack/internal/componenttypes"
	"github.com/locktivity/epack/internal/limits"
	"github.com/locktivity/epack/internal/safefile"
	"github.com/locktivity/epack/internal/safeyaml"
	"github.com/locktivity/epack/internal/timestamp"
	"github.com/locktivity/epack/internal/yamlutil"
)

// DirName is the user config directory name.
const DirName = ".epack"

// ConfigFile is the filename for user configuration.
const ConfigFile = "config.yaml"

// UtilitiesLockFile is the filename for the utilities lockfile.
const UtilitiesLockFile = "utilities.lock"

// BinDir is the subdirectory for installed utility binaries.
const BinDir = "bin"

// Dir returns the user config directory path (~/.epack).
func Dir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("getting user home directory: %w", err)
	}
	return filepath.Join(home, DirName), nil
}

// UtilitiesLockPath returns the path to the utilities lockfile.
func UtilitiesLockPath() (string, error) {
	dir, err := Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, UtilitiesLockFile), nil
}

// BinPath returns the path to the utilities bin directory.
func BinPath() (string, error) {
	dir, err := Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, BinDir), nil
}

// UtilityInstallPath returns the full path where a utility binary will be installed.
// Format: ~/.epack/bin/{name}/{version}/{os}-{arch}/epack-util-{name}
func UtilityInstallPath(name, version string) (string, error) {
	binDir, err := BinPath()
	if err != nil {
		return "", err
	}

	platform := fmt.Sprintf("%s-%s", runtime.GOOS, runtime.GOARCH)
	binaryName := fmt.Sprintf("epack-util-%s", name)

	return filepath.Join(binDir, name, version, platform, binaryName), nil
}

// UtilityBinaryPath returns the path to an installed utility for the current platform.
// Returns the path if the utility is installed, or an error if not found.
func UtilityBinaryPath(name string) (string, error) {
	lf, err := LoadUtilitiesLock()
	if err != nil {
		return "", fmt.Errorf("loading utilities lock: %w", err)
	}

	utility, ok := lf.Utilities[name]
	if !ok {
		return "", fmt.Errorf("utility %q not installed", name)
	}

	path, err := UtilityInstallPath(name, utility.Version)
	if err != nil {
		return "", err
	}

	if _, err := os.Stat(path); err != nil {
		return "", fmt.Errorf("utility %q binary not found at %s", name, path)
	}

	return path, nil
}

// EnsureDir creates the user config directory if it doesn't exist.
func EnsureDir() error {
	dir, err := Dir()
	if err != nil {
		return err
	}

	return os.MkdirAll(dir, 0755)
}

// EnsureBinDir creates the bin directory if it doesn't exist.
func EnsureBinDir() error {
	binDir, err := BinPath()
	if err != nil {
		return err
	}

	return os.MkdirAll(binDir, 0755)
}

// UtilitiesLock is the lockfile format for user-installed utilities.
// It mirrors the structure of the project lockfile but only contains utilities.
type UtilitiesLock struct {
	SchemaVersion int                                     `yaml:"schema_version"`
	Utilities     map[string]componenttypes.LockedUtility `yaml:"utilities,omitempty"`
}

// NewUtilitiesLock creates an empty utilities lockfile.
func NewUtilitiesLock() *UtilitiesLock {
	return &UtilitiesLock{
		SchemaVersion: 1,
		Utilities:     make(map[string]componenttypes.LockedUtility),
	}
}

// LoadUtilitiesLock loads the utilities lockfile from the user config directory.
// Returns an empty lockfile if the file doesn't exist.
func LoadUtilitiesLock() (*UtilitiesLock, error) {
	path, err := UtilitiesLockPath()
	if err != nil {
		return nil, err
	}

	if _, err := os.Stat(path); os.IsNotExist(err) {
		return NewUtilitiesLock(), nil
	}

	return LoadUtilitiesLockFromPath(path)
}

// LoadUtilitiesLockFromPath loads a utilities lockfile from a specific path.
func LoadUtilitiesLockFromPath(path string) (*UtilitiesLock, error) {
	data, err := safefile.ReadFile(path, limits.LockFile)
	if err != nil {
		return nil, fmt.Errorf("reading utilities lock: %w", err)
	}

	return ParseUtilitiesLock(data)
}

// ParseUtilitiesLock parses utilities lockfile data.
func ParseUtilitiesLock(data []byte) (*UtilitiesLock, error) {
	var lf UtilitiesLock
	if err := safeyaml.Unmarshal(data, limits.LockFile, &lf); err != nil {
		return nil, fmt.Errorf("parsing utilities lock: %w", err)
	}

	if lf.Utilities == nil {
		lf.Utilities = make(map[string]componenttypes.LockedUtility)
	}
	if lf.SchemaVersion == 0 {
		lf.SchemaVersion = 1
	}

	// SECURITY: Enforce count limits to prevent DoS
	if len(lf.Utilities) > limits.MaxUtilityCount {
		return nil, fmt.Errorf("utilities lockfile count %d exceeds limit of %d",
			len(lf.Utilities), limits.MaxUtilityCount)
	}

	// Validate all utility entries to prevent path traversal attacks
	if err := lf.validateUtilitiesForParse(); err != nil {
		return nil, err
	}

	return &lf, nil
}

// validateUtilitiesForParse validates all utilities during lockfile parsing.
// This includes name validation, platform count limits, version validation, and timestamp validation.
// Iterates in sorted order for deterministic error messages.
func (lf *UtilitiesLock) validateUtilitiesForParse() error {
	// Sort keys for deterministic error messages
	names := make([]string, 0, len(lf.Utilities))
	for name := range lf.Utilities {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		u := lf.Utilities[name]

		// Validate utility name to prevent path traversal
		if err := config.ValidateUtilityName(name); err != nil {
			return fmt.Errorf("utilities lockfile contains invalid name %q: %w", name, err)
		}

		// SECURITY: Enforce platform count limit
		if len(u.Platforms) > limits.MaxPlatformCount {
			return fmt.Errorf("utility %q has %d platforms, exceeds limit of %d",
				name, len(u.Platforms), limits.MaxPlatformCount)
		}

		// Validate version to prevent path traversal
		if u.Version != "" {
			if err := config.ValidateVersion(u.Version); err != nil {
				return fmt.Errorf("utility %q has invalid version: %w", name, err)
			}
		}

		// Validate timestamp formats if present
		if u.LockedAt != "" {
			if err := timestamp.Validate(u.LockedAt); err != nil {
				return fmt.Errorf("utility %q has invalid locked_at timestamp: %w", name, err)
			}
		}
		if u.Verification != nil && u.Verification.VerifiedAt != "" {
			if err := timestamp.Validate(u.Verification.VerifiedAt); err != nil {
				return fmt.Errorf("utility %q has invalid verified_at timestamp: %w", name, err)
			}
		}
	}
	return nil
}

// Save writes the utilities lockfile to the user config directory.
func (lf *UtilitiesLock) Save() error {
	path, err := UtilitiesLockPath()
	if err != nil {
		return err
	}

	return lf.SaveToPath(path)
}

// SaveToPath writes the utilities lockfile to a specific path.
// SECURITY: Uses symlink-safe operations and atomic write via temp file + rename.
func (lf *UtilitiesLock) SaveToPath(path string) error {
	// Validate utilities before saving
	if err := lf.validateUtilitiesForSave(); err != nil {
		return err
	}

	dir := filepath.Dir(path)

	// Get home directory as security root for symlink validation
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("getting home directory: %w", err)
	}

	// SECURITY: Validate no symlinks in parent path ancestry.
	// This prevents symlink-based attacks where the lockfile parent directory
	// is a symlink pointing elsewhere.
	hasSymlink, err := safefile.ContainsSymlink(dir)
	if err != nil {
		return fmt.Errorf("checking for symlinks: %w", err)
	}
	if hasSymlink {
		return fmt.Errorf("refusing to save utilities lock: path contains symlink: %s", dir)
	}
	_ = home // home was used for ValidateNoSymlinks root, but ContainsSymlink checks the whole path

	// Create directory safely
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("creating utilities lock dir: %w", err)
	}

	// SECURITY: Check if target is a symlink (refuse to follow)
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing to overwrite symlink at %s", path)
		}
	}

	data, err := lf.marshalDeterministic()
	if err != nil {
		return fmt.Errorf("marshaling utilities lock: %w", err)
	}

	// Atomic write: write to temp file, then rename
	tmpFile, err := os.CreateTemp(dir, ".utilities.lock.*.tmp")
	if err != nil {
		return fmt.Errorf("creating temp utilities lock: %w", err)
	}
	tmpPath := tmpFile.Name()

	// Ensure cleanup on failure
	success := false
	defer func() {
		if !success {
			_ = os.Remove(tmpPath)
		}
	}()

	// TOCTOU mitigation: Re-validate after temp file creation.
	// This closes the race window between initial validation and temp file creation.
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			_ = tmpFile.Close()
			return fmt.Errorf("refusing to overwrite symlink at %s (race detected)", path)
		}
	}

	if _, err := tmpFile.Write(data); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("writing temp utilities lock: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("closing temp utilities lock: %w", err)
	}

	// Set permissions before rename
	if err := os.Chmod(tmpPath, 0644); err != nil {
		return fmt.Errorf("setting utilities lock permissions: %w", err)
	}

	// Atomic rename
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("renaming temp utilities lock: %w", err)
	}

	success = true
	return nil
}

// validateUtilitiesForSave validates all utilities before saving the lockfile.
func (lf *UtilitiesLock) validateUtilitiesForSave() error {
	for name, u := range lf.Utilities {
		if err := config.ValidateUtilityName(name); err != nil {
			return fmt.Errorf("cannot save utilities lock with invalid name %q: %w", name, err)
		}
		// Validate version to prevent path traversal
		if u.Version != "" {
			if err := config.ValidateVersion(u.Version); err != nil {
				return fmt.Errorf("cannot save utilities lock with invalid version for %q: %w", name, err)
			}
		}
	}
	return nil
}

// marshalDeterministic serializes the lockfile with deterministic map ordering.
func (lf *UtilitiesLock) marshalDeterministic() ([]byte, error) {
	return yamlutil.MarshalDeterministic(lf)
}

// GetUtility returns a utility entry by name.
// Returns a defensive copy to prevent callers from mutating internal state.
func (lf *UtilitiesLock) GetUtility(name string) (componenttypes.LockedUtility, bool) {
	u, ok := lf.Utilities[name]
	if !ok {
		return componenttypes.LockedUtility{}, false
	}
	// Return defensive copy
	return componenttypes.LockedUtility{
		Source:       u.Source,
		Version:      u.Version,
		Signer:       copySigner(u.Signer),
		ResolvedFrom: copyResolvedFrom(u.ResolvedFrom),
		Verification: copyVerification(u.Verification),
		LockedAt:     u.LockedAt,
		Platforms:    copyPlatforms(u.Platforms),
	}, true
}

// SetUtility sets a utility entry.
func (lf *UtilitiesLock) SetUtility(name string, utility componenttypes.LockedUtility) {
	lf.Utilities[name] = utility
}

// RemoveUtility removes a utility entry.
func (lf *UtilitiesLock) RemoveUtility(name string) {
	delete(lf.Utilities, name)
}

// ListUtilities returns a sorted list of installed utility names.
func (lf *UtilitiesLock) ListUtilities() []string {
	names := make([]string, 0, len(lf.Utilities))
	for name := range lf.Utilities {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// UtilityDigest returns the expected digest for a utility on the current platform.
// The digest is used for TOCTOU-safe binary verification during dispatch.
func (lf *UtilitiesLock) UtilityDigest(name string) (string, error) {
	utility, ok := lf.Utilities[name]
	if !ok {
		return "", fmt.Errorf("utility %q not installed", name)
	}

	platform := fmt.Sprintf("%s-%s", runtime.GOOS, runtime.GOARCH)
	plat, ok := utility.Platforms[platform]
	if !ok {
		return "", fmt.Errorf("utility %q not available for platform %s", name, platform)
	}

	if plat.Digest == "" {
		return "", fmt.Errorf("utility %q has no digest for platform %s", name, platform)
	}

	return plat.Digest, nil
}

// copyPlatforms creates a defensive copy of a platforms map.
func copyPlatforms(src map[string]componenttypes.LockedPlatform) map[string]componenttypes.LockedPlatform {
	if src == nil {
		return nil
	}
	dst := make(map[string]componenttypes.LockedPlatform, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

// copySigner creates a defensive copy of a LockedSigner pointer.
func copySigner(src *componenttypes.LockedSigner) *componenttypes.LockedSigner {
	if src == nil {
		return nil
	}
	cp := *src
	return &cp
}

// copyResolvedFrom creates a defensive copy of a ResolvedFrom pointer.
func copyResolvedFrom(src *componenttypes.ResolvedFrom) *componenttypes.ResolvedFrom {
	if src == nil {
		return nil
	}
	cp := *src
	return &cp
}

// copyVerification creates a defensive copy of a Verification pointer.
func copyVerification(src *componenttypes.Verification) *componenttypes.Verification {
	if src == nil {
		return nil
	}
	cp := *src
	return &cp
}

// Config represents user configuration from ~/.epack/config.yaml
type Config struct {
	Component ComponentConfig `yaml:"component,omitempty"`
}

// ComponentConfig holds component authoring settings.
type ComponentConfig struct {
	// TrustLocal skips confirmation prompts when running local binaries
	// with 'epack component run'.
	TrustLocal bool `yaml:"trust_local,omitempty"`
}

// ConfigPath returns the path to the user config file.
func ConfigPath() (string, error) {
	dir, err := Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, ConfigFile), nil
}

// LoadConfig loads the user configuration from ~/.epack/config.yaml.
// Returns an empty config if the file doesn't exist.
func LoadConfig() (*Config, error) {
	path, err := ConfigPath()
	if err != nil {
		return nil, err
	}

	if _, err := os.Stat(path); os.IsNotExist(err) {
		return &Config{}, nil
	}

	data, err := safefile.ReadFile(path, limits.ConfigFile)
	if err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}

	var cfg Config
	if err := safeyaml.Unmarshal(data, limits.ConfigFile, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	return &cfg, nil
}

// SaveConfig saves the user configuration to ~/.epack/config.yaml.
func SaveConfig(cfg *Config) error {
	path, err := ConfigPath()
	if err != nil {
		return err
	}

	if err := EnsureDir(); err != nil {
		return fmt.Errorf("creating config directory: %w", err)
	}

	data, err := yamlutil.MarshalDeterministic(cfg)
	if err != nil {
		return fmt.Errorf("marshaling config: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("writing config: %w", err)
	}

	return nil
}

// SetConfigValue sets a configuration value by dot-separated key path.
// Currently supported: component.trust_local
func SetConfigValue(key string, value string) error {
	cfg, err := LoadConfig()
	if err != nil {
		return err
	}

	switch key {
	case "component.trust_local":
		cfg.Component.TrustLocal = value == "true" || value == "1"
	default:
		return fmt.Errorf("unknown config key: %s", key)
	}

	return SaveConfig(cfg)
}

// GetConfigValue gets a configuration value by dot-separated key path.
func GetConfigValue(key string) (string, error) {
	cfg, err := LoadConfig()
	if err != nil {
		return "", err
	}

	switch key {
	case "component.trust_local":
		if cfg.Component.TrustLocal {
			return "true", nil
		}
		return "false", nil
	default:
		return "", fmt.Errorf("unknown config key: %s", key)
	}
}
