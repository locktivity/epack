package lockfile

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/locktivity/epack/internal/component/config"
	"github.com/locktivity/epack/internal/componenttypes"
	"github.com/locktivity/epack/internal/limits"
	"github.com/locktivity/epack/internal/safefile"
	"github.com/locktivity/epack/internal/safeyaml"
	"github.com/locktivity/epack/internal/timestamp"
	"github.com/locktivity/epack/internal/yamlutil"
)

// FileName is the canonical lockfile filename for pinned collectors and tools.
const FileName = "epack.lock.yaml"

// LockFile is the v1 collector, tool, and remote adapter lockfile.
type LockFile struct {
	SchemaVersion int                        `yaml:"schema_version"`
	Collectors    map[string]LockedCollector `yaml:"collectors,omitempty"`
	Tools         map[string]LockedTool      `yaml:"tools,omitempty"`
	Remotes       map[string]LockedRemote    `yaml:"remotes,omitempty"`
}

// LockedCollector pins either a source-based or external collector entry.
type LockedCollector struct {
	Kind         string                                      `yaml:"kind,omitempty"` // "external" or empty for source-based
	Source       string                                      `yaml:"source,omitempty"`
	Version      string                                      `yaml:"version,omitempty"`
	Signer       *componenttypes.LockedSigner                `yaml:"signer,omitempty"`
	ResolvedFrom *componenttypes.ResolvedFrom                `yaml:"resolved_from,omitempty"`
	Verification *componenttypes.Verification                `yaml:"verification,omitempty"`
	LockedAt     string                                      `yaml:"locked_at,omitempty"`
	Platforms    map[string]componenttypes.LockedPlatform    `yaml:"platforms"`
}

// LockedTool pins either a source-based or external tool entry.
// Tools share the same structure as collectors since they use
// the same supply chain security model (Sigstore + digest verification).
type LockedTool struct {
	Kind         string                                      `yaml:"kind,omitempty"` // "external" or empty for source-based
	Source       string                                      `yaml:"source,omitempty"`
	Version      string                                      `yaml:"version,omitempty"`
	Signer       *componenttypes.LockedSigner                `yaml:"signer,omitempty"`
	ResolvedFrom *componenttypes.ResolvedFrom                `yaml:"resolved_from,omitempty"`
	Verification *componenttypes.Verification                `yaml:"verification,omitempty"`
	LockedAt     string                                      `yaml:"locked_at,omitempty"`
	Platforms    map[string]componenttypes.LockedPlatform    `yaml:"platforms"`
}

// LockedRemote pins either a source-based or external remote adapter entry.
// Remote adapters use the same supply chain security model as collectors and tools.
type LockedRemote struct {
	Kind         string                                      `yaml:"kind,omitempty"` // "external" or empty for source-based
	Source       string                                      `yaml:"source,omitempty"`
	Version      string                                      `yaml:"version,omitempty"`
	Signer       *componenttypes.LockedSigner                `yaml:"signer,omitempty"`
	ResolvedFrom *componenttypes.ResolvedFrom                `yaml:"resolved_from,omitempty"`
	Verification *componenttypes.Verification                `yaml:"verification,omitempty"`
	LockedAt     string                                      `yaml:"locked_at,omitempty"`
	Platforms    map[string]componenttypes.LockedPlatform    `yaml:"platforms"`
}

// New returns an empty lockfile model.
func New() *LockFile {
	return &LockFile{
		SchemaVersion: 1,
		Collectors:    make(map[string]LockedCollector),
		Tools:         make(map[string]LockedTool),
		Remotes:       make(map[string]LockedRemote),
	}
}

// Load reads lockfile from path.
// Enforces size and structural limits to prevent DoS attacks.
// SECURITY: Uses O_NOFOLLOW to refuse symlinks, preventing symlink-based attacks
// where an attacker could redirect lockfile reads to arbitrary files.
func Load(path string) (*LockFile, error) {
	// SECURITY: ReadFile uses O_NOFOLLOW to refuse symlinks atomically
	// and checks file size before reading to prevent DoS via large files.
	data, err := safefile.ReadFile(path, limits.LockFile)
	if err != nil {
		return nil, err
	}

	return Parse(data)
}

// Parse parses and validates a lockfile from raw YAML data.
// Enforces size and structural limits to prevent DoS attacks.
func Parse(data []byte) (*LockFile, error) {
	// SECURITY: Use safeyaml which validates size and alias bombs BEFORE parsing.
	var lf LockFile
	if err := safeyaml.Unmarshal(data, limits.LockFile, &lf); err != nil {
		return nil, fmt.Errorf("lockfile validation: %w", err)
	}
	if lf.Collectors == nil {
		lf.Collectors = make(map[string]LockedCollector)
	}
	if lf.Tools == nil {
		lf.Tools = make(map[string]LockedTool)
	}
	if lf.Remotes == nil {
		lf.Remotes = make(map[string]LockedRemote)
	}
	if lf.SchemaVersion == 0 {
		lf.SchemaVersion = 1
	}

	// SECURITY: Enforce count limits to prevent DoS
	if len(lf.Collectors) > limits.MaxCollectorCount {
		return nil, fmt.Errorf("lockfile collector count %d exceeds limit of %d",
			len(lf.Collectors), limits.MaxCollectorCount)
	}
	if len(lf.Tools) > limits.MaxToolCount {
		return nil, fmt.Errorf("lockfile tool count %d exceeds limit of %d",
			len(lf.Tools), limits.MaxToolCount)
	}
	if len(lf.Remotes) > limits.MaxRemoteCount {
		return nil, fmt.Errorf("lockfile remote count %d exceeds limit of %d",
			len(lf.Remotes), limits.MaxRemoteCount)
	}

	// Validate all component names and versions to prevent path traversal via malicious lockfile
	if err := lf.validateComponentsForParse(); err != nil {
		return nil, err
	}

	return &lf, nil
}

// componentEntry captures the common fields needed for validation.
type componentEntry struct {
	kind         string
	version      string
	lockedAt     string
	verification *componenttypes.Verification
	platforms    map[string]componenttypes.LockedPlatform
}

// validateComponentsForParse validates all components during lockfile parsing.
// This includes name validation, platform count limits, version validation, and timestamp validation.
func (lf *LockFile) validateComponentsForParse() error {
	// Validate collectors
	for name, c := range lf.Collectors {
		if err := validateComponentForParse("collector", name, componentEntry{
			kind:         c.Kind,
			version:      c.Version,
			lockedAt:     c.LockedAt,
			verification: c.Verification,
			platforms:    c.Platforms,
		}, config.ValidateCollectorName); err != nil {
			return err
		}
	}

	// Validate tools
	for name, t := range lf.Tools {
		if err := validateComponentForParse("tool", name, componentEntry{
			kind:         t.Kind,
			version:      t.Version,
			lockedAt:     t.LockedAt,
			verification: t.Verification,
			platforms:    t.Platforms,
		}, config.ValidateToolName); err != nil {
			return err
		}
	}

	// Validate remotes
	for name, r := range lf.Remotes {
		if err := validateComponentForParse("remote", name, componentEntry{
			kind:         r.Kind,
			version:      r.Version,
			lockedAt:     r.LockedAt,
			verification: r.Verification,
			platforms:    r.Platforms,
		}, config.ValidateRemoteName); err != nil {
			return err
		}
	}

	return nil
}

// validateComponentForParse validates a single component entry during parsing.
func validateComponentForParse(kindLabel, name string, entry componentEntry, validateName func(string) error) error {
	// Validate name
	if err := validateName(name); err != nil {
		return fmt.Errorf("lockfile contains invalid %s name %q: %w", kindLabel, name, err)
	}

	// SECURITY: Enforce platform count limit
	if len(entry.platforms) > limits.MaxPlatformCount {
		return fmt.Errorf("lockfile %s %q has %d platforms, exceeds limit of %d",
			kindLabel, name, len(entry.platforms), limits.MaxPlatformCount)
	}

	// Validate version for source-based components (external components may have empty version)
	if entry.kind != "external" {
		if entry.version == "" {
			return fmt.Errorf("lockfile contains source-based %s %q with empty version", kindLabel, name)
		}
		if err := config.ValidateVersion(entry.version); err != nil {
			return fmt.Errorf("lockfile contains invalid version for %s %q: %w", kindLabel, name, err)
		}
	}

	// Validate timestamp formats if present
	if entry.lockedAt != "" {
		if err := timestamp.Validate(entry.lockedAt); err != nil {
			return fmt.Errorf("lockfile %s %q has invalid locked_at timestamp: %w", kindLabel, name, err)
		}
	}
	if entry.verification != nil && entry.verification.VerifiedAt != "" {
		if err := timestamp.Validate(entry.verification.VerifiedAt); err != nil {
			return fmt.Errorf("lockfile %s %q has invalid verified_at timestamp: %w", kindLabel, name, err)
		}
	}

	return nil
}

// Save writes lockfile to path atomically, refusing to follow symlinks.
// Uses TOCTOU-safe operations: symlink-safe directory creation and
// fd-pinned rename to prevent race conditions.
//
// SECURITY: The path must be under the current working directory. Paths outside
// cwd are rejected to ensure all operations use the hardened fd-relative path.
func (lf *LockFile) Save(path string) error {
	// Validate all component names and versions before saving
	if err := lf.validateComponentsForSave(); err != nil {
		return err
	}

	dir := filepath.Dir(path)

	// Get current working directory as the security root
	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("getting working directory: %w", err)
	}

	// Handle special case where dir is "." (current directory)
	if dir == "." {
		dir = cwd
	}

	absDir, err := filepath.Abs(dir)
	if err != nil {
		return fmt.Errorf("resolving lockfile directory path: %w", err)
	}
	absCwd, err := filepath.Abs(cwd)
	if err != nil {
		return fmt.Errorf("resolving working directory path: %w", err)
	}

	// SECURITY: Reject paths outside cwd to ensure we always use the hardened
	// fd-relative operations. This eliminates the race window that existed when
	// falling back to os.Rename for paths outside cwd.
	if !strings.HasPrefix(absDir, absCwd+string(filepath.Separator)) && absDir != absCwd {
		return fmt.Errorf("refusing to save lockfile outside working directory: %s", path)
	}

	// Validate no symlinks in lockfile parent path ancestry.
	// This prevents symlink-based attacks where the lockfile parent directory
	// is a symlink pointing elsewhere, which would cause lockfile writes
	// outside the intended location.
	hasSymlink, err := safefile.ContainsSymlink(dir)
	if err != nil {
		return fmt.Errorf("checking for symlinks: %w", err)
	}
	if hasSymlink {
		return fmt.Errorf("refusing to save lockfile: path contains symlink: %s", dir)
	}

	// Create directory using safefile.MkdirAll (fd-relative, race-safe)
	if err := safefile.MkdirAll(cwd, dir); err != nil {
		return fmt.Errorf("creating lockfile dir: %w", err)
	}

	// Check if target is a symlink (refuse to follow)
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing to overwrite symlink at %s", path)
		}
	}

	// Use deterministic marshaling to ensure consistent output order
	data, err := lf.marshalDeterministic()
	if err != nil {
		return fmt.Errorf("marshaling lockfile: %w", err)
	}

	// Atomic write: write to temp file, then rename
	tmpFile, err := os.CreateTemp(dir, ".epack.lock.*.tmp")
	if err != nil {
		return fmt.Errorf("creating temp lockfile: %w", err)
	}
	tmpPath := tmpFile.Name()

	// Ensure cleanup on failure
	success := false
	defer func() {
		if !success {
			_ = os.Remove(tmpPath)
		}
	}()

	// TOCTOU mitigation: Re-validate the directory after temp file creation.
	// This closes the race window between initial validation and temp file creation.
	hasSymlink, err = safefile.ContainsSymlink(dir)
	if err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("checking for symlinks (race check): %w", err)
	}
	if hasSymlink {
		_ = tmpFile.Close()
		return fmt.Errorf("refusing to save lockfile (race detected): path contains symlink: %s", dir)
	}

	// Also re-check that target hasn't become a symlink during the race window
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			_ = tmpFile.Close()
			return fmt.Errorf("refusing to overwrite symlink at %s (race detected)", path)
		}
	}

	if _, err := tmpFile.Write(data); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("writing temp lockfile: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("closing temp lockfile: %w", err)
	}

	// Set permissions before rename
	if err := os.Chmod(tmpPath, 0644); err != nil {
		return fmt.Errorf("setting lockfile permissions: %w", err)
	}

	// TOCTOU-safe atomic rename: Use fd-relative rename to prevent symlink swaps
	// between the validation above and the rename operation.
	//
	// Rename keeps directory fds pinned throughout the operation,
	// preventing symlink swaps that could redirect the lockfile to an arbitrary location.
	fileName := filepath.Base(path)
	if err := safefile.Rename(cwd, tmpPath, filepath.Join(dir, fileName)); err != nil {
		return fmt.Errorf("renaming temp lockfile: %w", err)
	}

	success = true
	return nil
}

// validateComponentsForSave validates all components before saving the lockfile.
func (lf *LockFile) validateComponentsForSave() error {
	// Validate collectors
	for name, c := range lf.Collectors {
		if err := validateComponentForSave("collector", name, c.Kind, c.Version, config.ValidateCollectorName); err != nil {
			return err
		}
	}

	// Validate tools
	for name, t := range lf.Tools {
		if err := validateComponentForSave("tool", name, t.Kind, t.Version, config.ValidateToolName); err != nil {
			return err
		}
	}

	// Validate remotes
	for name, r := range lf.Remotes {
		if err := validateComponentForSave("remote", name, r.Kind, r.Version, config.ValidateRemoteName); err != nil {
			return err
		}
	}

	return nil
}

// validateComponentForSave validates a single component entry before saving.
func validateComponentForSave(kindLabel, name, kind, version string, validateName func(string) error) error {
	if err := validateName(name); err != nil {
		return fmt.Errorf("cannot save lockfile with invalid %s name %q: %w", kindLabel, name, err)
	}
	// Validate version for source-based components
	if kind != "external" && version != "" {
		if err := config.ValidateVersion(version); err != nil {
			return fmt.Errorf("cannot save lockfile with invalid version for %s %q: %w", kindLabel, name, err)
		}
	}
	return nil
}

// marshalDeterministic serializes the lockfile with deterministic map ordering.
// This ensures lockfile output is consistent across runs, preventing spurious
// diffs and enabling reliable content comparison.
func (lf *LockFile) marshalDeterministic() ([]byte, error) {
	return yamlutil.MarshalDeterministic(lf)
}

// GetCollector returns a collector entry by logical name.
func (lf *LockFile) GetCollector(name string) (LockedCollector, bool) {
	c, ok := lf.Collectors[name]
	return c, ok
}

// GetPlatformDigest returns a digest for collector and platform key (os/arch).
func (lf *LockFile) GetPlatformDigest(name, platform string) (string, bool) {
	collector, ok := lf.Collectors[name]
	if !ok {
		return "", false
	}
	entry, ok := collector.Platforms[platform]
	if !ok {
		return "", false
	}
	if entry.Digest == "" {
		return "", false
	}
	return entry.Digest, true
}

// GetTool returns a tool entry by logical name.
func (lf *LockFile) GetTool(name string) (LockedTool, bool) {
	t, ok := lf.Tools[name]
	return t, ok
}

// GetToolPlatformDigest returns a digest for tool and platform key (os/arch).
func (lf *LockFile) GetToolPlatformDigest(name, platform string) (string, bool) {
	tool, ok := lf.Tools[name]
	if !ok {
		return "", false
	}
	entry, ok := tool.Platforms[platform]
	if !ok {
		return "", false
	}
	if entry.Digest == "" {
		return "", false
	}
	return entry.Digest, true
}

// GetRemote returns a remote entry by logical name.
func (lf *LockFile) GetRemote(name string) (LockedRemote, bool) {
	r, ok := lf.Remotes[name]
	return r, ok
}

// GetRemotePlatformDigest returns a digest for remote and platform key (os/arch).
func (lf *LockFile) GetRemotePlatformDigest(name, platform string) (string, bool) {
	remote, ok := lf.Remotes[name]
	if !ok {
		return "", false
	}
	entry, ok := remote.Platforms[platform]
	if !ok {
		return "", false
	}
	if entry.Digest == "" {
		return "", false
	}
	return entry.Digest, true
}

// LockedComponentInfo provides a unified view of locked component data.
// This enables generic handling of both collectors and tools.
type LockedComponentInfo struct {
	Kind         string
	Source       string
	Version      string
	Signer       *componenttypes.LockedSigner
	ResolvedFrom *componenttypes.ResolvedFrom
	Verification *componenttypes.Verification
	LockedAt     string
	Platforms    map[string]componenttypes.LockedPlatform
}

// GetComponentInfo returns a unified view of a component by kind and name.
// The returned Platforms map is a defensive copy to prevent callers from
// mutating the internal lockfile state.
func (lf *LockFile) GetComponentInfo(kind componenttypes.ComponentKind, name string) (LockedComponentInfo, bool) {
	switch kind {
	case componenttypes.KindCollector:
		c, ok := lf.Collectors[name]
		if !ok {
			return LockedComponentInfo{}, false
		}
		return LockedComponentInfo{
			Kind:         c.Kind,
			Source:       c.Source,
			Version:      c.Version,
			Signer:       copySigner(c.Signer),
			ResolvedFrom: copyResolvedFrom(c.ResolvedFrom),
			Verification: copyVerification(c.Verification),
			LockedAt:     c.LockedAt,
			Platforms:    copyPlatforms(c.Platforms),
		}, true
	case componenttypes.KindTool:
		t, ok := lf.Tools[name]
		if !ok {
			return LockedComponentInfo{}, false
		}
		return LockedComponentInfo{
			Kind:         t.Kind,
			Source:       t.Source,
			Version:      t.Version,
			Signer:       copySigner(t.Signer),
			ResolvedFrom: copyResolvedFrom(t.ResolvedFrom),
			Verification: copyVerification(t.Verification),
			LockedAt:     t.LockedAt,
			Platforms:    copyPlatforms(t.Platforms),
		}, true
	case componenttypes.KindRemote:
		r, ok := lf.Remotes[name]
		if !ok {
			return LockedComponentInfo{}, false
		}
		return LockedComponentInfo{
			Kind:         r.Kind,
			Source:       r.Source,
			Version:      r.Version,
			Signer:       copySigner(r.Signer),
			ResolvedFrom: copyResolvedFrom(r.ResolvedFrom),
			Verification: copyVerification(r.Verification),
			LockedAt:     r.LockedAt,
			Platforms:    copyPlatforms(r.Platforms),
		}, true
	default:
		return LockedComponentInfo{}, false
	}
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

// GetComponentPlatformDigest returns a digest for component and platform key.
func (lf *LockFile) GetComponentPlatformDigest(kind componenttypes.ComponentKind, name, platform string) (string, bool) {
	info, ok := lf.GetComponentInfo(kind, name)
	if !ok {
		return "", false
	}
	entry, ok := info.Platforms[platform]
	if !ok {
		return "", false
	}
	if entry.Digest == "" {
		return "", false
	}
	return entry.Digest, true
}
