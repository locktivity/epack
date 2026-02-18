package validate

import (
	"fmt"
	"path/filepath"
	"strings"
)

// PathComponent validates a single path component (filename or directory name).
// Rejects traversal segments and embedded separators.
//
// SECURITY: Use this when validating individual path segments that will be
// joined into a full path. This prevents injection of traversal sequences.
func PathComponent(seg string) error {
	if seg == "" {
		return fmt.Errorf("empty path component")
	}
	if seg == "." || seg == ".." {
		return fmt.Errorf("path component %q is traversal segment", seg)
	}
	// SECURITY: Reject segments starting with ".." (e.g., "..hidden")
	// These can confuse path manipulation or be exploited on edge-case systems.
	if strings.HasPrefix(seg, "..") {
		return fmt.Errorf("path component %q starts with double-dot", seg)
	}
	if strings.ContainsAny(seg, "/\\") {
		return fmt.Errorf("path component %q contains separator", seg)
	}
	return nil
}

// RelativePath validates a relative path against traversal and escapes.
// Does NOT resolve the path against the filesystem - just validates the string.
//
// SECURITY: Use this for paths that should be relative (e.g., paths from
// untrusted input like zip entries, config files, or user input).
func RelativePath(path string) error {
	if path == "" {
		return fmt.Errorf("empty path")
	}
	if filepath.IsAbs(path) {
		return fmt.Errorf("path %q is absolute", path)
	}

	cleaned := filepath.Clean(path)

	// After Clean, traversal would show as leading ".."
	if cleaned == ".." || strings.HasPrefix(cleaned, ".."+string(filepath.Separator)) {
		return fmt.Errorf("path %q escapes base directory", path)
	}

	return nil
}

// ContainedPath validates that joining baseDir + relPath stays within baseDir.
// Returns the joined absolute path on success.
//
// SECURITY: This is the primary function for safely joining untrusted relative
// paths with a trusted base directory. It prevents all path traversal attacks
// including those using symlinks in the path string itself.
//
// Note: This does NOT check for symlinks on the filesystem. For symlink-safe
// operations, use safefile.ValidatePath or safefile.WriteFile.
func ContainedPath(baseDir, relPath string) (string, error) {
	if err := RelativePath(relPath); err != nil {
		return "", err
	}

	absBase, err := filepath.Abs(baseDir)
	if err != nil {
		return "", fmt.Errorf("resolving base directory: %w", err)
	}

	joined := filepath.Join(absBase, filepath.Clean(relPath))

	// Verify containment with proper separator handling
	// Add trailing separator to prevent prefix matching issues
	// (e.g., /tmp/out matching /tmp/output)
	baseSep := absBase
	if !strings.HasSuffix(baseSep, string(filepath.Separator)) {
		baseSep += string(filepath.Separator)
	}

	if !strings.HasPrefix(joined, baseSep) && joined != absBase {
		return "", fmt.Errorf("path %q escapes base directory %q", relPath, baseDir)
	}

	return joined, nil
}

// PathSafe validates a string is safe for use in path construction.
// Rejects path traversal patterns without validating path format.
//
// Use cases:
//   - Component names, versions, project names
//   - Any untrusted string that becomes part of a path
//
// For validating actual paths, use RelativePath() or ContainedPath().
//
// SECURITY: Delegates to RejectPathTraversal which catches all known
// path traversal attack vectors including separators, .., and double-dots.
func PathSafe(s string) error {
	return RejectPathTraversal(s)
}

// RelativePathWithPrefix validates a relative path and ensures it has a required prefix.
// This is useful for paths like "artifacts/foo.json" that must be under a specific directory.
func RelativePathWithPrefix(path, requiredPrefix string) error {
	if err := RelativePath(path); err != nil {
		return err
	}
	if !strings.HasPrefix(path, requiredPrefix) {
		return fmt.Errorf("path %q must start with %q", path, requiredPrefix)
	}
	return nil
}
