//go:build windows

package safefile

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/locktivity/epack/errors"
	"github.com/locktivity/epack/internal/limits"
)

// WriteFile writes data atomically with symlink protection.
// Creates parent directories as needed. Uses standard permissions (0755/0644).
//
// On Windows, symlink protection is limited.
// TODO: Implement Windows-native symlink safety.
func WriteFile(baseDir, path string, data []byte) error {
	return writeFileInternal(baseDir, path, data, limits.StandardDirMode, limits.StandardFileMode, false)
}

// WriteFilePrivate writes data with restrictive permissions (0700/0600).
// Use for credentials, keys, tokens, or other sensitive data.
//
// On Windows, symlink protection is limited.
func WriteFilePrivate(baseDir, path string, data []byte) error {
	return writeFileInternal(baseDir, path, data, limits.PrivateDirMode, limits.PrivateFileMode, false)
}

// WriteFileExclusive writes data, failing if the file already exists.
// Use when overwriting would indicate a bug or race condition.
//
// On Windows, symlink protection is limited.
func WriteFileExclusive(baseDir, path string, data []byte) error {
	return writeFileInternal(baseDir, path, data, limits.StandardDirMode, limits.StandardFileMode, true)
}

// WriteJSON marshals v to indented JSON and writes atomically.
func WriteJSON(baseDir, path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling JSON: %w", err)
	}
	return WriteFile(baseDir, path, data)
}

// ReadFile reads a file with size limit enforcement.
//
// On Windows, symlink protection is limited.
// TODO: Implement Windows-native symlink safety.
func ReadFile(path string, limit limits.SizeLimit) ([]byte, error) {
	maxSize := limit.Bytes()

	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if info.Size() > maxSize {
		return nil, fmt.Errorf("file %s exceeds maximum size (%d bytes > %d bytes)",
			filepath.Base(path), info.Size(), maxSize)
	}

	data, err := io.ReadAll(io.LimitReader(f, maxSize+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxSize {
		return nil, fmt.Errorf("file %s exceeded maximum size during read (%d bytes)",
			filepath.Base(path), maxSize)
	}

	return data, nil
}

// MkdirAll creates a directory and all parents with symlink protection.
// Uses standard directory permissions (0755).
//
// On Windows, symlink protection is limited.
func MkdirAll(baseDir, targetDir string) error {
	return mkdirAllInternal(baseDir, targetDir, limits.StandardDirMode)
}

// MkdirAllPrivate creates directories with restrictive permissions (0700).
//
// On Windows, symlink protection is limited.
func MkdirAllPrivate(baseDir, targetDir string) error {
	return mkdirAllInternal(baseDir, targetDir, limits.PrivateDirMode)
}

// OpenForRead opens a file for reading.
// Returns an *os.File that the caller must close.
//
// On Windows, symlink protection is limited.
func OpenForRead(path string) (*os.File, error) {
	return os.Open(path)
}

// OpenForWrite opens a file for writing.
// Returns an *os.File that the caller must close.
//
// On Windows, symlink protection is limited.
func OpenForWrite(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, limits.StandardFileMode)
}

// ValidatePath validates that relPath stays within baseDir.
// Returns the absolute path if valid.
func ValidatePath(baseDir, relPath string) (string, error) {
	if filepath.IsAbs(relPath) {
		return "", errors.E(errors.PathTraversal,
			fmt.Sprintf("absolute paths not allowed: %s", relPath), nil)
	}

	cleaned := filepath.Clean(relPath)
	if strings.HasPrefix(cleaned, "..") {
		return "", errors.E(errors.PathTraversal,
			fmt.Sprintf("path traversal not allowed: %s", relPath), nil)
	}

	joined := filepath.Join(baseDir, cleaned)
	absJoined, err := filepath.Abs(joined)
	if err != nil {
		return "", err
	}

	absBaseDir, err := filepath.Abs(baseDir)
	if err != nil {
		return "", err
	}

	baseDirWithSep := absBaseDir
	if !strings.HasSuffix(baseDirWithSep, string(filepath.Separator)) {
		baseDirWithSep += string(filepath.Separator)
	}

	if !strings.HasPrefix(absJoined+string(filepath.Separator), baseDirWithSep) &&
		absJoined != absBaseDir {
		return "", errors.E(errors.PathTraversal,
			fmt.Sprintf("path escapes base directory: %s", relPath), nil)
	}

	return absJoined, nil
}

// ContainsSymlink checks if any component in the path is a symlink.
func ContainsSymlink(path string) (bool, error) {
	return ContainsSymlinkFrom(path, "")
}

// ContainsSymlinkFrom checks if any component in the path from root is a symlink.
// Only checks path components between root and path.
func ContainsSymlinkFrom(path, root string) (bool, error) {
	absPath, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		return false, err
	}

	var startPath string
	if root != "" {
		absRoot, err := filepath.Abs(filepath.Clean(root))
		if err != nil {
			return false, err
		}

		rootWithSep := absRoot
		if !strings.HasSuffix(rootWithSep, string(filepath.Separator)) {
			rootWithSep += string(filepath.Separator)
		}

		if strings.HasPrefix(absPath, rootWithSep) || absPath == absRoot {
			startPath = absRoot
		} else {
			startPath = filepath.VolumeName(absPath) + string(filepath.Separator)
		}
	} else {
		startPath = filepath.VolumeName(absPath) + string(filepath.Separator)
	}

	current := startPath
	rel, err := filepath.Rel(startPath, absPath)
	if err != nil {
		return false, err
	}

	if rel == "." {
		fi, err := os.Lstat(current)
		if err != nil {
			if os.IsNotExist(err) {
				return false, nil
			}
			return false, err
		}
		return fi.Mode()&os.ModeSymlink != 0, nil
	}

	components := strings.Split(rel, string(filepath.Separator))
	for _, component := range components {
		if component == "" || component == "." {
			continue
		}

		current = filepath.Join(current, component)

		fi, err := os.Lstat(current)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return false, err
		}

		if fi.Mode()&os.ModeSymlink != 0 {
			return true, nil
		}
	}

	return false, nil
}

// ValidateRegularFile validates that relPath is a regular file within root.
// Returns the absolute path if valid. Rejects symlinks and non-regular files.
func ValidateRegularFile(root, relPath string) (string, error) {
	abs, err := ValidatePath(root, relPath)
	if err != nil {
		return "", err
	}

	// Check for symlinks in the path from root to abs
	hasSymlink, err := ContainsSymlinkFrom(abs, root)
	if err != nil {
		return "", err
	}
	if hasSymlink {
		return "", errors.E(errors.SymlinkNotAllowed,
			fmt.Sprintf("symlink in path: %s", relPath), nil)
	}

	// Check file type
	info, err := os.Lstat(abs)
	if err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf("file does not exist: %s", relPath)
		}
		return "", fmt.Errorf("cannot stat file: %w", err)
	}

	if !info.Mode().IsRegular() {
		if info.Mode()&os.ModeSymlink != 0 {
			return "", errors.E(errors.SymlinkNotAllowed,
				fmt.Sprintf("path is a symlink: %s", relPath), nil)
		}
		return "", fmt.Errorf("not a regular file: %s (mode: %s)", relPath, info.Mode())
	}

	return abs, nil
}

// Rename atomically moves a file, creating destination directories as needed.
func Rename(baseDir, srcPath, dstPath string) error {
	if _, err := validateContained(baseDir, srcPath); err != nil {
		return err
	}
	dstDir := filepath.Dir(dstPath)
	if _, err := validateContained(baseDir, dstDir); err != nil {
		return err
	}

	if err := os.MkdirAll(dstDir, limits.StandardDirMode); err != nil {
		return fmt.Errorf("creating directories: %w", err)
	}

	return os.Rename(srcPath, dstPath)
}

// ErrFileExists is returned when WriteFileExclusive encounters an existing file.
var ErrFileExists = errors.E(errors.InvalidInput, "file already exists", nil)

// --- Internal implementation ---

func writeFileInternal(baseDir, path string, data []byte, dirPerm, filePerm os.FileMode, exclusive bool) error {
	parentDir := filepath.Dir(path)

	if _, err := validateContained(baseDir, parentDir); err != nil {
		return err
	}

	if err := os.MkdirAll(parentDir, dirPerm); err != nil {
		return fmt.Errorf("creating directories: %w", err)
	}

	if exclusive {
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, filePerm)
		if err != nil {
			if os.IsExist(err) {
				return ErrFileExists
			}
			return err
		}
		defer f.Close()

		if _, err := f.Write(data); err != nil {
			return err
		}
		return f.Sync()
	}

	// Atomic write via temp file + rename
	tmpPath := path + ".tmp"
	f, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, filePerm)
	if err != nil {
		return fmt.Errorf("creating temp file: %w", err)
	}

	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("writing temp file: %w", err)
	}

	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("syncing temp file: %w", err)
	}

	if err := f.Close(); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("closing temp file: %w", err)
	}

	if err := os.Rename(tmpPath, path); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("renaming to final: %w", err)
	}

	return nil
}

func mkdirAllInternal(baseDir, targetDir string, perm os.FileMode) error {
	if _, err := validateContained(baseDir, targetDir); err != nil {
		return err
	}

	rel, err := filepath.Rel(baseDir, targetDir)
	if err != nil {
		return fmt.Errorf("cannot make %s relative to %s: %w", targetDir, baseDir, err)
	}

	if rel == "." {
		return nil
	}

	return os.MkdirAll(targetDir, perm)
}

func validateContained(baseDir, candidate string) (string, error) {
	rel, err := filepath.Rel(baseDir, candidate)
	if err != nil {
		return "", fmt.Errorf("cannot make %s relative to %s: %w", candidate, baseDir, err)
	}
	if strings.HasPrefix(rel, "..") || filepath.IsAbs(rel) {
		return "", errors.E(errors.PathTraversal,
			fmt.Sprintf("path escapes base directory: %s", rel), nil)
	}
	return filepath.Join(baseDir, rel), nil
}
