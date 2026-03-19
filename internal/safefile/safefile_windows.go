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
	"github.com/locktivity/epack/internal/safefile/tx"
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

// EnsureBaseDir creates the base directory if it doesn't exist.
// Use this for trusted paths derived from code (like .epack in project root).
// For creating directories inside the base, use MkdirAll.
func EnsureBaseDir(baseDir string) error {
	return os.MkdirAll(baseDir, limits.StandardDirMode)
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
	if err := checkRegularFile(root, abs, relPath); err != nil {
		return "", err
	}
	return abs, nil
}

// ValidateAbsoluteFile validates that absPath is a regular file contained within root.
// Unlike ValidateRegularFile which takes a relative path, this takes an already-absolute path
// and verifies it's contained within root. Use this when config normalization has already
// resolved the path to absolute form.
//
// Returns the validated absolute path if valid. Rejects:
// - Paths not contained within root
// - Symlinks anywhere in the path
// - Non-regular files
func ValidateAbsoluteFile(root, absPath string) (string, error) {
	rel, err := checkContainment(root, absPath)
	if err != nil {
		return "", err
	}
	if err := checkRegularFile(root, absPath, rel); err != nil {
		return "", err
	}
	return absPath, nil
}

// checkContainment verifies absPath is contained within root.
// Returns the relative path for use in error messages.
func checkContainment(root, absPath string) (string, error) {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return "", fmt.Errorf("resolving root: %w", err)
	}
	rel, err := filepath.Rel(absRoot, absPath)
	if err != nil {
		return "", errors.E(errors.PathTraversal,
			fmt.Sprintf("path not relative to root: %s", absPath), err)
	}
	if strings.HasPrefix(rel, "..") || filepath.IsAbs(rel) {
		return "", errors.E(errors.PathTraversal,
			fmt.Sprintf("path escapes root directory: %s", absPath), nil)
	}
	return rel, nil
}

// checkRegularFile verifies absPath has no symlinks and is a regular file.
// displayPath is used in error messages (typically the relative or user-provided path).
func checkRegularFile(root, absPath, displayPath string) error {
	hasSymlink, err := ContainsSymlinkFrom(absPath, root)
	if err != nil {
		return err
	}
	if hasSymlink {
		return errors.E(errors.SymlinkNotAllowed,
			fmt.Sprintf("symlink in path: %s", displayPath), nil)
	}

	info, err := os.Lstat(absPath)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("file does not exist: %s", displayPath)
		}
		return fmt.Errorf("cannot stat file: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return errors.E(errors.SymlinkNotAllowed,
			fmt.Sprintf("path is a symlink: %s", displayPath), nil)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("not a regular file: %s (mode: %s)", displayPath, info.Mode())
	}
	return nil
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
	fullPath := filepath.Join(baseDir, path)
	parentDir := filepath.Dir(fullPath)

	if _, err := validateContained(baseDir, parentDir); err != nil {
		return err
	}

	if err := os.MkdirAll(parentDir, dirPerm); err != nil {
		return fmt.Errorf("creating directories: %w", err)
	}

	if exclusive {
		f, err := os.OpenFile(fullPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, filePerm)
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

	return tx.WriteAtomicPath(fullPath, data, filePerm)
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
