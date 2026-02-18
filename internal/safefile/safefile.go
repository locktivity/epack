//go:build !windows

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
	"golang.org/x/sys/unix"
)

// WriteFile writes data atomically with symlink protection.
// Creates parent directories as needed. Uses standard permissions (0755/0644).
//
// This is the default choice for writing files securely.
func WriteFile(baseDir, path string, data []byte) error {
	return writeFileInternal(baseDir, path, data, limits.StandardDirMode, limits.StandardFileMode, false)
}

// WriteFilePrivate writes data with restrictive permissions (0700/0600).
// Use for credentials, keys, tokens, or other sensitive data.
func WriteFilePrivate(baseDir, path string, data []byte) error {
	return writeFileInternal(baseDir, path, data, limits.PrivateDirMode, limits.PrivateFileMode, false)
}

// WriteFileExclusive writes data, failing if the file already exists.
// Use when overwriting would indicate a bug or race condition.
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

// ReadFile reads a file with size limit enforcement and symlink protection.
//
// SECURITY:
//   - Uses O_NOFOLLOW to atomically refuse symlinks
//   - Validates size before reading to prevent memory exhaustion
//   - Uses fstat on open fd to avoid TOCTOU races
func ReadFile(path string, limit limits.SizeLimit) ([]byte, error) {
	maxSize := limit.Bytes()

	// Open with O_NOFOLLOW to refuse symlinks atomically
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW, 0)
	if err != nil {
		if err == unix.ELOOP {
			return nil, errors.E(errors.SymlinkNotAllowed,
				fmt.Sprintf("refusing to read symlink: %s", path), nil)
		}
		return nil, err
	}

	f := os.NewFile(uintptr(fd), path)
	defer func() { _ = f.Close() }()

	// Check file size via fstat on open fd (race-free)
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if info.Size() > maxSize {
		return nil, fmt.Errorf("file %s exceeds maximum size (%d bytes > %d bytes)",
			filepath.Base(path), info.Size(), maxSize)
	}

	// Use LimitReader as defense-in-depth
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
func MkdirAll(baseDir, targetDir string) error {
	return mkdirAllInternal(baseDir, targetDir, limits.StandardDirMode)
}

// MkdirAllPrivate creates directories with restrictive permissions (0700).
func MkdirAllPrivate(baseDir, targetDir string) error {
	return mkdirAllInternal(baseDir, targetDir, limits.PrivateDirMode)
}

// OpenForRead opens a file for reading, refusing symlinks.
// Returns an *os.File that the caller must close.
// Use for streaming reads when ReadFile's size limit is not appropriate.
func OpenForRead(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW, 0)
	if err != nil {
		if err == unix.ELOOP {
			return nil, errors.E(errors.SymlinkNotAllowed,
				fmt.Sprintf("refusing to read symlink: %s", path), nil)
		}
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}

// OpenForWrite opens a file for writing, refusing symlinks.
// Returns an *os.File that the caller must close.
// Use for streaming writes when WriteFile is not appropriate.
func OpenForWrite(path string) (*os.File, error) {
	flags := unix.O_WRONLY | unix.O_CREAT | unix.O_TRUNC | unix.O_NOFOLLOW
	fd, err := unix.Open(path, flags, uint32(limits.StandardFileMode))
	if err != nil {
		if err == unix.ELOOP {
			return nil, errors.E(errors.SymlinkNotAllowed,
				fmt.Sprintf("refusing to write symlink: %s", path), nil)
		}
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}

// ValidatePath validates that relPath stays within baseDir.
// Returns the absolute path if valid.
//
// This is a pure string operation - it does not access the filesystem.
// Use this when you need path validation without file I/O.
func ValidatePath(baseDir, relPath string) (string, error) {
	// Reject absolute paths
	if filepath.IsAbs(relPath) {
		return "", errors.E(errors.PathTraversal,
			fmt.Sprintf("absolute paths not allowed: %s", relPath), nil)
	}

	// Clean and check for traversal
	cleaned := filepath.Clean(relPath)
	if strings.HasPrefix(cleaned, "..") {
		return "", errors.E(errors.PathTraversal,
			fmt.Sprintf("path traversal not allowed: %s", relPath), nil)
	}

	// Join and get absolute path
	joined := filepath.Join(baseDir, cleaned)
	absJoined, err := filepath.Abs(joined)
	if err != nil {
		return "", err
	}

	absBaseDir, err := filepath.Abs(baseDir)
	if err != nil {
		return "", err
	}

	// Verify result is under baseDir
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

// ContainsSymlink checks if any component in the path from root is a symlink.
// If root is empty, checks from filesystem root.
// Returns true if a symlink is found, false otherwise.
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
			startPath = "/"
		}
	} else {
		startPath = "/"
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
// Both source and destination must be under baseDir.
func Rename(baseDir, srcPath, dstPath string) error {
	// Validate both paths are contained
	if _, err := validateContained(baseDir, srcPath); err != nil {
		return err
	}
	dstDir := filepath.Dir(dstPath)
	dstName := filepath.Base(dstPath)

	if _, err := validateContained(baseDir, dstDir); err != nil {
		return err
	}

	// Validate dstName has no path separators
	if strings.Contains(dstName, "/") || strings.Contains(dstName, string(filepath.Separator)) {
		return fmt.Errorf("destination name must not contain path separators: %s", dstName)
	}

	// Get path relative to baseDir for component walking
	rel, err := filepath.Rel(baseDir, dstDir)
	if err != nil {
		return fmt.Errorf("cannot make %s relative to %s: %w", dstDir, baseDir, err)
	}

	var components []string
	if rel != "." {
		components = strings.Split(rel, string(filepath.Separator))
	}

	// Open the base directory with O_NOFOLLOW
	dstDirFd, err := unix.Open(baseDir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("opening base directory: %w", err)
	}
	defer func() { _ = unix.Close(dstDirFd) }()

	// Walk through each component, creating directories as needed
	for _, component := range components {
		if component == "" || component == "." {
			continue
		}

		err := unix.Mkdirat(dstDirFd, component, uint32(limits.StandardDirMode))
		if err != nil && err != unix.EEXIST {
			return fmt.Errorf("creating directory %s: %w", component, err)
		}

		newFd, err := unix.Openat(dstDirFd, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
		if err != nil {
			if err == unix.ELOOP || err == unix.ENOTDIR {
				return errors.E(errors.SymlinkNotAllowed,
					fmt.Sprintf("symlink detected: %s", component), nil)
			}
			return fmt.Errorf("opening directory %s: %w", component, err)
		}

		_ = unix.Close(dstDirFd)
		dstDirFd = newFd
	}

	// Open source directory
	srcDir := filepath.Dir(srcPath)
	srcName := filepath.Base(srcPath)

	srcDirFd, err := unix.Open(srcDir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("opening source directory: %w", err)
	}
	defer func() { _ = unix.Close(srcDirFd) }()

	// Atomic rename
	if err := unix.Renameat(srcDirFd, srcName, dstDirFd, dstName); err != nil {
		return fmt.Errorf("renaming %s to %s: %w", srcPath, dstPath, err)
	}

	return nil
}

// ErrFileExists is returned when WriteFileExclusive encounters an existing file.
var ErrFileExists = errors.E(errors.InvalidInput, "file already exists", nil)

// --- Internal implementation ---

func writeFileInternal(baseDir, path string, data []byte, dirPerm, filePerm os.FileMode, exclusive bool) error {
	// path is relative to baseDir
	fullPath := filepath.Join(baseDir, path)
	parentDir := filepath.Dir(fullPath)
	fileName := filepath.Base(fullPath)

	// Validate containment
	if _, err := validateContained(baseDir, parentDir); err != nil {
		return err
	}

	// Get path relative to baseDir
	rel, err := filepath.Rel(baseDir, parentDir)
	if err != nil {
		return fmt.Errorf("cannot make %s relative to %s: %w", parentDir, baseDir, err)
	}

	var components []string
	if rel != "." {
		components = strings.Split(rel, string(filepath.Separator))
	}

	// Open base directory with O_NOFOLLOW
	dirFd, err := unix.Open(baseDir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("opening base directory: %w", err)
	}
	defer func() { _ = unix.Close(dirFd) }()

	// Walk and create parent directories
	for _, component := range components {
		if component == "" || component == "." {
			continue
		}

		err := unix.Mkdirat(dirFd, component, uint32(dirPerm))
		if err != nil && err != unix.EEXIST {
			return fmt.Errorf("creating directory %s: %w", component, err)
		}

		newFd, err := unix.Openat(dirFd, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
		if err != nil {
			if err == unix.ELOOP || err == unix.ENOTDIR {
				return errors.E(errors.SymlinkNotAllowed,
					fmt.Sprintf("symlink in path: %s", component), nil)
			}
			return fmt.Errorf("opening directory %s: %w", component, err)
		}

		_ = unix.Close(dirFd)
		dirFd = newFd
	}

	// Write file
	var flags int
	if exclusive {
		flags = unix.O_CREAT | unix.O_EXCL | unix.O_WRONLY | unix.O_NOFOLLOW
	} else {
		// Use temp file + rename for atomic writes
		tmpName := fileName + ".tmp"
		fileFd, err := unix.Openat(dirFd, tmpName, unix.O_WRONLY|unix.O_CREAT|unix.O_TRUNC|unix.O_NOFOLLOW, uint32(filePerm))
		if err != nil {
			if err == unix.ELOOP {
				return errors.E(errors.SymlinkNotAllowed,
					fmt.Sprintf("symlink at temp path: %s", tmpName), nil)
			}
			return fmt.Errorf("creating temp file: %w", err)
		}

		n, err := unix.Write(fileFd, data)
		if err != nil {
			_ = unix.Close(fileFd)
			_ = unix.Unlinkat(dirFd, tmpName, 0)
			return fmt.Errorf("writing temp file: %w", err)
		}
		if n != len(data) {
			_ = unix.Close(fileFd)
			_ = unix.Unlinkat(dirFd, tmpName, 0)
			return fmt.Errorf("short write: %d of %d bytes", n, len(data))
		}

		if err := unix.Fsync(fileFd); err != nil {
			_ = unix.Close(fileFd)
			_ = unix.Unlinkat(dirFd, tmpName, 0)
			return fmt.Errorf("syncing temp file: %w", err)
		}

		if err := unix.Close(fileFd); err != nil {
			_ = unix.Unlinkat(dirFd, tmpName, 0)
			return fmt.Errorf("closing temp file: %w", err)
		}

		// SECURITY: Check if destination is a symlink before rename.
		// Renameat would overwrite a symlink, which could be a security issue.
		var stat unix.Stat_t
		err = unix.Fstatat(dirFd, fileName, &stat, unix.AT_SYMLINK_NOFOLLOW)
		if err == nil {
			// File exists - check if it's a symlink
			if stat.Mode&unix.S_IFMT == unix.S_IFLNK {
				_ = unix.Unlinkat(dirFd, tmpName, 0)
				return errors.E(errors.SymlinkNotAllowed,
					fmt.Sprintf("refusing to overwrite symlink: %s", fileName), nil)
			}
		}
		// If file doesn't exist (ENOENT), that's fine - we'll create it

		// Atomic rename
		if err := unix.Renameat(dirFd, tmpName, dirFd, fileName); err != nil {
			_ = unix.Unlinkat(dirFd, tmpName, 0)
			return fmt.Errorf("renaming to final: %w", err)
		}

		_ = unix.Fsync(dirFd) // Best-effort directory sync
		return nil
	}

	// Exclusive write (no temp file needed)
	fileFd, err := unix.Openat(dirFd, fileName, flags, uint32(filePerm))
	if err != nil {
		if err == unix.EEXIST {
			return ErrFileExists
		}
		if err == unix.ELOOP {
			return errors.E(errors.SymlinkNotAllowed,
				fmt.Sprintf("symlink at path: %s", fileName), nil)
		}
		return fmt.Errorf("creating file: %w", err)
	}
	defer func() { _ = unix.Close(fileFd) }()

	n, err := unix.Write(fileFd, data)
	if err != nil {
		return fmt.Errorf("writing file: %w", err)
	}
	if n != len(data) {
		return fmt.Errorf("short write: %d of %d bytes", n, len(data))
	}

	return unix.Fsync(fileFd)
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

	components := strings.Split(rel, string(filepath.Separator))

	dirFd, err := unix.Open(baseDir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("opening base directory: %w", err)
	}
	defer func() { _ = unix.Close(dirFd) }()

	for _, component := range components {
		if component == "" || component == "." {
			continue
		}

		err := unix.Mkdirat(dirFd, component, uint32(perm))
		if err != nil && err != unix.EEXIST {
			return fmt.Errorf("creating directory %s: %w", component, err)
		}

		newFd, err := unix.Openat(dirFd, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
		if err != nil {
			if err == unix.ELOOP || err == unix.ENOTDIR {
				return errors.E(errors.SymlinkNotAllowed,
					fmt.Sprintf("symlink detected: %s", component), nil)
			}
			return fmt.Errorf("opening directory %s: %w", component, err)
		}

		_ = unix.Close(dirFd)
		dirFd = newFd
	}

	return nil
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
