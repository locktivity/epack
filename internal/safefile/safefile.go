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
	"github.com/locktivity/epack/internal/safefile/tx"
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

// EnsureBaseDir creates the base directory if it doesn't exist.
// Use this for trusted paths derived from code (like .epack in project root).
// For creating directories inside the base, use MkdirAll.
func EnsureBaseDir(baseDir string) error {
	return os.MkdirAll(baseDir, limits.StandardDirMode)
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

	startPath, err := resolveSymlinkStartPath(absPath, root)
	if err != nil {
		return false, err
	}

	rel, err := filepath.Rel(startPath, absPath)
	if err != nil {
		return false, err
	}

	if rel == "." {
		return isSymlinkIfExists(startPath)
	}

	components := strings.Split(rel, string(filepath.Separator))
	current := startPath
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
// Both source and destination must be under baseDir.
func Rename(baseDir, srcPath, dstPath string) error {
	dstDir, dstName, err := validateRenameInputs(baseDir, srcPath, dstPath)
	if err != nil {
		return err
	}

	dstDirFd, err := openContainedDir(baseDir, dstDir, limits.StandardDirMode)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(dstDirFd) }()

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

	dirFd, err := openContainedDir(baseDir, parentDir, dirPerm)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(dirFd) }()

	if exclusive {
		return writeExclusiveFile(dirFd, fileName, data, filePerm)
	}
	return writeAtomicFile(dirFd, fileName, data, filePerm)
}

func resolveSymlinkStartPath(absPath, root string) (string, error) {
	if root == "" {
		return "/", nil
	}
	absRoot, err := filepath.Abs(filepath.Clean(root))
	if err != nil {
		return "", err
	}
	rootWithSep := absRoot
	if !strings.HasSuffix(rootWithSep, string(filepath.Separator)) {
		rootWithSep += string(filepath.Separator)
	}
	if strings.HasPrefix(absPath, rootWithSep) || absPath == absRoot {
		return absRoot, nil
	}
	return "/", nil
}

func isSymlinkIfExists(path string) (bool, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	return fi.Mode()&os.ModeSymlink != 0, nil
}

func validateRenameInputs(baseDir, srcPath, dstPath string) (string, string, error) {
	if _, err := validateContained(baseDir, srcPath); err != nil {
		return "", "", err
	}
	dstDir := filepath.Dir(dstPath)
	dstName := filepath.Base(dstPath)
	if _, err := validateContained(baseDir, dstDir); err != nil {
		return "", "", err
	}
	if strings.Contains(dstName, "/") || strings.Contains(dstName, string(filepath.Separator)) {
		return "", "", fmt.Errorf("destination name must not contain path separators: %s", dstName)
	}
	return dstDir, dstName, nil
}

func openContainedDir(baseDir, targetDir string, perm os.FileMode) (int, error) {
	components, err := containedRelativeComponents(baseDir, targetDir)
	if err != nil {
		return -1, err
	}
	dirFd, err := openBaseDirectoryFD(baseDir)
	if err != nil {
		return -1, fmt.Errorf("opening base directory: %w", err)
	}
	if len(components) == 0 {
		return dirFd, nil
	}
	for _, component := range components {
		nextFD, err := ensureAndOpenChildDir(dirFd, component, perm)
		if err != nil {
			_ = unix.Close(dirFd)
			return -1, err
		}
		_ = unix.Close(dirFd)
		dirFd = nextFD
	}
	return dirFd, nil
}

func writeExclusiveFile(dirFd int, fileName string, data []byte, filePerm os.FileMode) error {
	flags := unix.O_CREAT | unix.O_EXCL | unix.O_WRONLY | unix.O_NOFOLLOW
	fileFd, err := unix.Openat(dirFd, fileName, flags, uint32(filePerm))
	if err != nil {
		if err == unix.EEXIST {
			return ErrFileExists
		}
		if err == unix.ELOOP {
			return errors.E(errors.SymlinkNotAllowed, fmt.Sprintf("symlink at path: %s", fileName), nil)
		}
		return fmt.Errorf("creating file: %w", err)
	}
	defer func() { _ = unix.Close(fileFd) }()
	return writeAndSyncFD(fileFd, data, "file")
}

func writeAtomicFile(dirFd int, fileName string, data []byte, filePerm os.FileMode) error {
	return tx.WriteAtomicAt(dirFd, fileName, data, filePerm)
}

func writeAndSyncFD(fileFd int, data []byte, what string) error {
	n, err := unix.Write(fileFd, data)
	if err != nil {
		return fmt.Errorf("writing %s: %w", what, err)
	}
	if n != len(data) {
		return fmt.Errorf("short write: %d of %d bytes", n, len(data))
	}
	if err := unix.Fsync(fileFd); err != nil {
		return fmt.Errorf("syncing %s: %w", what, err)
	}
	return nil
}

func mkdirAllInternal(baseDir, targetDir string, perm os.FileMode) error {
	components, err := containedRelativeComponents(baseDir, targetDir)
	if err != nil {
		return err
	}
	if len(components) == 0 {
		return nil
	}

	dirFd, err := openBaseDirectoryFD(baseDir)
	if err != nil {
		return fmt.Errorf("opening base directory: %w", err)
	}
	defer func() { _ = unix.Close(dirFd) }()

	for _, component := range components {
		newFd, err := ensureAndOpenChildDir(dirFd, component, perm)
		if err != nil {
			return err
		}
		_ = unix.Close(dirFd)
		dirFd = newFd
	}

	return nil
}

func containedRelativeComponents(baseDir, targetDir string) ([]string, error) {
	if _, err := validateContained(baseDir, targetDir); err != nil {
		return nil, err
	}
	rel, err := filepath.Rel(baseDir, targetDir)
	if err != nil {
		return nil, fmt.Errorf("cannot make %s relative to %s: %w", targetDir, baseDir, err)
	}
	if rel == "." {
		return nil, nil
	}
	return filterPathComponents(strings.Split(rel, string(filepath.Separator))), nil
}

func filterPathComponents(components []string) []string {
	out := make([]string, 0, len(components))
	for _, component := range components {
		if component == "" || component == "." {
			continue
		}
		out = append(out, component)
	}
	return out
}

func openBaseDirectoryFD(baseDir string) (int, error) {
	return unix.Open(baseDir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
}

func ensureAndOpenChildDir(dirFd int, component string, perm os.FileMode) (int, error) {
	if err := unix.Mkdirat(dirFd, component, uint32(perm)); err != nil && err != unix.EEXIST {
		return -1, fmt.Errorf("creating directory %s: %w", component, err)
	}
	newFD, err := unix.Openat(dirFd, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err == nil {
		return newFD, nil
	}
	if err == unix.ELOOP || err == unix.ENOTDIR {
		return -1, errors.E(errors.SymlinkNotAllowed, fmt.Sprintf("symlink detected: %s", component), nil)
	}
	return -1, fmt.Errorf("opening directory %s: %w", component, err)
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
