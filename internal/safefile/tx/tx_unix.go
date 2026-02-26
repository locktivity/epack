//go:build !windows

package tx

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/locktivity/epack/errors"
	"golang.org/x/sys/unix"
)

// WriteAtomicPath writes data atomically to path using temp+rename in the same directory.
// It refuses symlinks in the directory path and refuses overwriting symlink destinations.
func WriteAtomicPath(path string, data []byte, filePerm os.FileMode) error {
	dir := filepath.Dir(path)
	fileName := filepath.Base(path)

	dirFD, err := openDirNoSymlinkPath(dir)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(dirFD) }()

	return WriteAtomicAt(dirFD, fileName, data, filePerm)
}

// WriteAtomicAt writes data atomically into dirFD/fileName.
// Callers own dirFD and must close it.
func WriteAtomicAt(dirFD int, fileName string, data []byte, filePerm os.FileMode) error {
	tmpName := fileName + ".tmp"
	fileFD, err := unix.Openat(dirFD, tmpName, unix.O_WRONLY|unix.O_CREAT|unix.O_TRUNC|unix.O_NOFOLLOW, uint32(filePerm))
	if err != nil {
		if err == unix.ELOOP {
			return errors.E(errors.SymlinkNotAllowed, fmt.Sprintf("symlink at temp path: %s", tmpName), nil)
		}
		return fmt.Errorf("creating temp file: %w", err)
	}

	if err := writeAndCloseTempFile(dirFD, fileFD, tmpName, data); err != nil {
		return err
	}
	if err := refuseSymlinkOverwrite(dirFD, fileName, tmpName); err != nil {
		return err
	}
	if err := unix.Renameat(dirFD, tmpName, dirFD, fileName); err != nil {
		_ = unix.Unlinkat(dirFD, tmpName, 0)
		return fmt.Errorf("renaming to final: %w", err)
	}
	_ = unix.Fsync(dirFD)
	return nil
}

func openDirNoSymlinkPath(dir string) (int, error) {
	absDir, err := filepath.Abs(filepath.Clean(dir))
	if err != nil {
		return -1, fmt.Errorf("resolving absolute path: %w", err)
	}

	dirFD, err := unix.Open(absDir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		if err == unix.ELOOP || err == unix.ENOTDIR {
			return -1, errors.E(errors.SymlinkNotAllowed,
				fmt.Sprintf("symlink detected in path: %s", absDir), nil)
		}
		return -1, fmt.Errorf("opening directory %s: %w", absDir, err)
	}

	return dirFD, nil
}

func writeAndCloseTempFile(dirFD, fileFD int, tmpName string, data []byte) error {
	if err := writeAndSyncFD(fileFD, data, "temp file"); err != nil {
		_ = unix.Close(fileFD)
		_ = unix.Unlinkat(dirFD, tmpName, 0)
		return err
	}
	if err := unix.Close(fileFD); err != nil {
		_ = unix.Unlinkat(dirFD, tmpName, 0)
		return fmt.Errorf("closing temp file: %w", err)
	}
	return nil
}

func writeAndSyncFD(fileFD int, data []byte, what string) error {
	n, err := unix.Write(fileFD, data)
	if err != nil {
		return fmt.Errorf("writing %s: %w", what, err)
	}
	if n != len(data) {
		return fmt.Errorf("short write: %d of %d bytes", n, len(data))
	}
	if err := unix.Fsync(fileFD); err != nil {
		return fmt.Errorf("syncing %s: %w", what, err)
	}
	return nil
}

func refuseSymlinkOverwrite(dirFD int, fileName, tmpName string) error {
	var stat unix.Stat_t
	err := unix.Fstatat(dirFD, fileName, &stat, unix.AT_SYMLINK_NOFOLLOW)
	if err == nil && stat.Mode&unix.S_IFMT == unix.S_IFLNK {
		_ = unix.Unlinkat(dirFD, tmpName, 0)
		return errors.E(errors.SymlinkNotAllowed, fmt.Sprintf("refusing to overwrite symlink: %s", fileName), nil)
	}
	return nil
}
