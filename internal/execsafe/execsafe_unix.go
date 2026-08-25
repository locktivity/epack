//go:build unix

package execsafe

import (
	"fmt"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

func openVerifiedSourceFile(binaryPath string) (*os.File, error) {
	fd, err := unix.Open(binaryPath, unix.O_RDONLY|unix.O_NOFOLLOW, 0)
	if err != nil {
		if err == unix.ELOOP {
			return nil, fmt.Errorf("refusing to execute symlink: %s", binaryPath)
		}
		return nil, fmt.Errorf("opening binary: %w", err)
	}
	return os.NewFile(uintptr(fd), binaryPath), nil
}

// OpenBinaryNoFollow opens a binary with O_NOFOLLOW to prevent symlink attacks.
// Returns the fd and an error.
func OpenBinaryNoFollow(path string) (int, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW, 0)
	if err != nil {
		if err == unix.ELOOP {
			return -1, fmt.Errorf("refusing to open symlink: %s", path)
		}
		return -1, err
	}
	return fd, nil
}

// FstatInode returns the inode of a file descriptor.
func FstatInode(fd int) (uint64, error) {
	var stat syscall.Stat_t
	if err := syscall.Fstat(fd, &stat); err != nil {
		return 0, err
	}
	return stat.Ino, nil
}
