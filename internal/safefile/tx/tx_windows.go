//go:build windows

package tx

import (
	"fmt"
	"os"
	"path/filepath"
)

// WriteAtomicPath writes data atomically to path using temp+rename in the same directory.
func WriteAtomicPath(path string, data []byte, filePerm os.FileMode) error {
	tmpPath := path + ".tmp"

	f, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, filePerm)
	if err != nil {
		return fmt.Errorf("creating temp file: %w", err)
	}

	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("writing temp file: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("syncing temp file: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("closing temp file: %w", err)
	}

	finalInfo, statErr := os.Lstat(path)
	if statErr == nil && finalInfo.Mode()&os.ModeSymlink != 0 {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("refusing to overwrite symlink: %s", filepath.Base(path))
	}

	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("renaming to final: %w", err)
	}

	return nil
}
