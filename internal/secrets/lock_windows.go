//go:build windows

package secrets

import (
	"errors"
	"time"

	"golang.org/x/sys/windows"
)

func lockFile(path string, exclusive bool, wait time.Duration) (func(), error) {
	f, err := openLockFile(path)
	if err != nil {
		return nil, err
	}
	flags := uint32(windows.LOCKFILE_FAIL_IMMEDIATELY)
	if exclusive {
		flags |= windows.LOCKFILE_EXCLUSIVE_LOCK
	}
	deadline := time.Now().Add(wait)
	for {
		overlapped := new(windows.Overlapped)
		err := windows.LockFileEx(windows.Handle(f.Fd()), flags, 0, 1, 0, overlapped)
		if err == nil {
			return func() {
				_ = windows.UnlockFileEx(windows.Handle(f.Fd()), 0, 1, 0, new(windows.Overlapped))
				_ = f.Close()
			}, nil
		}
		if !errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
			_ = f.Close()
			return nil, err
		}
		if time.Now().After(deadline) {
			_ = f.Close()
			return nil, busy()
		}
		time.Sleep(50 * time.Millisecond)
	}
}
