//go:build !windows

package secrets

import (
	"errors"
	"time"

	"golang.org/x/sys/unix"
)

func lockFile(path string, exclusive bool, wait time.Duration) (func(), error) {
	f, err := openLockFile(path)
	if err != nil {
		return nil, err
	}
	how := unix.LOCK_SH
	if exclusive {
		how = unix.LOCK_EX
	}
	deadline := time.Now().Add(wait)
	for {
		err := unix.Flock(int(f.Fd()), how|unix.LOCK_NB)
		if err == nil {
			return func() {
				_ = unix.Flock(int(f.Fd()), unix.LOCK_UN)
				_ = f.Close()
			}, nil
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) {
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
