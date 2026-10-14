package secrets

import (
	"os"
	"path/filepath"
	"time"
)

// lockWait bounds how long a command waits for another command that holds
// the same configuration's secrets.
const lockWait = 10 * time.Second

// lockScope takes the scope's file lock: exclusive for commands that write
// values or metadata, shared for the resolution inside a run or a check. The
// operating system releases it when the process ends.
func (p Paths) lockScope(scope Scope, exclusive bool) (func(), error) {
	if err := p.ensure(); err != nil {
		return nil, err
	}
	path := filepath.Join(p.locksDir(), scope.fileStem()+".lock")
	return lockFile(path, exclusive, lockWait)
}

func openLockFile(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
}

func busy() error {
	return &StoreError{Code: CodeBusy, Message: "another epack command is changing this configuration's secrets"}
}
