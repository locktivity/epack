package userconfig

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/locktivity/epack/internal/component/config"
	"github.com/locktivity/epack/internal/component/lockfile"
	"github.com/locktivity/epack/internal/safefile"
	"github.com/locktivity/epack/internal/safefile/tx"
	"github.com/locktivity/epack/internal/yamlutil"
)

// RemotesLockFile pins the remote adapters installed for the user outside any
// project, so a remote can be reached by name before a config exists.
const RemotesLockFile = "remotes.lock"

// RemotesLockPath returns the path of the user-level remotes lockfile.
func RemotesLockPath() (string, error) {
	dir, err := Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, RemotesLockFile), nil
}

// LoadRemotesLockFromPath reads a remotes lockfile, or returns an empty one
// when the file does not exist yet.
func LoadRemotesLockFromPath(path string) (*lockfile.LockFile, error) {
	lf, err := lockfile.Load(path)
	if os.IsNotExist(err) {
		return lockfile.New(), nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading remotes lock: %w", err)
	}
	return lf, nil
}

// SaveRemotesLockToPath writes a remotes lockfile atomically. The project
// lockfile's own Save refuses paths outside the working directory, which is
// right for a project and wrong for a file in the home directory.
func SaveRemotesLockToPath(path string, lf *lockfile.LockFile) error {
	for name, locked := range lf.Remotes {
		if err := config.ValidateRemoteName(name); err != nil {
			return fmt.Errorf("cannot save remotes lock: %w", err)
		}
		if locked.Version != "" {
			if err := config.ValidateVersion(locked.Version); err != nil {
				return fmt.Errorf("cannot save remotes lock with invalid version for %q: %w", name, err)
			}
		}
	}
	dir := filepath.Dir(path)
	if err := safefile.EnsureBaseDir(dir); err != nil {
		return fmt.Errorf("creating %s: %w", dir, err)
	}
	if err := validateUserLockPath(path, dir); err != nil {
		return err
	}
	data, err := yamlutil.MarshalDeterministic(lf)
	if err != nil {
		return fmt.Errorf("marshaling remotes lock: %w", err)
	}
	if err := tx.WriteAtomicPath(path, data, 0644); err != nil {
		return fmt.Errorf("writing remotes lock atomically: %w", err)
	}
	return nil
}
