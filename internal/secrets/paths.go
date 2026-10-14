package secrets

import (
	"path/filepath"

	"github.com/locktivity/epack/internal/safefile"
	"github.com/locktivity/epack/internal/userconfig"
)

// Paths is where epack keeps what it knows about stored secrets, never the
// values: the metadata file, the approved configuration snapshots, and the
// lock files, all under the user config directory and readable only by the
// user.
type Paths struct {
	Root string
}

// DefaultPaths points at ~/.epack.
func DefaultPaths() (Paths, error) {
	dir, err := userconfig.Dir()
	if err != nil {
		return Paths{}, err
	}
	return Paths{Root: dir}, nil
}

func (p Paths) metadataFile() string { return filepath.Join(p.Root, "secrets.yaml") }
func (p Paths) secretsDir() string   { return filepath.Join(p.Root, "secrets") }
func (p Paths) snapshotsDir() string { return filepath.Join(p.secretsDir(), "snapshots") }
func (p Paths) locksDir() string     { return filepath.Join(p.secretsDir(), "locks") }

func (p Paths) ensure() error {
	if err := safefile.EnsureBaseDir(p.Root); err != nil {
		return err
	}
	for _, dir := range []string{p.secretsDir(), p.snapshotsDir(), p.locksDir()} {
		if err := safefile.MkdirAllPrivate(p.Root, dir); err != nil {
			return err
		}
	}
	return nil
}
