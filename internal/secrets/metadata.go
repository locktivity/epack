package secrets

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/locktivity/epack/internal/limits"
	"github.com/locktivity/epack/internal/safefile"
	"github.com/locktivity/epack/internal/safefile/tx"
	"github.com/locktivity/epack/internal/safeyaml"
	"github.com/locktivity/epack/internal/yamlutil"
)

// Metadata is what epack records about stored secrets: which scope and name
// each belongs to, where it is kept, when, and what it was approved for.
// Values are never in it.
type Metadata struct {
	Version int                     `yaml:"version"`
	Scopes  map[string]*ScopeRecord `yaml:"scopes,omitempty"`
}

// ScopeRecord holds one configuration's secrets.
type ScopeRecord struct {
	Remote        string                   `yaml:"remote"`
	Configuration string                   `yaml:"configuration"`
	Label         string                   `yaml:"label,omitempty"`
	Secrets       map[string]*SecretRecord `yaml:"secrets,omitempty"`
}

// SecretRecord describes one stored value without holding it.
type SecretRecord struct {
	Store    string    `yaml:"store"`
	StoredAt string    `yaml:"stored_at"`
	Approved *Approval `yaml:"approved,omitempty"`
}

// Approval is the configuration a secret was approved for: the readers as
// they were, each with a digest of its entry, and the digest of the fetched
// file, whose snapshot lets a later change be shown.
type Approval struct {
	At           string   `yaml:"at"`
	Revision     int      `yaml:"revision,omitempty"`
	ConfigDigest string   `yaml:"config_digest"`
	Readers      []Reader `yaml:"readers"`
}

var snapshotName = regexp.MustCompile(`^[0-9a-f]{64}$`)

func (p Paths) loadMetadata() (*Metadata, error) {
	m := &Metadata{Version: 1, Scopes: map[string]*ScopeRecord{}}
	data, err := safefile.ReadFile(p.metadataFile(), limits.ConfigFile)
	if os.IsNotExist(err) {
		return m, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", p.metadataFile(), err)
	}
	if err := safeyaml.Unmarshal(data, limits.ConfigFile, m); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", p.metadataFile(), err)
	}
	if m.Scopes == nil {
		m.Scopes = map[string]*ScopeRecord{}
	}
	for _, scope := range m.Scopes {
		if scope.Secrets == nil {
			scope.Secrets = map[string]*SecretRecord{}
		}
	}
	return m, nil
}

func (p Paths) saveMetadata(m *Metadata) error {
	if err := p.ensure(); err != nil {
		return err
	}
	m.Version = 1
	for key, scope := range m.Scopes {
		if len(scope.Secrets) == 0 {
			delete(m.Scopes, key)
		}
	}
	data, err := yamlutil.MarshalDeterministic(m)
	if err != nil {
		return fmt.Errorf("encoding secrets metadata: %w", err)
	}
	if err := tx.WriteAtomicPath(p.metadataFile(), data, limits.PrivateFileMode); err != nil {
		return fmt.Errorf("writing %s: %w", p.metadataFile(), err)
	}
	p.pruneSnapshots(m)
	return nil
}

func (m *Metadata) scope(s Scope, create bool) *ScopeRecord {
	record, ok := m.Scopes[s.Key()]
	if ok {
		if s.Label != "" {
			record.Label = s.Label
		}
		return record
	}
	if !create {
		return nil
	}
	record = &ScopeRecord{Remote: s.Remote, Configuration: s.Configuration, Label: s.Label, Secrets: map[string]*SecretRecord{}}
	m.Scopes[s.Key()] = record
	return record
}

func (m *Metadata) record(s Scope, name string) *SecretRecord {
	scope := m.scope(s, false)
	if scope == nil {
		return nil
	}
	return scope.Secrets[name]
}

// ConfigDigest names a fetched configuration file by content.
func ConfigDigest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func (p Paths) snapshotFile(digest string) (string, bool) {
	hexPart := strings.TrimPrefix(digest, "sha256:")
	if !snapshotName.MatchString(hexPart) {
		return "", false
	}
	return filepath.Join(p.snapshotsDir(), hexPart+".yaml"), true
}

func (p Paths) saveSnapshot(digest string, raw []byte) error {
	path, ok := p.snapshotFile(digest)
	if !ok {
		return fmt.Errorf("invalid configuration digest %q", digest)
	}
	if err := p.ensure(); err != nil {
		return err
	}
	if _, err := os.Stat(path); err == nil {
		return nil
	}
	return tx.WriteAtomicPath(path, raw, limits.PrivateFileMode)
}

func (p Paths) loadSnapshot(digest string) ([]byte, error) {
	path, ok := p.snapshotFile(digest)
	if !ok {
		return nil, os.ErrNotExist
	}
	return safefile.ReadFile(path, limits.ConfigFile)
}

// pruneSnapshots deletes snapshots no approval refers to.
func (p Paths) pruneSnapshots(m *Metadata) {
	referenced := map[string]bool{}
	for _, scope := range m.Scopes {
		for _, secret := range scope.Secrets {
			if secret.Approved != nil {
				referenced[strings.TrimPrefix(secret.Approved.ConfigDigest, "sha256:")] = true
			}
		}
	}
	entries, err := os.ReadDir(p.snapshotsDir())
	if err != nil {
		return
	}
	for _, entry := range entries {
		hexPart := strings.TrimSuffix(entry.Name(), ".yaml")
		if snapshotName.MatchString(hexPart) && !referenced[hexPart] {
			_ = os.Remove(filepath.Join(p.snapshotsDir(), entry.Name()))
		}
	}
}
