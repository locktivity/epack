package secrets

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/locktivity/epack/internal/component/config"
	"github.com/locktivity/epack/internal/execsafe"
	"github.com/locktivity/epack/internal/limits"
	"github.com/locktivity/epack/internal/project"
	"github.com/locktivity/epack/internal/safefile"
)

// Service is what the secret commands do: store, approve, list, and remove
// values for one configuration, holding the scope's lock for each.
type Service struct {
	Paths Paths
	Store Store
	// Now is the clock for stored-at and approved-at times; nil means time.Now.
	Now func() time.Time
}

// Configuration is a folder's epack.yaml, parsed and as written.
type Configuration struct {
	Config *config.JobConfig
	Raw    []byte
}

// LoadConfiguration reads the folder's epack.yaml.
func LoadConfiguration(workDir string) (*Configuration, error) {
	path := filepath.Join(workDir, project.ConfigFileName)
	cfg, err := config.Load(path)
	if err != nil {
		return nil, err
	}
	raw, err := safefile.ReadFile(path, limits.ConfigFile)
	if err != nil {
		return nil, err
	}
	return &Configuration{Config: cfg, Raw: raw}, nil
}

var namePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// ValidateName checks that a name can be an environment variable a
// configuration lists.
func ValidateName(name string) error {
	if !namePattern.MatchString(name) {
		return fmt.Errorf("%q is not a variable name", name)
	}
	return execsafe.ValidateSecretName(name)
}

// Entry is one stored secret as 'epack secret list' shows it.
type Entry struct {
	Name             string
	Readers          []Reader
	StoredAt         string
	ApprovedRevision int
	NeedsApproval    bool
	Reason           string
}

// Pending is one stored secret that needs approval, with what changed.
type Pending struct {
	Name             string
	ApprovedRevision int
	Changes          []Change
}

// Set stores a value and approves it for its readers as they are now,
// touching no other secret's approval. A name no component lists is refused
// unless unlisted is set.
func (s *Service) Set(scope Scope, name, value string, conf *Configuration, interactive, unlisted bool) ([]Reader, error) {
	if err := ValidateName(name); err != nil {
		return nil, err
	}
	if value == "" {
		return nil, fmt.Errorf("the value for %s is empty", name)
	}
	if len(value) > MaxValueBytes {
		return nil, &StoreError{Code: CodeTooLarge, Message: fmt.Sprintf("%s is %d bytes; the store holds up to %d", name, len(value), MaxValueBytes)}
	}
	readers := ReadersOf(conf.Config, name)
	if len(readers) == 0 && !unlisted {
		return nil, &UnlistedError{Name: name}
	}
	unlock, err := s.Paths.lockScope(scope, true)
	if err != nil {
		return nil, err
	}
	defer unlock()
	if err := s.Store.Set(scope, name, value, interactive); err != nil {
		return nil, err
	}
	meta, err := s.Paths.loadMetadata()
	if err != nil {
		return nil, err
	}
	record := meta.scope(scope, true)
	now := s.now()
	record.Secrets[name] = &SecretRecord{Store: s.Store.Kind(), StoredAt: now, Approved: s.approval(conf, name, scope, now)}
	if err := s.Paths.saveSnapshot(ConfigDigest(conf.Raw), conf.Raw); err != nil {
		return nil, err
	}
	if err := s.Paths.saveMetadata(meta); err != nil {
		return nil, err
	}
	return readers, nil
}

// Pending lists the stored secrets that need approval for the configuration
// as it is now, with what changed for each. With names, only those; without,
// every secret recorded for the scope plus any listed name the store holds
// without a record.
func (s *Service) Pending(scope Scope, conf *Configuration, names []string, interactive bool) ([]Pending, error) {
	unlock, err := s.Paths.lockScope(scope, false)
	if err != nil {
		return nil, err
	}
	defer unlock()
	meta, err := s.Paths.loadMetadata()
	if err != nil {
		return nil, err
	}
	record := meta.scope(scope, false)
	candidates := names
	if len(candidates) == 0 {
		seen := map[string]bool{}
		if record != nil {
			for name := range record.Secrets {
				seen[name] = true
				candidates = append(candidates, name)
			}
		}
		for _, listed := range listedSecrets(conf.Config) {
			if seen[listed.name] {
				continue
			}
			if _, err := s.Store.Get(scope, listed.name, interactive); err == nil {
				candidates = append(candidates, listed.name)
			}
		}
		sort.Strings(candidates)
	}
	var pending []Pending
	for _, name := range candidates {
		var secret *SecretRecord
		if record != nil {
			secret = record.Secrets[name]
		}
		var approved *Approval
		if secret != nil {
			approved = secret.Approved
		}
		if needed, _ := needsApproval(approved, ReadersOf(conf.Config, name)); !needed {
			continue
		}
		item := Pending{Name: name, Changes: outstanding(approved, s.snapshotConfig(approved), conf.Config, name)}
		if approved != nil {
			item.ApprovedRevision = approved.Revision
		}
		pending = append(pending, item)
	}
	return pending, nil
}

// Approve records the configuration as approved for one secret. A secret
// the store holds without a record gets one.
func (s *Service) Approve(scope Scope, name string, conf *Configuration, interactive bool) error {
	if err := ValidateName(name); err != nil {
		return err
	}
	unlock, err := s.Paths.lockScope(scope, true)
	if err != nil {
		return err
	}
	defer unlock()
	meta, err := s.Paths.loadMetadata()
	if err != nil {
		return err
	}
	record := meta.scope(scope, true)
	secret := record.Secrets[name]
	if secret == nil {
		if _, err := s.Store.Get(scope, name, interactive); err != nil {
			return err
		}
		secret = &SecretRecord{Store: s.Store.Kind(), StoredAt: s.now()}
		record.Secrets[name] = secret
	}
	secret.Approved = s.approval(conf, name, scope, s.now())
	if err := s.Paths.saveSnapshot(ConfigDigest(conf.Raw), conf.Raw); err != nil {
		return err
	}
	return s.Paths.saveMetadata(meta)
}

// List describes the secrets recorded for the scope against the
// configuration as it is now.
func (s *Service) List(scope Scope, conf *Configuration) ([]Entry, error) {
	meta, err := s.Paths.loadMetadata()
	if err != nil {
		return nil, err
	}
	record := meta.scope(scope, false)
	if record == nil {
		return nil, nil
	}
	entries := make([]Entry, 0, len(record.Secrets))
	for _, name := range sortedKeys(record.Secrets) {
		secret := record.Secrets[name]
		entry := Entry{Name: name, Readers: ReadersOf(conf.Config, name), StoredAt: secret.StoredAt}
		if secret.Approved != nil {
			entry.ApprovedRevision = secret.Approved.Revision
		}
		entry.NeedsApproval, entry.Reason = needsApproval(secret.Approved, entry.Readers)
		entries = append(entries, entry)
	}
	return entries, nil
}

// ScopeEntry is one configuration with stored secrets, for 'list --all'.
type ScopeEntry struct {
	Scope Scope
	Names []string
}

// ListAll names every scope on this machine with a stored secret.
func (s *Service) ListAll() ([]ScopeEntry, error) {
	meta, err := s.Paths.loadMetadata()
	if err != nil {
		return nil, err
	}
	entries := make([]ScopeEntry, 0, len(meta.Scopes))
	for _, key := range sortedKeys(meta.Scopes) {
		record := meta.Scopes[key]
		entries = append(entries, ScopeEntry{
			Scope: Scope{Remote: record.Remote, Configuration: record.Configuration, Label: record.Label},
			Names: sortedKeys(record.Secrets),
		})
	}
	return entries, nil
}

// Remove erases one value and its record.
func (s *Service) Remove(scope Scope, name string, interactive bool) error {
	if err := ValidateName(name); err != nil {
		return err
	}
	unlock, err := s.Paths.lockScope(scope, true)
	if err != nil {
		return err
	}
	defer unlock()
	if err := s.Store.Erase(scope, name, interactive); err != nil {
		return err
	}
	meta, err := s.Paths.loadMetadata()
	if err != nil {
		return err
	}
	if record := meta.scope(scope, false); record != nil {
		delete(record.Secrets, name)
	}
	return s.Paths.saveMetadata(meta)
}

func (s *Service) approval(conf *Configuration, name string, scope Scope, now string) *Approval {
	return &Approval{At: now, Revision: scope.Revision, ConfigDigest: ConfigDigest(conf.Raw), Readers: ReadersOf(conf.Config, name)}
}

func (s *Service) snapshotConfig(approved *Approval) *config.JobConfig {
	if approved == nil {
		return nil
	}
	raw, err := s.Paths.loadSnapshot(approved.ConfigDigest)
	if err != nil {
		return nil
	}
	cfg, err := config.Parse(raw)
	if err != nil {
		return nil
	}
	return cfg
}

func (s *Service) now() string {
	now := s.Now
	if now == nil {
		now = time.Now
	}
	return now().UTC().Format(time.RFC3339)
}

// ReadValue reads a value for 'epack secret set' from a file or from stdin,
// stripping exactly one trailing newline.
func ReadValue(path string, stdin func() ([]byte, error)) (string, error) {
	var data []byte
	var err error
	if path != "" {
		data, err = os.ReadFile(path)
	} else {
		data, err = stdin()
	}
	if err != nil {
		return "", err
	}
	value := string(data)
	value = strings.TrimSuffix(value, "\n")
	value = strings.TrimSuffix(value, "\r")
	return value, nil
}
