package secrets

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"

	"github.com/locktivity/epack/internal/component/config"
	"github.com/locktivity/epack/internal/component/github"
	"github.com/locktivity/epack/internal/yamlutil"
)

// Reader is a component that lists a secret, as it was when the secret was
// approved: its name, kind, publisher, and a digest of its whole entry in
// epack.yaml.
type Reader struct {
	Name        string `yaml:"name" json:"name"`
	Kind        string `yaml:"kind" json:"kind"`
	Publisher   string `yaml:"publisher" json:"publisher"`
	EntryDigest string `yaml:"entry_digest" json:"entry_digest"`
}

// Label names the reader for a person: "microsoft-cloud (github.com/locktivity)".
func (r Reader) Label() string {
	if r.Publisher == "" {
		return r.Name
	}
	return r.Name + " (" + r.Publisher + ")"
}

func (r Reader) key() string { return r.Kind + "/" + r.Name }

// listedSecret is one variable a configuration lists, with everything that
// reads it. Optional means every reader marked it optional.
type listedSecret struct {
	name     string
	readers  []Reader
	optional bool
}

// listedSecrets collects every variable the configuration lists, sorted by
// name, the way the summary and the check count them.
func listedSecrets(cfg *config.JobConfig) []listedSecret {
	byName := map[string]*listedSecret{}
	add := func(reader Reader, secrets config.SecretList) {
		for _, secret := range secrets {
			entry, ok := byName[secret.Name]
			if !ok {
				entry = &listedSecret{name: secret.Name, optional: true}
				byName[secret.Name] = entry
			}
			entry.optional = entry.optional && secret.Optional
			entry.readers = append(entry.readers, reader)
		}
	}
	for _, name := range sortedKeys(cfg.Collectors) {
		c := cfg.Collectors[name]
		add(Reader{Name: name, Kind: "collector", Publisher: publisherOf(c.Source, c.Binary), EntryDigest: entryDigest(c)}, c.Secrets)
	}
	for _, name := range sortedKeys(cfg.Tools) {
		t := cfg.Tools[name]
		add(Reader{Name: name, Kind: "tool", Publisher: publisherOf(t.Source, t.Binary), EntryDigest: entryDigest(t)}, t.Secrets)
	}
	for _, name := range sortedKeys(cfg.Remotes) {
		r := cfg.Remotes[name]
		add(Reader{Name: name, Kind: "remote", Publisher: publisherOf(r.Source, r.Binary), EntryDigest: entryDigest(r)}, r.Secrets)
	}
	names := make([]string, 0, len(byName))
	for name := range byName {
		names = append(names, name)
	}
	sort.Strings(names)
	listed := make([]listedSecret, 0, len(names))
	for _, name := range names {
		listed = append(listed, *byName[name])
	}
	return listed
}

// ReadersOf lists the components that read a variable, sorted by kind and
// name.
func ReadersOf(cfg *config.JobConfig, name string) []Reader {
	for _, listed := range listedSecrets(cfg) {
		if listed.name == name {
			return listed.readers
		}
	}
	return nil
}

func entryDigest(entry any) string {
	data, err := yamlutil.MarshalDeterministic(entry)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func publisherOf(source, binary string) string {
	if source != "" {
		if owner, _, _, err := github.ParseSource(source); err == nil {
			return "github.com/" + strings.ToLower(owner)
		}
		return source
	}
	if binary != "" {
		return "a local binary"
	}
	return ""
}

func readerNames(readers []Reader) []string {
	names := make([]string, 0, len(readers))
	for _, reader := range readers {
		names = append(names, reader.Name)
	}
	return names
}

func sortedKeys[T any](m map[string]T) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
