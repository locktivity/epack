package remoteconfig

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/locktivity/epack/internal/component/config"
	"github.com/locktivity/epack/internal/component/github"
	"github.com/locktivity/epack/internal/component/lockfile"
	"github.com/locktivity/epack/internal/project"
)

// Component is one collector, tool, or remote a configuration runs, with the
// publisher it comes from.
type Component struct {
	Name    string `json:"name"`
	Kind    string `json:"kind"`
	Owner   string `json:"owner,omitempty"`
	Repo    string `json:"repo,omitempty"`
	Version string `json:"version,omitempty"`
	Binary  string `json:"binary,omitempty"`
}

// Publisher is where the component's binary is built, as shown to a person.
func (c Component) Publisher() string {
	if c.Binary != "" {
		return "local binary " + c.Binary
	}
	return "github.com/" + c.Owner
}

// Label is the name with the version a person would recognise.
func (c Component) Label() string {
	if c.Version == "" {
		return c.Name
	}
	return c.Name + " " + c.Version
}

// EnvVar is an environment variable the configuration reads, with the
// components that receive it and whether it is set right now.
type EnvVar struct {
	Name   string   `json:"name"`
	Set    bool     `json:"set"`
	UsedBy []string `json:"used_by"`
}

// Hook is a hook script in the folder and whether it is still the remote's
// template.
type Hook struct {
	Path     string `json:"path"`
	Template bool   `json:"template"`
}

// Summary is what a configuration will do when it runs, read from the files
// on disk rather than from anything the remote said about them.
type Summary struct {
	Collectors []Component `json:"collectors"`
	Tools      []Component `json:"tools"`
	Remotes    []Component `json:"remotes"`
	Env        []EnvVar    `json:"env"`
	Hooks      []Hook      `json:"hooks"`
	Locked     bool        `json:"locked"`
}

// Summarize reads the project in dir. getenv decides which variables count
// as set; nil means the process environment.
func Summarize(dir string, getenv func(string) string) (*Summary, error) {
	if getenv == nil {
		getenv = os.Getenv
	}
	cfg, err := config.Load(filepath.Join(dir, project.ConfigFileName))
	if err != nil {
		return nil, err
	}
	lf, err := lockfile.Load(filepath.Join(dir, lockfile.FileName))
	locked := err == nil
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("reading lockfile: %w", err)
	}

	summary := &Summary{Locked: locked}
	env := map[string]*EnvVar{}
	collect := func(kind, name, source, binary string, secrets []string, version string) {
		component := describeComponent(kind, name, source, binary, version)
		switch kind {
		case "collector":
			summary.Collectors = append(summary.Collectors, component)
		case "tool":
			summary.Tools = append(summary.Tools, component)
		default:
			summary.Remotes = append(summary.Remotes, component)
		}
		for _, secret := range secrets {
			entry, ok := env[secret]
			if !ok {
				entry = &EnvVar{Name: secret, Set: getenv(secret) != ""}
				env[secret] = entry
			}
			entry.UsedBy = append(entry.UsedBy, name)
		}
	}

	for _, name := range sortedKeys(cfg.Collectors) {
		c := cfg.Collectors[name]
		version := ""
		if locked {
			if entry, ok := lf.GetCollector(name); ok {
				version = entry.Version
			}
		}
		collect("collector", name, c.Source, c.Binary, c.Secrets, version)
	}
	for _, name := range sortedKeys(cfg.Tools) {
		t := cfg.Tools[name]
		version := ""
		if locked {
			if entry, ok := lf.GetTool(name); ok {
				version = entry.Version
			}
		}
		collect("tool", name, t.Source, t.Binary, t.Secrets, version)
	}
	for _, name := range sortedKeys(cfg.Remotes) {
		r := cfg.Remotes[name]
		version := ""
		if locked {
			if entry, ok := lf.GetRemote(name); ok {
				version = entry.Version
			}
		}
		collect("remote", name, r.Source, r.Binary, r.Secrets, version)
	}

	for _, name := range sortedKeys(env) {
		summary.Env = append(summary.Env, *env[name])
	}

	hookPaths, _ := filepath.Glob(filepath.Join(dir, ".epack", "hooks", "*.sh"))
	sort.Strings(hookPaths)
	for _, hookPath := range hookPaths {
		rel, err := filepath.Rel(dir, hookPath)
		if err != nil {
			continue
		}
		rel = filepath.ToSlash(rel)
		template, err := IsRemoteTemplate(dir, rel)
		if err != nil {
			return nil, err
		}
		summary.Hooks = append(summary.Hooks, Hook{Path: rel, Template: template})
	}
	return summary, nil
}

func describeComponent(kind, name, source, binary, lockedVersion string) Component {
	component := Component{Name: name, Kind: kind, Binary: binary, Version: lockedVersion}
	if source == "" {
		return component
	}
	owner, repo, constraint, err := github.ParseSource(source)
	if err != nil {
		component.Owner = source
		return component
	}
	component.Owner = owner
	component.Repo = repo
	if component.Version == "" {
		component.Version = constraint
	}
	return component
}

// VersionChange records a component whose version moved between revisions.
type VersionChange struct {
	Name string `json:"name"`
	Kind string `json:"kind"`
	From string `json:"from"`
	To   string `json:"to"`
}

// Changes is what a newer revision does differently from the one before.
type Changes struct {
	Added   []Component     `json:"added"`
	Removed []Component     `json:"removed"`
	Changed []VersionChange `json:"changed"`
	NewEnv  []EnvVar        `json:"new_env"`
}

// Empty reports whether nothing a person would care about changed.
func (c *Changes) Empty() bool {
	return c == nil || len(c.Added)+len(c.Removed)+len(c.Changed)+len(c.NewEnv) == 0
}

// Diff compares what two revisions run and read.
func Diff(before, after *Summary) *Changes {
	changes := &Changes{}
	previous := map[string]Component{}
	for _, component := range before.components() {
		previous[component.Kind+"/"+component.Name] = component
	}
	current := map[string]bool{}
	for _, component := range after.components() {
		key := component.Kind + "/" + component.Name
		current[key] = true
		old, ok := previous[key]
		switch {
		case !ok:
			changes.Added = append(changes.Added, component)
		case old.Version != component.Version || old.Owner != component.Owner || old.Repo != component.Repo:
			changes.Changed = append(changes.Changed, VersionChange{Name: component.Name, Kind: component.Kind, From: old.Label(), To: component.Label()})
		}
	}
	for _, component := range before.components() {
		if !current[component.Kind+"/"+component.Name] {
			changes.Removed = append(changes.Removed, component)
		}
	}
	known := map[string]bool{}
	for _, v := range before.Env {
		known[v.Name] = true
	}
	for _, v := range after.Env {
		if !known[v.Name] {
			changes.NewEnv = append(changes.NewEnv, v)
		}
	}
	return changes
}

func (s *Summary) components() []Component {
	all := make([]Component, 0, len(s.Collectors)+len(s.Tools)+len(s.Remotes))
	all = append(all, s.Collectors...)
	all = append(all, s.Tools...)
	all = append(all, s.Remotes...)
	return all
}

func sortedKeys[T any](m map[string]T) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// PublisherGroups joins components by publisher in first-seen order, for a
// one-line listing such as "tls v0.1.4, dns v0.2.0 from github.com/locktivity".
func PublisherGroups(components []Component) []string {
	order := []string{}
	byPublisher := map[string][]string{}
	for _, component := range components {
		publisher := component.Publisher()
		if _, seen := byPublisher[publisher]; !seen {
			order = append(order, publisher)
		}
		byPublisher[publisher] = append(byPublisher[publisher], component.Label())
	}
	groups := make([]string, 0, len(order))
	for _, publisher := range order {
		groups = append(groups, strings.Join(byPublisher[publisher], ", ")+" from "+publisher)
	}
	return groups
}
