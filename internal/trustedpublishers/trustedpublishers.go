// Package trustedpublishers decides whether a fetched configuration may run
// the components it names. A publisher is the GitHub owner of a component's
// source repository, the identity Sigstore attests at install time.
package trustedpublishers

import (
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/locktivity/epack/internal/component/config"
)

// EnvVar lists publishers trusted for one process, comma separated.
const EnvVar = "EPACK_TRUSTED_PUBLISHERS"

// Flag is the command-line form of the same grant.
const Flag = "--trust-publisher"

var namePattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,37}[a-z0-9])?$`)

// Requirement is a publisher a configuration draws from and the
// repositories it draws.
type Requirement struct {
	Publisher    string
	Repositories []string
}

// Normalize folds a publisher name the way the comparison does.
func Normalize(name string) string {
	return strings.ToLower(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(name), "github.com/")))
}

// Validate reports whether a name can be a GitHub owner.
func Validate(name string) error {
	if !namePattern.MatchString(Normalize(name)) {
		return fmt.Errorf("invalid publisher name %q: expected a GitHub owner such as locktivity", name)
	}
	return nil
}

// OwnerRepo splits a component source into its owner and repository,
// accepting the forms a configuration uses: owner/repo@range,
// github.com/owner/repo, and https://github.com/owner/repo.
func OwnerRepo(source string) (owner, repo string, ok bool) {
	trimmed := strings.TrimSpace(source)
	trimmed = strings.TrimPrefix(trimmed, "https://")
	trimmed = strings.TrimPrefix(trimmed, "github.com/")
	if at := strings.Index(trimmed, "@"); at >= 0 {
		trimmed = trimmed[:at]
	}
	parts := strings.Split(trimmed, "/")
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return "", "", false
	}
	return Normalize(parts[0]), strings.TrimSuffix(parts[1], ".git"), true
}

// Required lists the publishers a configuration needs, with their
// repositories. A component that runs a local binary has no publisher and
// is refused: a fetched configuration may only name published components.
func Required(cfg *config.JobConfig) ([]Requirement, error) {
	repos := map[string]map[string]struct{}{}
	add := func(kind, name, source, binary string) error {
		if binary != "" {
			return fmt.Errorf("%s %s runs a local binary (%s); a fetched configuration may only name published components", kind, name, binary)
		}
		owner, repo, ok := OwnerRepo(source)
		if !ok {
			return fmt.Errorf("%s %s: cannot tell the publisher of source %q", kind, name, source)
		}
		if repos[owner] == nil {
			repos[owner] = map[string]struct{}{}
		}
		repos[owner][owner+"/"+repo] = struct{}{}
		return nil
	}
	for _, name := range sortedKeys(cfg.Collectors) {
		c := cfg.Collectors[name]
		if err := add("collector", name, c.Source, c.Binary); err != nil {
			return nil, err
		}
	}
	for _, name := range sortedKeys(cfg.Tools) {
		t := cfg.Tools[name]
		if err := add("tool", name, t.Source, t.Binary); err != nil {
			return nil, err
		}
	}
	for _, name := range sortedKeys(cfg.Remotes) {
		r := cfg.Remotes[name]
		if err := add("remote", name, r.Source, r.Binary); err != nil {
			return nil, err
		}
	}

	out := make([]Requirement, 0, len(repos))
	for _, owner := range sortedKeys(repos) {
		out = append(out, Requirement{Publisher: owner, Repositories: sortedKeys(repos[owner])})
	}
	return out, nil
}

// Set is the trust in force for one process.
type Set map[string]struct{}

// NewSet builds a set from names, normalizing each.
func NewSet(names ...string) Set {
	s := Set{}
	s.Add(names...)
	return s
}

// Add records more names.
func (s Set) Add(names ...string) {
	for _, name := range names {
		if normalized := Normalize(name); normalized != "" {
			s[normalized] = struct{}{}
		}
	}
}

// Has reports whether the publisher is trusted.
func (s Set) Has(name string) bool {
	_, ok := s[Normalize(name)]
	return ok
}

// AddFromEnv records the publishers named in EnvVar.
func (s Set) AddFromEnv(getenv func(string) string) {
	if getenv == nil {
		getenv = os.Getenv
	}
	for _, name := range strings.FieldsFunc(getenv(EnvVar), func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == '\t' }) {
		s.Add(name)
	}
}

// Missing returns the requirements the set does not cover.
func Missing(required []Requirement, trusted Set) []Requirement {
	var missing []Requirement
	for _, req := range required {
		if !trusted.Has(req.Publisher) {
			missing = append(missing, req)
		}
	}
	return missing
}

// Error names what a run could not trust and how to grant it.
type Error struct {
	Missing []Requirement
}

func (e *Error) Error() string {
	var b strings.Builder
	b.WriteString("this configuration runs components from publishers you have not trusted:\n")
	names := make([]string, 0, len(e.Missing))
	for _, req := range e.Missing {
		fmt.Fprintf(&b, "  github.com/%s: %s\n", req.Publisher, strings.Join(req.Repositories, ", "))
		names = append(names, req.Publisher)
	}
	joined := strings.Join(names, ",")
	fmt.Fprintf(&b, "In a job, set %s=%s. In a terminal, run without --yes to be asked once, or pass %s %s.", EnvVar, joined, Flag, names[0])
	return b.String()
}

func sortedKeys[T any](m map[string]T) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
