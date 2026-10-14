package runflow

import (
	"fmt"
	"os"
	"strings"

	"github.com/locktivity/epack/internal/component/config"
	"github.com/locktivity/epack/internal/secrets"
)

// resolveSecrets finds the values the configuration's components receive:
// the environment first, then the store for this folder's scope, never
// interactively. Covered names, which a signed-in session already provides,
// are left out.
func resolveSecrets(cfg *config.JobConfig, opts Options, remoteName string, covered map[string]bool) (*secrets.Resolution, error) {
	scope, err := secrets.ScopeFor(opts.WorkDir, remoteName, os.Getenv)
	if err != nil {
		return nil, fmt.Errorf("reading the pull record: %w", err)
	}
	resolver := secrets.Resolver{Paths: opts.SecretPaths, Store: opts.SecretStore, Env: os.Getenv}
	switch {
	case opts.SkipSecretStore:
		resolver.Skip, resolver.SkipReason = true, "the store is not consulted before publishers are trusted, or in CI"
	case secrets.InCI(os.Getenv):
		resolver.Skip, resolver.SkipReason = true, "running in CI"
	}
	return resolver.Resolve(cfg, scope, covered)
}

// coveredNames are the variables only remotes read. With a signed-in
// session they are the remote's fallback credential, which the run will not
// need.
func coveredNames(cfg *config.JobConfig, signedInAs string) map[string]bool {
	if signedInAs == "" {
		return nil
	}
	return remoteOnlyNames(cfg)
}

func remoteOnlyNames(cfg *config.JobConfig) map[string]bool {
	others := map[string]bool{}
	for _, c := range cfg.Collectors {
		for _, name := range c.Secrets.Names() {
			others[name] = true
		}
	}
	for _, t := range cfg.Tools {
		for _, name := range t.Secrets.Names() {
			others[name] = true
		}
	}
	covered := map[string]bool{}
	for _, r := range cfg.Remotes {
		for _, name := range r.Secrets.Names() {
			if !others[name] {
				covered[name] = true
			}
		}
	}
	return covered
}

// secretsError stops a run before collecting when a required variable is
// not ready, naming each one and the command that resolves it.
type secretsError struct {
	rows []secrets.Row
}

func (e *secretsError) Error() string {
	findings := make([]string, 0, len(e.rows))
	for _, row := range e.rows {
		findings = append(findings, row.Finding())
	}
	return strings.Join(findings, "; ")
}
