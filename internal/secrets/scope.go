package secrets

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"github.com/locktivity/epack/internal/remoteconfig"
)

// PipelineIDEnvVar names the configuration a folder belongs to when the
// folder carries no pull record; runflow exports it from the record.
const PipelineIDEnvVar = "EPACK_PIPELINE_ID"

// Scope is where a value is stored: one configuration on one remote. Label
// is the configuration's name for messages; it is not part of the key.
type Scope struct {
	Remote        string
	Configuration string
	Label         string
	Revision      int
}

// Key identifies the scope in metadata.
func (s Scope) Key() string { return s.Remote + ":" + s.Configuration }

// Service is the keychain service string.
func (s Scope) Service() string { return "epack:" + s.Remote + ":" + s.Configuration }

// String names the scope for a person.
func (s Scope) String() string {
	label := s.Label
	if label == "" {
		label = s.Configuration
	}
	if s.Remote == "" {
		return label
	}
	return label + " on " + s.Remote
}

// Zero reports whether the scope has no configuration.
func (s Scope) Zero() bool { return s.Configuration == "" }

// fileStem is a filesystem-safe name for the scope's lock file.
func (s Scope) fileStem() string {
	sum := sha256.Sum256([]byte(s.Remote + "\x00" + s.Configuration))
	return hex.EncodeToString(sum[:16])
}

// ScopeFor reads the folder's pull record and names the scope: the remote
// the run uses and the configuration's identifier, from EPACK_PIPELINE_ID
// when set, else from the record. A folder without either has no scope.
func ScopeFor(workDir, remoteName string, getenv func(string) string) (Scope, error) {
	if getenv == nil {
		getenv = func(string) string { return "" }
	}
	state, err := remoteconfig.LoadState(workDir)
	if err != nil {
		return Scope{}, err
	}
	scope := Scope{Remote: remoteName, Configuration: strings.TrimSpace(getenv(PipelineIDEnvVar))}
	if state != nil {
		if scope.Configuration == "" {
			scope.Configuration = state.ID
		}
		scope.Label = state.Name
		scope.Revision = state.Revision
		if scope.Remote == "" {
			scope.Remote = state.Remote
		}
	}
	if scope.Configuration == "" || scope.Remote == "" {
		return Scope{}, nil
	}
	return scope, nil
}

// InCI reports whether the process runs in a CI job, where the store is
// never consulted and variables come from the platform through the
// environment.
func InCI(getenv func(string) string) bool {
	if getenv == nil {
		return false
	}
	for _, name := range []string{"CI", "GITHUB_ACTIONS", "GITLAB_CI"} {
		if strings.TrimSpace(getenv(name)) != "" {
			return true
		}
	}
	return false
}
