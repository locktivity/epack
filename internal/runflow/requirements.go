package runflow

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/locktivity/epack/internal/component/config"
	"github.com/locktivity/epack/internal/component/semver"
	"github.com/locktivity/epack/internal/lockprovenance"
	"github.com/locktivity/epack/internal/project"
	"github.com/locktivity/epack/internal/remote"
	"github.com/locktivity/epack/internal/remoteconfig"
	"github.com/locktivity/epack/internal/secrets"
	"github.com/locktivity/epack/internal/trustedpublishers"
)

// FailureRequirements is the code a run reports when the revision it
// fetched needs something this runner lacks and no earlier revision it ran
// can stand in.
const FailureRequirements = "requirements_missing"

// MissingRequirement is one thing a fetched revision needs that this runner
// lacks. Fix is the step that supplies it, when epack knows one.
type MissingRequirement struct {
	remote.Requirement
	Fix string
}

// Problem says what is missing, without a value.
func (m MissingRequirement) Problem() string {
	switch m.Kind {
	case remote.RequirementVariable:
		return m.Name + " is not set"
	case remote.RequirementSecretApproval:
		return m.Name + " is stored but not approved for what reads it now"
	case remote.RequirementPublisher:
		return "github.com/" + m.Name + " is not a trusted publisher here"
	case remote.RequirementEpack:
		return "epack " + strings.TrimPrefix(m.Name, "v") + " or later is needed"
	default:
		return m.Name
	}
}

// MissingRequirements lists what the configuration in opts.WorkDir needs
// that this runner lacks, the way a check decides it. A fetched revision
// came through a sign-in, so the remote's own variables are covered. In a
// terminal a new publisher is offered once, as a run offers it.
func MissingRequirements(opts Options) ([]MissingRequirement, error) {
	opts, err := withDefaults(opts)
	if err != nil {
		return nil, err
	}
	cfg, err := config.Load(filepath.Join(opts.WorkDir, project.ConfigFileName))
	if err != nil {
		return nil, fmt.Errorf("loading config: %w", err)
	}
	state, err := remoteconfig.LoadState(opts.WorkDir)
	if err != nil {
		return nil, fmt.Errorf("reading the pull record: %w", err)
	}
	remoteName, err := ResolveRemote(cfg, opts.Remote)
	if err != nil {
		return nil, err
	}
	missing, opts, err := lacksTrust(cfg, state, opts)
	if err != nil {
		return nil, err
	}
	variables, _, err := lacksVariables(cfg, opts, remoteName, true)
	if err != nil {
		return nil, err
	}
	return append(missing, variables...), nil
}

// lacksTrust is what has to hold before anything installs: an epack at
// least as new as the revision needs, and trust in each publisher it
// installs from. With a publisher untrusted, the secret store stays closed.
func lacksTrust(cfg *config.JobConfig, state *remoteconfig.State, opts Options) ([]MissingRequirement, Options, error) {
	var missing []MissingRequirement
	if opts.Requirements != nil && olderEpack(opts.Version, opts.Requirements.Epack) {
		missing = append(missing, MissingRequirement{
			Requirement: remote.Requirement{Kind: remote.RequirementEpack, Name: opts.Requirements.Epack},
			Fix:         "upgrade epack to " + opts.Requirements.Epack + " or later",
		})
	}
	if err := checkPublishers(cfg, state, opts); err != nil {
		var trustErr *trustedpublishers.Error
		if !errors.As(err, &trustErr) {
			return nil, opts, err
		}
		for _, req := range trustErr.Missing {
			missing = append(missing, MissingRequirement{
				Requirement: remote.Requirement{Kind: remote.RequirementPublisher, Name: req.Publisher},
				Fix:         fmt.Sprintf("add %s to %s", req.Publisher, trustedpublishers.EnvVar),
			})
		}
		opts.SkipSecretStore = true
	}
	return missing, opts, nil
}

// lacksVariables is each variable or keychain secret the components read
// that is missing or waiting for approval. A signed-in run leaves out the
// remote's own variables, since the sign-in stands in for them.
func lacksVariables(cfg *config.JobConfig, opts Options, remoteName string, signedIn bool) ([]MissingRequirement, *secrets.Resolution, error) {
	resolution, err := resolveSecrets(cfg, opts, remoteName, coveredNames(cfg, signedIn))
	if err != nil {
		return nil, nil, err
	}
	var missing []MissingRequirement
	for _, row := range resolution.Blocking() {
		switch row.Status {
		case secrets.StatusMissing:
			missing = append(missing, MissingRequirement{Requirement: remote.Requirement{Kind: remote.RequirementVariable, Name: row.Name}, Fix: row.Fix})
		case secrets.StatusApprovalNeeded:
			missing = append(missing, MissingRequirement{Requirement: remote.Requirement{Kind: remote.RequirementSecretApproval, Name: row.Name}, Fix: row.Fix})
		}
	}
	return missing, resolution, nil
}

// olderEpack reports whether running is a release older than needed. A
// build without a release version, such as a local one, is never older.
func olderEpack(running, needed string) bool {
	if strings.TrimSpace(needed) == "" {
		return false
	}
	have, err := semver.ParseVersion(running)
	if err != nil {
		return false
	}
	want, err := semver.ParseVersion(needed)
	if err != nil {
		return false
	}
	return semver.Compare(have, want) < 0
}

// Requirements returns the bare requirements, the way the remote takes them.
func Requirements(missing []MissingRequirement) []remote.Requirement {
	out := make([]remote.Requirement, 0, len(missing))
	for _, m := range missing {
		out = append(out, m.Requirement)
	}
	return out
}

// RequirementsReport is the report a run for pipelineID sends when it stops
// before installing anything: the revision in workDir needs what missing
// lists, and no earlier revision runs without what lacking lists, which
// also names what the earlier revisions it was offered needed.
func RequirementsReport(workDir, pipelineID string, revision int, missing, lacking []MissingRequirement) (*lockprovenance.Provenance, error) {
	names := make([]string, 0, len(missing))
	for _, m := range missing {
		names = append(names, m.Name)
	}
	return lockprovenance.Build(lockprovenance.Options{
		ProjectRoot:    workDir,
		Getenv:         withPipelineID(pipelineID),
		TriggerKind:    lockprovenance.TriggerFrozenCheck,
		Outcome:        lockprovenance.OutcomeFailure,
		FailureCode:    FailureRequirements,
		FailureMessage: fmt.Sprintf("revision %d needs %s", revision, strings.Join(names, ", ")),
		Metadata: map[string]any{
			"requirements": map[string]any{"revision": revision, "missing": Requirements(lacking)},
		},
	})
}

// withPipelineID reads the environment with the pipeline named, as a job's
// variables would name it.
func withPipelineID(pipelineID string) func(string) string {
	return func(name string) string {
		if name == PipelineIDEnvVar && pipelineID != "" {
			return pipelineID
		}
		return os.Getenv(name)
	}
}
