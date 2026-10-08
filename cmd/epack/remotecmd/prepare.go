//go:build components

package remotecmd

import (
	"context"
	"fmt"
	"io"
	"path/filepath"

	"github.com/locktivity/epack/internal/component/config"
	"github.com/locktivity/epack/internal/project"
	"github.com/locktivity/epack/internal/remote"
	"github.com/locktivity/epack/internal/securityaudit"
	"github.com/locktivity/epack/internal/securitypolicy"
	"github.com/locktivity/epack/internal/trustedpublishers"
	"github.com/locktivity/epack/internal/userremote"
)

// PreparedRemote is an adapter ready to run for one remote: the project's
// pinned adapter when the current project names the remote, otherwise the
// adapter installed for the user.
type PreparedRemote struct {
	Name        string
	Exec        *remote.Executor
	Caps        *remote.Capabilities
	Target      remote.TargetConfig
	ProjectRoot string
	// Publisher is the GitHub owner the adapter was installed from, empty
	// for an adapter run from a local binary.
	Publisher string
}

// Close releases the adapter.
func (p *PreparedRemote) Close() {
	if p != nil && p.Exec != nil {
		p.Exec.Close()
	}
}

// PrepareOptions controls how the adapter is found and verified.
type PrepareOptions struct {
	AllowUnpinned bool
	Step          remote.StepCallback
	PromptInstall remote.PromptInstallFunc
	Stderr        io.Writer
}

// PrepareRemote resolves, verifies, and probes the adapter for remoteName.
func PrepareRemote(ctx context.Context, remoteName string, opts PrepareOptions) (*PreparedRemote, error) {
	projectRoot, cfg, remoteCfg, err := projectRemote(remoteName)
	if err != nil {
		return nil, err
	}
	verification := remote.VerificationOptions{
		Unsafe: remote.VerificationUnsafeOverrides{AllowUnverifiedSource: opts.AllowUnpinned},
	}
	if remoteCfg != nil {
		if err := validateRemoteCommandFlags(opts.Stderr, remoteName, remoteCfg, opts.AllowUnpinned); err != nil {
			return nil, err
		}
		exec, caps, err := remote.PrepareAdapterExecutor(ctx, projectRoot, remoteName, cfg, remoteCfg, remote.AdapterExecutorOptions{
			PromptInstall: opts.PromptInstall,
			Step:          opts.Step,
			Stderr:        opts.Stderr,
			Verification:  verification,
		})
		if err != nil {
			return nil, err
		}
		return &PreparedRemote{
			Name:        remoteName,
			Exec:        exec,
			Caps:        caps,
			Target:      remote.TargetConfig{Workspace: remoteCfg.Target.Workspace, Environment: remoteCfg.Target.Environment},
			ProjectRoot: projectRoot,
			Publisher:   publisherOf(remoteCfg.Source),
		}, nil
	}
	if err := validateUserRemoteFlags(opts.AllowUnpinned); err != nil {
		return nil, err
	}
	resolver, err := userremote.New()
	if err != nil {
		return nil, err
	}
	resolver.Stderr = opts.Stderr
	resolver.Step = opts.Step
	resolver.Verification = verification
	exec, caps, err := resolver.Prepare(ctx, remoteName)
	if err != nil {
		return nil, err
	}
	source, err := resolver.Source(remoteName)
	if err != nil {
		exec.Close()
		return nil, err
	}
	return &PreparedRemote{Name: remoteName, Exec: exec, Caps: caps, Publisher: publisherOf(source)}, nil
}

func publisherOf(source string) string {
	owner, _, ok := trustedpublishers.OwnerRepo(source)
	if !ok {
		return ""
	}
	return owner
}

// projectRemote returns the current project's config for remoteName, or nil
// configs when there is no project here or it does not name the remote.
func projectRemote(remoteName string) (string, *config.JobConfig, *config.RemoteConfig, error) {
	projectRoot, err := project.FindRoot("")
	if err != nil {
		return "", nil, nil, nil
	}
	cfg, err := config.Load(filepath.Join(projectRoot, project.ConfigFileName))
	if err != nil {
		return "", nil, nil, fmt.Errorf("loading config: %w", err)
	}
	if _, ok := cfg.Remotes[remoteName]; !ok {
		return "", nil, nil, nil
	}
	remoteCfg, err := remote.ResolveRemoteConfig(cfg, remoteName, "")
	if err != nil {
		return "", nil, nil, err
	}
	return projectRoot, cfg, remoteCfg, nil
}

func validateUserRemoteFlags(allowUnpinned bool) error {
	return securitypolicy.EnforceStrictProduction("remote_cli", allowUnpinned)
}

func validateRemoteCommandFlags(stderr io.Writer, remoteName string, remoteCfg *config.RemoteConfig, allowUnpinned bool) error {
	hasUnsafeOverrides := allowUnpinned
	attrs := map[string]string{}
	if allowUnpinned {
		attrs["insecure_allow_unpinned"] = "true"
	}

	state, err := inspectRemoteInsecureState(remoteCfg)
	if err != nil {
		return err
	}
	warnRemoteCustomEndpoints(stderr, state.override)
	if state.override.Active() {
		hasUnsafeOverrides = true
		mergeAuditAttrs(attrs, state.attrs)
	}

	if err := securitypolicy.EnforceStrictProduction("remote_cli", hasUnsafeOverrides); err != nil {
		return err
	}
	if hasUnsafeOverrides {
		securityaudit.Emit(securityaudit.Event{
			Type:        securityaudit.EventInsecureBypass,
			Component:   "remote",
			Name:        remoteName,
			Description: "remote command running with insecure execution override",
			Attrs:       attrs,
		})
	}
	return nil
}
