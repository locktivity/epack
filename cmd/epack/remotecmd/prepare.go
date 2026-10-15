//go:build components

package remotecmd

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	gosync "sync"

	"github.com/locktivity/epack/internal/broker"
	"github.com/locktivity/epack/internal/component/config"
	"github.com/locktivity/epack/internal/project"
	"github.com/locktivity/epack/internal/remote"
	"github.com/locktivity/epack/internal/securityaudit"
	"github.com/locktivity/epack/internal/securitypolicy"
	"github.com/locktivity/epack/internal/trustedpublishers"
	"github.com/locktivity/epack/internal/userconfig"
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

// PrepareOptions controls how the adapter is found and verified. Install
// decides whether a project's pinned adapter that is missing gets
// installed, and nil installs nothing. Pipeline signs a job in for its
// pipeline when no folder names the remote. TrustPublishers adds the
// publishers this run trusts.
type PrepareOptions struct {
	AllowUnpinned   bool
	Step            remote.StepCallback
	Install         InstallPolicy
	Stderr          io.Writer
	Pipeline        *broker.PipelineIdentity
	TrustPublishers []string
}

// InstallPolicy decides whether to install the adapter a project pins when
// it is not installed yet. publisher is who the lock pins it from, and
// trusted is every publisher the run trusts.
type InstallPolicy func(remoteName, adapterName, publisher string, trusted trustedpublishers.Set) bool

// AskToInstall leaves the install to the person at the terminal. Without a
// prompt it installs nothing.
func AskToInstall(prompt remote.PromptInstallFunc) InstallPolicy {
	if prompt == nil {
		return nil
	}
	return func(remoteName, adapterName, _ string, _ trustedpublishers.Set) bool {
		return prompt(remoteName, adapterName)
	}
}

// InstallTrustedPin installs without asking when the pin's publisher is
// trusted, as a run with nobody at the terminal needs. The install takes
// only the binary the lock pins and verifies it before it runs.
func InstallTrustedPin(_, _, publisher string, trusted trustedpublishers.Set) bool {
	return publisher != "" && trusted.Has(publisher)
}

// PrepareRemote resolves, verifies, and probes the adapter for remoteName.
func PrepareRemote(ctx context.Context, remoteName string, opts PrepareOptions) (*PreparedRemote, error) {
	projectRoot, cfg, remoteCfg, err := projectRemote(remoteName)
	if err != nil {
		return nil, err
	}
	trusted := gosync.OnceValues(func() (trustedpublishers.Set, error) {
		return userconfig.TrustedPublisherSet(opts.TrustPublishers...)
	})
	verification := remote.VerificationOptions{
		Unsafe: remote.VerificationUnsafeOverrides{AllowUnverifiedSource: opts.AllowUnpinned},
	}
	if remoteCfg == nil {
		return prepareUserRemote(ctx, remoteName, opts, verification, trusted)
	}
	if err := validateRemoteCommandFlags(opts.Stderr, remoteName, remoteCfg, opts.AllowUnpinned); err != nil {
		return nil, err
	}
	publisher := publisherOf(remoteCfg.Source)
	exec, caps, err := remote.PrepareAdapterExecutor(ctx, projectRoot, remoteName, cfg, remoteCfg, remote.AdapterExecutorOptions{
		PromptInstall: opts.promptInstall(publisher, trusted),
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
		Publisher:   publisher,
	}, nil
}

func (opts PrepareOptions) promptInstall(publisher string, trusted func() (trustedpublishers.Set, error)) remote.PromptInstallFunc {
	if opts.Install == nil {
		return nil
	}
	return func(remoteName, adapterName string) bool {
		// Publishers that can't be read count as none trusted.
		set, _ := trusted()
		return opts.Install(remoteName, adapterName, publisher, set)
	}
}

// prepareUserRemote prepares the adapter installed for the user, pointed at
// the endpoints an operator set and, for a job, signed in to its pipeline.
// A job admits only an adapter from a publisher it trusts, before it is
// installed or run, since an adapter that runs can read what the job holds.
func prepareUserRemote(ctx context.Context, remoteName string, opts PrepareOptions, verification remote.VerificationOptions, trusted func() (trustedpublishers.Set, error)) (*PreparedRemote, error) {
	if err := validateUserRemoteFlags(opts.AllowUnpinned); err != nil {
		return nil, err
	}
	endpoints, err := userRemoteEndpoints(opts.Stderr, remoteName)
	if err != nil {
		return nil, err
	}
	resolver, err := userremote.New()
	if err != nil {
		return nil, err
	}
	resolver.Stderr = opts.Stderr
	resolver.Step = opts.Step
	resolver.Verification = verification
	resolver.ExplicitEnv = endpoints
	if opts.Pipeline != nil {
		resolver.Admit = func(source string) error {
			return admitForPipeline(remoteName, publisherOf(source), opts.Pipeline.ID, trusted)
		}
	}
	adapter, err := resolver.Prepare(ctx, remoteName)
	if err != nil {
		return nil, err
	}
	prepared := &PreparedRemote{Name: remoteName, Exec: adapter.Exec, Caps: adapter.Caps, Publisher: publisherOf(adapter.Source)}
	if opts.Pipeline == nil || !adapter.Caps.SupportsConfigPull() {
		return prepared, nil
	}
	session, err := pipelineSession(ctx, remoteName, *opts.Pipeline, opts.Stderr)
	if err != nil {
		prepared.Close()
		return nil, err
	}
	prepared.Exec.ManagedEnv = session
	return prepared, nil
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
