// Package shadow runs a candidate collector version beside the locked one
// and reports what would change, without any value from the account.
//
// It runs the locked version, then the candidate, then the locked version
// again, each with the project's config and secrets. A difference between
// the two locked runs is noise, such as a timestamp or a count that moved,
// and stays out of the changes. The candidate is locked, installed, and
// verified in a throwaway project under .epack, through the same lock,
// sync, and digest checks as any collector, so the project's own lockfile
// never changes.
package shadow

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/locktivity/epack/componentsdk"
	"github.com/locktivity/epack/internal/collector"
	"github.com/locktivity/epack/internal/component/config"
	"github.com/locktivity/epack/internal/component/github"
	"github.com/locktivity/epack/internal/component/lockfile"
	"github.com/locktivity/epack/internal/component/sync"
	"github.com/locktivity/epack/internal/credentials"
	"github.com/locktivity/epack/internal/securityaudit"
	"github.com/locktivity/epack/internal/securitypolicy"
)

// Options says which collector to shadow and with what.
type Options struct {
	// WorkDir is the project directory, which holds epack.yaml, the
	// lockfile, and .epack.
	WorkDir string
	// Collector names the collector in the project's config.
	Collector string
	// Version is a release of the collector's source to run as the
	// candidate. Binary is a local build to run instead. Set one.
	Version string
	Binary  string
	// Timeout limits each run. Zero uses the runner's default.
	Timeout time.Duration
	// Getenv reads the secrets the collector lists. nil reads the process
	// environment.
	Getenv func(string) string
	// Credentials resolves the Locktivity-managed credentials the collector
	// declares. The zero value resolves with the run's CI identity, as
	// epack collect does.
	Credentials credentials.Resolver
	// Stderr receives the warning for a custom credential broker. nil
	// discards it.
	Stderr io.Writer
	// Registry and Verifier replace GitHub and Sigstore when locking and
	// installing a candidate release, in tests.
	Registry sync.RegistryClient
	Verifier sync.SigstoreVerifier
	// Validate replaces the project's validate tool, in tests. nil runs the
	// tool epack.yaml configures, and there are no control results without
	// one.
	Validate Validator
}

// Run shadows one collector. It returns the report, which holds no values
// and may be shared, and the preview of the values behind each change,
// which stays on this machine.
func Run(ctx context.Context, cfg *config.JobConfig, opts Options) (*Report, *Preview, error) {
	p, err := newPlan(cfg, opts)
	if err != nil {
		return nil, nil, err
	}
	scratch, err := scratchDir(opts.WorkDir)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = os.RemoveAll(scratch) }()
	if err := p.prepare(ctx, scratch); err != nil {
		return nil, nil, err
	}
	outs, packs, err := p.runAll(ctx)
	if err != nil {
		return nil, nil, err
	}
	rep, preview := p.compare(ctx, outs, packs)
	return &rep, &preview, nil
}

// plan is one shadow, set up to run: the project's config and lockfile, and
// the config each version runs from. prepare sets the rest in the scratch
// project.
type plan struct {
	cfg                     *config.JobConfig
	opts                    Options
	level                   string
	lf                      *lockfile.LockFile
	lockedCfg, candidateCfg *config.JobConfig

	scratch  string
	packLF   *lockfile.LockFile
	controls controlCheck
}

// newPlan checks the options, reads the project's lockfile, and sets up the
// config each version runs from. It writes nothing.
func newPlan(cfg *config.JobConfig, opts Options) (*plan, error) {
	c, ok := cfg.Collectors[opts.Collector]
	if !ok {
		return nil, fmt.Errorf("epack.yaml has no collector named %q", opts.Collector)
	}
	switch {
	case opts.Version == "" && opts.Binary == "":
		return nil, fmt.Errorf("name the candidate to run with --version <release> or --binary <path>")
	case opts.Version != "" && opts.Binary != "":
		return nil, fmt.Errorf("give the candidate as --version or --binary, not both")
	}
	if opts.Version != "" && c.Source == "" {
		return nil, fmt.Errorf("%s runs a local binary, so its candidate must be one too; use --binary", opts.Collector)
	}
	if err := enforcePolicy(c, opts); err != nil {
		return nil, err
	}
	lf, err := lockfile.Load(filepath.Join(opts.WorkDir, lockfile.FileName))
	if err != nil {
		return nil, fmt.Errorf("reading the lockfile: %w; run epack lock and epack sync first", err)
	}
	candidateCfg, err := candidateConfig(cfg, opts, c)
	if err != nil {
		return nil, err
	}
	return &plan{
		cfg:          cfg,
		opts:         opts,
		level:        string(componentsdk.LevelOf(c.Config)),
		lf:           lf,
		lockedCfg:    onlyCollector(cfg, opts.Collector, c),
		candidateCfg: candidateCfg,
	}, nil
}

// prepare locks and installs the candidate in the scratch project, pins it
// in the lockfile its pack is built with, and sets up the control check.
func (p *plan) prepare(ctx context.Context, scratch string) error {
	p.scratch = scratch
	if err := installCandidate(ctx, scratch, p.candidateCfg, p.opts); err != nil {
		return fmt.Errorf("preparing the candidate: %w", err)
	}
	candidateLF, err := lockfile.Load(filepath.Join(scratch, lockfile.FileName))
	if err != nil {
		return fmt.Errorf("reading the candidate's lockfile: %w", err)
	}
	// Each run's pack carries the project's profiles, and the candidate's
	// pins the candidate as its source.
	packLF := *p.lf
	packLF.Collectors = map[string]lockfile.LockedCollector{}
	for name, entry := range p.lf.Collectors {
		packLF.Collectors[name] = entry
	}
	packLF.Collectors[p.opts.Collector] = candidateLF.Collectors[p.opts.Collector]
	p.packLF = &packLF
	packDir := filepath.Join(scratch, "packs")
	if err := os.MkdirAll(packDir, 0o700); err != nil {
		return err
	}
	p.controls = newControlCheck(p.cfg, p.opts, scratch, packDir)
	return nil
}

// runAll runs the locked version, then the candidate, then the locked
// version again, building each run's pack when there are controls to check.
func (p *plan) runAll(ctx context.Context) (outs trio[RunOutput], packs trio[string], err error) {
	locked := collector.NewRunner(p.opts.WorkDir)
	candidate := collector.NewRunner(p.scratch)
	outs.Locked1, packs.Locked1, err = runOnce(ctx, locked, p.lockedCfg, p.opts, p.controls.packer("locked-1", p.lf))
	if err != nil {
		return outs, packs, fmt.Errorf("running the locked version: %w", err)
	}
	outs.Candidate, packs.Candidate, err = runOnce(ctx, candidate, p.candidateCfg, p.opts, p.controls.packer("candidate", p.packLF))
	if err != nil {
		return outs, packs, fmt.Errorf("running the candidate: %w", err)
	}
	outs.Locked2, packs.Locked2, err = runOnce(ctx, locked, p.lockedCfg, p.opts, p.controls.packer("locked-2", p.lf))
	if err != nil {
		return outs, packs, fmt.Errorf("running the locked version again: %w", err)
	}
	return outs, packs, nil
}

// compare compares the three runs and their control results, and names
// each version in the report.
func (p *plan) compare(ctx context.Context, outs trio[RunOutput], packs trio[string]) (Report, Preview) {
	rep, preview := Compare(p.opts.Collector, p.level, outs.Locked1, outs.Locked2, outs.Candidate)
	p.controls.check(ctx, outs, packs, &rep, &preview)
	rep.Locked.Version = p.lf.Collectors[p.opts.Collector].Version
	if rep.Locked.Version == "" {
		rep.Locked.Version = "local binary"
	}
	rep.Candidate.Version = p.opts.Version
	if p.opts.Version == "" {
		rep.Candidate.Version = "local build"
	}
	return rep, preview
}

// enforcePolicy applies the policy epack collect applies to what a shadow
// runs. A local build is not pinned in the project's lockfile, so strict
// production refuses it, as it refuses an unpinned binary, and any other
// run records it. A custom credential broker gets the same check as it
// does for collect.
func enforcePolicy(c config.CollectorConfig, opts Options) error {
	if opts.Binary != "" {
		if err := securitypolicy.EnforceStrictProduction("shadow_cli", true); err != nil {
			return err
		}
		securityaudit.Emit(securityaudit.Event{
			Type:        securityaudit.EventInsecureBypass,
			Component:   "shadow",
			Name:        opts.Collector,
			Description: "shadow running a local build that the lockfile does not pin",
			Attrs:       map[string]string{"binary": opts.Binary},
		})
	}
	return credentials.ValidateManagedCredentialBrokerOverride(opts.Stderr, c.Credentials, credentials.BrokerOverridePolicy{
		StrictProductionComponent: "shadow_cli",
		AuditComponent:            "shadow",
		AuditName:                 opts.Collector,
		AuditDescription:          "shadow running with insecure custom credential broker override",
	})
}

// candidateConfig is the project's config for the collector, with its
// source pinned to the candidate release or its binary set to the local
// build. It keeps the collector's name, config, secrets, and credentials,
// so both versions run the same way and write the same paths.
func candidateConfig(cfg *config.JobConfig, opts Options, c config.CollectorConfig) (*config.JobConfig, error) {
	candidate := c
	if opts.Version != "" {
		owner, repo, _, err := github.ParseSource(c.Source)
		if err != nil {
			return nil, err
		}
		candidate.Source = fmt.Sprintf("%s/%s@%s", owner, repo, opts.Version)
	} else {
		abs, err := filepath.Abs(opts.Binary)
		if err != nil {
			return nil, err
		}
		candidate.Source = ""
		candidate.Binary = abs
	}
	return onlyCollector(cfg, opts.Collector, candidate), nil
}

// onlyCollector is the project's config with c as its only collector. Each
// version runs from one, so both resolve the same credential sets.
func onlyCollector(cfg *config.JobConfig, name string, c config.CollectorConfig) *config.JobConfig {
	return &config.JobConfig{
		Stream:         cfg.Stream,
		CredentialSets: cfg.CredentialSets,
		Collectors:     map[string]config.CollectorConfig{name: c},
	}
}

// scratchDir makes the throwaway project for the candidate under the
// project's .epack, since a lockfile is written only below the working
// directory.
func scratchDir(workDir string) (string, error) {
	parent := filepath.Join(workDir, ".epack")
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return "", err
	}
	return os.MkdirTemp(parent, "shadow-")
}

// installCandidate locks the candidate into the throwaway project and, for
// a release, installs it, with the Sigstore and digest checks lock and
// sync always make.
func installCandidate(ctx context.Context, scratch string, cfg *config.JobConfig, opts Options) error {
	locker := sync.NewLocker(scratch)
	syncer := sync.NewSyncer(scratch)
	if opts.Registry != nil {
		locker = sync.NewLockerWithRegistry(opts.Registry, scratch)
		syncer = sync.NewSyncerWithRegistry(opts.Registry, scratch)
	}
	locker.Verifier, syncer.Verifier = opts.Verifier, opts.Verifier
	if _, err := locker.Lock(ctx, cfg, sync.LockOpts{}); err != nil {
		return err
	}
	if opts.Version == "" {
		return nil
	}
	_, err := syncer.Sync(ctx, cfg, sync.SyncOpts{})
	return err
}

// runOnce runs the one collector through the runner, frozen to its
// lockfile, and parses what it wrote. When build is set and the run
// succeeded, it also builds the run's pack and returns its path.
func runOnce(ctx context.Context, runner *collector.Runner, cfg *config.JobConfig, opts Options, build func([]collector.RunResult) (string, error)) (RunOutput, string, error) {
	res, err := runner.Run(ctx, cfg, collector.RunOptions{
		Secure:      collector.SecureRunOptions{Frozen: true, Only: []string{opts.Collector}, Timeout: opts.Timeout, Parallel: 1},
		Getenv:      opts.Getenv,
		Credentials: opts.Credentials,
	})
	if err != nil {
		return RunOutput{}, "", err
	}
	defer func() { _ = res.Close() }()
	for _, r := range res.Results {
		if r.Collector != opts.Collector {
			continue
		}
		out := ParseRun(opts.Collector, r.Output, r.Success)
		if build == nil || out.Failed {
			return out, "", nil
		}
		path, err := build(res.Results)
		if err != nil {
			return RunOutput{}, "", err
		}
		return out, path, nil
	}
	return RunOutput{Failed: true}, "", nil
}
