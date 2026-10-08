// Package runflow runs the workflow a project describes, start to finish:
// install what the lock pins, run the hooks around collection, collect, run
// the tools, sign, and push. A failing stage is reported to the remote with a
// stable code before the error is returned.
package runflow

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/locktivity/epack/internal/cmdutil"
	"github.com/locktivity/epack/internal/collector"
	"github.com/locktivity/epack/internal/component/config"
	"github.com/locktivity/epack/internal/component/lockfile"
	"github.com/locktivity/epack/internal/component/sync"
	"github.com/locktivity/epack/internal/dispatch"
	"github.com/locktivity/epack/internal/hooks"
	"github.com/locktivity/epack/internal/lockprovenance"
	"github.com/locktivity/epack/internal/platform"
	"github.com/locktivity/epack/internal/project"
	"github.com/locktivity/epack/internal/push"
	"github.com/locktivity/epack/internal/redact"
	"github.com/locktivity/epack/internal/remote"
	"github.com/locktivity/epack/internal/remoteconfig"
	"github.com/locktivity/epack/internal/trustedpublishers"
	"github.com/locktivity/epack/internal/userconfig"
	"github.com/locktivity/epack/sign"
)

// DefaultPackName is the pack file a run builds in the project folder.
const DefaultPackName = "evidence.epack"

// Stages, in the order they run.
const (
	StageInstall     = "install"
	StagePreCollect  = "pre-collect"
	StageCollect     = "collect"
	StagePostCollect = "post-collect"
	StageTools       = "tools"
	StageSign        = "sign"
	StagePush        = "push"
)

// Failure codes reported to the remote, one per stage.
const (
	FailureInstall = "install_failed"
	FailureHook    = "hook_failed"
	FailureCollect = "collect_failed"
	FailureTool    = "tool_failed"
	FailureSign    = "sign_failed"
	FailurePush    = "push_failed"
)

// Options configures a run.
type Options struct {
	// WorkDir is the project folder. The run makes it the working directory,
	// which the collect, tool, and push workflows read their config from.
	WorkDir string
	// Remote is the remote to push to. Empty picks the only configured one;
	// a project with none skips the push.
	Remote string
	// PackPath is where the pack is built. Empty means DefaultPackName in WorkDir.
	PackPath string
	// AllowUnpinned permits adapters and components missing from the lock.
	AllowUnpinned bool
	// NonInteractive disables prompts.
	NonInteractive bool
	// TrustPublishers are publishers trusted for this run only, from
	// --trust-publisher; EPACK_TRUSTED_PUBLISHERS adds more.
	TrustPublishers []string
	// PromptTrustPublisher asks whether to trust a publisher a fetched
	// configuration needs; a yes is recorded for the user. Nil means ask nobody.
	PromptTrustPublisher func(trustedpublishers.Requirement) bool
	// Sign configures how the pack is signed.
	Sign sign.SignPackOptions
	// Unsigned skips the sign stage, for a run whose key the remote does not
	// accept yet; the pack is pushed without a signature.
	Unsigned bool

	Stdout io.Writer
	Stderr io.Writer

	// OnStage is called as each stage starts (true) and finishes (false).
	OnStage func(stage string, started bool)
	// OnStep receives the finer steps inside a stage, such as the push workflow's.
	OnStep func(step string, started bool)
	// OnNote receives one-line remarks worth showing, such as a hook left unrun.
	OnNote               func(note string)
	OnCollectorEvent     func(collector.CollectorEvent)
	OnUploadProgress     func(written, total int64)
	PromptInstallAdapter func(remoteName, adapterName string) bool
	// ToolOutput receives tool wrapper warnings; nil means stderr.
	ToolOutput dispatch.Output
}

// Result is what a run produced, including partial results when a stage failed.
type Result struct {
	PackPath        string
	Remote          string
	LockedNow       bool
	LockResults     []sync.LockResult
	SyncResults     []sync.SyncResult
	Collect         *collector.CollectWorkflowResult
	Tools           []string
	Signed          bool
	Push            *push.Result
	FailureReported bool
}

// StageError says which stage failed and the code reported to the remote.
type StageError struct {
	Stage string
	Code  string
	Err   error
}

func (e *StageError) Error() string {
	return fmt.Sprintf("%s failed: %v", e.Stage, e.Err)
}

func (e *StageError) Unwrap() error {
	return e.Err
}

// Run executes the stages in order and stops at the first failure.
func Run(ctx context.Context, opts Options) (*Result, error) {
	opts, err := withDefaults(opts)
	if err != nil {
		return nil, err
	}
	if err := os.Chdir(opts.WorkDir); err != nil {
		return nil, fmt.Errorf("entering %s: %w", opts.WorkDir, err)
	}
	cfg, err := config.Load(filepath.Join(opts.WorkDir, project.ConfigFileName))
	if err != nil {
		return nil, fmt.Errorf("loading config: %w", err)
	}
	state, err := remoteconfig.LoadState(opts.WorkDir)
	if err != nil {
		return nil, fmt.Errorf("reading the pull record: %w", err)
	}
	if err := exportPipelineID(opts.WorkDir, state); err != nil {
		return nil, err
	}
	if err := checkPublishers(cfg, state, opts); err != nil {
		return nil, err
	}
	remoteName, err := ResolveRemote(cfg, opts.Remote)
	if err != nil {
		return nil, err
	}
	result := &Result{PackPath: opts.PackPath, Remote: remoteName}
	err = runStages(ctx, cfg, opts, result)
	var stageErr *StageError
	if errors.As(err, &stageErr) && remoteName != "" {
		result.FailureReported = reportFailure(ctx, cfg, opts, remoteName, stageErr)
	}
	return result, err
}

// PipelineIDEnvVar names the pipeline a run belongs to.
const PipelineIDEnvVar = "EPACK_PIPELINE_ID"

// exportPipelineID lets a run made from a fetched configuration name its
// pipeline the way a generated job does through its variables, so the push
// and any report land on the right pipeline. A folder laid out by hand from
// a downloaded bundle carries no record; the adapter that made the bundle
// recognises the folder itself.
func exportPipelineID(workDir string, state *remoteconfig.State) error {
	if strings.TrimSpace(os.Getenv(PipelineIDEnvVar)) != "" {
		return nil
	}
	if state == nil || state.ID == "" {
		return nil
	}
	return os.Setenv(PipelineIDEnvVar, state.ID)
}

// ConfigReference names the configuration a folder belongs to as the remote
// knows it: the exported variable or the pull record's identifier, with the
// configuration name as the label when the record has one.
func ConfigReference(workDir string) (id, label string, err error) {
	id = strings.TrimSpace(os.Getenv(PipelineIDEnvVar))
	state, err := remoteconfig.LoadState(workDir)
	if err != nil {
		return "", "", err
	}
	if state != nil {
		if id == "" {
			id = state.ID
		}
		label = state.Name
	}
	if label == "" {
		label = id
	}
	return id, label, nil
}

// checkPublishers stops a run made from a fetched configuration before any
// download when the configuration draws a collector, tool, or remote from a
// publisher nobody trusted. A folder without a pull record is the person's
// own and is not checked. In a terminal a new publisher is offered once and
// a yes is recorded for the user; without one the run names the variable.
func checkPublishers(cfg *config.JobConfig, state *remoteconfig.State, opts Options) error {
	if state == nil {
		return nil
	}
	required, err := trustedpublishers.Required(cfg)
	if err != nil {
		return fmt.Errorf("checking publishers: %w", err)
	}
	recorded, err := userconfig.TrustedPublishers()
	if err != nil {
		return fmt.Errorf("reading trusted publishers: %w", err)
	}
	trusted := trustedpublishers.NewSet(recorded...)
	trusted.Add(opts.TrustPublishers...)
	trusted.AddFromEnv(os.Getenv)
	missing := trustedpublishers.Missing(required, trusted)
	if len(missing) == 0 {
		return nil
	}
	if opts.NonInteractive || opts.PromptTrustPublisher == nil {
		return &trustedpublishers.Error{Missing: missing}
	}
	var refused []trustedpublishers.Requirement
	for _, req := range missing {
		if !opts.PromptTrustPublisher(req) {
			refused = append(refused, req)
			continue
		}
		if _, err := userconfig.TrustPublisher(req.Publisher); err != nil {
			return fmt.Errorf("recording trusted publisher: %w", err)
		}
		opts.OnNote(fmt.Sprintf("github.com/%s is now a trusted publisher on this machine", req.Publisher))
	}
	if len(refused) > 0 {
		return &trustedpublishers.Error{Missing: refused}
	}
	return nil
}

// ResolveRemote picks the remote to push to: the named one, else the only
// configured one, else none.
func ResolveRemote(cfg *config.JobConfig, name string) (string, error) {
	if name != "" {
		if _, ok := cfg.Remotes[name]; !ok {
			return "", fmt.Errorf("remote %q not found in config", name)
		}
		return name, nil
	}
	names := sortedNames(cfg.Remotes)
	switch len(names) {
	case 0:
		return "", nil
	case 1:
		return names[0], nil
	default:
		return "", fmt.Errorf("config names several remotes (%v); pass --remote to choose one", names)
	}
}

func withDefaults(opts Options) (Options, error) {
	workDir, err := filepath.Abs(opts.WorkDir)
	if err != nil {
		return opts, err
	}
	opts.WorkDir = workDir
	if opts.PackPath == "" {
		opts.PackPath = filepath.Join(workDir, DefaultPackName)
	}
	if opts.Stdout == nil {
		opts.Stdout = os.Stdout
	}
	if opts.Stderr == nil {
		opts.Stderr = os.Stderr
	}
	if opts.OnStage == nil {
		opts.OnStage = func(string, bool) {}
	}
	if opts.OnStep == nil {
		opts.OnStep = func(string, bool) {}
	}
	if opts.OnNote == nil {
		opts.OnNote = func(string) {}
	}
	if opts.ToolOutput == nil {
		opts.ToolOutput = dispatch.StdOutput{}
	}
	return opts, nil
}

func runStages(ctx context.Context, cfg *config.JobConfig, opts Options, result *Result) error {
	if err := stage(opts, StageInstall, FailureInstall, func() error { return install(ctx, cfg, opts, result) }); err != nil {
		return err
	}
	if err := stage(opts, StagePreCollect, FailureHook, func() error { return runHook(ctx, opts, "pre-collect") }); err != nil {
		return err
	}
	collectErr := stage(opts, StageCollect, FailureCollect, func() error { return collect(ctx, cfg, opts, result) })
	postErr := stage(opts, StagePostCollect, FailureHook, func() error { return runHook(ctx, opts, "post-collect") })
	if collectErr != nil {
		if postErr != nil {
			_, _ = fmt.Fprintf(opts.Stderr, "Warning: %v\n", postErr)
		}
		return collectErr
	}
	if postErr != nil {
		return postErr
	}
	if len(cfg.Tools) > 0 {
		if err := stage(opts, StageTools, FailureTool, func() error { return runTools(ctx, cfg, opts, result) }); err != nil {
			return err
		}
	}
	if !opts.Unsigned {
		if err := stage(opts, StageSign, FailureSign, func() error { return signPack(ctx, opts, result) }); err != nil {
			return err
		}
	}
	if result.Remote == "" {
		return nil
	}
	return stage(opts, StagePush, FailurePush, func() error { return pushPack(ctx, opts, result) })
}

func stage(opts Options, name, code string, fn func() error) error {
	opts.OnStage(name, true)
	if err := fn(); err != nil {
		return &StageError{Stage: name, Code: code, Err: err}
	}
	opts.OnStage(name, false)
	return nil
}

func install(ctx context.Context, cfg *config.JobConfig, opts Options, result *Result) error {
	locked, lockResults, err := lockIfNeeded(ctx, cfg, opts)
	if err != nil {
		return err
	}
	result.LockedNow = locked
	result.LockResults = lockResults
	syncOpts := sync.SyncOpts{Secure: sync.SyncSecureOptions{Locked: true}}
	results, err := sync.NewSyncer(opts.WorkDir).Sync(ctx, cfg, syncOpts)
	if err != nil {
		return fmt.Errorf("installing dependencies: %w", err)
	}
	result.SyncResults = results
	return nil
}

// lockIfNeeded locks the configuration when its lock is missing or behind,
// for the platforms the configuration lists or else this machine's.
func lockIfNeeded(ctx context.Context, cfg *config.JobConfig, opts Options) (bool, []sync.LockResult, error) {
	platformKey := platform.Key(runtime.GOOS, runtime.GOARCH)
	needsLock, err := lockNeeded(cfg, opts.WorkDir, platformKey)
	if err != nil || !needsLock {
		return false, nil, err
	}
	opts.OnStep("Locking dependencies", true)
	platforms := cfg.Platforms
	if len(platforms) == 0 {
		platforms = []string{platformKey}
	}
	results, err := sync.NewLocker(opts.WorkDir).Lock(ctx, cfg, sync.LockOpts{Platforms: platforms})
	if err != nil {
		return false, nil, fmt.Errorf("locking dependencies: %w", err)
	}
	opts.OnStep("Locked dependencies", false)
	return true, results, nil
}

func lockNeeded(cfg *config.JobConfig, workDir, platformKey string) (bool, error) {
	if !cfg.NeedsLocking() {
		return false, nil
	}
	lf, err := lockfile.Load(filepath.Join(workDir, lockfile.FileName))
	if os.IsNotExist(err) {
		return true, nil
	}
	if err != nil {
		return false, fmt.Errorf("loading lockfile: %w", err)
	}
	return cmdutil.LockfileNeedsUpdate(cfg, lf, platformKey, workDir), nil
}

// runHook runs a hook the person wrote. A hook still matching the template
// the remote delivered is the remote's script, and a fetched configuration
// does not get to run shell on this machine.
func runHook(ctx context.Context, opts Options, name string) error {
	template, err := remoteconfig.IsRemoteTemplate(opts.WorkDir, path.Join(".epack", "hooks", name+".sh"))
	if err != nil {
		return fmt.Errorf("checking %s hook: %w", name, err)
	}
	if template {
		opts.OnNote(fmt.Sprintf("%s.sh is the remote's template and was not run; edit it to add your own steps", name))
		return nil
	}
	return hooks.Runner{WorkDir: opts.WorkDir, Stdout: opts.Stdout, Stderr: opts.Stderr}.Run(ctx, name)
}

func collect(ctx context.Context, cfg *config.JobConfig, opts Options, result *Result) error {
	collected, err := collector.Collect(ctx, cfg, collector.CollectOpts{
		Secure:           collector.SecureRunOptions{Frozen: !opts.AllowUnpinned},
		Unsafe:           collector.UnsafeOverrides{AllowUnpinned: opts.AllowUnpinned},
		WorkDir:          opts.WorkDir,
		Stderr:           opts.Stderr,
		OutputPath:       opts.PackPath,
		OnCollectorEvent: opts.OnCollectorEvent,
	})
	result.Collect = collected
	return err
}

func runTools(ctx context.Context, cfg *config.JobConfig, opts Options, result *Result) error {
	for _, name := range sortedNames(cfg.Tools) {
		opts.OnStep(fmt.Sprintf("Running %s", name), true)
		flags := dispatch.WrapperFlags{PackPath: opts.PackPath, InsecureAllowUnpinned: opts.AllowUnpinned}
		if err := dispatch.ToolWithFlags(ctx, opts.ToolOutput, name, nil, flags); err != nil {
			return fmt.Errorf("tool %s: %w", name, err)
		}
		result.Tools = append(result.Tools, name)
		opts.OnStep(fmt.Sprintf("Ran %s", name), false)
	}
	return nil
}

func signPack(ctx context.Context, opts Options, result *Result) error {
	signer, err := sign.NewSignerFromOptions(ctx, opts.Sign)
	if err != nil {
		return fmt.Errorf("creating signer: %w", err)
	}
	if err := sign.SignPackFile(ctx, opts.PackPath, signer); err != nil {
		return err
	}
	result.Signed = true
	return nil
}

func pushPack(ctx context.Context, opts Options, result *Result) error {
	pushOpts := push.Options{
		Remote:               result.Remote,
		PackPath:             opts.PackPath,
		NonInteractive:       opts.NonInteractive,
		Stderr:               opts.Stderr,
		OnStep:               opts.OnStep,
		OnUploadProgress:     opts.OnUploadProgress,
		PromptInstallAdapter: opts.PromptInstallAdapter,
	}
	pushOpts.Unsafe.AllowUnpinned = opts.AllowUnpinned
	pushed, err := push.Push(ctx, pushOpts)
	if err != nil {
		return err
	}
	result.Push = pushed
	return nil
}

// reportFailure tells the remote which stage failed. It is best effort: a
// report that cannot be sent is noted on stderr and never masks the failure.
func reportFailure(ctx context.Context, cfg *config.JobConfig, opts Options, remoteName string, stageErr *StageError) bool {
	remoteCfg, err := remote.ResolveRemoteConfig(cfg, remoteName, "")
	if err != nil {
		return false
	}
	exec, caps, err := remote.PrepareAdapterExecutor(ctx, opts.WorkDir, remoteName, cfg, remoteCfg, remote.AdapterExecutorOptions{
		Stderr: opts.Stderr,
		Verification: remote.VerificationOptions{
			Unsafe: remote.VerificationUnsafeOverrides{AllowUnverifiedSource: opts.AllowUnpinned},
		},
	})
	if err != nil {
		_, _ = fmt.Fprintf(opts.Stderr, "Warning: could not report the failure to %s: %v\n", remoteName, err)
		return false
	}
	defer exec.Close()
	if !caps.SupportsLockReport() {
		return false
	}
	provenance, err := lockprovenance.Build(lockprovenance.Options{
		ProjectRoot:    opts.WorkDir,
		TriggerKind:    lockprovenance.TriggerFrozenCheck,
		Outcome:        lockprovenance.OutcomeFailure,
		FailureCode:    stageErr.Code,
		FailureMessage: redact.Error(stageErr.Err.Error()),
	})
	if err != nil {
		_, _ = fmt.Fprintf(opts.Stderr, "Warning: could not report the failure to %s: %v\n", remoteName, err)
		return false
	}
	_, err = exec.ReportLock(ctx, &remote.LockReportRequest{
		Remote:         remoteName,
		Target:         remote.TargetConfig{Workspace: remoteCfg.Target.Workspace, Environment: remoteCfg.Target.Environment},
		LockProvenance: *provenance,
	})
	if err != nil {
		_, _ = fmt.Fprintf(opts.Stderr, "Warning: could not report the failure to %s: %v\n", remoteName, err)
		return false
	}
	return true
}

func sortedNames[T any](m map[string]T) []string {
	names := make([]string, 0, len(m))
	for name := range m {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
