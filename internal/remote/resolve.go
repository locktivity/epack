// Package remote provides remote adapter resolution and execution.
//
// This file contains shared resolution logic for push/pull workflows,
// including adapter path resolution, config merging, and auto-install.
package remote

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"runtime"

	"github.com/locktivity/epack/errors"
	"github.com/locktivity/epack/internal/component/config"
	"github.com/locktivity/epack/internal/component/lockfile"
	"github.com/locktivity/epack/internal/component/sync"
	"github.com/locktivity/epack/internal/componenttypes"
	"github.com/locktivity/epack/internal/credentials"
	"github.com/locktivity/epack/internal/exitcode"
	"github.com/locktivity/epack/internal/securityaudit"
	"github.com/locktivity/epack/internal/securitypolicy"
)

// StepCallback is called when a workflow step starts or completes.
// step is the step name, started indicates whether the step is starting (true) or done (false).
type StepCallback func(step string, started bool)

// PromptInstallFunc prompts the user to install an adapter.
// Returns true if the adapter should be installed, false otherwise.
type PromptInstallFunc func(remoteName, adapterName string) bool

// AdapterExecutorOptions controls shared adapter setup behavior.
type AdapterExecutorOptions struct {
	// PromptInstall is called when the adapter is not installed.
	// If it returns true, adapter installation is attempted automatically.
	PromptInstall PromptInstallFunc

	// Step receives workflow step start/complete events.
	Step StepCallback

	// Stderr is where adapter stderr output is written.
	// If nil, adapter stderr is discarded by default.
	Stderr io.Writer

	// Verification configures adapter security checks.
	Verification VerificationOptions
}

// ResolveAdapterPathWithInstall resolves the adapter path, offering to install if missing.
// If resolution fails and the remote has a source configured, prompts to install.
// On acceptance, installs via sync and retries resolution.
//
// SECURITY: Source-based adapters are installed via sync which performs Sigstore
// verification and digest pinning (unless --insecure-skip-verify was used at sync time).
func ResolveAdapterPathWithInstall(
	ctx context.Context,
	projectRoot string,
	remoteName string,
	cfg *config.JobConfig,
	remoteCfg *config.RemoteConfig,
	promptInstall PromptInstallFunc,
	step StepCallback,
	stderr io.Writer,
) (string, error) {
	path, err := ResolveAdapterPath(projectRoot, remoteName, remoteCfg)
	if err == nil {
		return path, nil
	}
	if remoteCfg.EffectiveAdapter() == "" {
		return "", fmt.Errorf("remote %q has no adapter configured", remoteName)
	}
	adapterName, canInstall, canPrompt := classifyAdapterInstallability(remoteName, remoteCfg, promptInstall)
	if !canInstall || !canPrompt {
		return "", err
	}
	if installErr := installRemoteAdapter(ctx, projectRoot, remoteName, adapterName, remoteCfg, step); installErr != nil {
		return "", installErr
	}
	return ResolveAdapterPath(projectRoot, remoteName, remoteCfg)
}

func classifyAdapterInstallability(remoteName string, remoteCfg *config.RemoteConfig, promptInstall PromptInstallFunc) (adapterName string, canInstall bool, canPrompt bool) {
	adapterName = remoteCfg.EffectiveAdapter()
	if adapterName == "" {
		return "", false, false
	}
	if remoteCfg.Source == "" || promptInstall == nil {
		return adapterName, false, false
	}
	return adapterName, true, promptInstall(remoteName, adapterName)
}

func installRemoteAdapter(
	ctx context.Context,
	projectRoot, remoteName, adapterName string,
	remoteCfg *config.RemoteConfig,
	step StepCallback,
) error {
	if step != nil {
		step("Resolving adapter", false)
		step("Installing adapter", true)
	}
	lockfilePath := filepath.Join(projectRoot, lockfile.FileName)
	lf, err := lockfile.Load(lockfilePath)
	if err != nil {
		return fmt.Errorf("loading lockfile: %w", err)
	}
	syncer := sync.NewSyncer(filepath.Join(projectRoot, ".epack"))
	platform := runtime.GOOS + "/" + runtime.GOARCH
	result, err := syncer.SyncRemote(ctx, remoteName, *remoteCfg, lf, platform, sync.SyncOpts{})
	if err != nil {
		return fmt.Errorf("installing adapter: %w", err)
	}
	if step != nil {
		if result != nil && result.Installed {
			step(fmt.Sprintf("Installed %s %s", adapterName, result.Version), false)
		} else {
			step("Installing adapter", false)
		}
		step("Resolving adapter", true)
	}
	return nil
}

// PrepareAdapterExecutor resolves, verifies, and probes a remote adapter.
//
// This is the shared setup path for push/pull workflows:
//  1. Resolve adapter path (with optional auto-install)
//  2. Load lockfile and digest metadata
//  3. Enforce adapter security policy
//  4. Create executor (verified when digest is pinned)
//  5. Query adapter capabilities
//
// Callers must call Close() on the returned executor.
func PrepareAdapterExecutor(
	ctx context.Context,
	projectRoot string,
	remoteName string,
	cfg *config.JobConfig,
	remoteCfg *config.RemoteConfig,
	opts AdapterExecutorOptions,
) (*Executor, *Capabilities, error) {
	adapterPath, err := ResolveAdapterPathWithInstall(
		ctx, projectRoot, remoteName, cfg, remoteCfg,
		opts.PromptInstall, opts.Step, opts.Stderr)
	if err != nil {
		return nil, nil, err
	}
	if err := credentials.ValidateManagedCredentialBrokerOverride(opts.Stderr, remoteCfg.Credentials, credentials.BrokerOverridePolicy{
		StrictProductionComponent: "remote_adapter",
		AuditComponent:            string(componenttypes.KindRemote),
		AuditName:                 remoteName,
		AuditDescription:          "remote adapter running with insecure custom credential broker override",
	}); err != nil {
		return nil, nil, err
	}
	managedEnv, err := credentials.Resolver{}.ResolveComponentEnv(ctx, cfg, remoteCfg.Credentials)
	if err != nil {
		return nil, nil, fmt.Errorf("resolving Locktivity-managed credentials: %w", err)
	}
	customEndpoints, err := ResolveCustomEndpointOverride(remoteCfg)
	if err != nil {
		return nil, nil, err
	}

	lockfilePath := filepath.Join(projectRoot, lockfile.FileName)
	lf, err := lockfile.Load(lockfilePath)
	if err != nil {
		// Lockfile may not exist for PATH-based adapters
		lf = lockfile.New()
	}

	platform := runtime.GOOS + "/" + runtime.GOARCH
	digestInfo := GetAdapterDigestInfo(remoteName, remoteCfg, lf, platform)

	if err := CheckAdapterSecurity(remoteName, adapterPath, digestInfo, opts.Verification); err != nil {
		return nil, nil, err
	}

	var exec *Executor
	if digestInfo.NeedsVerification && digestInfo.Digest != "" {
		// TOCTOU-safe: verify digest and execute verified copy
		exec, err = NewVerifiedExecutor(adapterPath, digestInfo.Digest, remoteCfg.EffectiveAdapter())
		if err != nil {
			securityaudit.Emit(securityaudit.Event{
				Type:        securityaudit.EventVerificationFail,
				Component:   string(componenttypes.KindRemote),
				Name:        remoteName,
				Description: "adapter digest verification failed",
				Attrs: map[string]string{
					"path": adapterPath,
				},
			})
			return nil, nil, fmt.Errorf("verifying adapter: %w", err)
		}
	} else {
		// Unverified execution (PATH-based or explicitly allowed)
		exec = NewExecutor(adapterPath, remoteCfg.EffectiveAdapter())
	}
	exec.Stderr = opts.Stderr
	exec.Secrets = remoteCfg.Secrets
	exec.ManagedEnv = managedEnv
	exec.ExplicitEnv = customEndpoints.ExplicitEnv()

	caps, err := QueryCapabilities(ctx, exec.BinaryPath)
	if err != nil {
		exec.Close()
		return nil, nil, fmt.Errorf("querying adapter capabilities: %w", err)
	}

	if !caps.SupportsProtocolVersion(ProtocolVersion) {
		exec.Close()
		return nil, nil, fmt.Errorf("adapter protocol version %d not supported (need %d)",
			caps.DeployProtocolVersion, ProtocolVersion)
	}

	return exec, caps, nil
}

// ResolveAdapterPath resolves the adapter binary path for a remote.
//
// Remotes must be configured with either source: or binary: in epack.yaml.
// There is no PATH discovery fallback (matching the collector model).
//
// For source-based remotes, the binary must be installed via 'epack sync' first.
// For external remotes, the configured absolute path is returned directly.
//
// SECURITY: External binary paths MUST be absolute to prevent PATH injection.
func ResolveAdapterPath(projectRoot, remoteName string, cfg *config.RemoteConfig) (string, error) {
	// Remote must have source or binary configured
	if cfg.Source == "" && cfg.Binary == "" {
		return "", fmt.Errorf("remote %q has no source or binary configured in epack.yaml", remoteName)
	}

	baseDir := filepath.Join(projectRoot, ".epack")
	lockfilePath := filepath.Join(projectRoot, lockfile.FileName)

	// For binary-based remotes, lockfile is not required
	var lf *lockfile.LockFile
	if cfg.Binary != "" {
		lf = lockfile.New()
	} else {
		var err error
		lf, err = lockfile.Load(lockfilePath)
		if err != nil {
			return "", fmt.Errorf("loading lockfile: %w", err)
		}
	}

	path, err := sync.ResolveRemoteBinaryPath(baseDir, remoteName, *cfg, lf)
	if err != nil {
		return "", fmt.Errorf("resolving adapter path: %w", err)
	}
	if path == "" {
		if cfg.Source != "" {
			return "", fmt.Errorf("adapter for remote %q not installed (run 'epack sync' first)", remoteName)
		}
		return "", fmt.Errorf("binary for remote %q not found at configured path", remoteName)
	}

	return path, nil
}

// ResolveRemoteConfig resolves the remote configuration with environment overrides.
//
// Environment overrides allow different target workspaces, endpoints, and settings
// for different deployment environments (staging, production, etc.) while sharing
// the same base remote configuration.
func ResolveRemoteConfig(cfg *config.JobConfig, remoteName, envName string) (*config.RemoteConfig, error) {
	baseCfg, ok := cfg.Remotes[remoteName]
	if !ok {
		return nil, fmt.Errorf("remote %q not found in config", remoteName)
	}

	if envName == "" {
		return &baseCfg, nil
	}

	envRemoteCfg, err := resolveEnvRemoteOverride(cfg, remoteName, envName)
	if err != nil || envRemoteCfg == nil {
		if err != nil {
			return nil, err
		}
		return &baseCfg, nil
	}
	merged := mergeRemoteConfig(baseCfg, *envRemoteCfg)
	return &merged, nil
}

func resolveEnvRemoteOverride(cfg *config.JobConfig, remoteName, envName string) (*config.RemoteConfig, error) {
	envCfg, ok := cfg.Environments[envName]
	if !ok {
		return nil, fmt.Errorf("environment %q not found in config", envName)
	}
	envRemoteCfg, ok := envCfg.Remotes[remoteName]
	if !ok {
		return nil, nil
	}
	return &envRemoteCfg, nil
}

func mergeRemoteConfig(baseCfg, envRemoteCfg config.RemoteConfig) config.RemoteConfig {
	merged := baseCfg
	if envRemoteCfg.Adapter != "" {
		merged.Adapter = envRemoteCfg.Adapter
	}
	mergeRemoteTargetOverrides(&merged, envRemoteCfg)
	mergeRemoteAuthOverrides(&merged, envRemoteCfg)
	mergeRemoteReleaseOverrides(&merged, envRemoteCfg)
	mergeRemoteRunOverrides(&merged, envRemoteCfg)
	return merged
}

func mergeRemoteTargetOverrides(merged *config.RemoteConfig, envRemoteCfg config.RemoteConfig) {
	if envRemoteCfg.Target.Workspace != "" {
		merged.Target.Workspace = envRemoteCfg.Target.Workspace
	}
	if envRemoteCfg.Target.Environment != "" {
		merged.Target.Environment = envRemoteCfg.Target.Environment
	}
	if envRemoteCfg.InsecureEndpoint != "" {
		merged.InsecureEndpoint = envRemoteCfg.InsecureEndpoint
	}
}

func mergeRemoteAuthOverrides(merged *config.RemoteConfig, envRemoteCfg config.RemoteConfig) {
	if envRemoteCfg.Auth.Mode != "" {
		merged.Auth.Mode = envRemoteCfg.Auth.Mode
	}
	if envRemoteCfg.Auth.Profile != "" {
		merged.Auth.Profile = envRemoteCfg.Auth.Profile
	}
	if envRemoteCfg.Auth.InsecureEndpoint != "" {
		merged.Auth.InsecureEndpoint = envRemoteCfg.Auth.InsecureEndpoint
	}
}

func mergeRemoteReleaseOverrides(merged *config.RemoteConfig, envRemoteCfg config.RemoteConfig) {
	if len(envRemoteCfg.Release.Labels) > 0 {
		merged.Release.Labels = envRemoteCfg.Release.Labels
	}
	if envRemoteCfg.Release.Notes != "" {
		merged.Release.Notes = envRemoteCfg.Release.Notes
	}
}

func mergeRemoteRunOverrides(merged *config.RemoteConfig, envRemoteCfg config.RemoteConfig) {
	if envRemoteCfg.Runs.Sync != nil {
		merged.Runs.Sync = envRemoteCfg.Runs.Sync
	}
	if envRemoteCfg.Runs.RequireSuccess {
		merged.Runs.RequireSuccess = true
	}
}

// AdapterDigestInfo contains information about an adapter's digest and verification state.
type AdapterDigestInfo struct {
	// Digest is the expected SHA256 digest from the lockfile (empty if not pinned).
	Digest string

	// NeedsVerification is true if the adapter should be verified before execution.
	NeedsVerification bool

	// IsSourceAdapter is true if this is a source-based adapter (installed via sync).
	IsSourceAdapter bool

	// IsExternalBinary is true if this is an external adapter (binary path in config).
	IsExternalBinary bool

	// MissingDigest is true if the adapter is in the lockfile but has no digest.
	MissingDigest bool
}

// GetAdapterDigestInfo retrieves digest information for an adapter from the lockfile.
//
// SECURITY: This function determines whether TOCTOU-safe verification is required
// for the adapter. Source-based adapters should always have a digest pinned in the
// lockfile for secure execution.
//
// Note: Remotes must be configured with either source: or binary: in epack.yaml.
// There is no PATH discovery fallback (matching the collector model).
func GetAdapterDigestInfo(remoteName string, remoteCfg *config.RemoteConfig, lf *lockfile.LockFile, platform string) AdapterDigestInfo {
	info := AdapterDigestInfo{}

	// External binary (binary path in config)
	if remoteCfg.Binary != "" {
		info.IsExternalBinary = true
		info.NeedsVerification = true
		// External binaries should be pinned in lockfile
		locked, ok := lf.GetRemote(remoteName)
		if ok {
			platformEntry, hasPlat := locked.Platforms[platform]
			if hasPlat && platformEntry.Digest != "" {
				info.Digest = platformEntry.Digest
			} else {
				info.MissingDigest = true
			}
		} else {
			info.MissingDigest = true
		}
		return info
	}

	// Source-based adapter
	info.IsSourceAdapter = true
	info.NeedsVerification = true

	locked, ok := lf.GetRemote(remoteName)
	if !ok {
		info.MissingDigest = true
		return info
	}

	platformEntry, ok := locked.Platforms[platform]
	if !ok {
		info.MissingDigest = true
		return info
	}

	if platformEntry.Digest == "" {
		info.MissingDigest = true
		return info
	}

	info.Digest = platformEntry.Digest
	return info
}

type VerificationSecureOptions struct {
	// Frozen requires all adapters to be pinned with digests (CI mode).
	Frozen bool
}

type VerificationUnsafeOverrides struct {
	// AllowUnverifiedInstall permits execution of adapters installed with --insecure-skip-verify.
	AllowUnverifiedInstall bool

	// AllowUnverifiedSource permits execution of source-based adapters without digest.
	// SECURITY WARNING: This bypasses TOCTOU protection for source-based adapters.
	AllowUnverifiedSource bool
}

// VerificationOptions controls adapter verification behavior.
type VerificationOptions struct {
	// Secure defaults.
	Secure VerificationSecureOptions
	// Explicit insecure overrides.
	Unsafe VerificationUnsafeOverrides
}

// DefaultVerificationOptions returns secure defaults for adapter verification.
func DefaultVerificationOptions() VerificationOptions {
	return VerificationOptions{
		Secure: VerificationSecureOptions{
			Frozen: false,
		},
		Unsafe: VerificationUnsafeOverrides{
			AllowUnverifiedInstall: false,
			AllowUnverifiedSource:  false,
		},
	}
}

// CheckAdapterSecurity performs security checks before adapter execution.
// Validates:
//  1. Insecure install marker (adapter was installed with --insecure-skip-verify)
//  2. Source-based adapters have digests pinned (unless explicitly allowed)
//  3. External adapters are pinned in lockfile (unless explicitly allowed)
//  4. Frozen mode requirements (all adapters must be pinned)
//
// Returns nil if execution is allowed, or an error describing the security violation.
func CheckAdapterSecurity(remoteName, binaryPath string, digestInfo AdapterDigestInfo, opts VerificationOptions) error {
	if err := enforceAdapterExecutionPolicy(opts); err != nil {
		return err
	}
	if err := sync.CheckInsecureMarkerAllowed(remoteName, componenttypes.KindRemote, binaryPath, opts.Secure.Frozen, opts.Unsafe.AllowUnverifiedInstall); err != nil {
		return err
	}
	if err := checkSourceAdapterDigest(remoteName, digestInfo, opts); err != nil {
		return err
	}
	if err := checkExternalAdapterDigest(remoteName, digestInfo, opts); err != nil {
		return err
	}
	if err := checkFrozenAdapterPinning(remoteName, digestInfo, opts); err != nil {
		return err
	}
	maybeAuditUnverifiedAdapter(remoteName, digestInfo, opts)
	return nil
}

func enforceAdapterExecutionPolicy(opts VerificationOptions) error {
	if err := (securitypolicy.ExecutionPolicy{
		Frozen:        opts.Secure.Frozen,
		AllowUnpinned: opts.Unsafe.AllowUnverifiedSource,
	}).Enforce(); err != nil {
		return err
	}
	return securitypolicy.EnforceStrictProduction("remote_adapter",
		opts.Unsafe.AllowUnverifiedInstall || opts.Unsafe.AllowUnverifiedSource,
	)
}

func checkSourceAdapterDigest(remoteName string, digestInfo AdapterDigestInfo, opts VerificationOptions) error {
	if !digestInfo.IsSourceAdapter || !digestInfo.MissingDigest {
		return nil
	}
	if opts.Secure.Frozen {
		return errors.WithHint(errors.LockfileInvalid, exitcode.LockInvalid,
			fmt.Sprintf("remote %q missing digest in lockfile (required in --frozen mode)", remoteName),
			"Run 'epack lock' to compute and pin digests", nil)
	}
	if !opts.Unsafe.AllowUnverifiedSource {
		return errors.WithHint(errors.LockfileInvalid, exitcode.LockInvalid,
			fmt.Sprintf("remote %q missing digest in lockfile", remoteName),
			"Run 'epack lock' to compute and pin digests, or use --insecure-allow-unpinned", nil)
	}
	securityaudit.Emit(securityaudit.Event{
		Type:        securityaudit.EventInsecureBypass,
		Component:   string(componenttypes.KindRemote),
		Name:        remoteName,
		Description: "allowing source adapter execution without lockfile digest",
		Attrs: map[string]string{
			"reason": "allow_unverified_source",
		},
	})
	return nil
}

func checkExternalAdapterDigest(remoteName string, digestInfo AdapterDigestInfo, opts VerificationOptions) error {
	if !digestInfo.IsExternalBinary || !digestInfo.MissingDigest {
		return nil
	}
	if opts.Secure.Frozen {
		return errors.WithHint(errors.LockfileInvalid, exitcode.LockInvalid,
			fmt.Sprintf("external remote %q is not pinned in lockfile (required in --frozen mode)", remoteName),
			"Run 'epack lock' to pin external remotes", nil)
	}
	if !opts.Unsafe.AllowUnverifiedSource {
		return errors.WithHint(errors.LockfileInvalid, exitcode.LockInvalid,
			fmt.Sprintf("external remote %q is not pinned in lockfile", remoteName),
			"Run 'epack lock' to pin external remotes, or use --insecure-allow-unpinned", nil)
	}
	securityaudit.Emit(securityaudit.Event{
		Type:        securityaudit.EventUnpinnedExecution,
		Component:   string(componenttypes.KindRemote),
		Name:        remoteName,
		Description: "executing external adapter without lockfile pin",
		Attrs: map[string]string{
			"reason": "allow_unverified_source",
		},
	})
	return nil
}

func checkFrozenAdapterPinning(remoteName string, digestInfo AdapterDigestInfo, opts VerificationOptions) error {
	if !opts.Secure.Frozen || !digestInfo.NeedsVerification || digestInfo.Digest != "" {
		return nil
	}
	return errors.WithHint(errors.LockfileInvalid, exitcode.LockInvalid,
		fmt.Sprintf("remote %q not pinned in lockfile (required in --frozen mode)", remoteName),
		"Run 'epack lock' to pin all remotes", nil)
}

func maybeAuditUnverifiedAdapter(remoteName string, digestInfo AdapterDigestInfo, opts VerificationOptions) {
	if digestInfo.Digest != "" || !opts.Unsafe.AllowUnverifiedSource {
		return
	}
	securityaudit.Emit(securityaudit.Event{
		Type:        securityaudit.EventInsecureBypass,
		Component:   string(componenttypes.KindRemote),
		Name:        remoteName,
		Description: "adapter execution proceeds without digest verification",
	})
}
