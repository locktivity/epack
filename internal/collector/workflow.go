package collector

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/locktivity/epack/internal/component/config"
	"github.com/locktivity/epack/internal/component/lockfile"
	"github.com/locktivity/epack/internal/component/sync"
	"github.com/locktivity/epack/internal/credentials"
	"github.com/locktivity/epack/internal/packpath"
	"github.com/locktivity/epack/internal/platform"
	"github.com/locktivity/epack/internal/securitypolicy"
	"github.com/locktivity/epack/internal/timestamp"
	"github.com/locktivity/epack/pack"
	"github.com/locktivity/epack/pack/builder"
)

// CollectOpts configures the full evidence collection workflow.
type CollectOpts struct {
	// Secure defaults.
	Secure SecureRunOptions
	// Explicit insecure overrides.
	Unsafe UnsafeOverrides

	// WorkDir is the working directory (defaults to cwd).
	WorkDir string

	// Stderr receives runtime security warnings.
	Stderr io.Writer

	// OutputPath is the output pack file path.
	// If empty, defaults to "evidence-<timestamp>.epack".
	OutputPath string

	// OnCollectorEvent receives collector lifecycle events while running.
	OnCollectorEvent func(CollectorEvent)
}

// CollectWorkflowResult contains the outcomes of evidence collection.
type CollectWorkflowResult struct {
	// PackPath is the path to the created evidence pack.
	PackPath string

	// Stream is the stream identifier from config.
	Stream string

	// CollectorResults contains results for each collector.
	CollectorResults []RunResult

	// Failures is the count of failed collectors.
	Failures int

	// LockfileUpdated indicates if the lockfile was modified.
	LockfileUpdated bool

	// LockResults contains results from locking (if performed).
	LockResults []LockWorkflowResult

	// SyncResults contains results from syncing.
	SyncResults []SyncWorkflowResult
}

// LockWorkflowResult contains the outcome of locking a single collector.
type LockWorkflowResult struct {
	Name    string
	Version string
	IsNew   bool
	Updated bool
}

// SyncWorkflowResult contains the outcome of syncing a single collector.
type SyncWorkflowResult struct {
	Name      string
	Version   string
	Installed bool
	Verified  bool
	Skipped   bool
}

// Collect runs the full evidence collection workflow.
//
// In non-frozen mode (default):
//  1. Lock collectors if lockfile is missing or stale
//  2. Sync (download) any missing collectors
//  3. Run all collectors
//  4. Build an evidence pack
//
// In frozen mode:
//  1. Verify lockfile exists and matches config
//  2. Verify all collectors are installed with correct digests
//  3. Run all collectors
//  4. Build an evidence pack
func Collect(ctx context.Context, cfg *config.JobConfig, opts CollectOpts) (*CollectWorkflowResult, error) {
	if err := (securitypolicy.ExecutionPolicy{
		Frozen:        opts.Secure.Frozen,
		AllowUnpinned: opts.Unsafe.AllowUnpinned,
	}).Enforce(); err != nil {
		return nil, err
	}
	if err := securitypolicy.EnforceStrictProduction("collector_workflow", opts.Unsafe.AllowUnverifiedInstall || opts.Unsafe.AllowUnpinned); err != nil {
		return nil, err
	}
	if cfg == nil {
		return nil, fmt.Errorf("job config is required")
	}
	if err := credentials.ValidateManagedCredentialBrokerOverride(opts.Stderr, managedCredentialRefsForCollectors(cfg.Collectors), credentials.BrokerOverridePolicy{
		StrictProductionComponent: "collect_cli",
		AuditComponent:            "collect",
		AuditName:                 "collect",
		AuditDescription:          "collect command running with insecure custom credential broker override",
	}); err != nil {
		return nil, err
	}

	workDir := opts.WorkDir
	if workDir == "" {
		var err error
		workDir, err = os.Getwd()
		if err != nil {
			return nil, fmt.Errorf("getting working directory: %w", err)
		}
	}

	if opts.Secure.Frozen {
		return collectFrozen(ctx, cfg, workDir, opts)
	}
	return collectAuto(ctx, cfg, workDir, opts)
}

// collectFrozen runs in strict CI mode: no auto-lock, no auto-sync.
func collectFrozen(ctx context.Context, cfg *config.JobConfig, workDir string, opts CollectOpts) (*CollectWorkflowResult, error) {
	result := &CollectWorkflowResult{
		Stream: cfg.Stream,
	}

	// Sync in frozen mode (verify only, no downloads)
	syncer := sync.NewSyncer(workDir)

	syncOpts := sync.SyncOpts{
		Secure: sync.SyncSecureOptions{
			Frozen: true,
		},
	}

	syncResults, err := syncer.Sync(ctx, cfg, syncOpts)
	if err != nil {
		return nil, fmt.Errorf("sync verification failed: %w", err)
	}

	for _, r := range syncResults {
		result.SyncResults = append(result.SyncResults, SyncWorkflowResult{
			Name:     r.Name,
			Version:  r.Version,
			Verified: r.Verified,
			Skipped:  r.Skipped,
		})
	}

	// Run collectors and build pack
	return runAndBuildPackWorkflow(ctx, cfg, workDir, opts, result)
}

// collectAuto runs with auto-lock and auto-sync.
func collectAuto(ctx context.Context, cfg *config.JobConfig, workDir string, opts CollectOpts) (*CollectWorkflowResult, error) {
	result := &CollectWorkflowResult{
		Stream: cfg.Stream,
	}

	lockfilePath := filepath.Join(workDir, lockfile.FileName)
	platform := platform.Key(runtime.GOOS, runtime.GOARCH)

	// Check if we need to lock
	needsLock := false

	if cfg.NeedsLocking() {
		lf, err := lockfile.Load(lockfilePath)
		if os.IsNotExist(err) {
			needsLock = true
		} else if err != nil {
			return nil, fmt.Errorf("loading lockfile: %w", err)
		} else {
			// Check if lockfile needs updating (including content drift)
			needsLock = lockfileNeedsUpdateWorkflow(cfg, lf, platform, workDir)
		}
	}

	if needsLock {
		locker := sync.NewLocker(workDir)

		// Determine platforms to lock
		platforms := cfg.Platforms
		if len(platforms) == 0 {
			// Default to current platform only
			platforms = []string{platform}
		}

		lockOpts := sync.LockOpts{
			Platforms: platforms,
		}

		lockResults, err := locker.Lock(ctx, cfg, lockOpts)
		if err != nil {
			return nil, fmt.Errorf("locking collectors: %w", err)
		}

		for _, r := range lockResults {
			result.LockResults = append(result.LockResults, LockWorkflowResult{
				Name:    r.Name,
				Version: r.Version,
				IsNew:   r.IsNew,
				Updated: r.Updated,
			})
		}
		result.LockfileUpdated = true
	}

	// Sync (download missing collectors)
	syncer := sync.NewSyncer(workDir)
	syncOpts := sync.SyncOpts{
		Secure: sync.SyncSecureOptions{
			Frozen: false,
		},
	}

	syncResults, err := syncer.Sync(ctx, cfg, syncOpts)
	if err != nil {
		return nil, fmt.Errorf("syncing collectors: %w", err)
	}

	for _, r := range syncResults {
		result.SyncResults = append(result.SyncResults, SyncWorkflowResult{
			Name:      r.Name,
			Version:   r.Version,
			Installed: r.Installed,
			Verified:  r.Verified,
			Skipped:   r.Skipped,
		})
	}

	// Run collectors and build pack
	return runAndBuildPackWorkflow(ctx, cfg, workDir, opts, result)
}

// runAndBuildPackWorkflow runs collectors and builds the evidence pack.
func runAndBuildPackWorkflow(ctx context.Context, cfg *config.JobConfig, workDir string, opts CollectOpts, result *CollectWorkflowResult) (*CollectWorkflowResult, error) {
	runner := NewRunner(workDir)

	runOpts := RunOptions{
		Secure: SecureRunOptions{
			Frozen:  opts.Secure.Frozen,
			Only:    opts.Secure.Only,
			Timeout: opts.Secure.Timeout,
		},
		Unsafe: UnsafeOverrides{
			AllowUnverifiedInstall: opts.Unsafe.AllowUnverifiedInstall,
			AllowUnpinned:          opts.Unsafe.AllowUnpinned,
		},
		Progress: ProgressHooks{
			OnCollectorEvent: opts.OnCollectorEvent,
		},
	}

	runResult, err := runner.Run(ctx, cfg, runOpts)
	if err != nil {
		return nil, fmt.Errorf("running collectors: %w", err)
	}

	// Copy collector results
	result.CollectorResults = runResult.Results
	result.Failures = runResult.Failures

	// Check for failures
	if result.Failures > 0 {
		return result, fmt.Errorf("%d collector(s) failed", result.Failures)
	}

	// Build evidence pack
	outputPath := resolveOutputPath(opts.OutputPath)

	b := builder.New(cfg.Stream)

	// Load lockfile to get collector versions and digests for source metadata
	lockfilePath := filepath.Join(workDir, lockfile.FileName)
	lf, _ := lockfile.Load(lockfilePath) // Ignore error; sources are optional

	// Get current platform for binary digest lookup
	platformKey := platform.Key(runtime.GOOS, runtime.GOARCH)

	// Add each collector as a source with its version and provenance from the lockfile
	for _, r := range runResult.Results {
		if !r.Success {
			continue
		}
		version := ""
		source := ""
		commit := ""
		binaryDigest := ""
		if lf != nil {
			if locked, ok := lf.GetCollector(r.Collector); ok {
				version = locked.Version
				source = locked.Source
				commit = locked.Commit
				// Get the binary digest for the current platform
				if platformEntry, ok := locked.Platforms[platformKey]; ok {
					binaryDigest = platformEntry.Digest
				}
			}
		}
		b.AddSourceWithOptions(r.Collector, version, builder.SourceOptions{
			Source:       source,
			Commit:       commit,
			BinaryDigest: binaryDigest,
		})
	}

	// Record collection timestamp for all artifacts (freshness checking)
	collectedAt := timestamp.Now().String()

	// Add each collector's output as an artifact using shared helper
	if err := addCollectorArtifacts(b, runResult.Results, collectedAt); err != nil {
		return nil, err
	}

	// Set profile and overlay refs for traceability (builder handles empty slices)
	b.SetProfiles(buildProfileRefs(cfg, lf))
	b.SetOverlays(buildOverlayRefs(cfg, lf))

	if err := b.Build(outputPath); err != nil {
		return nil, fmt.Errorf("building pack: %w", err)
	}

	result.PackPath = outputPath
	return result, nil
}

// buildProfileRefs builds profile refs from config and lockfile for manifest traceability.
func buildProfileRefs(cfg *config.JobConfig, lf *lockfile.LockFile) []pack.ProfileRef {
	if len(cfg.Profiles) == 0 {
		return nil
	}

	refs := make([]pack.ProfileRef, 0, len(cfg.Profiles))
	for _, profile := range cfg.Profiles {
		key := profile.Key()
		ref := pack.ProfileRef{Source: key}
		if lf != nil {
			ref.Digest, _ = lf.GetProfileDigest(key)
		}
		refs = append(refs, ref)
	}
	return refs
}

// buildOverlayRefs builds overlay refs from config and lockfile for manifest traceability.
func buildOverlayRefs(cfg *config.JobConfig, lf *lockfile.LockFile) []pack.ProfileRef {
	if len(cfg.Overlays) == 0 {
		return nil
	}

	refs := make([]pack.ProfileRef, 0, len(cfg.Overlays))
	for _, overlay := range cfg.Overlays {
		key := overlay.Key()
		ref := pack.ProfileRef{Source: key}
		if lf != nil {
			ref.Digest, _ = lf.GetOverlayDigest(key)
		}
		refs = append(refs, ref)
	}
	return refs
}

// resolveOutputPath determines the output pack file path.
// If path is empty, generates a default timestamped filename.
// If path is a directory, generates a timestamped filename inside it.
// Otherwise returns the path unchanged.
func resolveOutputPath(path string) string {
	if path == "" {
		return defaultPackFilename()
	}

	// Check if path is a directory
	info, err := os.Stat(path)
	if err == nil && info.IsDir() {
		return filepath.Join(path, defaultPackFilename())
	}

	return path
}

// defaultPackFilename generates a timestamped pack filename.
func defaultPackFilename() string {
	timestamp := time.Now().UTC().Format("20060102-150405")
	return fmt.Sprintf("evidence-%s%s", timestamp, packpath.PackExtension)
}

// lockfileNeedsUpdateWorkflow checks if the lockfile needs updating for the given platform.
// This includes checking for missing entries AND content drift (profiles/overlays modified after locking).
func lockfileNeedsUpdateWorkflow(cfg *config.JobConfig, lf *lockfile.LockFile, platform, workDir string) bool {
	// Check source collectors
	for name, collectorCfg := range cfg.Collectors {
		// Skip external collectors
		if collectorCfg.Source == "" {
			continue
		}

		locked, ok := lf.GetCollector(name)
		if !ok {
			return true // Collector not in lockfile
		}

		// Check if platform exists
		if _, ok := locked.Platforms[platform]; !ok {
			return true // Platform not locked
		}
	}

	// Check profiles (need lockfile entries with digest for verification)
	for _, profile := range cfg.Profiles {
		if _, ok := lf.GetProfileDigest(profile.Key()); !ok {
			return true
		}
	}

	// Check overlays (need lockfile entries with digest for verification)
	for _, overlay := range cfg.Overlays {
		if _, ok := lf.GetOverlayDigest(overlay.Key()); !ok {
			return true
		}
	}

	// Check for content drift (profiles/overlays modified after locking)
	if sync.HasProfileDigestDrift(cfg, lf, workDir) {
		return true
	}

	return false
}

// addCollectorArtifacts adds collector outputs as artifacts to the builder.
// This is the canonical implementation for artifact packaging - both Collect and
// RunAndBuild use this to ensure consistent output format.
//
// Output handling:
//   - Multiple artifacts: each artifact gets its own path (from artifact or default)
//   - Protocol envelope output: extracts artifacts array or data field
//   - Plain JSON output: uses as-is as single artifact
//   - Non-JSON output: wraps in {"collector": name, "raw": output}
//
// Artifact paths:
//   - If artifact specifies a path, use it directly
//   - Otherwise, default to "artifacts/{collector}.json" for first artifact
//   - For additional artifacts without paths, use "artifacts/{collector}_{index}.json"
//
// The collectedAt timestamp is recorded on all artifacts for freshness checking by validators.
func addCollectorArtifacts(b *builder.Builder, results []RunResult, collectedAt string) error {
	for _, r := range results {
		if !r.Success {
			continue
		}

		// Parse collector output using the canonical parser.
		// This handles protocol envelopes, plain JSON, and non-JSON output uniformly.
		envelope, err := ParseCollectorOutput(r.Output)
		if err != nil {
			return fmt.Errorf("parsing collector output for %s: %w", r.Collector, err)
		}

		// Add each artifact
		for i, artifact := range envelope.Artifacts {
			artifactPath := artifact.PathOrDefault(r.Collector, i)
			opts := builder.ArtifactOptions{
				Schema:      artifact.Schema,
				CollectedAt: collectedAt,
			}
			if err := b.AddBytesWithOptions(artifactPath, artifact.RawData, opts); err != nil {
				return fmt.Errorf("adding artifact %s: %w", artifactPath, err)
			}
		}
	}
	return nil
}

// RunAndBuildOpts configures the run-only workflow (no lock/sync).
type RunAndBuildOpts struct {
	// Secure defaults.
	Secure SecureRunOptions
	// Explicit insecure overrides.
	Unsafe UnsafeOverrides

	// WorkDir is the working directory (required).
	WorkDir string

	// Stderr receives runtime security warnings.
	Stderr io.Writer

	// OutputPath is the output pack file path.
	// If empty, defaults to "evidence-<timestamp>.epack".
	OutputPath string

	// OnCollectorEvent receives collector lifecycle events while running.
	OnCollectorEvent func(CollectorEvent)
}

// RunAndBuildResult contains the outcomes of running collectors and building a pack.
type RunAndBuildResult struct {
	// PackPath is the path to the created evidence pack.
	PackPath string

	// Stream is the stream identifier from config.
	Stream string

	// CollectorResults contains results for each collector.
	CollectorResults []RunResult

	// Failures is the count of failed collectors.
	Failures int
}

// RunAndBuild executes collectors and builds an evidence pack.
//
// Unlike Collect, this does NOT auto-lock or auto-sync.
// It assumes collectors are already installed and verified.
func RunAndBuild(ctx context.Context, cfg *config.JobConfig, opts RunAndBuildOpts) (*RunAndBuildResult, error) {
	if err := (securitypolicy.ExecutionPolicy{
		Frozen:        opts.Secure.Frozen,
		AllowUnpinned: opts.Unsafe.AllowUnpinned,
	}).Enforce(); err != nil {
		return nil, err
	}
	if err := securitypolicy.EnforceStrictProduction("collector_run", opts.Unsafe.AllowUnverifiedInstall || opts.Unsafe.AllowUnpinned); err != nil {
		return nil, err
	}
	if cfg == nil {
		return nil, fmt.Errorf("job config is required")
	}

	result := &RunAndBuildResult{
		Stream: cfg.Stream,
	}

	runner := NewRunner(opts.WorkDir)

	runOpts := RunOptions{
		Secure: SecureRunOptions{
			Frozen:  opts.Secure.Frozen,
			Only:    opts.Secure.Only,
			Timeout: opts.Secure.Timeout,
		},
		Unsafe: UnsafeOverrides{
			AllowUnverifiedInstall: opts.Unsafe.AllowUnverifiedInstall,
			AllowUnpinned:          opts.Unsafe.AllowUnpinned,
		},
		Progress: ProgressHooks{
			OnCollectorEvent: opts.OnCollectorEvent,
		},
	}
	if err := credentials.ValidateManagedCredentialBrokerOverride(opts.Stderr, managedCredentialRefsForCollectors(runner.selectCollectors(cfg, runOpts)), credentials.BrokerOverridePolicy{
		StrictProductionComponent: "collector_run_cli",
		AuditComponent:            "collector_run",
		AuditName:                 "run",
		AuditDescription:          "collector run command running with insecure custom credential broker override",
	}); err != nil {
		return nil, err
	}

	runResult, err := runner.Run(ctx, cfg, runOpts)
	if err != nil {
		return nil, fmt.Errorf("running collectors: %w", err)
	}

	// Copy collector results
	result.CollectorResults = runResult.Results
	result.Failures = runResult.Failures

	// Check for failures
	if result.Failures > 0 {
		return result, fmt.Errorf("%d collector(s) failed", result.Failures)
	}

	// Build evidence pack
	outputPath := resolveOutputPath(opts.OutputPath)

	b := builder.New(cfg.Stream)

	// Record collection timestamp for all artifacts (freshness checking)
	collectedAt := timestamp.Now().String()

	// Add each collector's output as an artifact using shared helper
	if err := addCollectorArtifacts(b, runResult.Results, collectedAt); err != nil {
		return nil, err
	}

	lockfilePath := filepath.Join(opts.WorkDir, lockfile.FileName)
	lf, _ := lockfile.Load(lockfilePath)
	b.SetProfiles(buildProfileRefs(cfg, lf))
	b.SetOverlays(buildOverlayRefs(cfg, lf))

	if err := b.Build(outputPath); err != nil {
		return nil, fmt.Errorf("building pack: %w", err)
	}

	result.PackPath = outputPath
	return result, nil
}

func managedCredentialRefsForCollectors(collectors map[string]config.CollectorConfig) []string {
	if len(collectors) == 0 {
		return nil
	}
	refs := make([]string, 0)
	seen := make(map[string]struct{})
	for _, collectorCfg := range collectors {
		for _, ref := range collectorCfg.Credentials {
			if _, ok := seen[ref]; ok {
				continue
			}
			seen[ref] = struct{}{}
			refs = append(refs, ref)
		}
	}
	return refs
}
