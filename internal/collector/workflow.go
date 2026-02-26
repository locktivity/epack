package collector

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/locktivity/epack/internal/component/config"
	"github.com/locktivity/epack/internal/component/lockfile"
	"github.com/locktivity/epack/internal/component/sync"
	"github.com/locktivity/epack/internal/packpath"
	"github.com/locktivity/epack/internal/platform"
	"github.com/locktivity/epack/pack/builder"
)

// CollectOpts configures the full evidence collection workflow.
type CollectOpts struct {
	// WorkDir is the working directory (defaults to cwd).
	WorkDir string

	// OutputPath is the output pack file path.
	// If empty, defaults to "evidence-<timestamp>.pack".
	OutputPath string

	// Frozen enables strict CI mode: no auto-lock, no auto-sync.
	Frozen bool

	// Timeout per collector execution.
	Timeout time.Duration

	// Only runs specific collectors (empty means all).
	Only []string

	// InsecureAllowUnverified allows running collectors
	// installed with --insecure-skip-verify.
	InsecureAllowUnverified bool

	// InsecureAllowUnpinned allows running external collectors
	// not pinned in the lockfile.
	InsecureAllowUnpinned bool
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
	workDir := opts.WorkDir
	if workDir == "" {
		var err error
		workDir, err = os.Getwd()
		if err != nil {
			return nil, fmt.Errorf("getting working directory: %w", err)
		}
	}

	if opts.Frozen {
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
		Frozen: true,
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

	if cfg.HasSourceCollectors() {
		lf, err := lockfile.Load(lockfilePath)
		if os.IsNotExist(err) {
			needsLock = true
		} else if err != nil {
			return nil, fmt.Errorf("loading lockfile: %w", err)
		} else {
			// Check if lockfile needs updating
			needsLock = lockfileNeedsUpdateWorkflow(cfg, lf, platform)
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
		Frozen: false,
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
		Frozen:                  opts.Frozen,
		Only:                    opts.Only,
		InsecureAllowUnverified: opts.InsecureAllowUnverified,
		InsecureAllowUnpinned:   opts.InsecureAllowUnpinned,
		Timeout:                 opts.Timeout,
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
	outputPath := opts.OutputPath
	if outputPath == "" {
		timestamp := time.Now().UTC().Format("20060102-150405")
		outputPath = fmt.Sprintf("evidence-%s%s", timestamp, packpath.PackExtension)
	}

	b := builder.New(cfg.Stream)

	// Load lockfile to get collector versions for source metadata
	lockfilePath := filepath.Join(workDir, lockfile.FileName)
	lf, _ := lockfile.Load(lockfilePath) // Ignore error; sources are optional

	// Add each collector as a source with its version from the lockfile
	for _, r := range runResult.Results {
		if !r.Success {
			continue
		}
		version := ""
		if lf != nil {
			if locked, ok := lf.GetCollector(r.Collector); ok {
				version = locked.Version
			}
		}
		b.AddSource(r.Collector, version)
	}

	// Add each collector's output as an artifact using shared helper
	if err := addCollectorArtifacts(b, runResult.Results); err != nil {
		return nil, err
	}

	if err := b.Build(outputPath); err != nil {
		return nil, fmt.Errorf("building pack: %w", err)
	}

	result.PackPath = outputPath
	return result, nil
}

// lockfileNeedsUpdateWorkflow checks if the lockfile needs updating for the given platform.
func lockfileNeedsUpdateWorkflow(cfg *config.JobConfig, lf *lockfile.LockFile, platform string) bool {
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
	return false
}

// addCollectorArtifacts adds collector outputs as artifacts to the builder.
// This is the canonical implementation for artifact packaging - both Collect and
// RunAndBuild use this to ensure consistent output format.
//
// Output handling:
//   - Protocol envelope output: extracts data field only (strips protocol_version)
//   - Plain JSON output: uses as-is
//   - Non-JSON output: wraps in {"collector": name, "raw": output}
func addCollectorArtifacts(b *builder.Builder, results []RunResult) error {
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

		// Use RawData directly to preserve exact numeric values.
		// This avoids float64 precision loss for integers > 2^53-1.
		artifactData := envelope.RawData

		artifactPath := fmt.Sprintf("artifacts/%s.json", r.Collector)
		if err := b.AddBytes(artifactPath, artifactData); err != nil {
			return fmt.Errorf("adding artifact %s: %w", artifactPath, err)
		}
	}
	return nil
}

// RunAndBuildOpts configures the run-only workflow (no lock/sync).
type RunAndBuildOpts struct {
	// WorkDir is the working directory (required).
	WorkDir string

	// OutputPath is the output pack file path.
	// If empty, defaults to "evidence-<timestamp>.pack".
	OutputPath string

	// Frozen enables strict CI mode verification.
	Frozen bool

	// Timeout per collector execution.
	Timeout time.Duration

	// Only runs specific collectors (empty means all).
	Only []string

	// InsecureAllowUnverified allows running collectors
	// installed with --insecure-skip-verify.
	InsecureAllowUnverified bool

	// InsecureAllowUnpinned allows running external collectors
	// not pinned in the lockfile.
	InsecureAllowUnpinned bool
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
	result := &RunAndBuildResult{
		Stream: cfg.Stream,
	}

	runner := NewRunner(opts.WorkDir)

	runOpts := RunOptions{
		Frozen:                  opts.Frozen,
		Only:                    opts.Only,
		InsecureAllowUnverified: opts.InsecureAllowUnverified,
		InsecureAllowUnpinned:   opts.InsecureAllowUnpinned,
		Timeout:                 opts.Timeout,
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
	outputPath := opts.OutputPath
	if outputPath == "" {
		timestamp := time.Now().UTC().Format("20060102-150405")
		outputPath = fmt.Sprintf("evidence-%s%s", timestamp, packpath.PackExtension)
	}

	b := builder.New(cfg.Stream)

	// Add each collector's output as an artifact using shared helper
	if err := addCollectorArtifacts(b, runResult.Results); err != nil {
		return nil, err
	}

	if err := b.Build(outputPath); err != nil {
		return nil, fmt.Errorf("building pack: %w", err)
	}

	result.PackPath = outputPath
	return result, nil
}
