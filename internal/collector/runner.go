package collector

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"sync/atomic"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/locktivity/epack/errors"
	collectorexec "github.com/locktivity/epack/internal/collector/exec"
	"github.com/locktivity/epack/internal/component/config"
	"github.com/locktivity/epack/internal/component/lockfile"
	"github.com/locktivity/epack/internal/component/sync"
	"github.com/locktivity/epack/internal/componenttypes"
	"github.com/locktivity/epack/internal/execsafe"
	"github.com/locktivity/epack/internal/exitcode"
	"github.com/locktivity/epack/internal/limits"
	"github.com/locktivity/epack/internal/platform"
	"github.com/locktivity/epack/internal/securityaudit"
	"github.com/locktivity/epack/internal/securitypolicy"
)

// Collector config is passed only via EPACK_COLLECTOR_CONFIG.
// stdin is intentionally not used to avoid dual config channels and precedence ambiguity.

// CollectorOutput is the envelope returned by collectors via stdout.
type CollectorOutput struct {
	ProtocolVersion int `json:"protocol_version"`
	// Artifacts contains parsed artifact entries from the collector output.
	// For legacy format (single "data" field), this contains one artifact with no schema/path.
	Artifacts []CollectorArtifact `json:"-"`
}

// CollectorArtifact represents a single artifact from collector output.
type CollectorArtifact struct {
	// RawData holds the raw JSON bytes of the data field to preserve numeric precision.
	RawData json.RawMessage
	// Schema is the semantic schema type (e.g., "evidencepack/cloud-posture@v1").
	Schema string
	// Path is the artifact path within the pack (e.g., "posture/cloud.json").
	Path string
}

// PathOrDefault returns the artifact's path, or generates a default based on collector name and index.
func (a CollectorArtifact) PathOrDefault(collector string, index int) string {
	if a.Path != "" {
		return a.Path
	}
	if index == 0 {
		return fmt.Sprintf("artifacts/%s.json", collector)
	}
	return fmt.Sprintf("artifacts/%s_%d.json", collector, index)
}

// rawArtifactEntry is the JSON structure for artifacts in the protocol envelope.
type rawArtifactEntry struct {
	Data   json.RawMessage `json:"data"`
	Schema string          `json:"schema"`
	Path   string          `json:"path"`
}

// ParseCollectorOutput decodes collector stdout.
// If stdout is not protocol-envelope JSON, it is preserved as a single artifact for lossless passthrough.
// Handles:
// - New format with "artifacts" array (multiple artifacts with schema/path)
// - Legacy format with "data" field (single artifact)
// - Plain JSON (single artifact, no envelope)
// - Non-JSON (wrapped as string)
func ParseCollectorOutput(output []byte) (*CollectorOutput, error) {
	if !json.Valid(output) {
		return wrapNonJSONOutput(output)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(output, &raw); err == nil {
		if isResultEnvelope(raw) {
			return extractEnvelope(raw)
		}
	}

	return preserveAsRawData(output), nil
}

// isResultEnvelope checks if raw JSON is a collector result envelope.
// Accepts envelopes with either "artifacts" array or legacy "data" field.
func isResultEnvelope(raw map[string]json.RawMessage) bool {
	_, hasVersion := raw["protocol_version"]
	_, hasData := raw["data"]
	_, hasArtifacts := raw["artifacts"]

	if !hasVersion || (!hasData && !hasArtifacts) {
		return false
	}

	// Check if it has type field - if so, must be "epack_result"
	if typeBytes, hasType := raw["type"]; hasType {
		var msgType string
		if err := json.Unmarshal(typeBytes, &msgType); err != nil || msgType != "epack_result" {
			return false
		}
	}
	return true
}

// extractEnvelope extracts protocol_version and artifacts from a result envelope.
// Handles both "artifacts" array format and legacy "data" field format.
func extractEnvelope(raw map[string]json.RawMessage) (*CollectorOutput, error) {
	var version int
	if err := json.Unmarshal(raw["protocol_version"], &version); err != nil {
		return nil, fmt.Errorf("parsing protocol_version: %w", err)
	}

	output := &CollectorOutput{
		ProtocolVersion: version,
	}

	// Check for new "artifacts" array format first
	if artifactsRaw, hasArtifacts := raw["artifacts"]; hasArtifacts {
		artifacts, err := parseArtifactsArray(artifactsRaw)
		if err != nil {
			return nil, err
		}
		output.Artifacts = artifacts
		return output, nil
	}

	// Fall back to legacy "data" field format (single artifact)
	if dataRaw, hasData := raw["data"]; hasData {
		output.Artifacts = []CollectorArtifact{{RawData: dataRaw}}
		return output, nil
	}

	return nil, fmt.Errorf("envelope missing both 'artifacts' and 'data' fields")
}

// parseArtifactsArray parses the raw JSON artifacts array into CollectorArtifacts.
func parseArtifactsArray(raw json.RawMessage) ([]CollectorArtifact, error) {
	var entries []rawArtifactEntry
	if err := json.Unmarshal(raw, &entries); err != nil {
		return nil, fmt.Errorf("parsing artifacts: %w", err)
	}
	artifacts := make([]CollectorArtifact, len(entries))
	for i, e := range entries {
		artifacts[i] = CollectorArtifact{
			RawData: e.Data,
			Schema:  e.Schema,
			Path:    e.Path,
		}
	}
	return artifacts, nil
}

// wrapNonJSONOutput wraps non-JSON output as a JSON string in a single artifact.
func wrapNonJSONOutput(output []byte) (*CollectorOutput, error) {
	quoted, err := json.Marshal(string(output))
	if err != nil {
		return nil, fmt.Errorf("marshaling non-JSON output: %w", err)
	}
	return &CollectorOutput{
		ProtocolVersion: 0,
		Artifacts:       []CollectorArtifact{{RawData: quoted}},
	}, nil
}

// preserveAsRawData creates output with the original JSON preserved as a single artifact.
func preserveAsRawData(output []byte) *CollectorOutput {
	rawCopy := make([]byte, len(output))
	copy(rawCopy, output)
	return &CollectorOutput{
		ProtocolVersion: 0,
		Artifacts:       []CollectorArtifact{{RawData: rawCopy}},
	}
}

// Runner executes collectors and collects evidence.
type Runner struct {
	BaseDir      string // .epack directory
	LockfilePath string
}

// NewRunner creates a runner with default paths.
func NewRunner(workDir string) *Runner {
	return &Runner{
		BaseDir:      filepath.Join(workDir, ".epack"),
		LockfilePath: filepath.Join(workDir, lockfile.FileName),
	}
}

// RunOptions controls collector execution.
type SecureRunOptions struct {
	Frozen             bool          // Fail on any mismatch (CI mode)
	Only               []string      // Run only these collectors (empty = all)
	Timeout            time.Duration // Timeout per collector (0 = use DefaultCollectorTimeout)
	MaxAggregateBudget int64         // Total bytes retained across all collector outputs
	Parallel           int           // Max parallel collectors (0=auto, 1=sequential)
}

// UnsafeOverrides groups insecure execution toggles that require explicit opt-in.
type UnsafeOverrides struct {
	AllowUnverifiedInstall          bool // Allow components installed with insecure verification
	AllowUnpinned                   bool // Allow external collectors not pinned in lockfile
	AllowUnverifiedSourceCollectors bool // Allow source collectors missing lockfile digest
	InheritPath                     bool // Allow inheriting PATH from environment
}

type RunOptions struct {
	// Secure defaults.
	Secure SecureRunOptions
	// Explicit insecure overrides.
	Unsafe UnsafeOverrides
	// Optional progress hooks.
	Progress ProgressHooks
}

// CollectorEventType identifies collector lifecycle events.
type CollectorEventType string

const (
	CollectorEventStart    CollectorEventType = "start"
	CollectorEventFinish   CollectorEventType = "finish"
	CollectorEventStatus   CollectorEventType = "status"   // Indeterminate progress
	CollectorEventProgress CollectorEventType = "progress" // Progress with current/total
)

// CollectorEvent describes collector runtime progress.
type CollectorEvent struct {
	Type      CollectorEventType
	Collector string
	Index     int
	Total     int
	Success   bool
	Duration  time.Duration
	Error     error

	// Progress-specific fields (only set for status/progress events)
	Message         string // Status message or progress description
	ProgressCurrent int64  // Current progress value (for progress events)
	ProgressTotal   int64  // Total progress value (for progress events)
}

// ProgressHooks are optional callbacks for collection progress.
type ProgressHooks struct {
	OnCollectorEvent func(CollectorEvent)
}

// RunResult contains the result of running a collector.
type RunResult struct {
	Collector string
	Success   bool
	Output    []byte
	Error     error
}

// CollectResult contains all evidence from a collection run.
type CollectResult struct {
	Stream   string
	Results  []RunResult
	Failures int
}

// parallelResults collects results from concurrent collector executions.
// It provides thread-safe result collection with atomic failure counting.
type parallelResults struct {
	results  []RunResult
	failures int64 // atomic counter
}

// newParallelResults creates a parallelResults with pre-allocated slots.
func newParallelResults(size int) *parallelResults {
	return &parallelResults{
		results: make([]RunResult, size),
	}
}

// set stores a result at the given index and increments failure counter if needed.
// Thread-safe: each goroutine writes to its own slot.
func (p *parallelResults) set(index int, result RunResult) {
	p.results[index] = result
	if !result.Success {
		atomic.AddInt64(&p.failures, 1)
	}
}

// getFailures returns the number of failed collectors.
func (p *parallelResults) getFailures() int {
	return int(atomic.LoadInt64(&p.failures))
}

// Run executes all collectors and returns their outputs.
func (r *Runner) Run(ctx context.Context, cfg *config.JobConfig, opts RunOptions) (*CollectResult, error) {
	if err := validateRunPolicy(cfg, opts); err != nil {
		return nil, err
	}
	lf, err := r.loadLockfile(cfg, opts)
	if err != nil {
		return nil, err
	}

	platform := platform.Key(runtime.GOOS, runtime.GOARCH)
	if err := r.validateFrozenIfNeeded(cfg, lf, platform, opts.Secure.Frozen); err != nil {
		return nil, err
	}

	collectors := r.selectCollectors(cfg, opts)
	collectorNames := sortedCollectorNames(collectors)
	aggregateBudget := maxAggregateBudget(opts)
	result := &CollectResult{
		Stream:  cfg.Stream,
		Results: make([]RunResult, 0, len(collectors)),
	}
	r.runCollectors(ctx, collectorNames, collectors, lf, platform, opts, aggregateBudget, result)
	return result, nil
}

func validateRunPolicy(cfg *config.JobConfig, opts RunOptions) error {
	if err := (securitypolicy.ExecutionPolicy{
		Frozen:        opts.Secure.Frozen,
		AllowUnpinned: opts.Unsafe.AllowUnpinned,
	}).Enforce(); err != nil {
		return err
	}
	if err := securitypolicy.EnforceStrictProduction("collector",
		opts.Unsafe.AllowUnverifiedInstall || opts.Unsafe.AllowUnpinned || opts.Unsafe.AllowUnverifiedSourceCollectors || opts.Unsafe.InheritPath,
	); err != nil {
		return err
	}
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("invalid config: %w", err)
	}
	return nil
}

func (r *Runner) validateFrozenIfNeeded(cfg *config.JobConfig, lf *lockfile.LockFile, platformKey string, frozen bool) error {
	if !frozen {
		return nil
	}
	return r.validateFrozen(cfg, lf, platformKey)
}

func sortedCollectorNames(collectors map[string]config.CollectorConfig) []string {
	names := make([]string, 0, len(collectors))
	for name := range collectors {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func maxAggregateBudget(opts RunOptions) int64 {
	if opts.Secure.MaxAggregateBudget != 0 {
		return opts.Secure.MaxAggregateBudget
	}
	return limits.MaxAggregateOutputBytes
}

// effectiveParallelism determines the actual parallelism level to use.
// Returns 1 for sequential execution, or >1 for parallel execution.
func effectiveParallelism(configured int, collectorCount int) int {
	if collectorCount <= 1 {
		return 1 // No parallelism benefit with 0-1 collectors
	}
	if configured == 1 {
		return 1 // Explicit sequential
	}
	if configured > 1 {
		return min(configured, collectorCount)
	}
	// Auto: min(NumCPU, collectors, 8)
	auto := min(runtime.NumCPU(), collectorCount, 8)
	if auto < 1 {
		return 1
	}
	return auto
}

// runCollectors dispatches to sequential or parallel execution based on configuration.
func (r *Runner) runCollectors(
	ctx context.Context,
	collectorNames []string,
	collectors map[string]config.CollectorConfig,
	lf *lockfile.LockFile,
	platformKey string,
	opts RunOptions,
	aggregateBudget int64,
	result *CollectResult,
) {
	parallelism := effectiveParallelism(opts.Secure.Parallel, len(collectorNames))
	if parallelism <= 1 {
		r.runCollectorsSequential(ctx, collectorNames, collectors, lf, platformKey, opts, aggregateBudget, result)
		return
	}
	r.runCollectorsParallel(ctx, collectorNames, collectors, lf, platformKey, opts, aggregateBudget, parallelism, result)
}

// runCollectorsSequential executes collectors one at a time.
func (r *Runner) runCollectorsSequential(
	ctx context.Context,
	collectorNames []string,
	collectors map[string]config.CollectorConfig,
	lf *lockfile.LockFile,
	platformKey string,
	opts RunOptions,
	aggregateBudget int64,
	result *CollectResult,
) {
	var aggregateUsed int64
	for _, name := range collectorNames {
		idx := len(result.Results) + 1
		collectorCfg := collectors[name]
		if r.skipCollectorForBudget(name, idx, len(collectorNames), aggregateUsed, aggregateBudget, opts.Progress.OnCollectorEvent, result) {
			continue
		}

		emitCollectorEvent(opts.Progress.OnCollectorEvent, CollectorEvent{
			Type:      CollectorEventStart,
			Collector: name,
			Index:     idx,
			Total:     len(collectorNames),
		})
		started := time.Now()
		runResult := r.runOne(ctx, name, collectorCfg, lf, platformKey, opts, idx, len(collectorNames))
		aggregateUsed = enforceCollectorBudget(&runResult, aggregateUsed, aggregateBudget)
		result.Results = append(result.Results, runResult)
		emitCollectorEvent(opts.Progress.OnCollectorEvent, CollectorEvent{
			Type:      CollectorEventFinish,
			Collector: name,
			Index:     idx,
			Total:     len(collectorNames),
			Success:   runResult.Success,
			Duration:  time.Since(started),
			Error:     runResult.Error,
		})
		if !runResult.Success {
			result.Failures++
		}
	}
}

// runCollectorsParallel executes collectors concurrently with bounded parallelism.
func (r *Runner) runCollectorsParallel(
	ctx context.Context,
	collectorNames []string,
	collectors map[string]config.CollectorConfig,
	lf *lockfile.LockFile,
	platformKey string,
	opts RunOptions,
	aggregateBudget int64,
	parallelism int,
	result *CollectResult,
) {
	total := len(collectorNames)
	budget := limits.NewBytesBudget(aggregateBudget)
	presults := newParallelResults(total)

	// Map names to indices for deterministic result placement
	nameToIndex := make(map[string]int, total)
	for i, name := range collectorNames {
		nameToIndex[name] = i
	}

	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(parallelism)

	for _, name := range collectorNames {
		name := name // capture for goroutine
		collectorCfg := collectors[name]

		g.Go(func() error {
			idx := nameToIndex[name]

			// Check budget before running (early exit for clearly exceeded budget)
			if budget.BytesRemaining() <= 0 {
				runResult := RunResult{
					Collector: name,
					Success:   false,
					Error: fmt.Errorf("aggregate output budget exceeded (%d bytes); skipping collector",
						aggregateBudget),
				}
				presults.set(idx, runResult)
				emitCollectorEvent(opts.Progress.OnCollectorEvent, CollectorEvent{
					Type:      CollectorEventFinish,
					Collector: name,
					Index:     idx + 1,
					Total:     total,
					Success:   false,
					Error:     runResult.Error,
				})
				return nil // Don't fail the group
			}

			emitCollectorEvent(opts.Progress.OnCollectorEvent, CollectorEvent{
				Type:      CollectorEventStart,
				Collector: name,
				Index:     idx + 1,
				Total:     total,
			})

			started := time.Now()
			runResult := r.runOne(gctx, name, collectorCfg, lf, platformKey, opts, idx+1, total)

			// Enforce budget atomically after execution
			if runResult.Success {
				outputSize := int64(len(runResult.Output))
				if !budget.ReserveBytes(outputSize) {
					runResult.Success = false
					runResult.Output = nil
					runResult.Error = fmt.Errorf("collector output (%d bytes) would exceed aggregate budget (%d bytes)",
						outputSize, aggregateBudget)
				}
			}

			presults.set(idx, runResult)

			emitCollectorEvent(opts.Progress.OnCollectorEvent, CollectorEvent{
				Type:      CollectorEventFinish,
				Collector: name,
				Index:     idx + 1,
				Total:     total,
				Success:   runResult.Success,
				Duration:  time.Since(started),
				Error:     runResult.Error,
			})

			return nil // Never fail the group; track per-collector failures
		})
	}

	// Wait for all collectors to complete
	_ = g.Wait()

	result.Results = presults.results
	result.Failures = presults.getFailures()
}

func (r *Runner) skipCollectorForBudget(
	name string,
	idx, total int,
	aggregateUsed, aggregateBudget int64,
	onEvent func(CollectorEvent),
	result *CollectResult,
) bool {
	if aggregateUsed < aggregateBudget {
		return false
	}
	runResult := RunResult{
		Collector: name,
		Success:   false,
		Error: fmt.Errorf("aggregate output budget exceeded (%d bytes); skipping remaining collectors",
			aggregateBudget),
	}
	result.Results = append(result.Results, runResult)
	emitCollectorEvent(onEvent, CollectorEvent{
		Type:      CollectorEventFinish,
		Collector: name,
		Index:     idx,
		Total:     total,
		Success:   false,
		Error:     runResult.Error,
	})
	result.Failures++
	return true
}

func enforceCollectorBudget(runResult *RunResult, aggregateUsed, aggregateBudget int64) int64 {
	if !runResult.Success {
		return aggregateUsed
	}
	outputSize := int64(len(runResult.Output))
	if aggregateUsed+outputSize <= aggregateBudget {
		return aggregateUsed + outputSize
	}
	runResult.Success = false
	runResult.Output = nil
	runResult.Error = fmt.Errorf("collector output (%d bytes) would exceed aggregate budget (%d/%d bytes used)",
		outputSize, aggregateUsed, aggregateBudget)
	return aggregateUsed
}

func emitCollectorEvent(fn func(CollectorEvent), evt CollectorEvent) {
	if fn != nil {
		fn(evt)
	}
}

// runOne executes a single collector.
func (r *Runner) runOne(ctx context.Context, name string, cfg config.CollectorConfig, lf *lockfile.LockFile, platform string, opts RunOptions, collectorIndex, collectorTotal int) RunResult {
	result := RunResult{Collector: name}

	// Resolve binary path
	binaryPath, err := r.resolveBinaryPath(name, cfg, lf)
	if err != nil {
		result.Error = err
		return result
	}

	// Get expected digest for TOCTOU-safe execution
	dinfo := r.getExpectedDigest(name, lf, platform, opts)

	if err := validateCollectorDigestPolicy(name, dinfo, opts); err != nil {
		result.Error = err
		return result
	}

	// Check for insecure install marker before execution
	if err := r.checkInsecureMarker(name, binaryPath, opts); err != nil {
		result.Error = err
		return result
	}

	execPath, cleanup, err := resolveCollectorExecPath(name, binaryPath, cfg, dinfo, opts)
	if err != nil {
		result.Error = err
		return result
	}
	if cleanup != nil {
		defer cleanup()
	}

	// Execute the collector
	output, err := r.executeCollector(ctx, name, execPath, cfg.Config, cfg.Secrets, opts, collectorIndex, collectorTotal)
	if err != nil {
		result.Error = err
		return result
	}

	result.Success = true
	result.Output = output
	return result
}

func validateCollectorDigestPolicy(name string, dinfo digestInfo, opts RunOptions) error {
	if dinfo.IsSourceCollector && dinfo.MissingDigest && !opts.Unsafe.AllowUnverifiedSourceCollectors {
		return errors.WithHint(errors.LockfileInvalid, exitcode.LockInvalid,
			fmt.Sprintf("collector %q missing digest in lockfile (verification required for source collectors)", name),
			"Run 'epack collector lock' to compute and pin digests", nil)
	}
	if opts.Secure.Frozen && dinfo.NeedsVerification && dinfo.Digest == "" {
		return errors.WithHint(errors.LockfileInvalid, exitcode.LockInvalid,
			fmt.Sprintf("collector %q missing digest in lockfile (required in --frozen mode)", name),
			"Run 'epack collector lock' to compute and pin digests", nil)
	}
	if dinfo.IsSourceCollector && dinfo.MissingDigest && opts.Unsafe.AllowUnverifiedSourceCollectors {
		securityaudit.Emit(securityaudit.Event{
			Type:        securityaudit.EventInsecureBypass,
			Component:   string(componenttypes.KindCollector),
			Name:        name,
			Description: "allowing source collector execution without lockfile digest",
			Attrs: map[string]string{
				"reason": "allow_unverified_source_collectors",
			},
		})
	}
	return nil
}

func resolveCollectorExecPath(name, binaryPath string, cfg config.CollectorConfig, dinfo digestInfo, opts RunOptions) (string, func(), error) {
	if dinfo.NeedsVerification && dinfo.Digest != "" {
		execPath, cleanup, err := execsafe.VerifiedBinaryFD(binaryPath, dinfo.Digest)
		if err != nil {
			securityaudit.Emit(securityaudit.Event{
				Type:        securityaudit.EventVerificationFail,
				Component:   string(componenttypes.KindCollector),
				Name:        name,
				Description: "collector digest verification failed",
				Attrs: map[string]string{
					"path": binaryPath,
				},
			})
			return "", nil, errors.WithHint(errors.DigestMismatch, exitcode.DigestMismatch,
				fmt.Sprintf("verification failed for collector %q: %v (expected %s)", name, err, dinfo.Digest),
				"Binary may have been modified. Run 'epack collector sync' to reinstall", nil)
		}
		return execPath, cleanup, nil
	}
	if opts.Secure.Frozen {
		return "", nil, errors.WithHint(errors.LockfileInvalid, exitcode.LockInvalid,
			fmt.Sprintf("collector %q not pinned in lockfile (required in --frozen mode)", name),
			"Run 'epack collector lock' to pin all collectors", nil)
	}
	if cfg.Binary != "" && !opts.Unsafe.AllowUnpinned {
		return "", nil, errors.WithHint(errors.LockfileInvalid, exitcode.LockInvalid,
			fmt.Sprintf("external collector %q is not pinned in lockfile", name),
			"Run 'epack collector lock' to pin external collectors, or use --insecure-allow-unpinned", nil)
	}
	if cfg.Binary != "" && opts.Unsafe.AllowUnpinned {
		securityaudit.Emit(securityaudit.Event{
			Type:        securityaudit.EventUnpinnedExecution,
			Component:   string(componenttypes.KindCollector),
			Name:        name,
			Description: "executing external collector without lockfile pin",
			Attrs: map[string]string{
				"path": binaryPath,
			},
		})
	}
	return binaryPath, nil, nil
}

// executeCollector runs a collector binary and returns its output.
// SECURITY: execPath must be a verified path from verifiedBinaryFD or explicit opt-in.
func (r *Runner) executeCollector(ctx context.Context, name, execPath string, config map[string]interface{}, secrets []string, opts RunOptions, collectorIndex, collectorTotal int) ([]byte, error) {
	// Write config to temporary file
	// NOTE: We intentionally do NOT pass config via stdin JSON. Having a single
	// config source (file-based) is more secure than dual sources because:
	// 1. File-based config uses secure temp directories with proper permissions
	// 2. Eliminates confusion about which source takes precedence
	// 3. Matches the tool protocol pattern
	configPath, configCleanup, err := collectorexec.WriteConfig(config)
	if err != nil {
		return nil, fmt.Errorf("writing collector config: %w", err)
	}
	if configCleanup != nil {
		defer configCleanup()
	}

	// Build restricted environment with protocol variables
	env := collectorexec.BuildEnv(os.Environ(), name, configPath, secrets, os.Getenv, opts.Unsafe.InheritPath)

	// Create progress callback that forwards to the progress hooks
	var onProgress func(collectorexec.ProgressMessage)
	if opts.Progress.OnCollectorEvent != nil {
		onProgress = func(msg collectorexec.ProgressMessage) {
			evt := CollectorEvent{
				Collector: name,
				Index:     collectorIndex,
				Total:     collectorTotal,
				Message:   msg.Message,
			}
			switch msg.Kind {
			case "status":
				evt.Type = CollectorEventStatus
			case "progress":
				evt.Type = CollectorEventProgress
				evt.ProgressCurrent = msg.Current
				evt.ProgressTotal = msg.Total
			default:
				return // Unknown kind, ignore
			}
			opts.Progress.OnCollectorEvent(evt)
		}
	}

	// Execute collector with timeout and output limits
	result := collectorexec.Run(ctx, name, execPath, configPath, env, collectorexec.RunOptions{
		Timeout:             opts.Secure.Timeout,
		InsecureInheritPath: opts.Unsafe.InheritPath,
		OnProgress:          onProgress,
	})

	if result.Err != nil {
		return nil, result.Err
	}

	return result.Stdout, nil
}

// digestInfo contains information about a collector's digest and type.
type digestInfo struct {
	Digest            string
	NeedsVerification bool
	IsSourceCollector bool // true if this is a source-based collector (not external)
	MissingDigest     bool // true if collector exists but digest is empty/missing
}

// getExpectedDigest returns digest information for a collector.
func (r *Runner) getExpectedDigest(name string, lf *lockfile.LockFile, platform string, opts RunOptions) digestInfo {
	locked, ok := lf.GetCollector(name)
	if !ok {
		// External binary without lockfile entry
		return digestInfo{
			Digest:            "",
			NeedsVerification: opts.Secure.Frozen,
			IsSourceCollector: false,
			MissingDigest:     false,
		}
	}

	// Determine if this is a source-based collector (not external)
	isSource := locked.Kind != "external" && locked.Source != ""

	platformEntry, ok := locked.Platforms[platform]
	if !ok || platformEntry.Digest == "" {
		return digestInfo{
			Digest:            "",
			NeedsVerification: opts.Secure.Frozen || isSource, // Source collectors always need verification
			IsSourceCollector: isSource,
			MissingDigest:     true, // Collector exists but digest is missing
		}
	}

	return digestInfo{
		Digest:            platformEntry.Digest,
		NeedsVerification: true,
		IsSourceCollector: isSource,
		MissingDigest:     false,
	}
}

// checkInsecureMarker checks for insecure install marker and returns error if not allowed.
func (r *Runner) checkInsecureMarker(name, binaryPath string, opts RunOptions) error {
	return sync.CheckInsecureMarkerAllowed(name, componenttypes.KindCollector, binaryPath, opts.Secure.Frozen, opts.Unsafe.AllowUnverifiedInstall)
}

// resolveBinaryPath finds the binary for a collector.
func (r *Runner) resolveBinaryPath(name string, cfg config.CollectorConfig, lf *lockfile.LockFile) (string, error) {
	if cfg.Binary != "" {
		// External binary - use directly
		if !filepath.IsAbs(cfg.Binary) {
			return "", fmt.Errorf("external binary path must be absolute: %s", cfg.Binary)
		}
		return cfg.Binary, nil
	}

	// Source-based collector - resolve from lockfile
	locked, ok := lf.GetCollector(name)
	if !ok {
		return "", errors.WithHint(errors.LockfileInvalid, exitcode.LockInvalid,
			fmt.Sprintf("collector %q not found in lockfile", name),
			"Run 'epack collector lock && epack collector sync' first", nil)
	}

	binaryPath, err := sync.InstallPath(r.BaseDir, componenttypes.KindCollector, name, locked.Version, name)
	if err != nil {
		return "", errors.WithHint(errors.LockfileInvalid, exitcode.LockInvalid,
			fmt.Sprintf("invalid install path for collector %q: %v", name, err),
			"Check lockfile for invalid collector name or version", nil)
	}

	// Check binary exists
	if _, err := os.Stat(binaryPath); os.IsNotExist(err) {
		return "", errors.WithHint(errors.BinaryNotFound, exitcode.MissingBinary,
			fmt.Sprintf("collector %q not installed", name),
			"Run 'epack collector sync' to install collectors", nil)
	}

	return binaryPath, nil
}

// loadLockfile loads the lockfile, handling different requirements.
func (r *Runner) loadLockfile(cfg *config.JobConfig, opts RunOptions) (*lockfile.LockFile, error) {
	// Check if any source-based collectors exist
	hasSource := false
	for _, c := range cfg.Collectors {
		if c.Source != "" {
			hasSource = true
			break
		}
	}

	lf, err := lockfile.Load(r.LockfilePath)
	if os.IsNotExist(err) {
		if hasSource || opts.Secure.Frozen {
			return nil, errors.WithHint(errors.LockfileInvalid, exitcode.LockInvalid,
				"lockfile missing", "Run 'epack collector lock && epack collector sync' first", nil)
		}
		// All binary collectors, no lockfile needed in non-frozen mode
		return lockfile.New(), nil
	}
	if err != nil {
		return nil, fmt.Errorf("loading lockfile: %w", err)
	}

	return lf, nil
}

// validateFrozen performs frozen-mode validations.
// In frozen mode, ALL collectors (including external binaries) must be pinned
// in the lockfile with a platform-specific digest for integrity verification.
func (r *Runner) validateFrozen(cfg *config.JobConfig, lf *lockfile.LockFile, platform string) error {
	configNames := make([]string, 0, len(cfg.Collectors))
	for name := range cfg.Collectors {
		configNames = append(configNames, name)
	}
	sort.Strings(configNames)

	for _, name := range configNames {
		if err := validateFrozenConfigCollector(name, cfg.Collectors[name], lf, platform); err != nil {
			return err
		}
	}

	lockfileNames := make([]string, 0, len(lf.Collectors))
	for name := range lf.Collectors {
		lockfileNames = append(lockfileNames, name)
	}
	sort.Strings(lockfileNames)

	for _, name := range lockfileNames {
		if err := validateFrozenLockfileCollector(name, lf.Collectors[name], cfg.Collectors); err != nil {
			return err
		}
	}

	return nil
}

func validateFrozenConfigCollector(name string, c config.CollectorConfig, lf *lockfile.LockFile, platform string) error {
	locked, ok := lf.GetCollector(name)
	if c.Source != "" {
		if !ok {
			return errors.WithHint(errors.LockfileInvalid, exitcode.LockInvalid,
				fmt.Sprintf("config declares collector %q not found in lockfile", name),
				"Run 'epack collector lock' to update the lockfile", nil)
		}
		if locked.Kind == "external" {
			return errors.WithHint(errors.LockfileInvalid, exitcode.LockInvalid,
				fmt.Sprintf("config declares %q as source-based but lockfile has it as external", name),
				"Run 'epack collector lock' to update the lockfile", nil)
		}
		return validateFrozenPlatformDigest(name, platform, locked.Platforms, false)
	}

	if c.Binary != "" {
		if !ok {
			return errors.WithHint(errors.LockfileInvalid, exitcode.LockInvalid,
				fmt.Sprintf("external collector %q not found in lockfile (required in --frozen mode)", name),
				"Run 'epack collector lock' to pin external collectors", nil)
		}
		if locked.Kind != "external" {
			return errors.WithHint(errors.LockfileInvalid, exitcode.LockInvalid,
				fmt.Sprintf("config declares %q as external binary but lockfile has it as source-based", name),
				"Run 'epack collector lock' to update the lockfile", nil)
		}
		return validateFrozenPlatformDigest(name, platform, locked.Platforms, true)
	}
	return nil
}

func validateFrozenPlatformDigest(name, platform string, platforms map[string]componenttypes.LockedPlatform, external bool) error {
	platformEntry, hasPlatform := platforms[platform]
	if !hasPlatform {
		if external {
			return errors.WithHint(errors.LockfileInvalid, exitcode.LockInvalid,
				fmt.Sprintf("external collector %q missing platform %s in lockfile (required in --frozen mode)", name, platform),
				fmt.Sprintf("Run 'epack collector lock --platform %s' to pin external collectors", platform), nil)
		}
		return errors.WithHint(errors.BinaryNotFound, exitcode.MissingBinary,
			fmt.Sprintf("collector %q missing platform %s in lockfile", name, platform),
			fmt.Sprintf("Run 'epack collector lock --platform %s'", platform), nil)
	}
	if platformEntry.Digest == "" {
		if external {
			return errors.WithHint(errors.LockfileInvalid, exitcode.LockInvalid,
				fmt.Sprintf("external collector %q missing digest for platform %s (required in --frozen mode)", name, platform),
				fmt.Sprintf("Run 'epack collector lock --platform %s' to compute digest", platform), nil)
		}
		return errors.WithHint(errors.LockfileInvalid, exitcode.LockInvalid,
			fmt.Sprintf("collector %q missing digest for platform %s in lockfile", name, platform),
			fmt.Sprintf("Run 'epack collector lock --platform %s' to compute digest", platform), nil)
	}
	return nil
}

func validateFrozenLockfileCollector(name string, locked lockfile.LockedCollector, cfgCollectors map[string]config.CollectorConfig) error {
	if locked.Kind == "external" {
		return nil
	}
	cfgCollector, ok := cfgCollectors[name]
	if !ok {
		return errors.WithHint(errors.LockfileInvalid, exitcode.LockInvalid,
			fmt.Sprintf("lockfile has collector %q not found in config", name),
			"Remove stale entries or add collector to config", nil)
	}
	if cfgCollector.Source == "" {
		return errors.WithHint(errors.LockfileInvalid, exitcode.LockInvalid,
			fmt.Sprintf("lockfile has %q as source-based but config declares it as external", name),
			"Run 'epack collector lock' to update the lockfile", nil)
	}
	return nil
}

// selectCollectors filters collectors based on options.
// Always returns a copy to avoid shared mutable state issues.
func (r *Runner) selectCollectors(cfg *config.JobConfig, opts RunOptions) map[string]config.CollectorConfig {
	if len(opts.Secure.Only) == 0 {
		// Return a copy to prevent concurrent modification issues
		result := make(map[string]config.CollectorConfig, len(cfg.Collectors))
		for name, c := range cfg.Collectors {
			result[name] = c
		}
		return result
	}

	selected := make(map[string]config.CollectorConfig)
	for _, name := range opts.Secure.Only {
		if c, ok := cfg.Collectors[name]; ok {
			selected[name] = c
		}
	}
	return selected
}
