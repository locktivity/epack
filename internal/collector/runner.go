package collector

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"time"

	"github.com/locktivity/epack/errors"
	collectorexec "github.com/locktivity/epack/internal/collector/exec"
	"github.com/locktivity/epack/internal/component/config"
	"github.com/locktivity/epack/internal/component/lockfile"
	"github.com/locktivity/epack/internal/component/sync"
	"github.com/locktivity/epack/internal/platform"
	"github.com/locktivity/epack/internal/componenttypes"
	"github.com/locktivity/epack/internal/execsafe"
	"github.com/locktivity/epack/internal/exitcode"
	"github.com/locktivity/epack/internal/limits"
)

// Collector config is passed only via EPACK_COLLECTOR_CONFIG.
// stdin is intentionally not used to avoid dual config channels and precedence ambiguity.

// CollectorOutput is the envelope returned by collectors via stdout.
type CollectorOutput struct {
	ProtocolVersion int `json:"protocol_version"`
	// RawData holds the raw JSON bytes of the data field to preserve numeric precision.
	// Numbers in JSON can exceed float64 precision (2^53-1), so we keep them as raw bytes.
	RawData json.RawMessage `json:"-"`
}

// ParseCollectorOutput decodes collector stdout.
// If stdout is not protocol-envelope JSON, it is preserved as RawData for lossless passthrough.
func ParseCollectorOutput(output []byte) (*CollectorOutput, error) {
	// First, check if it's valid JSON at all
	if !json.Valid(output) {
		// Not valid JSON - wrap as JSON string to preserve exact content
		quoted, err := json.Marshal(string(output))
		if err != nil {
			return nil, fmt.Errorf("marshaling non-JSON output: %w", err)
		}
		return &CollectorOutput{
			ProtocolVersion: 0,
			RawData:         quoted,
		}, nil
	}

	// Check if it's a JSON object that looks like an envelope (has protocol_version and data)
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(output, &raw); err == nil {
		if versionBytes, hasVersion := raw["protocol_version"]; hasVersion {
			if dataBytes, hasData := raw["data"]; hasData {
				// It's a proper envelope - extract protocol_version and preserve data as raw
				var version int
				if err := json.Unmarshal(versionBytes, &version); err != nil {
					return nil, fmt.Errorf("parsing protocol_version: %w", err)
				}
				return &CollectorOutput{
					ProtocolVersion: version,
					RawData:         dataBytes,
				}, nil
			}
		}
	}

	// Valid JSON but not an envelope - treat whole thing as data (preserve as raw)
	// Defensive copy to avoid aliasing caller's buffer
	rawCopy := make([]byte, len(output))
	copy(rawCopy, output)
	return &CollectorOutput{
		ProtocolVersion: 0,
		RawData:         rawCopy,
	}, nil
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
type RunOptions struct {
	Frozen                  bool          // Fail on any mismatch (CI mode)
	Only                    []string      // Run only these collectors (empty = all)
	InsecureAllowUnverified bool          // Allow running collectors installed with --insecure-skip-verify
	InsecureAllowUnpinned   bool          // Allow external collectors not pinned in lockfile (security risk)
	Timeout                 time.Duration // Timeout per collector (0 = use DefaultCollectorTimeout)

	// MaxAggregateBudget overrides the default aggregate output budget (MaxAggregateOutputBytes).
	// Set to 0 to use the default. This is the total bytes retained across all collector outputs.
	MaxAggregateBudget int64

	// SECURITY: InsecureInheritPath allows inheriting PATH from the environment.
	// When false (default), collectors run with a safe, deterministic PATH.
	// This prevents PATH injection attacks where a malicious interpreter is used.
	InsecureInheritPath bool

	// AllowUnverifiedSourceCollectors permits executing source collectors without digest pinning.
	// Use only for explicit recovery workflows.
	AllowUnverifiedSourceCollectors bool
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

// Run executes all collectors and returns their outputs.
func (r *Runner) Run(ctx context.Context, cfg *config.JobConfig, opts RunOptions) (*CollectResult, error) {
	// SECURITY: Defense-in-depth validation of config structure.
	// Config should already be validated by LoadConfig/ParseConfig, but we
	// validate again in case the config was constructed programmatically.
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	// Load lockfile
	lf, err := r.loadLockfile(cfg, opts)
	if err != nil {
		return nil, err
	}

	platform := platform.Key(runtime.GOOS, runtime.GOARCH)

	// Validate in frozen mode
	if opts.Frozen {
		if err := r.validateFrozen(cfg, lf, platform); err != nil {
			return nil, err
		}
	}

	// Determine which collectors to run
	collectors := r.selectCollectors(cfg, opts)

	// Sort collector names for deterministic execution order.
	// This ensures consistent behavior when aggregate budget limits are reached.
	collectorNames := make([]string, 0, len(collectors))
	for name := range collectors {
		collectorNames = append(collectorNames, name)
	}
	sort.Strings(collectorNames)

	// SECURITY: Enforce aggregate output budget to prevent memory exhaustion.
	// Without this, N collectors each producing limits.MaxCollectorOutputBytes could
	// cause OOM with N * 64 MB of retained output data.
	aggregateBudget := opts.MaxAggregateBudget
	if aggregateBudget == 0 {
		aggregateBudget = limits.MaxAggregateOutputBytes
	}
	var aggregateUsed int64

	result := &CollectResult{
		Stream:  cfg.Stream,
		Results: make([]RunResult, 0, len(collectors)),
	}

	for _, name := range collectorNames {
		collectorCfg := collectors[name]
		// Check aggregate budget before running next collector
		if aggregateUsed >= aggregateBudget {
			result.Results = append(result.Results, RunResult{
				Collector: name,
				Success:   false,
				Error: fmt.Errorf("aggregate output budget exceeded (%d bytes); skipping remaining collectors",
					aggregateBudget),
			})
			result.Failures++
			continue
		}

		runResult := r.runOne(ctx, name, collectorCfg, lf, platform, opts)

		// SECURITY: Enforce aggregate budget as a hard cap.
		// If this collector's output would push us over budget, discard it.
		if runResult.Success {
			outputSize := int64(len(runResult.Output))
			if aggregateUsed+outputSize > aggregateBudget {
				// Discard output and mark as failed
				runResult.Success = false
				runResult.Output = nil
				runResult.Error = fmt.Errorf("collector output (%d bytes) would exceed aggregate budget (%d/%d bytes used)",
					outputSize, aggregateUsed, aggregateBudget)
			} else {
				aggregateUsed += outputSize
			}
		}

		result.Results = append(result.Results, runResult)
		if !runResult.Success {
			result.Failures++
		}
	}

	return result, nil
}

// runOne executes a single collector.
func (r *Runner) runOne(ctx context.Context, name string, cfg config.CollectorConfig, lf *lockfile.LockFile, platform string, opts RunOptions) RunResult {
	result := RunResult{Collector: name}

	// Resolve binary path
	binaryPath, err := r.resolveBinaryPath(name, cfg, lf)
	if err != nil {
		result.Error = err
		return result
	}

	// Get expected digest for TOCTOU-safe execution
	dinfo := r.getExpectedDigest(name, lf, platform, opts)

	// SECURITY: Source-based collectors MUST be verified unless explicitly opted out.
	// This prevents RCE attacks where an attacker modifies the lockfile to remove the
	// digest or drops a trojan binary at the predictable install path.
	if dinfo.IsSourceCollector && dinfo.MissingDigest && !opts.AllowUnverifiedSourceCollectors {
		result.Error = errors.WithHint(errors.LockfileInvalid, exitcode.LockInvalid,
			fmt.Sprintf("collector %q missing digest in lockfile (verification required for source collectors)", name),
			"Run 'epack collector lock' to compute and pin digests", nil)
		return result
	}

	// In frozen mode, verification is mandatory - fail if digest is missing
	// This prevents executing unpinned binaries in frozen mode
	if opts.Frozen && dinfo.NeedsVerification && dinfo.Digest == "" {
		result.Error = errors.WithHint(errors.LockfileInvalid, exitcode.LockInvalid,
			fmt.Sprintf("collector %q missing digest in lockfile (required in --frozen mode)", name),
			"Run 'epack collector lock' to compute and pin digests", nil)
		return result
	}

	// Check for insecure install marker before execution
	if err := r.checkInsecureMarker(name, binaryPath, opts); err != nil {
		result.Error = err
		return result
	}

	// Determine the path to execute
	var execPath string
	var cleanup func()

	if dinfo.NeedsVerification && dinfo.Digest != "" {
		// TOCTOU-safe execution: verify digest from fd and get safe exec path
		// This eliminates the race between verification and execution by:
		// 1. Opening the binary with O_NOFOLLOW
		// 2. Hashing content via the fd (not the path)
		// 3. Returning a path that refers to the same verified inode
		execPath, cleanup, err = execsafe.VerifiedBinaryFD(binaryPath, dinfo.Digest)
		if err != nil {
			result.Error = errors.WithHint(errors.DigestMismatch, exitcode.DigestMismatch,
				fmt.Sprintf("verification failed for collector %q: %v (expected %s)", name, err, dinfo.Digest),
				"Binary may have been modified. Run 'epack collector sync' to reinstall", nil)
			return result
		}
		if cleanup != nil {
			defer cleanup()
		}
	} else if opts.Frozen {
		// In frozen mode, all collectors must be verified
		// This branch handles edge cases where needsVerification returned false
		result.Error = errors.WithHint(errors.LockfileInvalid, exitcode.LockInvalid,
			fmt.Sprintf("collector %q not pinned in lockfile (required in --frozen mode)", name),
			"Run 'epack collector lock' to pin all collectors", nil)
		return result
	} else if cfg.Binary != "" && !opts.InsecureAllowUnpinned {
		// External binary without lockfile pinning - require explicit opt-in
		// This prevents config injection attacks where a compromised config
		// can execute arbitrary binaries without verification
		result.Error = errors.WithHint(errors.LockfileInvalid, exitcode.LockInvalid,
			fmt.Sprintf("external collector %q is not pinned in lockfile", name),
			"Run 'epack collector lock' to pin external collectors, or use --insecure-allow-unpinned", nil)
		return result
	} else {
		// Non-frozen mode with explicit opt-in for unpinned external collectors
		execPath = binaryPath
	}

	// Execute the collector
	output, err := r.executeCollector(ctx, name, execPath, cfg.Config, cfg.Secrets, opts)
	if err != nil {
		result.Error = err
		return result
	}

	result.Success = true
	result.Output = output
	return result
}

// executeCollector runs a collector binary and returns its output.
// SECURITY: execPath must be a verified path from verifiedBinaryFD or explicit opt-in.
func (r *Runner) executeCollector(ctx context.Context, name, execPath string, config map[string]interface{}, secrets []string, opts RunOptions) ([]byte, error) {
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
	env := collectorexec.BuildEnv(os.Environ(), name, configPath, secrets, os.Getenv, opts.InsecureInheritPath)

	// Execute collector with timeout and output limits
	result := collectorexec.Run(ctx, name, execPath, configPath, env, collectorexec.RunOptions{
		Timeout:             opts.Timeout,
		InsecureInheritPath: opts.InsecureInheritPath,
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
			NeedsVerification: opts.Frozen,
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
			NeedsVerification: opts.Frozen || isSource, // Source collectors always need verification
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
	return sync.CheckInsecureMarkerAllowed(name, componenttypes.KindCollector, binaryPath, opts.Frozen, opts.InsecureAllowUnverified)
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
		if hasSource || opts.Frozen {
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
	// Sort collector names for deterministic error messages
	configNames := make([]string, 0, len(cfg.Collectors))
	for name := range cfg.Collectors {
		configNames = append(configNames, name)
	}
	sort.Strings(configNames)

	// Check config/lockfile alignment for ALL collectors
	for _, name := range configNames {
		c := cfg.Collectors[name]
		locked, ok := lf.GetCollector(name)

		if c.Source != "" {
			// Source-based collector
			if !ok {
				return errors.WithHint(errors.LockfileInvalid, exitcode.LockInvalid,
					fmt.Sprintf("config declares collector %q not found in lockfile", name),
					"Run 'epack collector lock' to update the lockfile", nil)
			}
			// Verify lockfile entry is also source-based (not external)
			if locked.Kind == "external" {
				return errors.WithHint(errors.LockfileInvalid, exitcode.LockInvalid,
					fmt.Sprintf("config declares %q as source-based but lockfile has it as external", name),
					"Run 'epack collector lock' to update the lockfile", nil)
			}
			platformEntry, hasPlatform := locked.Platforms[platform]
			if !hasPlatform {
				return errors.WithHint(errors.BinaryNotFound, exitcode.MissingBinary,
					fmt.Sprintf("collector %q missing platform %s in lockfile", name, platform),
					fmt.Sprintf("Run 'epack collector lock --platform %s'", platform), nil)
			}
			// Require digest for frozen mode
			if platformEntry.Digest == "" {
				return errors.WithHint(errors.LockfileInvalid, exitcode.LockInvalid,
					fmt.Sprintf("collector %q missing digest for platform %s in lockfile", name, platform),
					fmt.Sprintf("Run 'epack collector lock --platform %s' to compute digest", platform), nil)
			}
		} else if c.Binary != "" {
			// External binary collector - MUST be pinned in frozen mode
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
			// Require platform entry with digest for external collectors in frozen mode
			platformEntry, hasPlatform := locked.Platforms[platform]
			if !hasPlatform {
				return errors.WithHint(errors.LockfileInvalid, exitcode.LockInvalid,
					fmt.Sprintf("external collector %q missing platform %s in lockfile (required in --frozen mode)", name, platform),
					fmt.Sprintf("Run 'epack collector lock --platform %s' to pin external collectors", platform), nil)
			}
			if platformEntry.Digest == "" {
				return errors.WithHint(errors.LockfileInvalid, exitcode.LockInvalid,
					fmt.Sprintf("external collector %q missing digest for platform %s (required in --frozen mode)", name, platform),
					fmt.Sprintf("Run 'epack collector lock --platform %s' to compute digest", platform), nil)
			}
		}
	}

	// Check lockfile entries match config
	// Sort lockfile collector names for deterministic error messages
	lockfileNames := make([]string, 0, len(lf.Collectors))
	for name := range lf.Collectors {
		lockfileNames = append(lockfileNames, name)
	}
	sort.Strings(lockfileNames)

	for _, name := range lockfileNames {
		locked := lf.Collectors[name]
		if locked.Kind == "external" {
			continue
		}
		cfgCollector, ok := cfg.Collectors[name]
		if !ok {
			return errors.WithHint(errors.LockfileInvalid, exitcode.LockInvalid,
				fmt.Sprintf("lockfile has collector %q not found in config", name),
				"Remove stale entries or add collector to config", nil)
		}
		// Verify config entry is also source-based (not external)
		if cfgCollector.Source == "" {
			return errors.WithHint(errors.LockfileInvalid, exitcode.LockInvalid,
				fmt.Sprintf("lockfile has %q as source-based but config declares it as external", name),
				"Run 'epack collector lock' to update the lockfile", nil)
		}
	}

	return nil
}

// selectCollectors filters collectors based on options.
// Always returns a copy to avoid shared mutable state issues.
func (r *Runner) selectCollectors(cfg *config.JobConfig, opts RunOptions) map[string]config.CollectorConfig {
	if len(opts.Only) == 0 {
		// Return a copy to prevent concurrent modification issues
		result := make(map[string]config.CollectorConfig, len(cfg.Collectors))
		for name, c := range cfg.Collectors {
			result[name] = c
		}
		return result
	}

	selected := make(map[string]config.CollectorConfig)
	for _, name := range opts.Only {
		if c, ok := cfg.Collectors[name]; ok {
			selected[name] = c
		}
	}
	return selected
}
