package collector

import (
	"context"

	"github.com/locktivity/epack/internal/component/config"
)

// CollectorRunner abstracts collector execution for testability.
// The default implementation is Runner which executes real binaries.
type CollectorRunner interface {
	// Run executes all collectors and returns their outputs.
	// Returns aggregate results including success/failure status.
	Run(ctx context.Context, cfg *config.JobConfig, opts RunOptions) (*CollectResult, error)
}

// CollectorExecutor abstracts single collector binary execution for testability.
// This is a lower-level interface than CollectorRunner.
type CollectorExecutor interface {
	// Execute runs a single collector binary and returns its output.
	// The execPath must be a verified path (from execsafe.VerifiedBinaryFD or explicit opt-in).
	Execute(ctx context.Context, name, execPath string, config map[string]interface{}, secrets []string, opts RunOptions) ([]byte, error)
}

// BinaryResolver abstracts collector binary path resolution for testability.
type BinaryResolver interface {
	// ResolvePath finds the binary for a collector.
	// For source-based collectors, this resolves from the lockfile.
	// For external collectors, this validates the configured binary path.
	ResolvePath(name string, cfg config.CollectorConfig) (string, error)
}

// Ensure Runner implements CollectorRunner interface.
var _ CollectorRunner = (*Runner)(nil)

// DefaultCollectorExecutor is the production implementation using executeCollector.
type DefaultCollectorExecutor struct {
	runner *Runner
}

// NewDefaultCollectorExecutor creates a CollectorExecutor backed by a Runner.
func NewDefaultCollectorExecutor(runner *Runner) *DefaultCollectorExecutor {
	return &DefaultCollectorExecutor{runner: runner}
}

// Execute implements CollectorExecutor using the runner's executeCollector method.
func (e *DefaultCollectorExecutor) Execute(ctx context.Context, name, execPath string, config map[string]interface{}, secrets []string, opts RunOptions) ([]byte, error) {
	return e.runner.executeCollector(ctx, name, execPath, config, secrets, opts)
}
