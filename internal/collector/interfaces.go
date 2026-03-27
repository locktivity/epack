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

// ExecutionRequest describes a single collector execution.
type ExecutionRequest struct {
	// Name is the collector name from epack.yaml.
	Name string

	// ExecPath is the resolved binary path. It must already be verified or explicitly allowed.
	ExecPath string

	// Config is written to the collector config file.
	Config map[string]interface{}

	// Secrets lists explicit env var names to pass through.
	Secrets []string

	// ManagedEnv is the trusted env bundle resolved at runtime.
	ManagedEnv map[string]string

	// CollectorIndex and CollectorTotal provide progress event context.
	CollectorIndex int
	CollectorTotal int
}

// CollectorExecutor abstracts single collector binary execution for testability.
// This is a lower-level interface than CollectorRunner.
type CollectorExecutor interface {
	// Execute runs a single collector binary and returns its output.
	Execute(ctx context.Context, req ExecutionRequest, opts RunOptions) ([]byte, error)
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
func (e *DefaultCollectorExecutor) Execute(ctx context.Context, req ExecutionRequest, opts RunOptions) ([]byte, error) {
	return e.runner.executeCollector(ctx, req, opts)
}
