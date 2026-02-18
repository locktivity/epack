package componentsdk

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/locktivity/epack/internal/componenttypes"
)

// CollectorSpec defines the collector's metadata.
type CollectorSpec struct {
	// Name is the collector name (without epack-collector- prefix).
	// Must match ^[a-z0-9][a-z0-9._-]{0,63}$
	Name string

	// Version is the semantic version (e.g., "1.0.0").
	Version string

	// Description is a human-readable description of what the collector gathers.
	Description string

	// Timeout is the maximum execution time. Default is 60 seconds.
	Timeout time.Duration
}

// CollectorHandler is the function signature for collector implementations.
// Return nil for success, or an error for failure.
// Use the typed error returns (ConfigError, AuthError, NetworkError) for
// appropriate exit codes.
type CollectorHandler func(ctx CollectorContext) error

// CollectorContext provides access to the collector execution environment.
type CollectorContext interface {
	// Context returns a context that is cancelled on SIGTERM or timeout.
	Context() context.Context

	// Name returns the collector name from EPACK_COLLECTOR_NAME.
	Name() string

	// Config returns the parsed configuration, or nil if none provided.
	Config() map[string]any

	// Secret returns the value of an environment variable.
	// Use this for secrets listed in epack.yaml secrets array.
	Secret(name string) string

	// Emit outputs the collected data. This should be called once.
	// The data is wrapped in the protocol envelope automatically.
	Emit(data any) error
}

// Typed errors for specific exit codes
type (
	// ConfigError indicates a configuration error (exit code 2).
	ConfigError struct{ Err error }

	// AuthError indicates an authentication error (exit code 3).
	AuthError struct{ Err error }

	// NetworkError indicates a network/API error (exit code 4).
	NetworkError struct{ Err error }
)

func (e ConfigError) Error() string  { return e.Err.Error() }
func (e AuthError) Error() string    { return e.Err.Error() }
func (e NetworkError) Error() string { return e.Err.Error() }

// Helper functions to create typed errors
func NewConfigError(format string, args ...any) error {
	return ConfigError{Err: fmt.Errorf(format, args...)}
}

func NewAuthError(format string, args ...any) error {
	return AuthError{Err: fmt.Errorf(format, args...)}
}

func NewNetworkError(format string, args ...any) error {
	return NetworkError{Err: fmt.Errorf(format, args...)}
}

// RunCollector executes the collector handler with full protocol compliance.
// It handles environment parsing, signal handling, timeout, protocol envelope
// output, and proper exit codes. This function does not return.
func RunCollector(spec CollectorSpec, handler CollectorHandler) {
	os.Exit(runCollectorInternal(spec, handler))
}

func runCollectorInternal(spec CollectorSpec, handler CollectorHandler) int {
	// Set default timeout
	timeout := spec.Timeout
	if timeout == 0 {
		timeout = 60 * time.Second
	}

	// Create context with timeout and signal handling
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Handle SIGTERM gracefully (COL-031)
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-sigChan
		cancel()
	}()

	// Parse environment
	collectorCtx := &collectorContext{
		ctx:  ctx,
		name: os.Getenv("EPACK_COLLECTOR_NAME"),
		spec: spec,
	}

	// Parse config if provided (COL-020)
	configPath := os.Getenv("EPACK_COLLECTOR_CONFIG")
	if configPath != "" {
		cfg, err := parseJSONFile(configPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error parsing config: %v\n", err)
			return componenttypes.ExitConfigError
		}
		collectorCtx.config = cfg
	}

	// Run handler
	if err := handler(collectorCtx); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)

		// Map error types to exit codes (COL-041 through COL-044)
		switch err.(type) {
		case ConfigError:
			return componenttypes.ExitConfigError
		case AuthError:
			return componenttypes.ExitAuthError
		case NetworkError:
			return componenttypes.ExitNetworkError
		default:
			return 1
		}
	}

	// Check if data was emitted
	if !collectorCtx.emitted {
		fmt.Fprintf(os.Stderr, "error: collector did not emit any data\n")
		return 1
	}

	return 0
}

// collectorContext implements CollectorContext
type collectorContext struct {
	ctx     context.Context
	name    string
	config  map[string]any
	spec    CollectorSpec
	emitted bool
}

func (c *collectorContext) Context() context.Context   { return c.ctx }
func (c *collectorContext) Name() string               { return c.name }
func (c *collectorContext) Config() map[string]any     { return c.config }
func (c *collectorContext) Secret(name string) string  { return os.Getenv(name) }

func (c *collectorContext) Emit(data any) error {
	if c.emitted {
		return fmt.Errorf("Emit can only be called once")
	}
	c.emitted = true

	// Wrap in protocol envelope (COL-002)
	envelope := map[string]any{
		"protocol_version": componenttypes.CollectorProtocolVersion,
		"data":             data,
	}

	// Output to stdout (COL-001)
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(envelope); err != nil {
		return fmt.Errorf("encoding output: %w", err)
	}

	return nil
}
