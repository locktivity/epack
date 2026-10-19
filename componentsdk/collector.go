package componentsdk

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/locktivity/epack/internal/componenttypes"
	"github.com/locktivity/epack/internal/redact"
	"github.com/locktivity/epack/internal/safefile"
	"github.com/locktivity/epack/internal/stagedartifact"
)

// CollectorSpec defines the collector's metadata.
type CollectorSpec struct {
	// Name is the collector name (without epack-collector- prefix).
	// Must match ^[a-z0-9][a-z0-9._-]{0,63}$
	Name string

	// Version is the semantic version (e.g., "1.0.0").
	Version string

	// Commit is the git commit SHA that built this binary.
	// Set via ldflags at build time for supply chain provenance.
	Commit string

	// Description is a human-readable description of what the collector gathers.
	Description string

	// Timeout is the maximum execution time. Default is 60 seconds. A runner
	// that passes EPACK_DEADLINE can shorten it: the collector then stops
	// early enough to emit what it collected before the runner's limit.
	Timeout time.Duration

	// Schemas holds JSON Schemas for the collector's artifacts, keyed by
	// artifact path or schema ID, such as its docs/schema files embedded with
	// go:embed. Emit checks each data artifact against its schema, or against
	// the SDK's schema for a normalized type (see NormalizedSchemaJSON), and
	// lists what it finds in the result artifact's checks. Each schema must be
	// self-contained: refs to other files or URLs are not loaded.
	Schemas map[string][]byte
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

	// Level returns the requested collection level from config.
	// Defaults to LevelTrust when absent or unrecognized; see Level for the
	// trust / audit / internal scheme.
	Level() Level

	// Secret returns the value of an environment variable.
	// Use this for secrets listed in epack.yaml secrets array. Values read
	// here are redacted from record details and failure messages.
	Secret(name string) string

	// Status reports a status update during collection.
	// Use this for indeterminate progress like "Connecting to API...".
	// Status messages are written to stdout as JSON for the CLI to display.
	Status(message string)

	// Progress reports progress with current/total counts.
	// Use this when iterating over a known number of items.
	// Example: Progress(5, 100, "Fetching repositories")
	Progress(current, total int64, message string)

	// Emit outputs collected artifacts wrapped in the protocol envelope.
	// Each artifact contains data and optional schema/path metadata. The SDK
	// adds the run's result artifact (schema ResultSchema) after them.
	Emit(artifacts []CollectedArtifact) error
}

// StagingContext exposes file-artifact staging helpers.
type StagingContext interface {
	// OutputDir returns the staging directory, or "" when unavailable.
	OutputDir() string

	// WriteStagedFile writes data beneath OutputDir and returns the file path
	// for CollectedArtifact.File.
	WriteStagedFile(relPath string, data []byte) (string, error)

	// StageFile opens a new file beneath OutputDir for streaming. The caller
	// must close the returned handle.
	StageFile(relPath string) (*os.File, string, error)
}

// Staging returns the file-artifact capability when this context has one.
func Staging(ctx CollectorContext) (StagingContext, bool) {
	s, ok := ctx.(StagingContext)
	return s, ok
}

// Level represents the depth of collection a collector should perform.
//
// Levels are cumulative: audit is a superset of trust, internal is a superset
// of audit. Collectors gate optional field collection on AtLeast(LevelAudit) or
// AtLeast(LevelInternal); fields present at lower levels remain present at
// higher levels.
//
// Unknown values must downgrade to LevelTrust rather than fail open: a typo
// or future-level value in config must never silently promote collection to
// data the customer didn't ask to gather.
type Level string

const (
	LevelTrust    Level = "trust"
	LevelAudit    Level = "audit"
	LevelInternal Level = "internal"
)

var levelRank = map[Level]int{
	LevelTrust:    0,
	LevelAudit:    1,
	LevelInternal: 2,
}

// AtLeast returns true if the receiver is at or above the given level in the
// trust < audit < internal ordering.
func (l Level) AtLeast(other Level) bool {
	return levelRank[l] >= levelRank[other]
}

// CollectedArtifact represents a single output artifact from a collector.
type CollectedArtifact struct {
	// Data is JSON-encoded artifact content. Mutually exclusive with File.
	Data any

	// Schema is the semantic schema type (e.g., "evidencepack/cloud-posture@v1").
	// Optional - if empty, the artifact has no schema type.
	Schema string

	// Path is the path within the pack; required for File artifacts.
	Path string

	// File references staged bytes for binary evidence. Use the path returned
	// by WriteStagedFile or StageFile. Mutually exclusive with Data.
	File string

	// DisplayName is a human-readable artifact name shown by epack inspect/list.
	DisplayName string

	// Description is a one-line artifact description.
	Description string

	// Controls lists the control IDs this artifact supports.
	Controls []string
}

// Typed errors for specific exit codes. A typed error keeps its exit code
// when returned as a pointer or wrapped with fmt.Errorf's %w.
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

func (e ConfigError) Unwrap() error  { return e.Err }
func (e AuthError) Unwrap() error    { return e.Err }
func (e NetworkError) Unwrap() error { return e.Err }

// exitCoder is implemented by the typed errors, in value and pointer form.
type exitCoder interface{ exitCode() int }

func (ConfigError) exitCode() int  { return componenttypes.ExitConfigError }
func (AuthError) exitCode() int    { return componenttypes.ExitAuthError }
func (NetworkError) exitCode() int { return componenttypes.ExitNetworkError }

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
// It handles --capabilities, --version, environment parsing, signal handling,
// timeout, protocol envelope output, and proper exit codes.
// This function does not return.
func RunCollector(spec CollectorSpec, handler CollectorHandler) {
	os.Exit(runCollectorInternal(spec, handler))
}

func runCollectorInternal(spec CollectorSpec, handler CollectorHandler) int {
	if code, handled := handleCollectorMetaFlags(spec); handled {
		return code
	}
	collectorCtx, cancel, errCode := buildCollectorContext(spec)
	if errCode != 0 {
		return errCode
	}
	defer cancel()
	return runCollectorWith(collectorCtx, handler)
}

// runCollectorWith runs handler and returns the exit code. A failure prints
// a coded record as a progress line before the exit.
func runCollectorWith(c *collectorContext, handler CollectorHandler) int {
	if err := handler(c); err != nil {
		c.reportFailure(err)
		return exitCodeFor(c.stderr(), err)
	}
	return finalizeCollectorRun(c)
}

func handleCollectorMetaFlags(spec CollectorSpec) (int, bool) {
	for _, arg := range os.Args[1:] {
		switch arg {
		case "--capabilities":
			return outputCollectorCapabilities(spec), true
		case "--version":
			fmt.Println(spec.Version)
			return 0, true
		}
	}
	return 0, false
}

func buildCollectorContext(spec CollectorSpec) (*collectorContext, context.CancelFunc, int) {
	ctx, cancel := context.WithDeadline(context.Background(), collectorDeadline(spec, os.Getenv, time.Now()))
	handleCollectorSignals(cancel)
	name := os.Getenv("EPACK_COLLECTOR_NAME")
	collectorCtx := &collectorContext{
		ctx:       ctx,
		name:      name,
		outputDir: os.Getenv("EPACK_COLLECTOR_OUTPUT_DIR"),
		spec:      spec,
		out:       os.Stdout,
		errOut:    os.Stderr,
		getenv:    os.Getenv,
		progress:  &progressWriter{out: os.Stdout},
		run:       newRun(spec, name, os.Getenv("EPACK_RUN_ID"), nil, uint64(time.Now().UnixNano())),
	}
	collectorCtx.run.schemas = compileSchemas(spec.Schemas, os.Stderr)
	if err := loadCollectorConfig(collectorCtx); err != nil {
		fmt.Fprintf(os.Stderr, "error parsing config: %v\n", err)
		collectorCtx.progress.writeFailure(CodeConfigInvalid, "", "error parsing config: "+err.Error())
		cancel()
		return nil, nil, componenttypes.ExitConfigError
	}
	return collectorCtx, cancel, 0
}

// collectorDeadline is the spec's timeout, shortened to stop ahead of a
// deadline the runner passes in EPACK_DEADLINE.
func collectorDeadline(spec CollectorSpec, getenv func(string) string, now time.Time) time.Time {
	timeout := spec.Timeout
	if timeout == 0 {
		timeout = 60 * time.Second
	}
	deadline := now.Add(timeout)
	raw := getenv("EPACK_DEADLINE")
	if raw == "" {
		return deadline
	}
	runnerDeadline, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		return deadline
	}
	margin := runnerDeadline.Sub(now) / 10
	if margin > 10*time.Second {
		margin = 10 * time.Second
	}
	if early := runnerDeadline.Add(-margin); early.Before(deadline) {
		return early
	}
	return deadline
}

func handleCollectorSignals(cancel context.CancelFunc) {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-sigChan
		cancel()
	}()
}

func loadCollectorConfig(ctx *collectorContext) error {
	configPath := os.Getenv("EPACK_COLLECTOR_CONFIG")
	if configPath == "" {
		return nil
	}
	cfg, err := parseJSONFile(configPath)
	if err != nil {
		return err
	}
	ctx.config = cfg
	return nil
}

// exitCodeFor picks the exit code from the outermost typed error in err's
// chain, so wrapping one with %w keeps its class. Without a typed error it
// follows the error's code: a deadline or a 5xx is a network error, a 401
// an auth error.
func exitCodeFor(stderr io.Writer, err error) int {
	_, _ = fmt.Fprintf(stderr, "error: %v\n", err)
	var typed exitCoder
	if errors.As(err, &typed) {
		return typed.exitCode()
	}
	if errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
		return 1
	}
	return classifyOrInternal(err).ExitCode()
}

func finalizeCollectorRun(ctx *collectorContext) int {
	if ctx.emitted {
		return 0
	}
	_, _ = fmt.Fprintf(ctx.stderr(), "error: collector did not emit any data\n")
	ctx.progressOut().writeFailure(CodeInternal, "", "collector did not emit any data")
	return 1
}

// maxFailureMessage bounds the text a failure record carries.
const maxFailureMessage = 500

// reportFailure prints err as a coded failure record. Its message is
// redacted by the values the collector read through Secret and by pattern.
func (c *collectorContext) reportFailure(err error) {
	message := redact.SensitiveAlways(redact.Values(err.Error(), c.runState().secrets.list()...))
	if len(message) > maxFailureMessage {
		message = message[:maxFailureMessage] + "... [truncated]"
	}
	c.progressOut().writeFailure(classifyOrInternal(err), VendorCodeOf(err), message)
}

// collectorContext implements CollectorContext
type collectorContext struct {
	ctx       context.Context
	name      string
	outputDir string
	config    map[string]any
	spec      CollectorSpec
	emitted   bool
	out       io.Writer
	errOut    io.Writer
	getenv    func(string) string
	progress  *progressWriter
	run       *run
}

// The accessors below default whatever a context was built without, so a
// zero-value context behaves like one RunCollector made.

func (c *collectorContext) stdout() io.Writer {
	if c.out != nil {
		return c.out
	}
	return os.Stdout
}

func (c *collectorContext) stderr() io.Writer {
	if c.errOut != nil {
		return c.errOut
	}
	return os.Stderr
}

func (c *collectorContext) env(key string) string {
	if c.getenv != nil {
		return c.getenv(key)
	}
	return os.Getenv(key)
}

func (c *collectorContext) progressOut() *progressWriter {
	if c.progress == nil {
		c.progress = &progressWriter{out: c.stdout()}
	}
	return c.progress
}

func (c *collectorContext) runState() *run {
	if c.run == nil {
		c.run = newRun(c.spec, c.name, "", nil, uint64(time.Now().UnixNano()))
	}
	return c.run
}

var (
	_ CollectorContext = (*collectorContext)(nil)
	_ StagingContext   = (*collectorContext)(nil)
)

func (c *collectorContext) Context() context.Context { return c.ctx }
func (c *collectorContext) Name() string             { return c.name }
func (c *collectorContext) Config() map[string]any   { return c.config }
func (c *collectorContext) OutputDir() string        { return c.outputDir }
func (c *collectorContext) sdkRun() *run             { return c.runState() }

func (c *collectorContext) Secret(name string) string {
	value := c.env(name)
	c.runState().secrets.add(value)
	return value
}

func (c *collectorContext) WriteStagedFile(relPath string, data []byte) (string, error) {
	if err := c.checkStagingPath(relPath); err != nil {
		return "", err
	}
	if err := safefile.WriteFilePrivate(c.outputDir, relPath, data); err != nil {
		return "", fmt.Errorf("writing staged file: %w", err)
	}
	return filepath.ToSlash(relPath), nil
}

func (c *collectorContext) StageFile(relPath string) (*os.File, string, error) {
	if err := c.checkStagingPath(relPath); err != nil {
		return nil, "", err
	}
	f, err := safefile.OpenForWriteBeneath(c.outputDir, relPath)
	if err != nil {
		return nil, "", fmt.Errorf("creating staged file: %w", err)
	}
	return f, filepath.ToSlash(relPath), nil
}

func (c *collectorContext) checkStagingPath(relPath string) error {
	if c.outputDir == "" {
		return fmt.Errorf("file artifacts require epack with EPACK_COLLECTOR_OUTPUT_DIR support; upgrade epack")
	}
	return stagedartifact.LocalPath(relPath)
}

// Level reads the "level" key from config and returns the requested
// collection level. Absent, empty, non-string, or unrecognized values produce
// LevelTrust; unrecognized values also emit a one-line warning to stderr.
func (c *collectorContext) Level() Level {
	raw, ok := c.config["level"]
	if !ok {
		return LevelTrust
	}
	s, ok := raw.(string)
	if !ok || s == "" {
		return LevelTrust
	}
	lvl := Level(s)
	if _, known := levelRank[lvl]; !known {
		_, _ = fmt.Fprintf(c.stderr(), "warning: unknown collection level %q in config; falling back to %q\n", s, LevelTrust)
		return LevelTrust
	}
	return lvl
}

func (c *collectorContext) Status(message string) {
	c.progressOut().writeStatus(message)
}

func (c *collectorContext) Progress(current, total int64, message string) {
	c.progressOut().writeProgress(current, total, message)
}

func (c *collectorContext) Emit(artifacts []CollectedArtifact) error {
	if c.emitted {
		return fmt.Errorf("Emit can only be called once")
	}
	if len(artifacts) == 0 {
		return fmt.Errorf("at least one artifact is required")
	}
	// Validate before marking emitted, so callers can retry after a rejected artifact.
	artifactEntries := make([]map[string]any, 0, len(artifacts)+1)
	for i, a := range artifacts {
		entry, err := c.collectorArtifactEntry(a)
		if err != nil {
			return fmt.Errorf("artifact %d: %w", i, err)
		}
		artifactEntries = append(artifactEntries, entry)
	}
	resultEntry, err := c.resultArtifactEntry(artifacts)
	if err != nil {
		return err
	}
	artifactEntries = append(artifactEntries, resultEntry)
	c.emitted = true

	envelope := map[string]any{
		"type":             "epack_result",
		"protocol_version": componenttypes.CollectorProtocolVersion,
		"artifacts":        artifactEntries,
	}

	enc := json.NewEncoder(c.stdout())
	enc.SetIndent("", "  ")
	if err := enc.Encode(envelope); err != nil {
		return fmt.Errorf("encoding output: %w", err)
	}

	return nil
}

// resultArtifactEntry builds the run's result artifact from the recorder and
// the call ledger.
func (c *collectorContext) resultArtifactEntry(artifacts []CollectedArtifact) (map[string]any, error) {
	result, err := buildResult(resultInput{
		run:       c.runState(),
		level:     c.Level(),
		artifacts: artifacts,
		getenv:    c.env,
		finished:  c.runState().now(),
	})
	if err != nil {
		return nil, err
	}
	path := resultPath(c.runState().name)
	for i, a := range artifacts {
		if artifactPath(a, c.runState().name, i) == path {
			return nil, fmt.Errorf("artifact %d uses %s, the path of the result artifact", i, path)
		}
	}
	return c.collectorArtifactEntry(CollectedArtifact{
		Data:        result,
		Schema:      ResultSchema,
		Path:        path,
		DisplayName: "Collector result",
		Description: "What the collector could not measure and why, the calls it made, and the identity it signed in as",
	})
}

func (c *collectorContext) collectorArtifactEntry(a CollectedArtifact) (map[string]any, error) {
	var entry map[string]any
	if a.File != "" {
		relPath, err := c.stagedFileRel(a)
		if err != nil {
			return nil, err
		}
		entry = map[string]any{
			"file": relPath,
			"path": a.Path,
		}
	} else {
		entry = map[string]any{
			"data": a.Data,
		}
		if a.Path != "" {
			entry["path"] = a.Path
		}
	}
	if a.Schema != "" {
		entry["schema"] = a.Schema
	}
	if a.DisplayName != "" {
		entry["display_name"] = a.DisplayName
	}
	if a.Description != "" {
		entry["description"] = a.Description
	}
	if len(a.Controls) > 0 {
		entry["controls"] = a.Controls
	}
	return entry, nil
}

func (c *collectorContext) stagedFileRel(a CollectedArtifact) (string, error) {
	if c.outputDir == "" {
		return "", fmt.Errorf("file artifacts require epack with EPACK_COLLECTOR_OUTPUT_DIR support; upgrade epack")
	}

	file := a.File
	if filepath.IsAbs(file) {
		rel, err := filepath.Rel(c.outputDir, file)
		if err != nil {
			return "", fmt.Errorf("file artifact %q is outside the staging directory", a.File)
		}
		file = rel
	}

	relPath, err := stagedartifact.Entry{HasData: a.Data != nil, File: file, Path: a.Path}.Validate()
	if err != nil {
		return "", fmt.Errorf("file artifact %q: %w", a.File, err)
	}
	if err := safefile.ValidateFileBeneath(c.outputDir, relPath); err != nil {
		return "", fmt.Errorf("file artifact %q: %w", a.File, err)
	}
	return relPath, nil
}

// outputCollectorCapabilities outputs the collector's capabilities as JSON.
func outputCollectorCapabilities(spec CollectorSpec) int {
	caps := map[string]any{
		"kind":             "collector",
		"name":             spec.Name,
		"version":          spec.Version,
		"protocol_version": componenttypes.CollectorProtocolVersion,
		"description":      spec.Description,
	}
	// Include commit if set (for supply chain provenance)
	if spec.Commit != "" {
		caps["commit"] = spec.Commit
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(caps); err != nil {
		fmt.Fprintf(os.Stderr, "error encoding capabilities: %v\n", err)
		return 1
	}
	return 0
}
