package componentsdk

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/locktivity/epack/internal/componenttypes"
	"github.com/locktivity/epack/internal/validate"
)

// ToolSpec defines the tool's metadata and capabilities.
type ToolSpec struct {
	// Name is the tool name (without epack-tool- prefix).
	// Must match ^[a-z0-9][a-z0-9._-]{0,63}$
	Name string

	// Version is the semantic version (e.g., "1.0.0").
	Version string

	// Description is a human-readable description of what the tool does.
	Description string

	// RequiresPack indicates whether this tool requires a pack to operate.
	// If true, ToolContext.Pack() will be available.
	RequiresPack bool

	// Network indicates whether the tool requires network access.
	Network bool

	// RequiresTools lists other tools this tool depends on.
	RequiresTools []string

	// RequiresOutputs lists outputs from other tools this tool depends on.
	RequiresOutputs []string
}

// ToolHandler is the function signature for tool implementations.
// Return nil for success, or an error for failure.
// The SDK handles result.json generation in both cases.
type ToolHandler func(ctx ToolContext) error

// ToolContext provides access to the tool execution environment.
type ToolContext interface {
	// RunID returns the unique run identifier.
	RunID() string

	// RunDir returns the run directory path where outputs should be written.
	RunDir() string

	// Pack returns the pack reader if a pack was provided.
	// Returns nil if no pack is available (check ToolSpec.RequiresPack).
	Pack() *Pack

	// PackPath returns the path to the pack file, or empty string if none.
	PackPath() string

	// PackDigest returns the pack's digest, or empty string if none.
	PackDigest() string

	// Config returns the parsed configuration, or nil if none provided.
	Config() map[string]any

	// WriteOutput writes data as JSON to the outputs directory and registers it.
	// The path must be a simple filename (no directories, no traversal).
	// Use WriteOutputBytes for non-JSON content.
	WriteOutput(filename string, data any) error

	// WriteOutputBytes writes raw bytes to the outputs directory and registers it.
	// The path must be a simple filename (no directories, no traversal).
	WriteOutputBytes(filename string, data []byte, mediaType string) error

	// Warn adds a warning to the result.
	Warn(code, message string, path string)

	// Error adds an error to the result (does not stop execution).
	Error(code, message string, path string)
}

// RunTool executes the tool handler with full protocol compliance.
// It handles --capabilities, --version, environment parsing, result.json generation,
// and proper exit codes. This function does not return.
func RunTool(spec ToolSpec, handler ToolHandler) {
	os.Exit(runToolInternal(spec, handler))
}

func runToolInternal(spec ToolSpec, handler ToolHandler) int {
	startTime := time.Now().UTC()

	// Check for --capabilities and --version flags
	for _, arg := range os.Args[1:] {
		switch arg {
		case "--capabilities":
			return outputToolCapabilities(spec)
		case "--version":
			fmt.Println(spec.Version)
			return 0
		}
	}

	// Parse environment
	ctx := &toolContext{
		runID:      os.Getenv("EPACK_RUN_ID"),
		runDir:     os.Getenv("EPACK_RUN_DIR"),
		packPath:   os.Getenv("EPACK_PACK_PATH"),
		packDigest: os.Getenv("EPACK_PACK_DIGEST"),
		startTime:  startTime,
		spec:       spec,
		outputs:    []outputEntry{},
		warnings:   []errorEntry{},
		errors:     []errorEntry{},
	}

	if ctx.runDir == "" {
		ctx.runDir = "."
	}

	// Generate run ID if not provided
	if ctx.runID == "" {
		ctx.runID = fmt.Sprintf("%s-%06d", startTime.Format("2006-01-02T15-04-05-000000Z"), 0)
	}

	// Parse config if provided
	configPath := os.Getenv("EPACK_TOOL_CONFIG")
	if configPath != "" {
		if cfg, err := parseJSONFile(configPath); err == nil {
			ctx.config = cfg
		}
	}

	// Open pack if provided
	if ctx.packPath != "" {
		pack, err := OpenPack(ctx.packPath)
		if err != nil {
			ctx.errors = append(ctx.errors, errorEntry{
				Code:    "PACK_OPEN_ERROR",
				Message: err.Error(),
			})
			return ctx.writeResult("failure", nil)
		}
		ctx.pack = pack
		defer func() { _ = pack.Close() }()
	} else if spec.RequiresPack {
		ctx.errors = append(ctx.errors, errorEntry{
			Code:    "PACK_REQUIRED",
			Message: "this tool requires a pack but none was provided",
		})
		return ctx.writeResult("failure", nil)
	}

	// Run handler
	err := handler(ctx)

	// Determine status and write result
	if err != nil {
		ctx.errors = append(ctx.errors, errorEntry{
			Code:    "TOOL_ERROR",
			Message: err.Error(),
		})
		return ctx.writeResult("failure", err)
	}

	return ctx.writeResult("success", nil)
}

func outputToolCapabilities(spec ToolSpec) int {
	caps := map[string]any{
		"kind":             "tool",
		"name":             spec.Name,
		"version":          spec.Version,
		"protocol_version": componenttypes.ToolProtocolVersion,
		"description":      spec.Description,
		"requires_pack":    spec.RequiresPack,
		"network":          spec.Network,
	}

	if len(spec.RequiresTools) > 0 {
		caps["requires_tools"] = spec.RequiresTools
	}
	if len(spec.RequiresOutputs) > 0 {
		caps["requires_outputs"] = spec.RequiresOutputs
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(caps); err != nil {
		fmt.Fprintf(os.Stderr, "error encoding capabilities: %v\n", err)
		return 1
	}
	return 0
}

// toolContext implements ToolContext
type toolContext struct {
	runID      string
	runDir     string
	packPath   string
	packDigest string
	pack       *Pack
	config     map[string]any
	startTime  time.Time
	spec       ToolSpec
	outputs    []outputEntry
	warnings   []errorEntry
	errors     []errorEntry
}

func (c *toolContext) RunID() string      { return c.runID }
func (c *toolContext) RunDir() string     { return c.runDir }
func (c *toolContext) Pack() *Pack        { return c.pack }
func (c *toolContext) PackPath() string   { return c.packPath }
func (c *toolContext) PackDigest() string { return c.packDigest }
func (c *toolContext) Config() map[string]any { return c.config }

func (c *toolContext) WriteOutput(filename string, data any) error {
	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling output: %w", err)
	}
	return c.WriteOutputBytes(filename, jsonData, "application/json")
}

func (c *toolContext) WriteOutputBytes(filename string, data []byte, mediaType string) error {
	// Validate filename (TOOL-040, 041, 042)
	if filepath.IsAbs(filename) {
		return fmt.Errorf("output path must be relative: %s", filename)
	}
	if validate.ContainsTraversal(filename) {
		return fmt.Errorf("output path must not contain traversal: %s", filename)
	}
	if filepath.Dir(filename) != "." {
		return fmt.Errorf("output path must be a simple filename: %s", filename)
	}

	// Ensure outputs directory exists (TOOL-043)
	outputsDir := filepath.Join(c.runDir, "outputs")
	if err := os.MkdirAll(outputsDir, 0755); err != nil {
		return fmt.Errorf("creating outputs directory: %w", err)
	}

	// Write file
	outputPath := filepath.Join(outputsDir, filename)
	if err := os.WriteFile(outputPath, data, 0644); err != nil {
		return fmt.Errorf("writing output: %w", err)
	}

	// Calculate digest and record output
	hash := sha256.Sum256(data)
	c.outputs = append(c.outputs, outputEntry{
		Path:      "outputs/" + filename,
		MediaType: mediaType,
		Digest:    "sha256:" + hex.EncodeToString(hash[:]),
		Bytes:     int64(len(data)),
	})

	return nil
}

func (c *toolContext) Warn(code, message, path string) {
	c.warnings = append(c.warnings, errorEntry{Code: code, Message: message, Path: path})
}

func (c *toolContext) Error(code, message, path string) {
	c.errors = append(c.errors, errorEntry{Code: code, Message: message, Path: path})
}

func (c *toolContext) writeResult(status string, _ error) int {
	completedAt := time.Now().UTC()
	duration := completedAt.Sub(c.startTime)

	// Format per TOOL-050, TOOL-051: YYYY-MM-DDTHH:MM:SSZ (no milliseconds)
	const timestampFormat = "2006-01-02T15:04:05Z"

	wrapperVersion := os.Getenv("EPACK_WRAPPER_VERSION")
	if wrapperVersion == "" {
		wrapperVersion = "unknown"
	}

	result := toolResult{
		SchemaVersion: 1,
		Wrapper: wrapperInfo{
			Name:    "epack",
			Version: wrapperVersion,
		},
		Tool: toolInfo{
			Name:            c.spec.Name,
			Version:         c.spec.Version,
			ProtocolVersion: componenttypes.ToolProtocolVersion,
		},
		RunID:       c.runID,
		StartedAt:   c.startTime.Format(timestampFormat),
		CompletedAt: completedAt.Format(timestampFormat),
		DurationMs:  duration.Milliseconds(),
		Status:      status,
		PackPath:    c.packPath,
		PackDigest:  c.packDigest,
		Inputs:      map[string]any{},
		Outputs:     c.outputs,
		Errors:      c.errors,
		Warnings:    c.warnings,
	}

	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error marshaling result: %v\n", err)
		return 1
	}

	resultPath := filepath.Join(c.runDir, "result.json")
	if err := os.WriteFile(resultPath, data, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "error writing result.json: %v\n", err)
		return 1
	}

	return 0
}

// Result types for JSON serialization
type toolResult struct {
	SchemaVersion int            `json:"schema_version"`
	Wrapper       wrapperInfo    `json:"wrapper"`
	Tool          toolInfo       `json:"tool"`
	RunID         string         `json:"run_id"`
	StartedAt     string         `json:"started_at"`
	CompletedAt   string         `json:"completed_at"`
	DurationMs    int64          `json:"duration_ms"`
	Status        string         `json:"status"`
	PackPath      string         `json:"pack_path,omitempty"`
	PackDigest    string         `json:"pack_digest,omitempty"`
	Inputs        map[string]any `json:"inputs"`
	Outputs       []outputEntry  `json:"outputs"`
	Errors        []errorEntry   `json:"errors"`
	Warnings      []errorEntry   `json:"warnings"`
}

type wrapperInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type toolInfo struct {
	Name            string `json:"name"`
	Version         string `json:"version"`
	ProtocolVersion int    `json:"protocol_version"`
}

type outputEntry struct {
	Path      string `json:"path"`
	MediaType string `json:"media_type"`
	Digest    string `json:"digest,omitempty"`
	Bytes     int64  `json:"bytes,omitempty"`
}

type errorEntry struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Path    string `json:"path,omitempty"`
}

func parseJSONFile(path string) (map[string]any, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var result map[string]any
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, err
	}
	return result, nil
}
