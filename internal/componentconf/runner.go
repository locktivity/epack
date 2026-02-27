//go:build conformance

package componentconf

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/locktivity/epack/internal/componenttypes"
	"github.com/locktivity/epack/internal/procexec"
	"github.com/locktivity/epack/internal/validate"
)

// Runner executes conformance tests against a component binary.
type Runner struct {
	Binary     string                       // Path to component binary
	Type       componenttypes.ComponentKind // Component type (collector, tool, remote, utility)
	Timeout    time.Duration                // Execution timeout
	WorkDir    string                       // Working directory for tests
	Verbose    bool                         // Enable verbose output
	results    []TestResult
	caps       map[string]interface{}
	binaryName string
}

// NewRunner creates a new conformance test runner.
func NewRunner(binary string, componentType componenttypes.ComponentKind) *Runner {
	return &Runner{
		Binary:  binary,
		Type:    componentType,
		Timeout: 30 * time.Second,
	}
}

// Run executes all applicable conformance tests and returns a report.
func (r *Runner) Run(ctx context.Context) (*Report, error) {
	// Extract binary name for naming tests
	r.binaryName = filepath.Base(r.Binary)

	// Ensure binary path is absolute (exec may change working directory)
	if !filepath.IsAbs(r.Binary) {
		abs, err := filepath.Abs(r.Binary)
		if err != nil {
			return nil, fmt.Errorf("resolve binary path: %w", err)
		}
		r.Binary = abs
	}

	// Create temp working directory
	var err error
	r.WorkDir, err = os.MkdirTemp("", "epack-conformance-*")
	if err != nil {
		return nil, fmt.Errorf("create work dir: %w", err)
	}
	defer os.RemoveAll(r.WorkDir)

	// Run tests based on component type
	switch r.Type {
	case componenttypes.KindCollector:
		r.runCollectorTests(ctx)
	case componenttypes.KindTool:
		r.runToolTests(ctx)
	case componenttypes.KindRemote:
		r.runRemoteTests(ctx)
	case componenttypes.KindUtility:
		r.runUtilityTests(ctx)
	}

	// Build report
	report := &Report{
		Component:    r.binaryName,
		Type:         r.Type,
		Results:      r.results,
		Capabilities: r.caps,
	}
	r.computeSummary(report)
	report.Level = report.ComputeLevel()

	return report, nil
}

func (r *Runner) computeSummary(report *Report) {
	for _, result := range r.results {
		if summary := report.Summary.summaryForLevel(result.Level); summary != nil {
			summary.increment(result.Status)
		}
	}
}

func (r *Runner) pass(id string) {
	req := RequirementByID(id)
	if req == nil {
		return
	}
	r.results = append(r.results, TestResult{
		ID:     id,
		Level:  req.Level,
		Status: StatusPass,
	})
}

func (r *Runner) fail(id, message string) {
	req := RequirementByID(id)
	if req == nil {
		return
	}
	r.results = append(r.results, TestResult{
		ID:      id,
		Level:   req.Level,
		Status:  StatusFail,
		Message: message,
	})
}

func (r *Runner) skip(id, reason string) {
	req := RequirementByID(id)
	if req == nil {
		return
	}
	r.results = append(r.results, TestResult{
		ID:     id,
		Level:  req.Level,
		Status: StatusSkip,
		Reason: reason,
	})
}

// execResult holds the result of executing a command.
type execResult struct {
	Stdout   []byte
	Stderr   []byte
	ExitCode int
	Err      error
}

func (r *Runner) exec(ctx context.Context, args []string, stdin []byte, env map[string]string) execResult {
	ctx, cancel := context.WithTimeout(ctx, r.Timeout)
	defer cancel()

	// Build environment
	cmdEnv := os.Environ()
	for k, v := range env {
		cmdEnv = append(cmdEnv, k+"="+v)
	}

	res, err := procexec.RunCapture(ctx, procexec.Spec{
		Path:  r.Binary,
		Args:  args,
		Dir:   r.WorkDir,
		Env:   cmdEnv,
		Stdin: bytes.NewReader(stdin),
	})

	result := execResult{
		Stdout: res.Stdout,
		Stderr: res.Stderr,
	}

	if err != nil {
		result.ExitCode = res.ExitCode
		result.Err = err
	}

	return result
}

// Common test helpers

var namePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

func (r *Runner) testBinaryNaming() {
	// C-001: Binary name follows pattern epack-{type}-{name}
	prefix := "epack-" + string(r.Type) + "-"
	if strings.HasPrefix(r.binaryName, prefix) {
		name := strings.TrimPrefix(r.binaryName, prefix)
		// C-002: Name segment matches pattern
		if namePattern.MatchString(name) {
			r.pass("C-001")
			r.pass("C-002")
		} else {
			r.pass("C-001")
			r.fail("C-002", fmt.Sprintf("name %q does not match ^[a-z0-9][a-z0-9._-]{0,63}$", name))
		}
		// C-003: No path separators
		if !strings.ContainsAny(name, "/\\") && !validate.ContainsTraversal(name) {
			r.pass("C-003")
		} else {
			r.fail("C-003", "name contains path separators or traversal sequences")
		}
	} else {
		r.fail("C-001", fmt.Sprintf("binary name %q does not start with %q", r.binaryName, prefix))
		r.skip("C-002", "depends on C-001")
		r.skip("C-003", "depends on C-001")
	}
}

func (r *Runner) testExitCodeSuccess(ctx context.Context, env map[string]string) {
	result := r.exec(ctx, nil, nil, env)
	if result.ExitCode == 0 {
		r.pass("C-020")
	} else {
		r.fail("C-020", fmt.Sprintf("exit code %d, expected 0", result.ExitCode))
	}
}

func isValidJSON(data []byte) bool {
	var v interface{}
	return json.Unmarshal(data, &v) == nil
}

// extractResultOutput filters stdout to extract only the result output,
// removing any progress messages. This handles the JSON Lines protocol where
// components can emit epack_progress messages before the final result.
func extractResultOutput(stdout []byte) []byte {
	var result bytes.Buffer
	lines := bytes.Split(stdout, []byte("\n"))

	for _, line := range lines {
		trimmed := bytes.TrimSpace(line)
		if len(trimmed) == 0 {
			continue
		}

		// Check if this line is a progress message
		if isProgressMessage(trimmed) {
			continue // Skip progress messages
		}

		// Include non-progress lines in result
		result.Write(line)
		result.WriteByte('\n')
	}

	return bytes.TrimSpace(result.Bytes())
}

// isProgressMessage checks if a line is an epack_progress JSON message.
func isProgressMessage(line []byte) bool {
	if len(line) == 0 || line[0] != '{' {
		return false
	}

	var msg struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(line, &msg); err != nil {
		return false
	}

	return msg.Type == "epack_progress"
}

func isValidUTF8(data []byte) bool {
	return utf8.Valid(data)
}

// containsANSI checks if data contains ANSI escape sequences.
func containsANSI(data []byte) bool {
	return strings.Contains(string(data), "\x1b[")
}

// testNoColor tests C-013: Component honors NO_COLOR for terminal output.
// The execFunc should execute the component and return the result.
// It is called twice: once without NO_COLOR and once with NO_COLOR=1.
func (r *Runner) testNoColor(ctx context.Context, args []string, stdin []byte, baseEnv map[string]string) {
	// Run without NO_COLOR
	resultWithColor := r.exec(ctx, args, stdin, baseEnv)

	// Run with NO_COLOR
	envNoColor := make(map[string]string)
	for k, v := range baseEnv {
		envNoColor[k] = v
	}
	envNoColor["NO_COLOR"] = "1"
	resultNoColor := r.exec(ctx, args, stdin, envNoColor)

	// Check if stderr contains ANSI escape codes
	hasColorWith := containsANSI(resultWithColor.Stderr)
	hasColorWithout := containsANSI(resultNoColor.Stderr)

	if hasColorWith && !hasColorWithout {
		// Had color without NO_COLOR, no color with NO_COLOR - perfect
		r.pass("C-013")
	} else if !hasColorWith && !hasColorWithout {
		// No color in either case - also acceptable
		r.pass("C-013")
	} else if hasColorWithout {
		// Has color even with NO_COLOR=1
		r.fail("C-013", "component outputs ANSI colors despite NO_COLOR=1")
	} else {
		// Inconclusive
		r.skip("C-013", "no color output to compare")
	}
}

// testFilesystemBoundary tests C-030: Component does not write outside designated output area.
// The execFunc should execute the component in a way that exercises its main functionality.
func (r *Runner) testFilesystemBoundary(ctx context.Context, args []string, stdin []byte, env map[string]string) {
	// Create a marker file outside work dir and check it's not modified
	outsideDir, err := os.MkdirTemp("", "epack-boundary-test-*")
	if err != nil {
		r.skip("C-030", "could not create boundary test directory")
		return
	}
	defer os.RemoveAll(outsideDir)

	markerPath := filepath.Join(outsideDir, "marker.txt")
	if err := os.WriteFile(markerPath, []byte("original"), 0644); err != nil {
		r.skip("C-030", "could not create marker file")
		return
	}

	// Run the component
	r.exec(ctx, args, stdin, env)

	// Check marker file is unchanged
	content, err := os.ReadFile(markerPath)
	if err != nil || string(content) != "original" {
		r.fail("C-030", "component modified files outside work directory")
	} else {
		r.pass("C-030")
	}
}
