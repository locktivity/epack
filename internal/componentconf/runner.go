//go:build conformance

package componentconf

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/locktivity/epack/internal/componenttypes"
	"github.com/locktivity/epack/internal/limits"
	"github.com/locktivity/epack/internal/procexec"
	"github.com/locktivity/epack/internal/validate"
)

// Runner executes conformance tests against a component binary.
type Runner struct {
	Binary          string                       // Path to component binary
	Type            componenttypes.ComponentKind // Component type (collector, tool, remote, utility)
	Timeout         time.Duration                // Execution timeout
	WorkDir         string                       // Working directory for tests
	Verbose         bool                         // Enable verbose output
	CollectorConfig string                       // Config file a collector can collect with (--config)
	// CollectorSecrets name the variables a collector reads credentials
	// from (--secret). Every run sets each to a canary value no output may
	// contain.
	CollectorSecrets []string
	results          []TestResult
	timeouts         int               // runs killed at Timeout
	signalDelay      time.Duration     // COL-031's wait for a collector that reports no progress
	canaries         map[string]string // secret name to its canary value
	leaks            []secretLeak
	collectRun       execResult // the run with --config, which should collect
	configName       string     // CollectorConfig as given, for messages
	caps             map[string]interface{}
	binaryName       string
}

// NewRunner creates a new conformance test runner.
func NewRunner(binary string, componentType componenttypes.ComponentKind) *Runner {
	return &Runner{
		Binary:      binary,
		Type:        componentType,
		Timeout:     30 * time.Second,
		signalDelay: defaultSignalDelay,
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
	r.configName = r.CollectorConfig
	if r.CollectorConfig != "" && !filepath.IsAbs(r.CollectorConfig) {
		abs, err := filepath.Abs(r.CollectorConfig)
		if err != nil {
			return nil, fmt.Errorf("resolve config path: %w", err)
		}
		r.CollectorConfig = abs
	}

	if len(r.CollectorSecrets) > 0 {
		r.canaries = make(map[string]string, len(r.CollectorSecrets))
		for _, name := range r.CollectorSecrets {
			canary, err := newCanary()
			if err != nil {
				return nil, err
			}
			r.canaries[name] = canary
		}
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
	env, outputDir, cleanup := r.withOutputDir(env)
	defer cleanup()

	res, err := procexec.RunCapture(ctx, procexec.Spec{
		Path:  r.Binary,
		Args:  args,
		Dir:   r.WorkDir,
		Env:   r.envList(env),
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
	if res.TimedOut {
		r.timeouts++
	}
	r.recordLeaks(env, res.Stdout, res.Stderr, res.ExitCode)
	r.recordFileLeaks(env, outputDir, res.ExitCode)

	return result
}

// withOutputDir gives a collector run a fresh staging directory, as the epack
// runner does, and returns the cleanup that removes it. It lives in the
// working directory, so a scan of that directory covers file artifacts too.
func (r *Runner) withOutputDir(env map[string]string) (map[string]string, string, func()) {
	if r.Type != componenttypes.KindCollector {
		return env, "", func() {}
	}
	dir, err := os.MkdirTemp(r.WorkDir, "output-")
	if err != nil {
		return env, "", func() {}
	}
	withDir := make(map[string]string, len(env)+1)
	for k, v := range env {
		withDir[k] = v
	}
	withDir["EPACK_COLLECTOR_OUTPUT_DIR"] = dir
	return withDir, dir, func() { _ = os.RemoveAll(dir) }
}

// envList is this process's environment with env added, then each secret's
// canary. Later entries win, so a real credential in this process's
// environment never reaches the component.
func (r *Runner) envList(env map[string]string) []string {
	list := os.Environ()
	for k, v := range env {
		list = append(list, k+"="+v)
	}
	for name, canary := range r.canaries {
		list = append(list, name+"="+canary)
	}
	return list
}

// secretLeak is a secret's canary found in something a run wrote.
type secretLeak struct {
	name   string
	stream string // "stdout", "stderr", "staged file <path>", or "working-directory file <path>"
	run    string
	exit   int
}

// newCanary returns a value no component could print by chance.
func newCanary() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generate canary: %w", err)
	}
	return "epack-canary-" + hex.EncodeToString(b[:]), nil
}

// recordLeaks notes each canary in a run's stdout, which carries its data
// artifacts and progress lines, and its stderr.
func (r *Runner) recordLeaks(env map[string]string, stdout, stderr []byte, exit int) {
	r.recordLeak(env, "stdout", stdout, exit)
	r.recordLeak(env, "stderr", stderr, exit)
}

// recordFileLeaks notes each canary in a file the run left in its working
// directory, which holds its staging directory and so its file artifacts.
// A file an earlier run left is scanned again but noted once.
func (r *Runner) recordFileLeaks(env map[string]string, outputDir string, exit int) {
	if len(r.canaries) == 0 {
		return
	}
	_ = filepath.WalkDir(r.WorkDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || !d.Type().IsRegular() {
			return nil
		}
		info, err := d.Info()
		if err != nil || info.Size() > limits.Artifact.Bytes() {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		where := "working-directory file "
		rel, err := filepath.Rel(r.WorkDir, path)
		if outputDir != "" {
			if staged, serr := filepath.Rel(outputDir, path); serr == nil && !strings.HasPrefix(staged, "..") {
				where, rel, err = "staged file ", staged, nil
			}
		}
		if err != nil {
			return nil
		}
		where += filepath.ToSlash(rel)
		for _, leak := range r.leaks {
			if leak.stream == where {
				return nil
			}
		}
		r.recordLeak(env, where, data, exit)
		return nil
	})
}

// recordLeak notes each canary in data. It matches the random part, so a
// leak survives a stripped prefix or quoting.
func (r *Runner) recordLeak(env map[string]string, where string, data []byte, exit int) {
	for name, canary := range r.canaries {
		if bytes.Contains(data, []byte(strings.TrimPrefix(canary, "epack-canary-"))) {
			r.leaks = append(r.leaks, secretLeak{name: name, stream: where, run: r.runLabel(env), exit: exit})
		}
	}
}

// runLabel names a collector run by the config it had.
func (r *Runner) runLabel(env map[string]string) string {
	switch env["EPACK_COLLECTOR_CONFIG"] {
	case "":
		return "the run without config"
	case r.CollectorConfig:
		return "the run with --config"
	default:
		return "a run with a test config"
	}
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
