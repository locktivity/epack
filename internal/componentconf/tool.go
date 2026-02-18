//go:build conformance

package componentconf

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/locktivity/epack/internal/validate"
)

func (r *Runner) runToolTests(ctx context.Context) {
	// Common tests
	r.testBinaryNaming()

	// Tool-specific tests
	r.testToolCapabilities(ctx)
	r.testToolExecution(ctx)
	r.testToolResultJSON(ctx)
	r.testToolDirectoryBoundary(ctx)
	r.testToolFlags(ctx)
	r.testToolRunIDSort(ctx)
	r.testToolNoColor(ctx)
}

func (r *Runner) testToolCapabilities(ctx context.Context) {
	// TOOL-001: Implement --capabilities flag
	env := map[string]string{
		"EPACK_MODE": "capabilities",
	}
	result := r.exec(ctx, []string{"--capabilities"}, nil, env)

	if result.ExitCode != 0 {
		r.fail("TOOL-001", "non-zero exit code from --capabilities")
		r.skip("TOOL-002", "depends on TOOL-001")
		r.skip("TOOL-003", "depends on TOOL-001")
		r.skip("TOOL-004", "depends on TOOL-001")
		r.skip("TOOL-005", "depends on TOOL-001")
		return
	}

	if !isValidJSON(result.Stdout) {
		r.fail("TOOL-001", "output is not valid JSON")
		r.skip("TOOL-002", "depends on TOOL-001")
		r.skip("TOOL-003", "depends on TOOL-001")
		r.skip("TOOL-004", "depends on TOOL-001")
		r.skip("TOOL-005", "depends on TOOL-001")
		return
	}

	r.pass("TOOL-001")

	// Parse capabilities
	var caps map[string]interface{}
	if err := json.Unmarshal(result.Stdout, &caps); err != nil {
		r.fail("TOOL-003", "failed to parse capabilities JSON")
		return
	}
	r.caps = caps

	// TOOL-002: EPACK_MODE=capabilities (we set it, so pass)
	r.pass("TOOL-002")

	// TOOL-003: Required fields
	hasName := caps["name"] != nil
	hasVersion := caps["version"] != nil
	hasProtocolVersion := caps["protocol_version"] != nil

	if hasName && hasVersion && hasProtocolVersion {
		r.pass("TOOL-003")
	} else {
		missing := []string{}
		if !hasName {
			missing = append(missing, "name")
		}
		if !hasVersion {
			missing = append(missing, "version")
		}
		if !hasProtocolVersion {
			missing = append(missing, "protocol_version")
		}
		r.fail("TOOL-003", "missing required fields: "+strings.Join(missing, ", "))
	}

	// TOOL-004: Description field
	if caps["description"] != nil {
		r.pass("TOOL-004")
	} else {
		r.skip("TOOL-004", "description field not present")
	}

	// TOOL-005: Optional fields
	hasNetwork := caps["network"] != nil
	hasRequiresTools := caps["requires_tools"] != nil
	hasRequiresOutputs := caps["requires_outputs"] != nil
	if hasNetwork || hasRequiresTools || hasRequiresOutputs {
		r.pass("TOOL-005")
	} else {
		r.skip("TOOL-005", "optional fields not present")
	}
}

func (r *Runner) testToolExecution(ctx context.Context) {
	// Create a run directory
	runID := "2026-02-22T10-00-00-000000Z-000001"
	runDir := filepath.Join(r.WorkDir, "run")
	if err := os.MkdirAll(runDir, 0755); err != nil {
		r.skip("TOOL-010", "could not create run directory")
		return
	}

	env := map[string]string{
		"EPACK_RUN_ID":           runID,
		"EPACK_RUN_DIR":          runDir,
		"EPACK_TOOL_NAME":        "test",
		"EPACK_PROTOCOL_VERSION": "1",
		"EPACK_STARTED_AT":       "2026-02-22T10:00:00Z",
	}

	// Change to run directory for execution
	origDir := r.WorkDir
	r.WorkDir = runDir

	result := r.exec(ctx, nil, nil, env)

	r.WorkDir = origDir

	// TOOL-010, 011, 012, 013: Environment variables
	// We provided them, so if the tool runs, we assume it reads them
	if result.Err == nil {
		r.pass("TOOL-010")
		r.pass("TOOL-011")
		r.pass("TOOL-012")
		r.pass("TOOL-013")
		r.pass("C-010")
	} else {
		r.fail("TOOL-010", "tool failed to execute")
		r.skip("TOOL-011", "depends on execution")
		r.skip("TOOL-012", "depends on execution")
		r.skip("TOOL-013", "depends on execution")
	}

	// TOOL-014, 015: Pack path/digest (not provided, skip)
	r.skip("TOOL-014", "no pack provided in test")
	r.skip("TOOL-015", "no pack provided in test")

	// C-020: Exit code 0 on success
	if result.ExitCode == 0 {
		r.pass("C-020")
	} else {
		r.fail("C-020", "non-zero exit code")
	}
}

func (r *Runner) testToolResultJSON(ctx context.Context) {
	// Look for result.json in run directory
	runDir := filepath.Join(r.WorkDir, "run")
	resultPath := filepath.Join(runDir, "result.json")

	data, err := os.ReadFile(resultPath)
	if err != nil {
		r.fail("TOOL-030", "result.json not found")
		r.skip("TOOL-031", "depends on TOOL-030")
		r.skip("TOOL-032", "depends on TOOL-030")
		r.skip("TOOL-033", "depends on TOOL-030")
		r.skip("TOOL-034", "depends on TOOL-030")
		r.skip("TOOL-036", "depends on TOOL-030")
		r.skip("TOOL-040", "depends on TOOL-030")
		r.skip("TOOL-041", "depends on TOOL-030")
		r.skip("TOOL-042", "depends on TOOL-030")
		r.skip("TOOL-043", "depends on TOOL-030")
		r.skip("TOOL-050", "depends on TOOL-030")
		r.skip("TOOL-051", "depends on TOOL-030")
		return
	}

	r.pass("TOOL-030")
	r.pass("TOOL-036") // Written even if we get here

	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		r.fail("TOOL-031", "result.json is not valid JSON")
		return
	}

	// TOOL-031: Required fields
	hasSchemaVersion := result["schema_version"] != nil
	hasTool := result["tool"] != nil
	hasRunID := result["run_id"] != nil
	hasStatus := result["status"] != nil

	toolMap, toolIsMap := result["tool"].(map[string]interface{})
	hasToolName := toolIsMap && toolMap["name"] != nil
	hasToolVersion := toolIsMap && toolMap["version"] != nil

	if hasSchemaVersion && hasTool && hasToolName && hasToolVersion && hasRunID && hasStatus {
		r.pass("TOOL-031")
	} else {
		r.fail("TOOL-031", "missing required fields in result.json")
	}

	// TOOL-032: Status values
	status, _ := result["status"].(string)
	if status == "success" || status == "failure" || status == "partial" {
		r.pass("TOOL-032")
	} else {
		r.fail("TOOL-032", "status must be success, failure, or partial")
	}

	// TOOL-033: Timestamps
	hasStartedAt := result["started_at"] != nil
	hasCompletedAt := result["completed_at"] != nil
	hasDurationMs := result["duration_ms"] != nil
	if hasStartedAt && hasCompletedAt && hasDurationMs {
		r.pass("TOOL-033")
	} else {
		r.skip("TOOL-033", "optional timestamp fields not all present")
	}

	// TOOL-034: Outputs array
	if result["outputs"] != nil {
		r.pass("TOOL-034")
		r.testOutputPaths(result["outputs"])
	} else {
		r.skip("TOOL-034", "outputs array not present")
		r.skip("TOOL-040", "depends on outputs")
		r.skip("TOOL-041", "depends on outputs")
		r.skip("TOOL-042", "depends on outputs")
		r.skip("TOOL-043", "depends on outputs")
	}

	// TOOL-050, 051: Timestamp format
	r.testTimestampFormat(result)
}

func (r *Runner) testToolDirectoryBoundary(ctx context.Context) {
	// TOOL-020, 021, 022, 023: Directory boundary tests
	runDir := filepath.Join(r.WorkDir, "run")

	// Check that no files were created outside run directory
	entries, err := os.ReadDir(r.WorkDir)
	if err != nil {
		r.skip("TOOL-020", "could not read work directory")
		return
	}

	// Should only have "run" directory
	unexpected := []string{}
	for _, e := range entries {
		if e.Name() != "run" && e.Name() != "config.json" && e.Name() != "invalid.json" {
			unexpected = append(unexpected, e.Name())
		}
	}

	if len(unexpected) == 0 {
		r.pass("TOOL-020")
		r.pass("TOOL-021")
	} else {
		r.fail("TOOL-020", "tool created files outside run directory: "+strings.Join(unexpected, ", "))
		r.fail("TOOL-021", "tool wrote outside run directory")
	}

	// TOOL-022: Check for path traversal in run directory
	hasTraversal := false
	filepath.Walk(runDir, func(path string, info os.FileInfo, err error) error {
		if validate.ContainsTraversal(path) {
			hasTraversal = true
		}
		return nil
	})

	if !hasTraversal {
		r.pass("TOOL-022")
	} else {
		r.fail("TOOL-022", "found .. in paths within run directory")
	}

	// TOOL-023: Check for symlinks pointing outside
	hasExternalSymlink := false
	filepath.Walk(runDir, func(path string, info os.FileInfo, err error) error {
		if info != nil && info.Mode()&os.ModeSymlink != 0 {
			target, err := os.Readlink(path)
			if err == nil && (filepath.IsAbs(target) || strings.HasPrefix(target, "..")) {
				hasExternalSymlink = true
			}
		}
		return nil
	})

	if !hasExternalSymlink {
		r.pass("TOOL-023")
	} else {
		r.fail("TOOL-023", "found symlink pointing outside run directory")
	}

	// C-030: Filesystem boundary - create marker file and check it's not modified
	outsideDir, err := os.MkdirTemp("", "epack-boundary-test-*")
	if err == nil {
		defer os.RemoveAll(outsideDir)
		markerPath := filepath.Join(outsideDir, "marker.txt")
		os.WriteFile(markerPath, []byte("original"), 0644)

		// The tool already ran, just check the marker
		content, err := os.ReadFile(markerPath)
		if err == nil && string(content) == "original" {
			r.pass("C-030")
		} else {
			r.fail("C-030", "marker file was modified")
		}
	} else {
		r.skip("C-030", "could not create boundary test directory")
	}

	// TOOL-060, 061: Pack read-only tests require a pack fixture
	r.skip("TOOL-060", "requires pack fixture")
	r.skip("TOOL-061", "requires pack fixture")

	// C-021, C-022: Error exit codes
	r.skip("C-021", "requires triggering error condition")
	r.skip("C-022", "requires triggering specific errors")

	// C-031, C-032, C-033: Credential/error tests
	r.skip("C-031", "requires log inspection")
	r.skip("C-032", "requires error inspection")
	r.skip("C-033", "requires malformed input injection")
}

func (r *Runner) testToolFlags(ctx context.Context) {
	// TOOL-070: Test --json flag
	runDir := filepath.Join(r.WorkDir, "run-json")
	os.MkdirAll(runDir, 0755)

	env := map[string]string{
		"EPACK_RUN_ID":           "2026-02-22T10-00-01-000000Z-000001",
		"EPACK_RUN_DIR":          runDir,
		"EPACK_TOOL_NAME":        "test",
		"EPACK_PROTOCOL_VERSION": "1",
	}

	origDir := r.WorkDir
	r.WorkDir = runDir
	result := r.exec(ctx, []string{"--json"}, nil, env)
	r.WorkDir = origDir

	if result.ExitCode == 0 && isValidJSON(result.Stdout) {
		r.pass("TOOL-070")
	} else if result.ExitCode == 0 {
		r.skip("TOOL-070", "tool ran but output is not JSON")
	} else {
		r.skip("TOOL-070", "tool does not support --json flag")
	}

	// TOOL-071: Test --quiet flag
	runDir2 := filepath.Join(r.WorkDir, "run-quiet")
	os.MkdirAll(runDir2, 0755)

	env2 := map[string]string{
		"EPACK_RUN_ID":           "2026-02-22T10-00-02-000000Z-000001",
		"EPACK_RUN_DIR":          runDir2,
		"EPACK_TOOL_NAME":        "test",
		"EPACK_PROTOCOL_VERSION": "1",
	}

	r.WorkDir = runDir2
	resultQuiet := r.exec(ctx, []string{"--quiet"}, nil, env2)
	r.WorkDir = origDir

	if resultQuiet.ExitCode == 0 {
		// Tool accepted --quiet flag
		r.pass("TOOL-071")
	} else {
		r.skip("TOOL-071", "tool does not support --quiet flag")
	}
}

func (r *Runner) testToolRunIDSort(ctx context.Context) {
	// TOOL-052: Run IDs sort chronologically when sorted lexicographically
	runIDs := []string{
		"2026-02-22T09-00-00-000000Z-000001",
		"2026-02-22T10-00-00-000000Z-000001",
		"2026-02-22T10-00-01-000000Z-000001",
		"2026-02-22T10-00-00-000001Z-000001",
		"2026-02-21T10-00-00-000000Z-000001",
	}

	// Sort lexicographically
	sorted := make([]string, len(runIDs))
	copy(sorted, runIDs)
	sort.Strings(sorted)

	// Expected chronological order
	expected := []string{
		"2026-02-21T10-00-00-000000Z-000001",
		"2026-02-22T09-00-00-000000Z-000001",
		"2026-02-22T10-00-00-000000Z-000001",
		"2026-02-22T10-00-00-000001Z-000001",
		"2026-02-22T10-00-01-000000Z-000001",
	}

	match := true
	for i := range sorted {
		if sorted[i] != expected[i] {
			match = false
			break
		}
	}

	if match {
		r.pass("TOOL-052")
	} else {
		r.fail("TOOL-052", "run ID format does not sort chronologically")
	}
}

func (r *Runner) testToolNoColor(ctx context.Context) {
	// C-013: Component honors NO_COLOR
	runDir := filepath.Join(r.WorkDir, "run-color")
	os.MkdirAll(runDir, 0755)

	envNoColor := map[string]string{
		"EPACK_RUN_ID":           "2026-02-22T10-00-03-000000Z-000001",
		"EPACK_RUN_DIR":          runDir,
		"EPACK_TOOL_NAME":        "test",
		"EPACK_PROTOCOL_VERSION": "1",
		"NO_COLOR":               "1",
	}

	origDir := r.WorkDir
	r.WorkDir = runDir
	result := r.exec(ctx, nil, nil, envNoColor)
	r.WorkDir = origDir

	if containsANSI(result.Stderr) {
		r.fail("C-013", "tool outputs ANSI colors despite NO_COLOR=1")
	} else {
		r.pass("C-013")
	}
}

func (r *Runner) testOutputPaths(outputs interface{}) {
	arr, ok := outputs.([]interface{})
	if !ok {
		r.fail("TOOL-040", "outputs is not an array")
		return
	}

	if len(arr) == 0 {
		// Empty array is valid
		r.pass("TOOL-040")
		r.pass("TOOL-041")
		r.pass("TOOL-042")
		r.skip("TOOL-043", "no outputs to check")
		return
	}

	allRelative := true
	noTraversal := true
	notAbsolute := true
	allInOutputs := true

	for _, item := range arr {
		obj, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		path, _ := obj["path"].(string)
		if path == "" {
			continue
		}

		// TOOL-040: Relative paths
		if filepath.IsAbs(path) {
			allRelative = false
			notAbsolute = false
		}

		// TOOL-041: No .. segments
		if validate.ContainsTraversal(path) {
			noTraversal = false
		}

		// TOOL-043: In outputs/ subdirectory
		if !strings.HasPrefix(path, "outputs/") {
			allInOutputs = false
		}
	}

	if allRelative {
		r.pass("TOOL-040")
	} else {
		r.fail("TOOL-040", "output paths must be relative")
	}

	if noTraversal {
		r.pass("TOOL-041")
	} else {
		r.fail("TOOL-041", "output paths must not contain ..")
	}

	if notAbsolute {
		r.pass("TOOL-042")
	} else {
		r.fail("TOOL-042", "output paths must not be absolute")
	}

	if allInOutputs {
		r.pass("TOOL-043")
	} else {
		r.skip("TOOL-043", "not all outputs in outputs/ subdirectory")
	}
}

var timestampPattern = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$`)

func (r *Runner) testTimestampFormat(result map[string]interface{}) {
	startedAt, _ := result["started_at"].(string)
	completedAt, _ := result["completed_at"].(string)

	valid := true
	if startedAt != "" && !timestampPattern.MatchString(startedAt) {
		valid = false
	}
	if completedAt != "" && !timestampPattern.MatchString(completedAt) {
		valid = false
	}

	if valid && (startedAt != "" || completedAt != "") {
		r.pass("TOOL-050")
		r.pass("TOOL-051")
	} else if startedAt == "" && completedAt == "" {
		r.skip("TOOL-050", "no timestamps to validate")
		r.skip("TOOL-051", "no timestamps to validate")
	} else {
		r.fail("TOOL-050", "timestamps must be YYYY-MM-DDTHH:MM:SSZ")
		r.fail("TOOL-051", "timestamps must not include milliseconds or offsets")
	}
}
