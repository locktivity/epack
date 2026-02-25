package toolprotocol

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/locktivity/epack/internal/componenttypes"
)

// TestRunIDFormat verifies run IDs match the spec format.
// Format: YYYY-MM-DDTHH-MM-SS-uuuuuuZ-NNNNNN
func TestRunIDFormat(t *testing.T) {
	runID := GenerateRunID()

	// Should be exactly 35 characters: 27 for timestamp + 1 hyphen + 6 for counter
	if len(runID) != 34 {
		t.Errorf("run ID length = %d, want 34", len(runID))
	}

	// Should match format: YYYY-MM-DDTHH-MM-SS-uuuuuuZ-NNNNNN
	parts := strings.Split(runID, "T")
	if len(parts) != 2 {
		t.Errorf("run ID should contain exactly one 'T': %s", runID)
	}

	// Date part should be YYYY-MM-DD
	if len(parts[0]) != 10 {
		t.Errorf("date part length = %d, want 10: %s", len(parts[0]), parts[0])
	}

	// Verify no colons (uses dashes for filesystem safety)
	if strings.Contains(runID, ":") {
		t.Errorf("run ID should not contain colons: %s", runID)
	}

	// Verify ends with Z-NNNNNN
	if !strings.Contains(runID, "Z-") {
		t.Errorf("run ID should contain 'Z-': %s", runID)
	}
}

// TestRunIDMonotonic verifies run IDs are monotonic within a process.
func TestRunIDMonotonic(t *testing.T) {
	var ids []string
	for i := 0; i < 10; i++ {
		ids = append(ids, GenerateRunID())
	}

	// All IDs generated in same microsecond should have incrementing counters
	for i := 1; i < len(ids); i++ {
		if ids[i] <= ids[i-1] {
			t.Errorf("IDs not monotonic: %s <= %s", ids[i], ids[i-1])
		}
	}
}

// TestTimestampFormat verifies timestamps match the normative format.
// Exactly 20 characters: YYYY-MM-DDTHH:MM:SSZ
func TestTimestampFormat(t *testing.T) {
	now := time.Now()
	ts := FormatTimestamp(now)

	if len(ts) != 20 {
		t.Errorf("timestamp length = %d, want 20: %s", len(ts), ts)
	}

	if !strings.HasSuffix(ts, "Z") {
		t.Errorf("timestamp should end with Z: %s", ts)
	}

	// Should be parseable
	parsed, err := ParseTimestamp(ts)
	if err != nil {
		t.Errorf("failed to parse timestamp: %v", err)
	}

	// Should round-trip (within second precision)
	if parsed.Unix() != now.UTC().Truncate(time.Second).Unix() {
		t.Errorf("timestamp did not round-trip: got %v, want %v", parsed.Unix(), now.UTC().Unix())
	}
}

// TestTimestampNoFractionalSeconds verifies no fractional seconds.
func TestTimestampNoFractionalSeconds(t *testing.T) {
	ts := FormatTimestamp(time.Now())

	// Count dots - should be zero (no fractional seconds)
	if strings.Count(ts, ".") > 0 {
		t.Errorf("timestamp should not have fractional seconds: %s", ts)
	}
}

// TestCreateRunDirCollision verifies run directory creation handles collisions.
func TestCreateRunDirCollision(t *testing.T) {
	tmpDir := t.TempDir()

	// Create first run dir
	runID1, runDir1, err := CreateRunDir(tmpDir, "test-tool", true)
	if err != nil {
		t.Fatalf("first CreateRunDir failed: %v", err)
	}

	// Verify structure: baseDir/tools/<tool>/<run-id>/
	expectedParent := filepath.Join(tmpDir, "tools", "test-tool")
	if !strings.HasPrefix(runDir1, expectedParent) {
		t.Errorf("runDir1 = %s, want prefix %s", runDir1, expectedParent)
	}

	if filepath.Base(runDir1) != runID1 {
		t.Errorf("runDir basename = %s, want %s", filepath.Base(runDir1), runID1)
	}

	// Create second run dir - should get different ID
	runID2, runDir2, err := CreateRunDir(tmpDir, "test-tool", true)
	if err != nil {
		t.Fatalf("second CreateRunDir failed: %v", err)
	}

	if runID1 == runID2 {
		t.Errorf("run IDs should be different: %s == %s", runID1, runID2)
	}

	if runDir1 == runDir2 {
		t.Errorf("run directories should be different: %s == %s", runDir1, runDir2)
	}
}

// TestCreateRunDirPackless verifies packless run directory structure.
func TestCreateRunDirPackless(t *testing.T) {
	tmpDir := t.TempDir()

	_, runDir, err := CreateRunDir(tmpDir, "test-tool", false)
	if err != nil {
		t.Fatalf("CreateRunDir failed: %v", err)
	}

	// For packless runs: baseDir/runs/<tool>/<run-id>/
	expectedParent := filepath.Join(tmpDir, "runs", "test-tool")
	if !strings.HasPrefix(runDir, expectedParent) {
		t.Errorf("runDir = %s, want prefix %s", runDir, expectedParent)
	}
}

// TestValidateOutputPath tests output path validation rules.
func TestValidateOutputPath(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a valid output file
	validPath := filepath.Join(tmpDir, "output.json")
	if err := os.WriteFile(validPath, []byte("{}"), 0600); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	tests := []struct {
		name      string
		path      string
		setup     func() // Optional setup
		wantErr   bool
		errSubstr string
	}{
		{
			name:    "valid relative path",
			path:    "output.json",
			wantErr: false,
		},
		{
			name:      "absolute path rejected",
			path:      "/etc/passwd",
			wantErr:   true,
			errSubstr: "must be relative",
		},
		{
			name:      "parent traversal rejected",
			path:      "../escape.txt",
			wantErr:   true,
			errSubstr: "escapes run directory",
		},
		{
			name:      "hidden parent traversal rejected",
			path:      "foo/../../escape.txt",
			wantErr:   true,
			errSubstr: "escapes run directory",
		},
		{
			name:      "dot-dot rejected",
			path:      "..",
			wantErr:   true,
			errSubstr: "escapes run directory",
		},
		{
			name: "symlink rejected",
			path: "link.txt",
			setup: func() {
				_ = os.Symlink("/etc/passwd", filepath.Join(tmpDir, "link.txt"))
			},
			wantErr:   true,
			errSubstr: "symlink",
		},
		{
			name:      "nonexistent file rejected",
			path:      "does-not-exist.txt",
			wantErr:   true,
			errSubstr: "does not exist",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.setup != nil {
				tc.setup()
			}

			err := ValidateOutputPath(tmpDir, tc.path)
			if tc.wantErr {
				if err == nil {
					t.Errorf("expected error containing %q, got nil", tc.errSubstr)
				} else if !strings.Contains(err.Error(), tc.errSubstr) {
					t.Errorf("error = %v, want substring %q", err, tc.errSubstr)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

// TestValidateDigest tests digest format validation.
func TestValidateDigest(t *testing.T) {
	tests := []struct {
		digest  string
		wantErr bool
	}{
		{"sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", false},
		{"sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", false},
		{"", true},        // empty
		{"sha256:", true}, // no hash
		{"md5:d41d8cd98f00b204e9800998ecf8427e", true}, // wrong algorithm
		{"sha256:UPPER", true},                         // uppercase
		{"sha256:short", true},                         // too short
		{"sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855extra", true}, // too long
	}

	for _, tc := range tests {
		t.Run(tc.digest, func(t *testing.T) {
			err := ValidateDigest(tc.digest)
			if tc.wantErr && err == nil {
				t.Errorf("expected error for digest %q", tc.digest)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("unexpected error for digest %q: %v", tc.digest, err)
			}
		})
	}
}

// TestComputeStatus tests status computation rules.
func TestComputeStatus(t *testing.T) {
	tests := []struct {
		name     string
		errors   []ErrorEntry
		warnings []ErrorEntry
		exitCode int
		want     string
	}{
		{
			name:     "success - no errors, no warnings, exit 0",
			errors:   nil,
			warnings: nil,
			exitCode: 0,
			want:     StatusSuccess,
		},
		{
			name:     "failure - has errors",
			errors:   []ErrorEntry{{Code: "ERR", Message: "error"}},
			warnings: nil,
			exitCode: 0,
			want:     StatusFailure,
		},
		{
			name:     "failure - non-zero exit",
			errors:   nil,
			warnings: nil,
			exitCode: 1,
			want:     StatusFailure,
		},
		{
			name:     "partial - only warnings",
			errors:   nil,
			warnings: []ErrorEntry{{Code: "WARN", Message: "warning"}},
			exitCode: 0,
			want:     StatusPartial,
		},
		{
			name:     "failure - errors override warnings",
			errors:   []ErrorEntry{{Code: "ERR", Message: "error"}},
			warnings: []ErrorEntry{{Code: "WARN", Message: "warning"}},
			exitCode: 0,
			want:     StatusFailure,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ComputeStatus(tc.errors, tc.warnings, tc.exitCode)
			if got != tc.want {
				t.Errorf("ComputeStatus() = %s, want %s", got, tc.want)
			}
		})
	}
}

// TestNormalizeExitCode tests exit code normalization.
func TestNormalizeExitCode(t *testing.T) {
	tests := []struct {
		toolCode    int
		wantWrapper int
		wantTool    int
	}{
		{0, 0, 0},
		{1, 1, 1},
		{9, 9, 9},
		{10, 1, 10}, // 10+ normalized to 1
		{127, 1, 127},
		{255, 1, 255},
	}

	for _, tc := range tests {
		t.Run("", func(t *testing.T) {
			wrapperCode, toolCodePtr := NormalizeExitCode(tc.toolCode)
			if wrapperCode != tc.wantWrapper {
				t.Errorf("wrapper code = %d, want %d", wrapperCode, tc.wantWrapper)
			}
			if toolCodePtr == nil {
				t.Error("toolCodePtr is nil")
			} else if *toolCodePtr != tc.wantTool {
				t.Errorf("tool code = %d, want %d", *toolCodePtr, tc.wantTool)
			}
		})
	}
}

// TestWriteResultAtomic tests atomic result writing.
func TestWriteResultAtomic(t *testing.T) {
	tmpDir := t.TempDir()

	result := &Result{
		SchemaVersion: CurrentSchemaVersion,
		Wrapper:       NewWrapperInfo("1.0.0"),
		Tool:          NewToolInfo("test-tool", "1.0.0", CurrentProtocolVersion),
		RunID:         "2025-01-15T10-30-00-000000Z-000000",
		StartedAt:     "2025-01-15T10:30:00Z",
		CompletedAt:   "2025-01-15T10:30:01Z",
		DurationMs:    1000,
		ExitCode:      0,
		Status:        StatusSuccess,
		Inputs:        map[string]any{},
		Outputs:       []OutputEntry{},
		Errors:        []ErrorEntry{},
		Warnings:      []ErrorEntry{},
	}

	err := WriteResultAtomic(tmpDir, result)
	if err != nil {
		t.Fatalf("WriteResultAtomic failed: %v", err)
	}

	// Verify file exists
	resultPath := filepath.Join(tmpDir, "result.json")
	data, err := os.ReadFile(resultPath)
	if err != nil {
		t.Fatalf("failed to read result.json: %v", err)
	}

	// Verify parseable
	var parsed Result
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("failed to parse result.json: %v", err)
	}

	// Verify key fields
	if parsed.SchemaVersion != CurrentSchemaVersion {
		t.Errorf("schema_version = %d, want %d", parsed.SchemaVersion, CurrentSchemaVersion)
	}
	if parsed.Status != StatusSuccess {
		t.Errorf("status = %s, want %s", parsed.Status, StatusSuccess)
	}

	// Verify no temp file left behind
	tmpPath := filepath.Join(tmpDir, "result.json.tmp")
	if _, err := os.Stat(tmpPath); !os.IsNotExist(err) {
		t.Errorf("temp file should be cleaned up: %s", tmpPath)
	}
}

// TestValidateResult tests result validation.
func TestValidateResult(t *testing.T) {
	validResult := &Result{
		SchemaVersion: CurrentSchemaVersion,
		Wrapper:       NewWrapperInfo("1.0.0"),
		Tool:          NewToolInfo("test", "1.0.0", 1),
		RunID:         "test-id",
		StartedAt:     "2025-01-15T10:30:00Z",
		CompletedAt:   "2025-01-15T10:30:01Z",
		Status:        StatusSuccess,
		Inputs:        map[string]any{},
		Outputs:       []OutputEntry{},
		Errors:        []ErrorEntry{},
		Warnings:      []ErrorEntry{},
	}

	if err := ValidateResult(validResult); err != nil {
		t.Errorf("valid result should pass validation: %v", err)
	}

	// Test missing fields
	tests := []struct {
		name   string
		modify func(*Result)
	}{
		{"missing schema_version", func(r *Result) { r.SchemaVersion = 0 }},
		{"missing wrapper.name", func(r *Result) { r.Wrapper.Name = "" }},
		{"missing tool.name", func(r *Result) { r.Tool.Name = "" }},
		{"missing run_id", func(r *Result) { r.RunID = "" }},
		{"missing started_at", func(r *Result) { r.StartedAt = "" }},
		{"missing completed_at", func(r *Result) { r.CompletedAt = "" }},
		{"missing status", func(r *Result) { r.Status = "" }},
		{"invalid status", func(r *Result) { r.Status = "invalid" }},
		{"missing inputs", func(r *Result) { r.Inputs = nil }},
		{"missing outputs", func(r *Result) { r.Outputs = nil }},
		{"missing errors", func(r *Result) { r.Errors = nil }},
		{"missing warnings", func(r *Result) { r.Warnings = nil }},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := &Result{
				SchemaVersion: CurrentSchemaVersion,
				Wrapper:       NewWrapperInfo("1.0.0"),
				Tool:          NewToolInfo("test", "1.0.0", 1),
				RunID:         "test-id",
				StartedAt:     "2025-01-15T10:30:00Z",
				CompletedAt:   "2025-01-15T10:30:01Z",
				Status:        StatusSuccess,
				Inputs:        map[string]any{},
				Outputs:       []OutputEntry{},
				Errors:        []ErrorEntry{},
				Warnings:      []ErrorEntry{},
			}
			tc.modify(r)
			if err := ValidateResult(r); err == nil {
				t.Errorf("expected validation error for %s", tc.name)
			}
		})
	}
}

// TestForwardCompatibility verifies unknown fields are preserved.
func TestForwardCompatibility(t *testing.T) {
	// JSON with unknown field
	jsonWithExtra := `{
		"schema_version": 1,
		"wrapper": {"name": "epack", "version": "1.0.0"},
		"tool": {"name": "test", "version": "1.0.0", "protocol_version": 1},
		"run_id": "test-id",
		"started_at": "2025-01-15T10:30:00Z",
		"completed_at": "2025-01-15T10:30:01Z",
		"duration_ms": 1000,
		"exit_code": 0,
		"tool_exit_code": 0,
		"status": "success",
		"inputs": {},
		"outputs": [],
		"errors": [],
		"warnings": [],
		"future_field": "should be ignored"
	}`

	var result Result
	err := json.Unmarshal([]byte(jsonWithExtra), &result)
	if err != nil {
		t.Fatalf("failed to unmarshal JSON with unknown field: %v", err)
	}

	// Should parse successfully despite unknown field
	if result.SchemaVersion != 1 {
		t.Errorf("schema_version = %d, want 1", result.SchemaVersion)
	}
}

// TestValidateResult_InputsType tests that inputs must be a JSON object, not a primitive.
func TestValidateResult_InputsType(t *testing.T) {
	baseResult := func() *Result {
		return &Result{
			SchemaVersion: CurrentSchemaVersion,
			Wrapper:       NewWrapperInfo("1.0.0"),
			Tool:          NewToolInfo("test", "1.0.0", 1),
			RunID:         "test-id",
			StartedAt:     "2025-01-15T10:30:00Z",
			CompletedAt:   "2025-01-15T10:30:01Z",
			Status:        StatusSuccess,
			Outputs:       []OutputEntry{},
			Errors:        []ErrorEntry{},
			Warnings:      []ErrorEntry{},
		}
	}

	tests := []struct {
		name    string
		inputs  any
		wantErr bool
	}{
		{
			name:    "valid empty object",
			inputs:  map[string]interface{}{},
			wantErr: false,
		},
		{
			name:    "valid object with keys",
			inputs:  map[string]interface{}{"key": "value"},
			wantErr: false,
		},
		{
			name:    "invalid string",
			inputs:  "not an object",
			wantErr: true,
		},
		{
			name:    "invalid number",
			inputs:  42,
			wantErr: true,
		},
		{
			name:    "invalid array",
			inputs:  []interface{}{"a", "b"},
			wantErr: true,
		},
		{
			name:    "invalid bool",
			inputs:  true,
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := baseResult()
			r.Inputs = tc.inputs
			err := ValidateResult(r)
			if tc.wantErr {
				if err == nil {
					t.Errorf("expected error for inputs type %T", tc.inputs)
				} else if !strings.Contains(err.Error(), "must be a JSON object") {
					t.Errorf("expected 'must be a JSON object' error, got: %v", err)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

// TestExitCodeConstants verifies exit code constants are in correct ranges.
func TestExitCodeConstants(t *testing.T) {
	// Wrapper exit codes should be in 10-19 range
	wrapperCodes := []int{
		componenttypes.ExitComponentNotFound,
		componenttypes.ExitVerifyFailed,
		componenttypes.ExitPackVerifyFailed,
		componenttypes.ExitLockfileMissing,
		componenttypes.ExitRunDirFailed,
		componenttypes.ExitConfigFailed,
		componenttypes.ExitPackRequired,
		componenttypes.ExitDependencyMissing,
	}

	for _, code := range wrapperCodes {
		if code < 10 || code > 19 {
			t.Errorf("wrapper exit code %d not in range 10-19", code)
		}
	}
}
