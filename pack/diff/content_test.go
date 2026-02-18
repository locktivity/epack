package diff

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/locktivity/epack/errors"
	"github.com/locktivity/epack/pack"
	"github.com/locktivity/epack/pack/builder"
)

func TestContent_Identical(t *testing.T) {
	p1 := createContentTestPack(t, "test/stream", map[string][]byte{
		"artifacts/a.json": []byte(`{"key": "value"}`),
	})
	defer func() { _ = p1.Close() }()

	p2 := createContentTestPack(t, "test/stream", map[string][]byte{
		"artifacts/a.json": []byte(`{"key": "value"}`),
	})
	defer func() { _ = p2.Close() }()

	result, err := Content(p1, p2, "artifacts/a.json")
	if err != nil {
		t.Fatalf("Content() error = %v", err)
	}

	if result.Status != ContentIdentical {
		t.Errorf("Status = %v, want ContentIdentical", result.Status)
	}
}

func TestContent_OnlyInPack1(t *testing.T) {
	p1 := createContentTestPack(t, "test/stream", map[string][]byte{
		"artifacts/a.json": []byte(`{}`),
	})
	defer func() { _ = p1.Close() }()

	p2 := createContentTestPack(t, "test/stream", map[string][]byte{
		"artifacts/b.json": []byte(`{}`),
	})
	defer func() { _ = p2.Close() }()

	result, err := Content(p1, p2, "artifacts/a.json")
	if err != nil {
		t.Fatalf("Content() error = %v", err)
	}

	if result.Status != ContentOnlyInPack1 {
		t.Errorf("Status = %v, want ContentOnlyInPack1", result.Status)
	}
}

func TestContent_OnlyInPack2(t *testing.T) {
	p1 := createContentTestPack(t, "test/stream", map[string][]byte{
		"artifacts/a.json": []byte(`{}`),
	})
	defer func() { _ = p1.Close() }()

	p2 := createContentTestPack(t, "test/stream", map[string][]byte{
		"artifacts/a.json": []byte(`{}`),
		"artifacts/b.json": []byte(`{}`),
	})
	defer func() { _ = p2.Close() }()

	result, err := Content(p1, p2, "artifacts/b.json")
	if err != nil {
		t.Fatalf("Content() error = %v", err)
	}

	if result.Status != ContentOnlyInPack2 {
		t.Errorf("Status = %v, want ContentOnlyInPack2", result.Status)
	}
}

func TestContent_NotFound(t *testing.T) {
	p1 := createContentTestPack(t, "test/stream", map[string][]byte{
		"artifacts/a.json": []byte(`{}`),
	})
	defer func() { _ = p1.Close() }()

	p2 := createContentTestPack(t, "test/stream", map[string][]byte{
		"artifacts/a.json": []byte(`{}`),
	})
	defer func() { _ = p2.Close() }()

	result, err := Content(p1, p2, "artifacts/nonexistent.json")
	if err != nil {
		t.Fatalf("Content() error = %v", err)
	}

	if result.Status != ContentNotFound {
		t.Errorf("Status = %v, want ContentNotFound", result.Status)
	}
}

func TestContent_JSONDiff(t *testing.T) {
	p1 := createContentTestPack(t, "test/stream", map[string][]byte{
		"artifacts/config.json": []byte(`{"name": "app", "version": "1.0"}`),
	})
	defer func() { _ = p1.Close() }()

	p2 := createContentTestPack(t, "test/stream", map[string][]byte{
		"artifacts/config.json": []byte(`{"name": "app", "version": "2.0", "new": "field"}`),
	})
	defer func() { _ = p2.Close() }()

	result, err := Content(p1, p2, "artifacts/config.json")
	if err != nil {
		t.Fatalf("Content() error = %v", err)
	}

	if result.Status != ContentDifferent {
		t.Errorf("Status = %v, want ContentDifferent", result.Status)
	}
	if !result.IsJSON {
		t.Error("IsJSON = false, want true")
	}
	if len(result.JSONChanges) == 0 {
		t.Error("JSONChanges is empty")
	}

	// Check for expected changes
	foundVersion := false
	foundNew := false
	for _, change := range result.JSONChanges {
		if change.Path == "version" && change.Type == JSONChanged {
			foundVersion = true
		}
		if change.Path == "new" && change.Type == JSONAdded {
			foundNew = true
		}
	}
	if !foundVersion {
		t.Error("Missing version change")
	}
	if !foundNew {
		t.Error("Missing new field addition")
	}
}

func TestContent_TextDiff(t *testing.T) {
	p1 := createContentTestPack(t, "test/stream", map[string][]byte{
		"artifacts/readme.txt": []byte("line 1\nline 2\nline 3"),
	})
	defer func() { _ = p1.Close() }()

	p2 := createContentTestPack(t, "test/stream", map[string][]byte{
		"artifacts/readme.txt": []byte("line 1\nmodified line 2\nline 3\nline 4"),
	})
	defer func() { _ = p2.Close() }()

	result, err := Content(p1, p2, "artifacts/readme.txt")
	if err != nil {
		t.Fatalf("Content() error = %v", err)
	}

	if result.Status != ContentDifferent {
		t.Errorf("Status = %v, want ContentDifferent", result.Status)
	}
	if result.IsJSON {
		t.Error("IsJSON = true, want false")
	}
	if len(result.TextDiff) == 0 {
		t.Error("TextDiff is empty")
	}
}

func TestComputeLineDiff(t *testing.T) {
	tests := []struct {
		name   string
		lines1 []string
		lines2 []string
		want   []LineDiff
	}{
		{
			name:   "identical",
			lines1: []string{"a", "b", "c"},
			lines2: []string{"a", "b", "c"},
			want: []LineDiff{
				{LineEqual, "a"},
				{LineEqual, "b"},
				{LineEqual, "c"},
			},
		},
		{
			name:   "addition",
			lines1: []string{"a", "c"},
			lines2: []string{"a", "b", "c"},
			want: []LineDiff{
				{LineEqual, "a"},
				{LineAdded, "b"},
				{LineEqual, "c"},
			},
		},
		{
			name:   "removal",
			lines1: []string{"a", "b", "c"},
			lines2: []string{"a", "c"},
			want: []LineDiff{
				{LineEqual, "a"},
				{LineRemoved, "b"},
				{LineEqual, "c"},
			},
		},
		{
			name:   "modification",
			lines1: []string{"a", "b", "c"},
			lines2: []string{"a", "B", "c"},
			want: []LineDiff{
				{LineEqual, "a"},
				{LineRemoved, "b"},
				{LineAdded, "B"},
				{LineEqual, "c"},
			},
		},
		{
			name:   "empty to content",
			lines1: []string{},
			lines2: []string{"a", "b"},
			want: []LineDiff{
				{LineAdded, "a"},
				{LineAdded, "b"},
			},
		},
		{
			name:   "content to empty",
			lines1: []string{"a", "b"},
			lines2: []string{},
			want: []LineDiff{
				{LineRemoved, "a"},
				{LineRemoved, "b"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ComputeLineDiff(tt.lines1, tt.lines2)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ComputeLineDiff() =\n%v\nwant\n%v", got, tt.want)
			}
		})
	}
}

func TestFormatJSONValue(t *testing.T) {
	tests := []struct {
		name string
		v    interface{}
		want string
	}{
		{"string", "hello", `"hello"`},
		{"null", nil, "null"},
		{"true", true, "true"},
		{"false", false, "false"},
		{"integer", float64(42), "42"},
		{"float", float64(3.14), "3.14"},
		{"empty array", []interface{}{}, "[]"},
		{"empty object", map[string]interface{}{}, "{}"},
		{"small array", []interface{}{"a", "b"}, `["a","b"]`},
		{"small object", map[string]interface{}{"k": "v"}, `{"k":"v"}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FormatJSONValue(tt.v)
			if got != tt.want {
				t.Errorf("FormatJSONValue(%v) = %q, want %q", tt.v, got, tt.want)
			}
		})
	}
}

// createContentTestPack creates a temporary pack for testing content diff.
func createContentTestPack(t *testing.T, stream string, artifacts map[string][]byte) *pack.Pack {
	t.Helper()

	dir := t.TempDir()
	packPath := filepath.Join(dir, "test.pack")

	b := builder.New(stream)
	for path, content := range artifacts {
		if err := b.AddBytes(path, content); err != nil {
			t.Fatalf("failed to add artifact %s: %v", path, err)
		}
	}

	if err := b.Build(packPath); err != nil {
		t.Fatalf("failed to build pack: %v", err)
	}

	p, err := pack.Open(packPath)
	if err != nil {
		t.Fatalf("failed to open pack: %v", err)
	}

	return p
}

// TestContent_IntegrityError verifies that integrity errors (digest/size mismatch)
// are reported as ContentIntegrityError, not masked as "missing".
func TestContent_IntegrityError(t *testing.T) {
	// Create a good pack for p1
	p1 := createContentTestPack(t, "test/stream", map[string][]byte{
		"artifacts/test.json": []byte(`{"good": "data"}`),
	})
	defer func() { _ = p1.Close() }()

	// Create a tampered pack for p2
	tamperedPath := createTamperedPackForDiff(t)
	p2, err := pack.Open(tamperedPath)
	if err != nil {
		t.Fatalf("failed to open tampered pack: %v", err)
	}
	defer func() { _ = p2.Close() }()

	// Diffing should detect the integrity error, NOT report as "only in pack 1"
	result, err := Content(p1, p2, "artifacts/test.json")
	if err != nil {
		t.Fatalf("Content() error = %v", err)
	}

	if result.Status != ContentIntegrityError {
		t.Errorf("Status = %v, want ContentIntegrityError (integrity failures must not be masked)", result.Status)
	}
	if result.IntegrityError == nil {
		t.Fatal("IntegrityError is nil, expected details")
	}
	if result.IntegrityError.Pack != "pack2" {
		t.Errorf("IntegrityError.Pack = %q, want \"pack2\"", result.IntegrityError.Pack)
	}
	// Code should be digest_mismatch or size_mismatch
	code := errors.Code(result.IntegrityError.Code)
	if code != errors.DigestMismatch && code != errors.SizeMismatch {
		t.Errorf("IntegrityError.Code = %q, want digest_mismatch or size_mismatch", result.IntegrityError.Code)
	}
}

// TestContent_IntegrityErrorString verifies the String() method for ContentIntegrityError.
func TestContent_IntegrityErrorString(t *testing.T) {
	if ContentIntegrityError.String() != "integrity error" {
		t.Errorf("ContentIntegrityError.String() = %q, want \"integrity error\"", ContentIntegrityError.String())
	}
}

// createTamperedPackForDiff creates a pack where the artifact content doesn't match the manifest digest.
func createTamperedPackForDiff(t *testing.T) string {
	t.Helper()

	artifactPath := "artifacts/test.json"
	fakeDigest := "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	actualContent := []byte(`MALICIOUS`)
	fakeSize := json.Number("999") // Wrong size

	// Build a manifest with fake digest/size but actual malicious content
	artifact := struct {
		Type   string       `json:"type"`
		Path   string       `json:"path"`
		Digest string       `json:"digest"`
		Size   *json.Number `json:"size,omitempty"`
	}{
		Type:   "embedded",
		Path:   artifactPath,
		Digest: fakeDigest,
		Size:   &fakeSize,
	}

	// Compute pack_digest that's internally consistent with manifest (but artifact is fake)
	canonical := artifact.Path + ":" + artifact.Digest
	h := sha256.Sum256([]byte(canonical))
	packDigest := "sha256:" + hex.EncodeToString(h[:])

	manifest := struct {
		SpecVersion string `json:"spec_version"`
		Stream      string `json:"stream"`
		GeneratedAt string `json:"generated_at"`
		PackDigest  string `json:"pack_digest"`
		Sources     []struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"sources"`
		Artifacts []struct {
			Type   string       `json:"type"`
			Path   string       `json:"path"`
			Digest string       `json:"digest"`
			Size   *json.Number `json:"size,omitempty"`
		} `json:"artifacts"`
	}{
		SpecVersion: "1.0",
		Stream:      "test-stream",
		GeneratedAt: "2024-01-15T10:30:00Z",
		PackDigest:  packDigest,
		Sources: []struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		}{{Name: "test-source", Version: "1.0.0"}},
		Artifacts: []struct {
			Type   string       `json:"type"`
			Path   string       `json:"path"`
			Digest string       `json:"digest"`
			Size   *json.Number `json:"size,omitempty"`
		}{artifact},
	}

	manifestData, _ := json.Marshal(manifest)

	var buf bytes.Buffer
	w := zip.NewWriter(&buf)

	fw, _ := w.Create("manifest.json")
	_, _ = fw.Write(manifestData)

	fw, _ = w.Create(artifactPath)
	_, _ = fw.Write(actualContent)

	_ = w.Close()

	dir := t.TempDir()
	path := filepath.Join(dir, "tampered-diff-test.zip")
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatalf("failed to write zip file: %v", err)
	}

	return path
}

// TestComputeLineDiff_LargeInputFallback verifies that large inputs fall back to simple diff
// to prevent DoS via quadratic memory explosion.
func TestComputeLineDiff_LargeInputFallback(t *testing.T) {
	// Create inputs that exceed MaxDiffLines
	lines1 := make([]string, MaxDiffLines+1)
	lines2 := make([]string, MaxDiffLines+1)
	for i := range lines1 {
		lines1[i] = "line from file 1"
		lines2[i] = "line from file 2"
	}

	// Should not panic and should return a simple diff
	result := ComputeLineDiff(lines1, lines2)

	// Should have some output (not empty)
	if len(result) == 0 {
		t.Error("expected non-empty diff result for large inputs")
	}

	// Should contain the truncation marker
	found := false
	for _, line := range result {
		if strings.Contains(line.Line, "more lines") {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected truncation marker in large diff output")
	}
}

// TestComputeLineDiff_MemoryLimitFallback verifies that inputs exceeding memory limit
// fall back to simple diff. This tests the integer overflow fix.
func TestComputeLineDiff_MemoryLimitFallback(t *testing.T) {
	// Create inputs where m*n would exceed memory limit but m and n individually
	// are under MaxDiffLines. This tests the tableSize calculation.
	// With MaxDiffMemoryBytes = 100MB and 8 bytes per cell:
	// Max cells = 100MB / 8 = 12.5M cells
	// sqrt(12.5M) ≈ 3535 lines each would be safe
	// So 5000 x 5000 = 25M cells = 200MB which exceeds limit

	n := 5000 // Under MaxDiffLines (10000) but product exceeds memory limit
	lines1 := make([]string, n)
	lines2 := make([]string, n)
	for i := range lines1 {
		lines1[i] = "a"
		lines2[i] = "b"
	}

	// Should not panic and should fall back to simple diff
	result := ComputeLineDiff(lines1, lines2)

	// Should have some output
	if len(result) == 0 {
		t.Error("expected non-empty diff result")
	}
}

// TestTableSizeCalculation verifies the integer overflow fix in table size calculation.
// On 32-bit systems, (m+1) could overflow int before conversion to int64.
func TestTableSizeCalculation(t *testing.T) {
	// This test verifies the fix by checking the formula doesn't panic
	// with edge case values. The actual fix is:
	// OLD: int64(m+1) * int64(n+1) * 8  -- (m+1) could overflow int first
	// NEW: (int64(m) + 1) * (int64(n) + 1) * 8  -- cast before arithmetic

	// Test with values near the line limit
	lines1 := make([]string, MaxDiffLines)
	lines2 := make([]string, 100)
	for i := range lines1 {
		lines1[i] = "line"
	}
	for i := range lines2 {
		lines2[i] = "line"
	}

	// Should not panic
	result := ComputeLineDiff(lines1, lines2)
	if result == nil {
		t.Error("expected non-nil result")
	}
}

// Ensure strconv is used (for compile check)
var _ = strconv.Itoa(0)

// TestJsonEqual_NaNHandling verifies that jsonEqual correctly handles NaN values
// which cannot be JSON marshaled.
func TestJsonEqual_NaNHandling(t *testing.T) {
	nan := math.NaN()

	// NaN should not equal itself in IEEE754, and our function should handle this
	// by falling back to reflect.DeepEqual (which returns false for NaN != NaN)
	if jsonEqual(nan, nan) {
		// Note: math.NaN() != math.NaN() is true in Go, so reflect.DeepEqual returns false
		t.Log("NaN equality behavior noted: reflect.DeepEqual(NaN, NaN) = false")
	}

	// NaN should definitely not equal a regular number
	if jsonEqual(nan, 42.0) {
		t.Error("jsonEqual(NaN, 42.0) = true, want false")
	}

	// Regular values should still work
	if !jsonEqual(42.0, 42.0) {
		t.Error("jsonEqual(42.0, 42.0) = false, want true")
	}
}

// TestJsonEqual_InfHandling verifies that jsonEqual correctly handles Inf values.
func TestJsonEqual_InfHandling(t *testing.T) {
	posInf := math.Inf(1)
	negInf := math.Inf(-1)

	// +Inf should not equal -Inf
	if jsonEqual(posInf, negInf) {
		t.Error("jsonEqual(+Inf, -Inf) = true, want false")
	}

	// +Inf should not equal a regular number
	if jsonEqual(posInf, 1e308) {
		t.Error("jsonEqual(+Inf, 1e308) = true, want false")
	}

	// +Inf should equal itself (reflect.DeepEqual returns true for Inf == Inf)
	if !jsonEqual(posInf, posInf) {
		t.Error("jsonEqual(+Inf, +Inf) = false, want true")
	}
}

// TestFormatJSONValue_SpecialFloats verifies that FormatJSONValue handles
// special float values (NaN, +Inf, -Inf) that cannot be JSON marshaled.
func TestFormatJSONValue_SpecialFloats(t *testing.T) {
	tests := []struct {
		name  string
		value float64
		want  string
	}{
		{"NaN", math.NaN(), "NaN"},
		{"+Inf", math.Inf(1), "+Inf"},
		{"-Inf", math.Inf(-1), "-Inf"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FormatJSONValue(tt.value)
			if got != tt.want {
				t.Errorf("FormatJSONValue(%v) = %q, want %q", tt.value, got, tt.want)
			}
		})
	}
}

// TestStrictJSONUnmarshal_TrailingData verifies that strictJSONUnmarshal correctly
// rejects JSON with trailing data (complete extra values or incomplete data).
func TestStrictJSONUnmarshal_TrailingData(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool // true = valid JSON, false = should be rejected
	}{
		// Valid cases
		{"empty object", "{}", true},
		{"simple object", `{"key":"value"}`, true},
		{"object with whitespace suffix", "{}  \n\t", true},
		{"array", `[1,2,3]`, true},
		{"string", `"hello"`, true},
		{"number", `42`, true},
		{"null", `null`, true},

		// Invalid: trailing complete values (the bug case)
		{"two objects", "{}{}", false},
		{"object then array", "{}[]", false},
		{"two arrays", "[][]", false},
		{"object space object", "{} {}", false},

		// Invalid: trailing incomplete data
		{"object then open brace", "{}{", false},
		{"object then garbage", "{}garbage", false},
		{"object then number start", "{}1", false},

		// Invalid: malformed JSON
		{"unclosed object", "{", false},
		{"invalid syntax", "{key}", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var v interface{}
			got := strictJSONUnmarshal([]byte(tt.input), &v)
			if got != tt.want {
				t.Errorf("strictJSONUnmarshal(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

// TestStrictJSONUnmarshal_NumberPrecision verifies that strictJSONUnmarshal
// preserves numeric precision for large integers (> 2^53).
func TestStrictJSONUnmarshal_NumberPrecision(t *testing.T) {
	// Two integers that differ but would be equal if converted to float64
	// 2^53 = 9007199254740992, 2^53+1 = 9007199254740993
	// These are indistinguishable as float64
	json1 := `{"n": 9007199254740992}`
	json2 := `{"n": 9007199254740993}`

	var v1, v2 interface{}
	if !strictJSONUnmarshal([]byte(json1), &v1) {
		t.Fatal("failed to parse json1")
	}
	if !strictJSONUnmarshal([]byte(json2), &v2) {
		t.Fatal("failed to parse json2")
	}

	// The values should NOT be equal (they are distinct large integers)
	if jsonEqual(v1, v2) {
		t.Error("jsonEqual returned true for distinct large integers; precision was lost")
	}

	// Extract the numbers and verify they preserved their exact values
	m1 := v1.(map[string]interface{})
	m2 := v2.(map[string]interface{})

	n1, ok1 := m1["n"].(json.Number)
	n2, ok2 := m2["n"].(json.Number)

	if !ok1 || !ok2 {
		t.Fatalf("numbers were not preserved as json.Number: v1=%T, v2=%T", m1["n"], m2["n"])
	}

	if string(n1) == string(n2) {
		t.Errorf("numbers should be different: %s vs %s", n1, n2)
	}
}

// TestFormatJSONValue_JsonNumber verifies that FormatJSONValue preserves
// the exact text representation of json.Number.
func TestFormatJSONValue_JsonNumber(t *testing.T) {
	tests := []struct {
		name   string
		number json.Number
		want   string
	}{
		{"large integer", json.Number("9007199254740993"), "9007199254740993"},
		{"small integer", json.Number("42"), "42"},
		{"float", json.Number("3.14159"), "3.14159"},
		{"negative", json.Number("-123"), "-123"},
		{"scientific", json.Number("1e10"), "1e10"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FormatJSONValue(tt.number)
			if got != tt.want {
				t.Errorf("FormatJSONValue(%v) = %q, want %q", tt.number, got, tt.want)
			}
		})
	}
}

// TestContent_LargeIntegerDiff verifies that diffs correctly detect changes
// in large integers that would be indistinguishable as float64.
func TestContent_LargeIntegerDiff(t *testing.T) {
	// Two JSON files with different large integers
	p1 := createContentTestPack(t, "test/stream", map[string][]byte{
		"artifacts/data.json": []byte(`{"count": 9007199254740992}`),
	})
	defer func() { _ = p1.Close() }()

	p2 := createContentTestPack(t, "test/stream", map[string][]byte{
		"artifacts/data.json": []byte(`{"count": 9007199254740993}`),
	})
	defer func() { _ = p2.Close() }()

	result, err := Content(p1, p2, "artifacts/data.json")
	if err != nil {
		t.Fatalf("Content() error = %v", err)
	}

	// Should detect as different, not identical
	if result.Status != ContentDifferent {
		t.Errorf("Status = %v, want ContentDifferent (large integers should be distinguished)", result.Status)
	}

	// Should have a JSON change for the count field
	if !result.IsJSON {
		t.Fatal("IsJSON = false, want true")
	}
	if len(result.JSONChanges) == 0 {
		t.Error("JSONChanges is empty, expected a change for 'count'")
	}

	foundCountChange := false
	for _, change := range result.JSONChanges {
		if change.Path == "count" && change.Type == JSONChanged {
			foundCountChange = true
			// Verify the values are preserved as json.Number
			_, ok1 := change.OldValue.(json.Number)
			_, ok2 := change.NewValue.(json.Number)
			if !ok1 || !ok2 {
				t.Errorf("large integer values not preserved as json.Number: old=%T, new=%T",
					change.OldValue, change.NewValue)
			}
		}
	}
	if !foundCountChange {
		t.Error("missing change for 'count' field")
	}
}
