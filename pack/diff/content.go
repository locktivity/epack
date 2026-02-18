package diff

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"sort"

	"github.com/locktivity/epack/errors"
	"github.com/locktivity/epack/internal/jsonutil"
	"github.com/locktivity/epack/pack"
)

// ContentStatus indicates the comparison status of an artifact.
type ContentStatus int

// JSONChangeType indicates the type of JSON change.
type JSONChangeType int

// LineDiffType indicates the type of line difference.
type LineDiffType int

const (
	// ContentIdentical means both artifacts have the same content.
	ContentIdentical ContentStatus = iota
	// ContentDifferent means the artifacts exist in both packs but have different content.
	ContentDifferent
	// ContentOnlyInPack1 means the artifact only exists in pack 1.
	ContentOnlyInPack1
	// ContentOnlyInPack2 means the artifact only exists in pack 2.
	ContentOnlyInPack2
	// ContentNotFound means the artifact doesn't exist in either pack.
	ContentNotFound
	// ContentIntegrityError means reading the artifact failed due to integrity check
	// (digest mismatch, size mismatch). This is a SECURITY-CRITICAL status that
	// indicates the pack may have been tampered with.
	ContentIntegrityError

	// JSON change types
	JSONAdded JSONChangeType = iota
	JSONRemoved
	JSONChanged

	// Line diff types
	LineEqual LineDiffType = iota
	LineAdded
	LineRemoved
)

// String returns a human-readable status description.
func (s ContentStatus) String() string {
	switch s {
	case ContentIdentical:
		return "identical"
	case ContentDifferent:
		return "different"
	case ContentOnlyInPack1:
		return "only in pack 1"
	case ContentOnlyInPack2:
		return "only in pack 2"
	case ContentNotFound:
		return "not found"
	case ContentIntegrityError:
		return "integrity error"
	default:
		return "unknown"
	}
}

// ContentResult contains the result of comparing a specific artifact's content.
type ContentResult struct {
	Status ContentStatus

	// IsJSON indicates whether both artifacts were valid JSON.
	IsJSON bool

	// JSONChanges contains the structured diff for JSON content.
	// Only populated when IsJSON is true and Status is ContentDifferent.
	JSONChanges []JSONChange

	// TextDiff contains the line-based diff for text content.
	// Only populated when IsJSON is false and Status is ContentDifferent.
	TextDiff []LineDiff

	// IntegrityError contains details about the integrity failure.
	// Only populated when Status is ContentIntegrityError.
	// SECURITY: This indicates potential pack tampering - do not ignore.
	IntegrityError *IntegrityErrorInfo
}

// IntegrityErrorInfo contains details about an integrity verification failure.
type IntegrityErrorInfo struct {
	// Pack indicates which pack had the integrity error ("pack1" or "pack2" or "both")
	Pack string
	// Code is the error code (e.g., "digest_mismatch", "size_mismatch")
	Code string
	// Message is the error message
	Message string
}

// String returns a human-readable change type.
func (t JSONChangeType) String() string {
	switch t {
	case JSONAdded:
		return "added"
	case JSONRemoved:
		return "removed"
	case JSONChanged:
		return "changed"
	default:
		return "unknown"
	}
}

// JSONChange represents a single change in JSON content.
type JSONChange struct {
	Type     JSONChangeType
	Path     string      // JSON path (e.g., "root.nested.key" or "[0].field")
	OldValue interface{} // nil for added
	NewValue interface{} // nil for removed
}

// LineDiff represents a single line in a text diff.
type LineDiff struct {
	Type LineDiffType
	Line string
}

// Content compares a specific artifact's content between two packs.
// SECURITY: If either pack has an integrity error (digest/size mismatch),
// this returns ContentIntegrityError instead of masking it as "missing".
func Content(p1, p2 *pack.Pack, artifactPath string) (*ContentResult, error) {
	data1, err1 := p1.ReadArtifact(artifactPath)
	data2, err2 := p2.ReadArtifact(artifactPath)

	// SECURITY: Check for integrity errors FIRST before treating as "missing".
	// Integrity errors (digest_mismatch, size_mismatch) indicate potential tampering
	// and must NOT be masked as "not found" or "only in other pack".
	if err1 != nil && isIntegrityError(err1) {
		return &ContentResult{
			Status: ContentIntegrityError,
			IntegrityError: &IntegrityErrorInfo{
				Pack:    "pack1",
				Code:    string(errors.CodeOf(err1)),
				Message: err1.Error(),
			},
		}, nil
	}
	if err2 != nil && isIntegrityError(err2) {
		return &ContentResult{
			Status: ContentIntegrityError,
			IntegrityError: &IntegrityErrorInfo{
				Pack:    "pack2",
				Code:    string(errors.CodeOf(err2)),
				Message: err2.Error(),
			},
		}, nil
	}

	// Handle cases where artifact doesn't exist (non-integrity errors)
	if err1 != nil && err2 != nil {
		return &ContentResult{Status: ContentNotFound}, nil
	}
	if err1 != nil {
		return &ContentResult{Status: ContentOnlyInPack2}, nil
	}
	if err2 != nil {
		return &ContentResult{Status: ContentOnlyInPack1}, nil
	}

	// Check if contents are identical
	if bytes.Equal(data1, data2) {
		return &ContentResult{Status: ContentIdentical}, nil
	}

	// Try to parse as JSON for structured diff
	// SECURITY: Use strict JSON decoding with duplicate key validation
	// to prevent ambiguous content comparisons.
	var json1, json2 interface{}
	isJSON1 := strictJSONUnmarshal(data1, &json1)
	isJSON2 := strictJSONUnmarshal(data2, &json2)

	if isJSON1 && isJSON2 {
		changes := computeJSONDiff(json1, json2, "")
		return &ContentResult{
			Status:      ContentDifferent,
			IsJSON:      true,
			JSONChanges: changes,
		}, nil
	}

	// Text diff
	lines1 := splitLines(string(data1))
	lines2 := splitLines(string(data2))
	textDiff := ComputeLineDiff(lines1, lines2)

	return &ContentResult{
		Status:   ContentDifferent,
		IsJSON:   false,
		TextDiff: textDiff,
	}, nil
}

// computeJSONDiff recursively computes differences between two JSON values.
func computeJSONDiff(v1, v2 interface{}, path string) []JSONChange {
	var changes []JSONChange

	switch val1 := v1.(type) {
	case map[string]interface{}:
		val2, ok := v2.(map[string]interface{})
		if !ok {
			// Type changed
			changes = append(changes, JSONChange{
				Type:     JSONChanged,
				Path:     pathOrRoot(path),
				OldValue: v1,
				NewValue: v2,
			})
			return changes
		}

		// Collect all keys
		keys := make(map[string]bool)
		for k := range val1 {
			keys[k] = true
		}
		for k := range val2 {
			keys[k] = true
		}

		// Sort keys for deterministic output
		sortedKeys := make([]string, 0, len(keys))
		for k := range keys {
			sortedKeys = append(sortedKeys, k)
		}
		sort.Strings(sortedKeys)

		for _, key := range sortedKeys {
			keyPath := appendPath(path, key)
			v1Val, in1 := val1[key]
			v2Val, in2 := val2[key]

			if !in1 {
				// Added
				changes = append(changes, JSONChange{
					Type:     JSONAdded,
					Path:     keyPath,
					NewValue: v2Val,
				})
			} else if !in2 {
				// Removed
				changes = append(changes, JSONChange{
					Type:     JSONRemoved,
					Path:     keyPath,
					OldValue: v1Val,
				})
			} else if !jsonEqual(v1Val, v2Val) {
				// Changed - recurse for nested objects/arrays
				_, isObj1 := v1Val.(map[string]interface{})
				_, isObj2 := v2Val.(map[string]interface{})
				_, isArr1 := v1Val.([]interface{})
				_, isArr2 := v2Val.([]interface{})

				if (isObj1 && isObj2) || (isArr1 && isArr2) {
					changes = append(changes, computeJSONDiff(v1Val, v2Val, keyPath)...)
				} else {
					changes = append(changes, JSONChange{
						Type:     JSONChanged,
						Path:     keyPath,
						OldValue: v1Val,
						NewValue: v2Val,
					})
				}
			}
		}

	case []interface{}:
		val2, ok := v2.([]interface{})
		if !ok {
			changes = append(changes, JSONChange{
				Type:     JSONChanged,
				Path:     pathOrRoot(path),
				OldValue: v1,
				NewValue: v2,
			})
			return changes
		}

		// For arrays, show element-by-element comparison
		maxLen := len(val1)
		if len(val2) > maxLen {
			maxLen = len(val2)
		}

		for i := 0; i < maxLen; i++ {
			indexPath := fmt.Sprintf("%s[%d]", path, i)
			if i >= len(val1) {
				changes = append(changes, JSONChange{
					Type:     JSONAdded,
					Path:     indexPath,
					NewValue: val2[i],
				})
			} else if i >= len(val2) {
				changes = append(changes, JSONChange{
					Type:     JSONRemoved,
					Path:     indexPath,
					OldValue: val1[i],
				})
			} else if !jsonEqual(val1[i], val2[i]) {
				// Recurse for nested structures
				_, isObj1 := val1[i].(map[string]interface{})
				_, isObj2 := val2[i].(map[string]interface{})
				_, isArr1 := val1[i].([]interface{})
				_, isArr2 := val2[i].([]interface{})

				if (isObj1 && isObj2) || (isArr1 && isArr2) {
					changes = append(changes, computeJSONDiff(val1[i], val2[i], indexPath)...)
				} else {
					changes = append(changes, JSONChange{
						Type:     JSONChanged,
						Path:     indexPath,
						OldValue: val1[i],
						NewValue: val2[i],
					})
				}
			}
		}

	default:
		// Primitive values
		if !jsonEqual(v1, v2) {
			changes = append(changes, JSONChange{
				Type:     JSONChanged,
				Path:     pathOrRoot(path),
				OldValue: v1,
				NewValue: v2,
			})
		}
	}

	return changes
}

// MaxDiffLines is the maximum number of lines supported for text diff.
// Prevents quadratic memory/time DoS attacks via large inputs.
// For larger files, use external diff tools.
const MaxDiffLines = 10000

// MaxDiffMemoryBytes is the maximum memory allowed for LCS table (100 MB).
const MaxDiffMemoryBytes = 100 * 1024 * 1024

// ErrDiffTooLarge is returned when input exceeds diff size limits.
type ErrDiffTooLarge struct {
	Lines1, Lines2 int
	Limit          int
}

func (e ErrDiffTooLarge) Error() string {
	return fmt.Sprintf("diff input too large: %d x %d lines exceeds limit of %d lines per input", e.Lines1, e.Lines2, e.Limit)
}

// ComputeLineDiff computes a diff between two slices of lines using LCS.
// Returns an error if input is too large to prevent DoS attacks.
// For inputs exceeding MaxDiffLines, returns ErrDiffTooLarge.
func ComputeLineDiff(lines1, lines2 []string) []LineDiff {
	m, n := len(lines1), len(lines2)

	// Enforce line count limits to prevent quadratic memory explosion
	if m > MaxDiffLines || n > MaxDiffLines {
		// Return a simple "files differ" result instead of failing
		// This provides useful output without DoS risk
		return computeSimpleDiff(lines1, lines2)
	}

	// Additional check: ensure LCS table won't exceed memory limit
	// Each cell is 8 bytes (int on 64-bit), so (m+1)*(n+1)*8 bytes
	// SECURITY: Cast to int64 BEFORE arithmetic to prevent integer overflow.
	// If we did int64(m+1), the (m+1) would overflow int first on 32-bit systems.
	tableSize := (int64(m) + 1) * (int64(n) + 1) * 8
	if tableSize > MaxDiffMemoryBytes {
		return computeSimpleDiff(lines1, lines2)
	}

	// Build LCS table using O(n) space optimization
	// Instead of full (m+1)*(n+1) table, use two rows
	prev := make([]int, n+1)
	curr := make([]int, n+1)

	for i := 1; i <= m; i++ {
		for j := 1; j <= n; j++ {
			if lines1[i-1] == lines2[j-1] {
				curr[j] = prev[j-1] + 1
			} else {
				if prev[j] > curr[j-1] {
					curr[j] = prev[j]
				} else {
					curr[j] = curr[j-1]
				}
			}
		}
		// Swap rows
		prev, curr = curr, prev
		// Clear curr for next iteration
		for j := range curr {
			curr[j] = 0
		}
	}

	// For backtracking, we need the full table. Use Hirschberg's algorithm
	// for linear space, but for simplicity with reasonable limits, rebuild
	// the table for backtracking (still O(m*n) time but bounded by limits)
	lcs := make([][]int, m+1)
	for i := range lcs {
		lcs[i] = make([]int, n+1)
	}

	for i := 1; i <= m; i++ {
		for j := 1; j <= n; j++ {
			if lines1[i-1] == lines2[j-1] {
				lcs[i][j] = lcs[i-1][j-1] + 1
			} else {
				if lcs[i-1][j] > lcs[i][j-1] {
					lcs[i][j] = lcs[i-1][j]
				} else {
					lcs[i][j] = lcs[i][j-1]
				}
			}
		}
	}

	// Backtrack to build diff
	var result []LineDiff
	i, j := m, n
	for i > 0 || j > 0 {
		if i > 0 && j > 0 && lines1[i-1] == lines2[j-1] {
			result = append(result, LineDiff{LineEqual, lines1[i-1]})
			i--
			j--
		} else if j > 0 && (i == 0 || lcs[i][j-1] >= lcs[i-1][j]) {
			result = append(result, LineDiff{LineAdded, lines2[j-1]})
			j--
		} else {
			result = append(result, LineDiff{LineRemoved, lines1[i-1]})
			i--
		}
	}

	// Reverse result
	for i, j := 0, len(result)-1; i < j; i, j = i+1, j-1 {
		result[i], result[j] = result[j], result[i]
	}

	return result
}

// computeSimpleDiff returns a simple diff showing all lines as removed/added
// when input is too large for full LCS computation.
func computeSimpleDiff(lines1, lines2 []string) []LineDiff {
	// Limit output to prevent memory issues
	const maxOutputLines = 1000

	var result []LineDiff

	// Show first N removed lines
	for i := 0; i < len(lines1) && i < maxOutputLines/2; i++ {
		result = append(result, LineDiff{LineRemoved, lines1[i]})
	}
	if len(lines1) > maxOutputLines/2 {
		result = append(result, LineDiff{LineRemoved, fmt.Sprintf("... (%d more lines)", len(lines1)-maxOutputLines/2)})
	}

	// Show first N added lines
	for i := 0; i < len(lines2) && i < maxOutputLines/2; i++ {
		result = append(result, LineDiff{LineAdded, lines2[i]})
	}
	if len(lines2) > maxOutputLines/2 {
		result = append(result, LineDiff{LineAdded, fmt.Sprintf("... (%d more lines)", len(lines2)-maxOutputLines/2)})
	}

	return result
}

// jsonEqual compares two JSON values for equality.
// Falls back to reflect.DeepEqual if json.Marshal fails (e.g., for NaN/Inf values).
func jsonEqual(v1, v2 interface{}) bool {
	b1, err1 := json.Marshal(v1)
	b2, err2 := json.Marshal(v2)
	if err1 != nil || err2 != nil {
		// Fall back to reflect.DeepEqual for unmarshalable values (NaN, Inf, etc.)
		return reflect.DeepEqual(v1, v2)
	}
	return bytes.Equal(b1, b2)
}

// splitLines splits text into lines.
func splitLines(text string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(text); i++ {
		if text[i] == '\n' {
			lines = append(lines, text[start:i])
			start = i + 1
		}
	}
	if start < len(text) {
		lines = append(lines, text[start:])
	}
	return lines
}

// appendPath appends a key to a JSON path.
func appendPath(path, key string) string {
	if path == "" {
		return key
	}
	return path + "." + key
}

// pathOrRoot returns the path or "(root)" if empty.
func pathOrRoot(path string) string {
	if path == "" {
		return "(root)"
	}
	return path
}

// isIntegrityError checks if an error is an integrity verification failure
// (digest mismatch or size mismatch). These indicate potential tampering
// and must be reported as security-critical, not masked as "missing".
func isIntegrityError(err error) bool {
	if err == nil {
		return false
	}
	code := errors.CodeOf(err)
	return code == errors.DigestMismatch || code == errors.SizeMismatch
}

// strictJSONUnmarshal parses JSON with strict validation:
//   - Validates no duplicate keys (prevents ambiguous comparisons)
//   - Rejects trailing data after the JSON value
//   - Preserves numeric precision using json.Number
//
// Returns true if parsing succeeded, false otherwise.
func strictJSONUnmarshal(data []byte, v interface{}) bool {
	// SECURITY: Validate no duplicate keys before unmarshaling.
	// json.Unmarshal silently keeps the last duplicate, which could cause
	// two files with different content to appear identical in diff output.
	if err := jsonutil.ValidateNoDuplicateKeys(data); err != nil {
		return false
	}

	// Use json.Decoder with UseNumber() to preserve numeric precision.
	// Without this, integers > 2^53 lose precision when converted to float64,
	// causing false "no change" results for distinct large integers.
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(v); err != nil {
		return false
	}

	// SECURITY: Reject trailing data - must detect both:
	// 1. Complete extra values like "{}{}" (extra decodes successfully)
	// 2. Incomplete trailing data like "{}{" (extra fails but More() is true)
	//
	// Note: dec.More() alone is insufficient - it's designed for array/object
	// context and returns false after first top-level value even with "{}{}".
	var extra any
	if err := dec.Decode(&extra); err == nil {
		// Successfully decoded another value - trailing data exists
		return false
	} else if dec.More() {
		// Couldn't parse trailing data but there are more tokens
		// This catches cases like "{}{" where trailing data is incomplete
		return false
	}

	return true
}

// FormatJSONValue formats a JSON value for display.
func FormatJSONValue(v interface{}) string {
	switch val := v.(type) {
	case json.Number:
		// json.Number preserves the exact text representation of numbers,
		// preventing precision loss for large integers (> 2^53).
		return string(val)
	case string:
		return fmt.Sprintf("%q", val)
	case nil:
		return "null"
	case bool:
		if val {
			return "true"
		}
		return "false"
	case float64:
		// Handle special float values that can't be JSON marshaled
		if math.IsNaN(val) {
			return "NaN"
		}
		if math.IsInf(val, 1) {
			return "+Inf"
		}
		if math.IsInf(val, -1) {
			return "-Inf"
		}
		// Check if it's an integer that fits in int64 range
		// Values outside [-2^63, 2^63-1] have undefined int64 conversion behavior
		if val >= math.MinInt64 && val <= math.MaxInt64 && val == float64(int64(val)) {
			return fmt.Sprintf("%d", int64(val))
		}
		return fmt.Sprintf("%g", val)
	case []interface{}:
		if len(val) == 0 {
			return "[]"
		}
		b, err := json.Marshal(val)
		if err != nil {
			return fmt.Sprintf("[...%d items]", len(val))
		}
		s := string(b)
		if len(s) > 60 {
			return fmt.Sprintf("[...%d items]", len(val))
		}
		return s
	case map[string]interface{}:
		if len(val) == 0 {
			return "{}"
		}
		b, err := json.Marshal(val)
		if err != nil {
			return fmt.Sprintf("{...%d keys}", len(val))
		}
		s := string(b)
		if len(s) > 60 {
			return fmt.Sprintf("{...%d keys}", len(val))
		}
		return s
	default:
		b, err := json.Marshal(v)
		if err != nil {
			return fmt.Sprintf("%v", v)
		}
		return string(b)
	}
}
