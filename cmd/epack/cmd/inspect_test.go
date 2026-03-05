package cmd

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/locktivity/epack/internal/cli/output"
)

func TestTruncateDigest(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"sha256:abcdef1234567890", "sha256:abcdef123456..."}, // 26 chars -> first 19 + ...
		{"sha256:abc", "sha256:abc"},                          // 10 chars (under limit)
		{"short", "short"},                                    // 5 chars (under limit)
		{"exactly19chars!!!!!", "exactly19chars!!!!!"},        // exactly 19 chars (not truncated)
		{"exactly20chars!!!!!!", "exactly20chars!!!!!..."},    // 20 chars -> first 19 + ...
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := output.FormatDigest(tt.input)
			if got != tt.want {
				t.Errorf("format.Digest(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestFormatBytes(t *testing.T) {
	tests := []struct {
		name     string
		inputStr string
		want     string
	}{
		{"bytes", "500", "500 B"},
		{"kilobytes", "1024", "1.0 KB"},
		{"kilobytes_partial", "1536", "1.5 KB"},
		{"megabytes", "1048576", "1.0 MB"},
		{"megabytes_partial", "1572864", "1.5 MB"},
		{"gigabytes", "1073741824", "1.0 GB"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			num := json.Number(tt.inputStr)
			got := output.FormatBytesFromJSON(&num)
			if got != tt.want {
				t.Errorf("format.BytesFromJSON(%s) = %q, want %q", tt.inputStr, got, tt.want)
			}
		})
	}
}

func TestInspectOutput_JSONSerialization(t *testing.T) {
	output := inspectOutput{
		SpecVersion:      "1.0",
		Stream:           "test/stream",
		PackDigest:       "sha256:abc123",
		ManifestDigest:   "abc123def456789012345678901234567890123456789012345678901234abcd",
		GeneratedAt:      "2024-01-01T00:00:00Z",
		ArtifactCount:    2,
		AttestationCount: 1,
		Sources:          nil,
		Artifacts:        nil,
		Attestations:     []string{"attestations/test.sigstore.json"},
	}

	data, err := json.Marshal(output)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	var decoded map[string]interface{}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	if decoded["spec_version"] != "1.0" {
		t.Errorf("spec_version = %v, want 1.0", decoded["spec_version"])
	}
	if decoded["stream"] != "test/stream" {
		t.Errorf("stream = %v, want test/stream", decoded["stream"])
	}
	if decoded["artifact_count"].(float64) != 2 {
		t.Errorf("artifact_count = %v, want 2", decoded["artifact_count"])
	}
}

func TestInspectOutput_AllFieldsPresent(t *testing.T) {
	output := inspectOutput{
		SpecVersion:      "1.0",
		Stream:           "test/stream",
		PackDigest:       "sha256:abc123",
		ManifestDigest:   "abc123def456789012345678901234567890123456789012345678901234abcd",
		GeneratedAt:      "2024-01-01T00:00:00Z",
		ArtifactCount:    0,
		AttestationCount: 0,
		Sources:          nil,
		Artifacts:        nil,
		Attestations:     nil,
	}

	data, err := json.Marshal(output)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	// Verify required fields exist
	var decoded map[string]interface{}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	requiredFields := []string{"spec_version", "stream", "pack_digest", "manifest_digest", "generated_at", "artifact_count", "attestation_count"}
	for _, field := range requiredFields {
		if _, exists := decoded[field]; !exists {
			t.Errorf("Missing required field: %s", field)
		}
	}
}

// Golden file tests for inspect output

func TestInspect_GoldenHuman(t *testing.T) {
	// Create a test pack - artifacts are sorted by path in the builder
	packPath := createTestPack(t, "test/golden-inspect", map[string][]byte{
		"artifacts/config.json": []byte(`{"key": "value"}`),
		"artifacts/data.json":   []byte(`{"items": [1, 2, 3]}`),
	})

	// Capture output with no color for deterministic comparison
	var buf bytes.Buffer
	var errBuf bytes.Buffer
	t.Setenv("NO_COLOR", "1")

	out = output.New(&buf, &errBuf, output.Options{
		Quiet:   false,
		JSON:    false,
		NoColor: true,
		Verbose: false,
	})

	// Reset flags
	inspectDigest = false
	inspectRaw = false
	inspectSummary = false

	err := runInspect(nil, []string{packPath})
	if err != nil {
		t.Fatalf("runInspect failed: %v", err)
	}

	got := buf.String()

	// Normalize dynamic values
	normalized := NormalizeDigests(got)
	normalized = NormalizeTimestamps(normalized)
	normalized = NormalizeTempPaths(normalized)

	assertGolden(t, goldenPath("inspect_human"), normalized)
}

func TestInspect_GoldenJSON(t *testing.T) {
	packPath := createTestPack(t, "test/golden-inspect-json", map[string][]byte{
		"artifacts/config.json": []byte(`{"key": "value"}`),
	})

	var buf bytes.Buffer
	var errBuf bytes.Buffer
	out = output.New(&buf, &errBuf, output.Options{
		Quiet:   false,
		JSON:    true,
		NoColor: true,
		Verbose: false,
	})

	inspectDigest = false
	inspectRaw = false
	inspectSummary = false

	err := runInspect(nil, []string{packPath})
	if err != nil {
		t.Fatalf("runInspect failed: %v", err)
	}

	got := buf.String()

	// Normalize dynamic values
	normalized := NormalizeDigests(got)
	normalized = NormalizeTimestamps(normalized)

	assertGolden(t, goldenPath("inspect_json"), normalized)
}

func TestInspect_GoldenSummary(t *testing.T) {
	packPath := createTestPack(t, "test/golden-summary", map[string][]byte{
		"artifacts/data.json": []byte(`{}`),
	})

	var buf bytes.Buffer
	var errBuf bytes.Buffer
	out = output.New(&buf, &errBuf, output.Options{
		Quiet:   false,
		JSON:    false,
		NoColor: true,
		Verbose: false,
	})

	inspectDigest = false
	inspectRaw = false
	inspectSummary = true

	err := runInspect(nil, []string{packPath})
	if err != nil {
		t.Fatalf("runInspect failed: %v", err)
	}

	got := buf.String()
	normalized := NormalizeTruncatedDigests(got)

	assertGolden(t, goldenPath("inspect_summary"), normalized)
}
