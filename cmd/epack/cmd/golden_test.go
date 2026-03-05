package cmd

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// Golden file test helpers for CLI output verification.
// Run with UPDATE_GOLDEN=1 to update golden files.

// assertGolden compares got against the golden file at goldenPath.
// If UPDATE_GOLDEN env is set, it updates the golden file instead.
func assertGolden(t *testing.T, goldenPath, got string) {
	t.Helper()

	if os.Getenv("UPDATE_GOLDEN") != "" {
		dir := filepath.Dir(goldenPath)
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatalf("failed to create golden dir: %v", err)
		}
		if err := os.WriteFile(goldenPath, []byte(got), 0644); err != nil {
			t.Fatalf("failed to update golden file: %v", err)
		}
		t.Logf("Updated golden file: %s", goldenPath)
		return
	}

	want, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("failed to read golden file %s: %v\nRun with UPDATE_GOLDEN=1 to create it", goldenPath, err)
	}

	if got != string(want) {
		t.Errorf("output mismatch with golden file %s\n\n--- WANT ---\n%s\n--- GOT ---\n%s\n\nRun with UPDATE_GOLDEN=1 to update",
			goldenPath, string(want), got)
	}
}

// goldenPath returns the path to a golden file in testdata.
func goldenPath(name string) string {
	return filepath.Join("testdata", name+".golden")
}

// NormalizeDigests replaces sha256 digests with a placeholder.
// Handles both prefixed (sha256:hex) and raw hex (manifest_digest) formats.
func NormalizeDigests(s string) string {
	// First, normalize prefixed digests
	re := regexp.MustCompile(`sha256:[a-f0-9]{64}`)
	s = re.ReplaceAllString(s, "sha256:<DIGEST>")
	// Then, normalize raw hex manifest_digest (64 chars on a JSON line)
	reManifest := regexp.MustCompile(`("manifest_digest":\s*")[a-f0-9]{64}(")`)
	return reManifest.ReplaceAllString(s, "${1}<MANIFEST_DIGEST>${2}")
}

// NormalizeTruncatedDigests replaces truncated digests (sha256:abc123...) with placeholder.
// Matches 8-16 hex characters followed by ... (covers various truncation lengths).
func NormalizeTruncatedDigests(s string) string {
	re := regexp.MustCompile(`sha256:[a-f0-9]{8,16}\.\.\.`)
	return re.ReplaceAllString(s, "sha256:<DIGEST>...")
}

// NormalizeTimestamps replaces ISO timestamps with a placeholder.
func NormalizeTimestamps(s string) string {
	// Match ISO 8601 timestamps like 2024-12-15T10:30:00Z or 2024-12-15T10:30:00.123Z
	re := regexp.MustCompile(`\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z`)
	return re.ReplaceAllString(s, "<TIMESTAMP>")
}

// NormalizeTempPaths replaces temp directory paths with a placeholder.
// Matches /tmp and /var/folders paths up to whitespace or quote characters.
func NormalizeTempPaths(s string) string {
	re := regexp.MustCompile(`(/tmp|/var/folders)/[^\s"]+`)
	return re.ReplaceAllString(s, "<PATH>")
}
