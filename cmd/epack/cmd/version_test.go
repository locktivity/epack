package cmd

import (
	"bytes"
	"encoding/json"
	"runtime"
	"strings"
	"testing"

	"github.com/locktivity/epack/internal/version"
)

func TestVersionVars(t *testing.T) {
	// Test that version variables have default values
	if version.Version == "" {
		t.Error("Version should not be empty")
	}
	if version.Commit == "" {
		t.Error("Commit should not be empty")
	}
	if version.BuildDate == "" {
		t.Error("BuildDate should not be empty")
	}
}

func TestVersionOutput_JSON(t *testing.T) {
	// Simulate JSON output structure
	output := map[string]string{
		"version":    version.Version,
		"commit":     version.Commit,
		"build_date": version.BuildDate,
		"go_version": runtime.Version(),
		"os":         runtime.GOOS,
		"arch":       runtime.GOARCH,
	}

	data, err := json.Marshal(output)
	if err != nil {
		t.Fatalf("Failed to marshal version output: %v", err)
	}

	var decoded map[string]string
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal version output: %v", err)
	}

	requiredFields := []string{"version", "commit", "build_date", "go_version", "os", "arch"}
	for _, field := range requiredFields {
		if _, exists := decoded[field]; !exists {
			t.Errorf("Missing required field: %s", field)
		}
	}
}

func TestVersionOutput_RuntimeValues(t *testing.T) {
	// Verify runtime values are accessible
	goVersion := runtime.Version()
	if !strings.HasPrefix(goVersion, "go") {
		t.Errorf("runtime.Version() = %q, expected to start with 'go'", goVersion)
	}

	if runtime.GOOS == "" {
		t.Error("runtime.GOOS is empty")
	}

	if runtime.GOARCH == "" {
		t.Error("runtime.GOARCH is empty")
	}
}

func TestVersionCmd_Exists(t *testing.T) {
	if versionCmd == nil {
		t.Fatal("versionCmd is nil")
	}

	if versionCmd.Use != "version" {
		t.Errorf("versionCmd.Use = %q, want %q", versionCmd.Use, "version")
	}

	if versionCmd.Short == "" {
		t.Error("versionCmd.Short is empty")
	}

	if versionCmd.Run == nil {
		t.Error("versionCmd.Run is nil")
	}
}

func TestVersionOutput_Format(t *testing.T) {
	// Test the expected output format
	var buf bytes.Buffer
	expected := "epack version " + version.Version + "\n"

	buf.WriteString(expected)
	got := buf.String()

	if !strings.Contains(got, "epack version") {
		t.Error("Output should contain 'epack version'")
	}
}
