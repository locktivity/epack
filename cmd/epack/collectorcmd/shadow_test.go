//go:build components

package collectorcmd

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/locktivity/epack/internal/cli/output"
	"github.com/locktivity/epack/internal/shadow"
)

func TestShadowFilesLandWhereTheyAreNamed(t *testing.T) {
	dir := t.TempDir()
	report := filepath.Join(dir, "shadow.json")
	values := filepath.Join(dir, "values.json")
	if err := writeShadowJSON(report, map[string]string{"collector": "demo"}, false); err != nil {
		t.Fatal(err)
	}
	if err := writeShadowJSON(values, map[string]string{"from": "50"}, true); err != nil {
		t.Fatal(err)
	}
	for path, mode := range map[string]os.FileMode{report: 0o644, values: 0o600} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if info.Mode().Perm() != mode {
			t.Errorf("%s mode = %v, want %v", filepath.Base(path), info.Mode().Perm(), mode)
		}
	}
}

func TestDefaultShadowReportPath(t *testing.T) {
	for _, tc := range []struct{ version, want string }{
		{"v0.7.0", "shadow-aws-v0.7.0.json"},
		{"", "shadow-aws-local.json"},
	} {
		if got := defaultShadowReportPath("aws", tc.version); got != tc.want {
			t.Errorf("defaultShadowReportPath(%q) = %q, want %q", tc.version, got, tc.want)
		}
	}
}

func TestShadowReportPrintsGapNoise(t *testing.T) {
	var stdout bytes.Buffer
	rep := &shadow.Report{Collector: "demo", GapNoise: []shadow.GapRef{
		{FieldRef: shadow.FieldRef{Kind: "demo", File: "artifacts/demo.json", Pointer: "/regions"}, Status: "partial", Code: "rate_limited"},
	}}
	printShadowReport(output.New(&stdout, io.Discard, output.Options{NoColor: true}), rep, &shadow.Preview{}, false)
	if !strings.Contains(stdout.String(), "rate_limited at demo /regions") {
		t.Errorf("report = %q, want the gap that differs between the locked runs listed as noise", stdout.String())
	}
}

func TestShadowShowsValuesOnlyAtATerminal(t *testing.T) {
	var buf bytes.Buffer
	for name, out := range map[string]*output.Writer{
		"piped": output.New(&buf, io.Discard, output.Options{}),
		"CI":    output.New(&buf, io.Discard, output.Options{CI: true}),
	} {
		if shadowShowsValues(out, false) {
			t.Errorf("%s: values shown, want none outside a terminal, where logs keep them", name)
		}
	}
}

func TestShadowShowsUsageWithoutACollector(t *testing.T) {
	cmd := NewShadowCommand()
	err := cmd.Args(cmd, nil)
	if err == nil || !strings.Contains(err.Error(), "Usage: epack shadow <collector> --version <release>") {
		t.Fatalf("Args(nil) = %v, want the usage", err)
	}
	if err := cmd.Args(cmd, []string{"aws", "okta"}); err == nil || !strings.Contains(err.Error(), "expected 1, got 2") {
		t.Fatalf("Args(two) = %v, want too many arguments", err)
	}
	if err := cmd.Args(cmd, []string{"aws"}); err != nil {
		t.Fatalf("Args(one) = %v", err)
	}
}
