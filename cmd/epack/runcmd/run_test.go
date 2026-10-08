//go:build components

package runcmd

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/locktivity/epack/internal/broker"
	"github.com/locktivity/epack/internal/cli/output"
	"github.com/locktivity/epack/internal/runflow"
)

func parseDuration(s string) (time.Duration, error) {
	return time.ParseDuration(s)
}

func TestRun_NotInProject(t *testing.T) {
	dir := t.TempDir()
	oldWd, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	defer func() { _ = os.Chdir(oldWd) }()

	cmd := NewCommand()
	cmd.SetArgs([]string{})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "not in an epack project") {
		t.Fatalf("err = %v", err)
	}
	if !strings.Contains(err.Error(), "epack run <name>") {
		t.Errorf("error should point at fetching a configuration: %v", err)
	}
}

func TestRun_SignsInWithTheKeyItSignsWith(t *testing.T) {
	t.Setenv(broker.SigningKeyEnvVar, "/keys/other.pem")
	t.Cleanup(func() { runKey = "" })
	dir := t.TempDir()
	oldWd, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	defer func() { _ = os.Chdir(oldWd) }()

	cmd := NewCommand()
	cmd.SetArgs([]string{"--key", "/keys/ci.pem"})
	_ = cmd.Execute()
	if got := os.Getenv(broker.SigningKeyEnvVar); got != "/keys/ci.pem" {
		t.Fatalf("%s = %q, want the --key path", broker.SigningKeyEnvVar, got)
	}
}

func TestRun_RejectsTheColonForm(t *testing.T) {
	isolateHome(t)
	cmd := NewCommand()
	cmd.SetArgs([]string{"locktivity:northwind-production"})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "--remote locktivity") {
		t.Fatalf("err = %v", err)
	}
}

func TestRun_NeedsARemoteForAName(t *testing.T) {
	isolateHome(t)
	dir := t.TempDir()
	oldWd, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	defer func() { _ = os.Chdir(oldWd) }()

	cmd := NewCommand()
	cmd.SetArgs([]string{"northwind-production"})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "epack remote login") {
		t.Fatalf("err = %v", err)
	}
}

func isolateHome(t *testing.T) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
}

func TestPrintCheckResult_PointsAtThePipelinePageOnlyForAWebLink(t *testing.T) {
	for _, tc := range []struct {
		link, shown string
	}{
		{link: "https://app.locktivity.com/evidence_packs/pipelines/9b2f", shown: "https://app.locktivity.com/evidence_packs/pipelines/9b2f"},
		{link: "http://localhost:3000/evidence_packs/pipelines/9b2f", shown: "http://localhost:3000/evidence_packs/pipelines/9b2f"},
		{link: ""},
		{link: "javascript:alert(1)"},
		{link: "file:///etc/passwd"},
		{link: "/evidence_packs/pipelines/9b2f"},
	} {
		result := &runflow.CheckResult{Remote: "locktivity", LockPresent: true, LockCurrent: true, PublishersTrusted: true, Reported: true, PipelineURL: tc.link}

		var stdout bytes.Buffer
		printCheckResult(output.New(&stdout, &stdout, output.Options{}), result)
		want := "\nReported to locktivity; the pipeline page shows this check.\n"
		if tc.shown != "" {
			want += "See it on the pipeline page: " + tc.shown + "\n"
		}
		if got := stdout.String(); !strings.HasSuffix(got, want) || (tc.shown == "" && strings.Contains(got, "See it on")) {
			t.Errorf("pipeline_url %q printed:\n%s", tc.link, got)
		}

		var jsonOut bytes.Buffer
		printCheckResult(output.New(&jsonOut, &jsonOut, output.Options{JSON: true}), result)
		var payload map[string]any
		if err := json.Unmarshal(jsonOut.Bytes(), &payload); err != nil {
			t.Fatalf("pipeline_url %q: %v\n%s", tc.link, err, jsonOut.String())
		}
		if got, ok := payload["pipeline_url"]; ok != (tc.shown != "") || (ok && got != tc.shown) {
			t.Errorf("pipeline_url %q gave JSON pipeline_url %v", tc.link, got)
		}
	}
}

func TestFormatDuration(t *testing.T) {
	cases := map[string]string{
		"250ms": "250ms",
		"4.2s":  "4.2s",
		"90s":   "1m30s",
	}
	for in, want := range cases {
		d, _ := parseDuration(in)
		if got := formatDuration(d); got != want {
			t.Errorf("formatDuration(%s) = %q, want %q", in, got, want)
		}
	}
}
