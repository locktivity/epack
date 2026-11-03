package shadow

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/locktivity/epack/internal/component/config"
)

func TestToolErrorsReadsTheRunRecord(t *testing.T) {
	dir := t.TempDir()
	run := filepath.Join(dir, "tools", "validate", "2026-11-03T22-45-43Z-000000")
	if err := os.MkdirAll(run, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(run, "result.json"), []byte(`{"status":"failure","errors":[{"code":"TOOL_ERROR","message":"resolving profile: no profiles configured in tool config"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := toolErrors(dir); got != "resolving profile: no profiles configured in tool config" {
		t.Errorf("toolErrors = %q", got)
	}
	if got := findFile(dir, "validation.json"); got != "" {
		t.Errorf("findFile = %q, want none", got)
	}
}

func TestValidateToolFindsTheProjectsValidator(t *testing.T) {
	for _, tc := range []struct {
		tools map[string]config.ToolConfig
		want  string
	}{
		{map[string]config.ToolConfig{"validate": {}}, "validate"},
		{map[string]config.ToolConfig{"checks": {Source: "locktivity/epack-tool-validate@^0.1"}}, "checks"},
		{map[string]config.ToolConfig{"ai": {Source: "locktivity/epack-tool-ai@^1"}}, ""},
	} {
		if got := validateTool(&config.JobConfig{Tools: tc.tools}); got != tc.want {
			t.Errorf("validateTool(%v) = %q, want %q", tc.tools, got, tc.want)
		}
	}
}

func TestCompareControls(t *testing.T) {
	validation := func(profile string, reqs ...Requirement) *Validation {
		v := &Validation{Requirements: reqs}
		v.Profile.ID = profile
		return v
	}
	req := func(id, name, status string, actual any) Requirement {
		return Requirement{ID: id, Name: name, Status: status, Actual: actual}
	}
	locked1 := validation("locked",
		req("SAME", "Same", "pass", nil),
		req("UP", "Up", "fail", 50),
		req("FLAKY", "Flaky", "pass", nil),
		req("GONE", "Gone", "pass", 1),
		req("L1ONLY", "L1 only", "pass", nil),
		req("L1C", "L1 and candidate", "pass", nil),
		req("EMPTY", "Empty", "", 7),
	)
	locked2 := validation("locked",
		req("SAME", "Same", "pass", nil),
		req("UP", "Up", "fail", 50),
		req("FLAKY", "Flaky", "fail", nil),
		req("GONE", "Gone", "pass", 1),
		req("L2ONLY", "L2 only", "pass", nil),
		req("L2C", "L2 and candidate", "pass", nil),
	)
	candidate := validation("candidate",
		req("SAME", "Same", "pass", nil),
		req("UP", "Up again", "pass", 100),
		req("FLAKY", "Flaky", "pass", nil),
		req("NEW", "New", "unknown", "x"),
		req("L1C", "L1 and candidate", "pass", nil),
		req("L2C", "L2 and candidate", "pass", nil),
		req("EMPTY", "", "pass", nil),
	)
	changes, noise, values := compareControls(trio[*Validation]{Locked1: locked1, Locked2: locked2, Candidate: candidate})
	// A requirement only the second locked run lists is not compared, and
	// one whose status is "" reads as missing.
	wantChanges := []ControlChange{
		{Profile: "candidate", ID: "EMPTY", Name: "Empty", From: "", To: "pass"},
		{Profile: "candidate", ID: "GONE", Name: "Gone", From: "pass", To: ""},
		{Profile: "candidate", ID: "NEW", Name: "New", From: "", To: "unknown"},
		{Profile: "candidate", ID: "UP", Name: "Up again", From: "fail", To: "pass"},
	}
	if !reflect.DeepEqual(changes, wantChanges) {
		t.Errorf("changes = %+v, want %+v", changes, wantChanges)
	}
	if want := []string{"FLAKY", "L1C", "L1ONLY", "L2C"}; !reflect.DeepEqual(noise, want) {
		t.Errorf("noise = %v, want %v", noise, want)
	}
	wantValues := []ControlValue{
		{ID: "EMPTY", From: 7},
		{ID: "GONE", From: 1},
		{ID: "NEW", To: "x"},
		{ID: "UP", From: 50, To: 100},
	}
	if !reflect.DeepEqual(values, wantValues) {
		t.Errorf("values = %+v, want %+v", values, wantValues)
	}

	changes, noise, values = compareControls(trio[*Validation]{Locked1: locked1, Locked2: locked1, Candidate: locked1})
	if changes != nil || noise != nil || values != nil {
		t.Errorf("compareControls of one validation = %v, %v, %v, want nil", changes, noise, values)
	}
}
