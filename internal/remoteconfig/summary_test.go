package remoteconfig

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const summaryConfig = `stream: northwind/production
collectors:
  tls:
    source: locktivity/epack-collector-tls@^0.1.0
    secrets:
    - TLS_TOKEN
  okta:
    source: northwind-security/epack-collector-okta@^1.0
    secrets:
    - OKTA_API_TOKEN
tools:
  validate:
    source: locktivity/epack-tool-validate@^0.4
remotes:
  locktivity:
    source: locktivity/epack-remote-locktivity@^0.1.0
    secrets:
    - LOCKTIVITY_CLIENT_ID
    - OKTA_API_TOKEN
`

func writeSummaryProject(t *testing.T, cfg string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "epack.yaml"), []byte(cfg), 0o644); err != nil {
		t.Fatalf("writing config: %v", err)
	}
	return dir
}

func TestSummarize_ReadsTheWrittenFiles(t *testing.T) {
	dir := writeSummaryProject(t, summaryConfig)
	getenv := func(name string) string {
		if name == "OKTA_API_TOKEN" {
			return "secret"
		}
		return ""
	}

	summary, err := Summarize(dir, getenv)
	if err != nil {
		t.Fatalf("Summarize: %v", err)
	}
	if summary.Locked {
		t.Error("Locked = true without a lockfile")
	}
	if len(summary.Collectors) != 2 || summary.Collectors[0].Name != "okta" || summary.Collectors[0].Owner != "northwind-security" || summary.Collectors[0].Version != "^1.0" {
		t.Errorf("collectors = %+v", summary.Collectors)
	}
	if len(summary.Tools) != 1 || summary.Tools[0].Publisher() != "github.com/locktivity" {
		t.Errorf("tools = %+v", summary.Tools)
	}
	if len(summary.Remotes) != 1 || summary.Remotes[0].Repo != "epack-remote-locktivity" {
		t.Errorf("remotes = %+v", summary.Remotes)
	}
	if len(summary.Env) != 3 {
		t.Fatalf("env = %+v", summary.Env)
	}
	okta := summary.Env[1]
	if okta.Name != "OKTA_API_TOKEN" || !okta.Set || strings.Join(okta.UsedBy, ",") != "okta,locktivity" {
		t.Errorf("OKTA_API_TOKEN = %+v", okta)
	}
	if summary.Env[2].Name != "TLS_TOKEN" || summary.Env[2].Set {
		t.Errorf("TLS_TOKEN = %+v", summary.Env[2])
	}

	groups := PublisherGroups(summary.Collectors)
	if len(groups) != 2 || groups[0] != "okta ^1.0 from github.com/northwind-security" || groups[1] != "tls ^0.1.0 from github.com/locktivity" {
		t.Errorf("groups = %v", groups)
	}
}

func TestSummarize_UsesLockedVersionsAndHookState(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "cfg")
	cfg := sampleConfig(1, summaryConfig)
	cfg.Lockfile = `schema_version: 1
collectors:
  tls:
    source: github.com/locktivity/epack-collector-tls
    version: v0.1.4
    platforms:
      darwin/arm64:
        digest: sha256:0000000000000000000000000000000000000000000000000000000000000000
`
	if _, err := Write(cfg, "locktivity", Options{Dir: dir, FilesDir: ".locktivity"}); err != nil {
		t.Fatalf("Write: %v", err)
	}
	summary, err := Summarize(dir, func(string) string { return "" })
	if err != nil {
		t.Fatalf("Summarize: %v", err)
	}
	if !summary.Locked {
		t.Error("Locked = false with a lockfile present")
	}
	var tls Component
	for _, c := range summary.Collectors {
		if c.Name == "tls" {
			tls = c
		}
	}
	if tls.Version != "v0.1.4" {
		t.Errorf("tls version = %q, want the locked v0.1.4", tls.Version)
	}
	if len(summary.Hooks) != 2 || !summary.Hooks[0].Template || !summary.Hooks[1].Template {
		t.Errorf("hooks = %+v, want two templates", summary.Hooks)
	}
}

func TestDiff(t *testing.T) {
	before := &Summary{
		Collectors: []Component{{Name: "tls", Kind: "collector", Owner: "locktivity", Version: "v0.1.4"}, {Name: "dns", Kind: "collector", Owner: "locktivity", Version: "v0.2.0"}},
		Env:        []EnvVar{{Name: "TLS_TOKEN"}},
	}
	after := &Summary{
		Collectors: []Component{{Name: "tls", Kind: "collector", Owner: "locktivity", Version: "v0.1.5"}, {Name: "aws", Kind: "collector", Owner: "locktivity", Version: "v0.3.0"}},
		Env:        []EnvVar{{Name: "TLS_TOKEN"}, {Name: "AWS_SECRET_ACCESS_KEY", Set: true}},
	}
	changes := Diff(before, after)
	if changes.Empty() {
		t.Fatal("expected changes")
	}
	if len(changes.Added) != 1 || changes.Added[0].Name != "aws" {
		t.Errorf("Added = %+v", changes.Added)
	}
	if len(changes.Removed) != 1 || changes.Removed[0].Name != "dns" {
		t.Errorf("Removed = %+v", changes.Removed)
	}
	if len(changes.Changed) != 1 || changes.Changed[0].From != "tls v0.1.4" || changes.Changed[0].To != "tls v0.1.5" {
		t.Errorf("Changed = %+v", changes.Changed)
	}
	if len(changes.NewEnv) != 1 || changes.NewEnv[0].Name != "AWS_SECRET_ACCESS_KEY" {
		t.Errorf("NewEnv = %+v", changes.NewEnv)
	}
	if !Diff(after, after).Empty() {
		t.Error("a revision compared with itself should show no changes")
	}
}
