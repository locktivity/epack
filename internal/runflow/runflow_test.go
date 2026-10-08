package runflow

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	epackerrors "github.com/locktivity/epack/errors"
	"github.com/locktivity/epack/internal/cli/exitmap"
	"github.com/locktivity/epack/internal/component/config"
	"github.com/locktivity/epack/internal/exitcode"
	"github.com/locktivity/epack/internal/remoteconfig"
	"github.com/locktivity/epack/internal/testutil/testhome"
	"github.com/locktivity/epack/internal/trustedpublishers"
	"github.com/locktivity/epack/internal/userconfig"
)

func TestResolveRemote(t *testing.T) {
	cfg := &config.JobConfig{Remotes: map[string]config.RemoteConfig{}}

	if got, err := ResolveRemote(cfg, ""); err != nil || got != "" {
		t.Errorf("no remotes: got %q, %v", got, err)
	}

	cfg.Remotes["locktivity"] = config.RemoteConfig{Source: "locktivity/epack-remote-locktivity@v1"}
	if got, err := ResolveRemote(cfg, ""); err != nil || got != "locktivity" {
		t.Errorf("one remote: got %q, %v", got, err)
	}
	if got, err := ResolveRemote(cfg, "locktivity"); err != nil || got != "locktivity" {
		t.Errorf("named remote: got %q, %v", got, err)
	}
	if _, err := ResolveRemote(cfg, "s3"); err == nil {
		t.Error("expected an error for a remote missing from config")
	}

	cfg.Remotes["s3"] = config.RemoteConfig{Source: "owner/epack-remote-s3@v1"}
	if _, err := ResolveRemote(cfg, ""); err == nil {
		t.Error("expected an error when several remotes are configured and none is named")
	}
}

func TestStageError_KeepsInnerExitCode(t *testing.T) {
	inner := &epackerrors.Error{Code: epackerrors.LockfileInvalid, Exit: exitcode.LockInvalid, Message: "lock drifted"}
	err := error(&StageError{Stage: StageInstall, Code: FailureInstall, Err: inner})

	var stageErr *StageError
	if !errors.As(err, &stageErr) || stageErr.Code != FailureInstall {
		t.Fatalf("errors.As did not find the stage error: %v", err)
	}
	msg, code := exitmap.ToExit(err)
	if code != exitcode.LockInvalid {
		t.Errorf("exit code = %d, want %d", code, exitcode.LockInvalid)
	}
	if msg != "install failed: lock drifted" {
		t.Errorf("message = %q", msg)
	}
}

func TestRun_MissingConfig(t *testing.T) {
	dir := t.TempDir()
	oldWd, _ := os.Getwd()
	defer func() { _ = os.Chdir(oldWd) }()

	_, err := Run(context.Background(), Options{WorkDir: dir})
	if err == nil {
		t.Fatal("expected an error without epack.yaml")
	}
	if _, statErr := os.Stat(filepath.Join(dir, DefaultPackName)); statErr == nil {
		t.Error("no pack should be built without a config")
	}
}

func TestExportPipelineID_FromThePullRecord(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".epack"), 0o755); err != nil {
		t.Fatal(err)
	}
	state := `{"remote":"locktivity","id":"pipe_1","name":"northwind-production","revision":1,"pulled_at":"2026-09-30T12:00:00Z","files":{}}`
	if err := os.WriteFile(filepath.Join(dir, ".epack", "remote-config.json"), []byte(state), 0o644); err != nil {
		t.Fatal(err)
	}

	record, err := remoteconfig.LoadState(dir)
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	t.Setenv(PipelineIDEnvVar, "")
	if err := exportPipelineID(dir, record); err != nil {
		t.Fatalf("exportPipelineID: %v", err)
	}
	if got := os.Getenv(PipelineIDEnvVar); got != "pipe_1" {
		t.Fatalf("%s = %q, want pipe_1", PipelineIDEnvVar, got)
	}

	t.Setenv(PipelineIDEnvVar, "explicit")
	if err := exportPipelineID(dir, record); err != nil {
		t.Fatalf("exportPipelineID: %v", err)
	}
	if got := os.Getenv(PipelineIDEnvVar); got != "explicit" {
		t.Fatalf("%s = %q, want the explicit value kept", PipelineIDEnvVar, got)
	}
}

func TestExportPipelineID_NothingWithoutAPullRecord(t *testing.T) {
	t.Setenv(PipelineIDEnvVar, "")
	if err := exportPipelineID(t.TempDir(), nil); err != nil {
		t.Fatalf("exportPipelineID: %v", err)
	}
	if got := os.Getenv(PipelineIDEnvVar); got != "" {
		t.Fatalf("%s = %q, want empty", PipelineIDEnvVar, got)
	}
}

func fetchedConfig() *config.JobConfig {
	return &config.JobConfig{
		Collectors: map[string]config.CollectorConfig{"tls": {Source: "locktivity/epack-collector-tls@^0.3"}},
		Remotes:    map[string]config.RemoteConfig{"locktivity": {Source: "locktivity/epack-remote-locktivity@^0.1"}},
	}
}

func pullRecord() *remoteconfig.State {
	return &remoteconfig.State{Remote: "locktivity", ID: "pipe_1", Name: "northwind-production", Revision: 1}
}

func TestCheckPublishers_LeavesAFolderWithoutAPullRecordAlone(t *testing.T) {
	testhome.Isolate(t)
	t.Setenv(trustedpublishers.EnvVar, "")

	if err := checkPublishers(fetchedConfig(), nil, Options{NonInteractive: true}); err != nil {
		t.Fatalf("checkPublishers: %v", err)
	}
}

func TestCheckPublishers_StopsAJobAndNamesTheVariable(t *testing.T) {
	testhome.Isolate(t)
	t.Setenv(trustedpublishers.EnvVar, "")

	err := checkPublishers(fetchedConfig(), pullRecord(), Options{NonInteractive: true})
	var trustErr *trustedpublishers.Error
	if !errors.As(err, &trustErr) {
		t.Fatalf("checkPublishers = %v, want a trust error", err)
	}
	for _, want := range []string{"github.com/locktivity: locktivity/epack-collector-tls, locktivity/epack-remote-locktivity", "EPACK_TRUSTED_PUBLISHERS=locktivity"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error missing %q:\n%s", want, err.Error())
		}
	}
}

func TestCheckPublishers_GrantsForOneProcess(t *testing.T) {
	testhome.Isolate(t)

	t.Setenv(trustedpublishers.EnvVar, "Locktivity")
	if err := checkPublishers(fetchedConfig(), pullRecord(), Options{NonInteractive: true}); err != nil {
		t.Fatalf("env grant: %v", err)
	}
	t.Setenv(trustedpublishers.EnvVar, "")
	if err := checkPublishers(fetchedConfig(), pullRecord(), Options{NonInteractive: true, TrustPublishers: []string{"locktivity"}}); err != nil {
		t.Fatalf("flag grant: %v", err)
	}
	if recorded, _ := userconfig.TrustedPublishers(); len(recorded) != 0 {
		t.Fatalf("a one-process grant must not be recorded, got %v", recorded)
	}
}

func TestCheckPublishers_AsksOnceInATerminalAndRecordsTheAnswer(t *testing.T) {
	testhome.Isolate(t)
	t.Setenv(trustedpublishers.EnvVar, "")

	var asked []string
	var notes []string
	opts := Options{
		OnNote: func(note string) { notes = append(notes, note) },
		PromptTrustPublisher: func(req trustedpublishers.Requirement) bool {
			asked = append(asked, req.Publisher)
			return true
		},
	}
	if err := checkPublishers(fetchedConfig(), pullRecord(), opts); err != nil {
		t.Fatalf("checkPublishers: %v", err)
	}
	if strings.Join(asked, ",") != "locktivity" {
		t.Fatalf("asked = %v", asked)
	}
	if recorded, _ := userconfig.TrustedPublishers(); strings.Join(recorded, ",") != "locktivity" {
		t.Fatalf("recorded = %v", recorded)
	}
	if len(notes) != 1 || !strings.Contains(notes[0], "trusted publisher") {
		t.Fatalf("notes = %v", notes)
	}

	asked = nil
	if err := checkPublishers(fetchedConfig(), pullRecord(), opts); err != nil || len(asked) != 0 {
		t.Fatalf("second run asked again: err=%v asked=%v", err, asked)
	}
}

func TestCheckPublishers_ANoStopsTheRun(t *testing.T) {
	testhome.Isolate(t)
	t.Setenv(trustedpublishers.EnvVar, "")

	opts := Options{
		OnNote:               func(string) {},
		PromptTrustPublisher: func(trustedpublishers.Requirement) bool { return false },
	}
	err := checkPublishers(fetchedConfig(), pullRecord(), opts)
	var trustErr *trustedpublishers.Error
	if !errors.As(err, &trustErr) {
		t.Fatalf("checkPublishers = %v, want a trust error", err)
	}
	if recorded, _ := userconfig.TrustedPublishers(); len(recorded) != 0 {
		t.Fatalf("a refusal must not be recorded, got %v", recorded)
	}
}

func TestCheckPublishers_YesNeverWidensTrust(t *testing.T) {
	testhome.Isolate(t)
	t.Setenv(trustedpublishers.EnvVar, "")

	opts := Options{
		NonInteractive:       true,
		PromptTrustPublisher: func(trustedpublishers.Requirement) bool { t.Fatal("prompted under --yes"); return true },
	}
	if err := checkPublishers(fetchedConfig(), pullRecord(), opts); err == nil {
		t.Fatal("expected the run to stop")
	}
}

func TestCheckPublishers_RefusesALocalBinaryInAFetchedConfiguration(t *testing.T) {
	testhome.Isolate(t)
	t.Setenv(trustedpublishers.EnvVar, "locktivity")

	cfg := fetchedConfig()
	cfg.Collectors["custom"] = config.CollectorConfig{Binary: "./bin/custom"}
	err := checkPublishers(cfg, pullRecord(), Options{NonInteractive: true})
	if err == nil || !strings.Contains(err.Error(), "collector custom runs a local binary") {
		t.Fatalf("checkPublishers = %v, want a refusal", err)
	}
}
