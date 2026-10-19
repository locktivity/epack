package collector

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	epackerrors "github.com/locktivity/epack/errors"
	"github.com/locktivity/epack/internal/cli/exitmap"
	"github.com/locktivity/epack/internal/cmdutil"
	"github.com/locktivity/epack/internal/component/config"
	"github.com/locktivity/epack/internal/component/lockfile"
	"github.com/locktivity/epack/internal/component/sync"
	"github.com/locktivity/epack/internal/componenttypes"
	"github.com/locktivity/epack/internal/exitcode"
	"github.com/locktivity/epack/internal/platform"
)

func TestParseCollectorOutput_RejectsOutputThatIsNotEvidence(t *testing.T) {
	tests := []struct {
		name   string
		output string
		want   string
	}{
		{"empty", "", "stdout is empty"},
		{"whitespace", " \n\t\n", "stdout is empty"},
		{"text", "collected 3 users\n", "stdout is not JSON (18 bytes)"},
		{"truncated JSON", `{"type":"epack_result","protocol_version":1,"artifacts":[`, "stdout is not JSON"},
		{"JSON null", "null\n", "stdout is JSON null"},
		{"empty artifacts", `{"type":"epack_result","protocol_version":1,"artifacts":[]}`, "the result lists no artifacts"},
		{"null artifacts", `{"type":"epack_result","protocol_version":1,"artifacts":null}`, "the result lists no artifacts"},
		{"untyped envelope with empty artifacts", `{"protocol_version":1,"artifacts":[]}`, "the result lists no artifacts"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output, err := ParseCollectorOutput([]byte(tt.output))
			if err == nil {
				t.Fatalf("ParseCollectorOutput() = %+v, want an error", output)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %q, want it to contain %q", err, tt.want)
			}
		})
	}
}

// runScriptCollector runs script as a pinned external collector named name.
func runScriptCollector(t *testing.T, name, script string, opts RunOptions) RunResult {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("script collectors need a POSIX shell")
	}
	dir := t.TempDir()
	scriptPath := filepath.Join(dir, name)
	if err := os.WriteFile(scriptPath, []byte("#!/bin/sh\n"+script), 0o755); err != nil {
		t.Fatal(err)
	}
	digest, err := sync.ComputeDigest(scriptPath)
	if err != nil {
		t.Fatal(err)
	}
	platformKey := platform.Key(runtime.GOOS, runtime.GOARCH)
	lf := lockfile.New()
	lf.Collectors[name] = lockfile.LockedCollector{
		Kind:      "external",
		Platforms: map[string]componenttypes.LockedPlatform{platformKey: {Digest: digest}},
	}
	runner := &Runner{BaseDir: dir}
	result := runner.runOne(context.Background(), nil, singleCollectorRun{
		Name:           name,
		Config:         config.CollectorConfig{Binary: scriptPath},
		CollectorIndex: 1,
		CollectorTotal: 1,
	}, lf, platformKey, opts)
	t.Cleanup(func() { _ = (&CollectResult{Results: []RunResult{result}}).Close() })
	return result
}

func TestRunOne_FailsAnExitZeroWithoutEvidence(t *testing.T) {
	tests := []struct {
		name   string
		script string
		want   string
	}{
		{"text", "echo 'collected 3 users'\n", "stdout is not JSON"},
		{"nothing", "exit 0\n", "stdout is empty"},
		{"progress only", `echo '{"type":"epack_progress","protocol_version":1,"kind":"status","message":"Connecting"}'` + "\n", "stdout is empty"},
		{"no artifacts", `echo '{"type":"epack_result","protocol_version":1,"artifacts":[]}'` + "\n", "the result lists no artifacts"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := runScriptCollector(t, "okta", tt.script, RunOptions{})
			if result.Success {
				t.Fatal("a collector that exits 0 without evidence must fail")
			}
			if got := epackerrors.CodeOf(result.Error); got != epackerrors.CollectorOutputInvalid {
				t.Errorf("code = %q, want %q", got, epackerrors.CollectorOutputInvalid)
			}
			want := "collector exited 0 without a usable result: " + tt.want
			if !strings.Contains(result.Error.Error(), want) {
				t.Errorf("error = %q, want it to contain %q", result.Error, want)
			}
			if result.Output != nil {
				t.Error("a failed collector keeps no output")
			}
		})
	}
}

func TestRunOne_AcceptsAnEnvelopeWithArtifacts(t *testing.T) {
	result := runScriptCollector(t, "okta", `echo '{"type":"epack_result","protocol_version":1,"artifacts":[{"data":{"users":3}}]}'`+"\n", RunOptions{})
	if !result.Success {
		t.Fatalf("runOne() failed: %v", result.Error)
	}
}

func TestFailures_ClassEachCollectorByItsExitCode(t *testing.T) {
	tests := []struct {
		exit int
		code epackerrors.Code
	}{
		{1, epackerrors.CollectorError},
		{2, epackerrors.CollectorConfigInvalid},
		{3, epackerrors.CollectorAuthFailed},
		{4, epackerrors.NetworkError},
		{7, epackerrors.CollectorError},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("exit %d", tt.exit), func(t *testing.T) {
			result := runScriptCollector(t, "okta", fmt.Sprintf("echo 'request failed' >&2\nexit %d\n", tt.exit), RunOptions{})
			failures := Failures([]RunResult{result})
			if len(failures) != 1 {
				t.Fatalf("failures = %+v, want one", failures)
			}
			f := failures[0]
			if f.Collector != "okta" || f.Code != tt.code || f.Exit != tt.exit || f.CodeSource != CodeFromExit {
				t.Errorf("failure = {%s %s %d %s}, want {okta %s %d exit_code}", f.Collector, f.Code, f.Exit, f.CodeSource, tt.code, tt.exit)
			}
			if want := fmt.Sprintf("exited with code %d: request failed", tt.exit); f.Message() != want {
				t.Errorf("message = %q, want %q", f.Message(), want)
			}
		})
	}
}

func TestFailures_ACollectorEndedBySignalHasNoExitCode(t *testing.T) {
	result := runScriptCollector(t, "okta", "kill -KILL $$\n", RunOptions{})
	failures := Failures([]RunResult{result})
	if len(failures) != 1 || failures[0].Code != epackerrors.CollectorError || failures[0].Exit != -1 {
		t.Fatalf("failures = %+v, want collector_error with exit -1", failures)
	}
	_, exit := exitmap.ToExit(&FailedError{Failures: failures})
	if exit != exitcode.General {
		t.Errorf("epack exit = %d, want %d: -1 is not an exit status", exit, exitcode.General)
	}
}

func TestFailures_KeepTheRunnerTimeout(t *testing.T) {
	result := runScriptCollector(t, "okta", "sleep 5\n", RunOptions{Secure: SecureRunOptions{Timeout: 200 * time.Millisecond}})
	failures := Failures([]RunResult{result})
	if len(failures) != 1 || failures[0].Code != epackerrors.Timeout || failures[0].Exit != exitcode.Timeout || failures[0].CodeSource != CodeFromRunner {
		t.Fatalf("failures = %+v, want timeout with exit %d from the runner", failures, exitcode.Timeout)
	}
}

func TestFailures_KeepEpackCodesAndSkipSuccesses(t *testing.T) {
	results := []RunResult{
		{Collector: "tls", Success: true},
		{Collector: "github", Error: epackerrors.WithHint(epackerrors.BinaryNotFound, exitcode.MissingBinary, `collector "github" not installed`, "Run 'epack collector sync'", nil)},
		{Collector: "sentry", Error: errors.New("creating collector staging dir: disk full")},
	}
	failures := Failures(results)
	if len(failures) != 2 {
		t.Fatalf("failures = %+v, want two", failures)
	}
	if f := failures[0]; f.Collector != "github" || f.Code != epackerrors.BinaryNotFound || f.Exit != exitcode.MissingBinary {
		t.Errorf("failure = %+v, want github binary_not_found %d", f, exitcode.MissingBinary)
	}
	if f := failures[1]; f.Collector != "sentry" || f.Code != epackerrors.CollectorError || f.Exit != exitcode.General {
		t.Errorf("failure = %+v, want sentry collector_error 1", f)
	}
}

func TestFailedError_OneCollectorKeepsItsCodeAndExit(t *testing.T) {
	result := runScriptCollector(t, "okta", "echo '401 Unauthorized' >&2\nexit 3\n", RunOptions{})
	var err error = &FailedError{Failures: Failures([]RunResult{result})}

	// epack run wraps the collect error in its stage error; the collect
	// commands pass it through cmdutil.HandleError.
	for name, wrapped := range map[string]error{
		"collect":     cmdutil.HandleError(err),
		"stage error": cmdutil.HandleError(fmt.Errorf("collect failed: %w", err)),
	} {
		t.Run(name, func(t *testing.T) {
			if got := epackerrors.CodeOf(wrapped); got != epackerrors.CollectFailed {
				t.Errorf("code = %q, want %q", got, epackerrors.CollectFailed)
			}
			msg, exit := exitmap.ToExit(wrapped)
			if exit != 3 {
				t.Errorf("exit = %d, want the collector's 3", exit)
			}
			if !strings.HasSuffix(msg, "okta: exited with code 3: 401 Unauthorized") {
				t.Errorf("message = %q", msg)
			}

			path := filepath.Join(t.TempDir(), "error.txt")
			if werr := exitmap.WriteErrorFile(path, wrapped); werr != nil {
				t.Fatal(werr)
			}
			data, rerr := os.ReadFile(path)
			if rerr != nil {
				t.Fatal(rerr)
			}
			want := "code=collect_failed\nexit=3\nsummary=" + msg + "\ncollector=okta code=auth_failed exit=3 code_source=exit_code\n"
			if string(data) != want {
				t.Errorf("error file = %q, want %q", data, want)
			}
		})
	}
}

func TestFailedError_ExitsWithOneCollectorsCode(t *testing.T) {
	tests := []struct {
		name string
		code epackerrors.Code
		exit int
		want int
	}{
		{"protocol exit passes through", epackerrors.CollectorAuthFailed, 3, 3},
		{"collector-specific exit passes through", epackerrors.CollectorError, 7, 7},
		{"general exit", epackerrors.CollectorError, 1, exitcode.General},
		{"a collector exit outside 2-9 never reads as epack's", epackerrors.CollectorError, exitcode.Timeout, exitcode.General},
		{"epack's timeout", epackerrors.Timeout, exitcode.Timeout, exitcode.Timeout},
		{"epack's missing binary", epackerrors.BinaryNotFound, exitcode.MissingBinary, exitcode.MissingBinary},
		{"unusable output", epackerrors.CollectorOutputInvalid, exitcode.General, exitcode.General},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := &FailedError{Failures: []Failure{{Collector: "okta", Code: tt.code, Exit: tt.exit, Err: errors.New("failed")}}}
			if _, exit := exitmap.ToExit(err); exit != tt.want {
				t.Errorf("exit = %d, want %d", exit, tt.want)
			}
		})
	}
}

func TestFailedError_SeveralCollectorsExitOne(t *testing.T) {
	err := &FailedError{Failures: []Failure{
		{Collector: "okta", Code: epackerrors.CollectorAuthFailed, Exit: 3, CodeSource: CodeFromExit, Err: errors.New("collector exited with code 3: 401")},
		{Collector: "sentry", Code: epackerrors.Timeout, Exit: exitcode.Timeout, CodeSource: CodeFromRunner, Err: errors.New(`collector "sentry" timed out after 10m0s`)},
	}}
	msg, exit := exitmap.ToExit(err)
	if msg != "2 collectors failed: okta, sentry" || exit != exitcode.General {
		t.Errorf("ToExit() = %q, %d", msg, exit)
	}

	path := filepath.Join(t.TempDir(), "error.txt")
	if werr := exitmap.WriteErrorFile(path, err); werr != nil {
		t.Fatal(werr)
	}
	data, rerr := os.ReadFile(path)
	if rerr != nil {
		t.Fatal(rerr)
	}
	want := "code=collect_failed\nexit=1\nsummary=2 collectors failed: okta, sentry\n" +
		"collector=okta code=auth_failed exit=3 code_source=exit_code\n" +
		fmt.Sprintf("collector=sentry code=timeout exit=%d code_source=runner\n", exitcode.Timeout)
	if string(data) != want {
		t.Errorf("error file = %q, want %q", data, want)
	}
}

func TestRunAndBuild_ReturnsTheFailedCollectors(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("script collectors need a POSIX shell")
	}
	dir := t.TempDir()
	scriptPath := filepath.Join(dir, "okta")
	if err := os.WriteFile(scriptPath, []byte("#!/bin/sh\necho 'tenant is required' >&2\nexit 2\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := &config.JobConfig{
		Stream:     "acme/prod",
		Collectors: map[string]config.CollectorConfig{"okta": {Binary: scriptPath}},
	}

	result, err := RunAndBuild(context.Background(), cfg, RunAndBuildOpts{
		WorkDir:    dir,
		OutputPath: filepath.Join(dir, "evidence.epack"),
		Unsafe:     UnsafeOverrides{AllowUnpinned: true},
	})
	var failed *FailedError
	if !errors.As(err, &failed) {
		t.Fatalf("RunAndBuild() error = %v, want a *FailedError", err)
	}
	if len(failed.Failures) != 1 || failed.Failures[0].Code != epackerrors.CollectorConfigInvalid || failed.Failures[0].Exit != 2 {
		t.Errorf("failures = %+v, want okta config_invalid 2", failed.Failures)
	}
	if result == nil || result.Failures != 1 {
		t.Errorf("result = %+v, want one failure", result)
	}
	if _, statErr := os.Stat(filepath.Join(dir, "evidence.epack")); statErr == nil {
		t.Error("no pack should be built when a collector fails")
	}
}

func TestFailures_PreferTheCodeTheCollectorReported(t *testing.T) {
	script := `echo '{"type":"epack_progress","protocol_version":1,"kind":"failure","message":"Defender returned 500","code":"vendor_error","owner":"vendor","vendor_code":"InternalError"}'
echo 'request failed' >&2
exit 4
`
	result := runScriptCollector(t, "microsoft-cloud", script, RunOptions{})
	failures := Failures([]RunResult{result})
	if len(failures) != 1 {
		t.Fatalf("failures = %+v, want one", failures)
	}
	f := failures[0]
	if f.Code != "vendor_error" || f.Exit != 4 || f.CodeSource != CodeFromCollector {
		t.Errorf("failure = {%s %d %s}, want {vendor_error 4 collector}", f.Code, f.Exit, f.CodeSource)
	}
	if f.Message() != "exited with code 4: request failed" {
		t.Errorf("message = %q, want the exit error's", f.Message())
	}
	var reported *ReportedFailure
	if !errors.As(result.Error, &reported) || reported.VendorCode != "InternalError" || reported.Owner != "vendor" {
		t.Errorf("reported = %+v", reported)
	}
}

func TestFailures_IgnoreAReportedCodeOutsideTheList(t *testing.T) {
	script := `echo '{"type":"epack_progress","protocol_version":1,"kind":"failure","message":"x","code":"made_up"}'
exit 3
`
	result := runScriptCollector(t, "okta", script, RunOptions{})
	failures := Failures([]RunResult{result})
	if len(failures) != 1 || failures[0].Code != epackerrors.CollectorAuthFailed || failures[0].CodeSource != CodeFromExit {
		t.Fatalf("failures = %+v, want the exit code's class", failures)
	}
}

func TestRunOne_PassesTheRunIDAndDeadline(t *testing.T) {
	script := `printf '{"type":"epack_result","protocol_version":1,"artifacts":[{"data":{"run":"%s","deadline":"%s"}}]}\n' "$EPACK_RUN_ID" "$EPACK_DEADLINE"
`
	before := time.Now()
	result := runScriptCollector(t, "okta", script, RunOptions{RunID: "run-123", Secure: SecureRunOptions{Timeout: time.Minute}})
	if !result.Success {
		t.Fatalf("runOne() failed: %v", result.Error)
	}
	parsed, err := ParseCollectorOutput(result.Output)
	if err != nil {
		t.Fatal(err)
	}
	var data struct {
		Run      string `json:"run"`
		Deadline string `json:"deadline"`
	}
	if err := json.Unmarshal(parsed.Artifacts[0].RawData, &data); err != nil {
		t.Fatal(err)
	}
	if data.Run != "run-123" {
		t.Errorf("EPACK_RUN_ID = %q", data.Run)
	}
	deadline, err := time.Parse(time.RFC3339Nano, data.Deadline)
	if err != nil {
		t.Fatalf("EPACK_DEADLINE = %q: %v", data.Deadline, err)
	}
	if deadline.Before(before.Add(59*time.Second)) || deadline.After(time.Now().Add(61*time.Second)) {
		t.Errorf("EPACK_DEADLINE = %s, want about a minute from the start", deadline)
	}
}
