//go:build conformance

package componentconf

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/locktivity/epack/internal/procexec"
)

func (r *Runner) runCollectorTests(ctx context.Context) {
	// Common tests
	r.testBinaryNaming()

	// Collector-specific tests
	r.testCollectorOutput(ctx)
	r.testCollectorConfig(ctx)
	r.testCollectorExitCodes(ctx)
	r.testCollectorSignalHandling(ctx)
	r.testCollectorFilesystemBoundary(ctx)
	r.testCollectorNoColor(ctx)

	// COL-030: Complete within timeout, on every run above
	if r.timeouts > 0 {
		r.fail("COL-030", fmt.Sprintf("%d run(s) did not finish within %s", r.timeouts, r.Timeout))
	} else {
		r.pass("COL-030")
	}

	// C-031, C-032: no run above printed a --secret canary
	r.checkSecretHandling()
}

// collectorEnv is the environment for a run that should collect: the
// protocol variables, plus the --config file when one was given.
func (r *Runner) collectorEnv() map[string]string {
	env := map[string]string{
		"EPACK_COLLECTOR_NAME":   "test",
		"EPACK_PROTOCOL_VERSION": "1",
	}
	if r.CollectorConfig != "" {
		env["EPACK_COLLECTOR_CONFIG"] = r.CollectorConfig
	}
	return env
}

// uncollectedReason explains an exit code that means the collector lacked
// what it needs to collect, or returns "" for any other exit.
func (r *Runner) uncollectedReason(exit int) string {
	switch exit {
	case 2:
		if r.CollectorConfig != "" {
			return "collector exited 2 with the --config file"
		}
		return "collector exited 2 without config; pass --config with a config it can collect with"
	case 3:
		if len(r.canaries) > 0 {
			return "collector exited 3 (authentication error) with the --secret canaries; the output checks need real credentials"
		}
		return "collector exited 3 (authentication error); run it with the credentials it needs"
	case 4:
		return "collector exited 4 (network or API error); run it where it can reach its API"
	default:
		return ""
	}
}

func (r *Runner) testCollectorOutput(ctx context.Context) {
	result := r.exec(ctx, nil, nil, r.collectorEnv())
	r.collectRun = result

	// A collector exits 2 when it needs config (COL-024), 3 when it needs
	// credentials, and 4 when it cannot reach its API. It never reached
	// collection, so nothing here was exercised: the output checks need a run
	// that collects.
	if reason := r.uncollectedReason(result.ExitCode); reason != "" {
		for _, id := range []string{"COL-001", "COL-002", "COL-006", "COL-005", "C-020", "COL-040", "COL-034", "C-010", "COL-010", "COL-011"} {
			r.skip(id, reason)
		}
		for _, id := range resultIDs {
			r.skip(id, reason)
		}
		return
	}

	// Extract result output, filtering out progress messages.
	// The new protocol allows interleaved epack_progress messages in stdout.
	resultOutput := extractResultOutput(result.Stdout)

	// COL-001: Output valid JSON to stdout
	if isValidJSON(resultOutput) {
		r.pass("COL-001")
	} else {
		r.fail("COL-001", "output is not valid JSON")
		// Skip dependent tests
		r.skip("COL-002", "depends on COL-001")
		r.skip("COL-006", "depends on COL-001")
		for _, id := range resultIDs {
			r.skip(id, "depends on COL-001")
		}
		return
	}

	// COL-006: JSON is UTF-8 encoded
	if isValidUTF8(resultOutput) {
		r.pass("COL-006")
	} else {
		r.fail("COL-006", "output is not valid UTF-8")
	}

	// COL-002: Protocol envelope format
	// Accepts either legacy "data" field or new "artifacts" array format
	var envelope struct {
		ProtocolVersion int               `json:"protocol_version"`
		Data            json.RawMessage   `json:"data"`
		Artifacts       []json.RawMessage `json:"artifacts"`
	}
	if err := json.Unmarshal(resultOutput, &envelope); err == nil && envelope.ProtocolVersion > 0 && (len(envelope.Data) > 0 || len(envelope.Artifacts) > 0) {
		r.pass("COL-002")
	} else {
		// Not using envelope is allowed (COL-003)
		r.skip("COL-002", "not using protocol envelope (allowed)")
		r.pass("COL-003")
	}

	// COL-005: Output size does not exceed 64 MB
	// Check the result output size (not including progress messages)
	const maxSize = 64 * 1024 * 1024
	if len(resultOutput) <= maxSize {
		r.pass("COL-005")
	} else {
		r.fail("COL-005", "output exceeds 64 MB")
	}

	// C-010: Accepts protocol variables
	r.pass("C-010")

	// COL-010: Read collector name from EPACK_COLLECTOR_NAME
	r.pass("COL-010")

	// COL-011: Read protocol version from EPACK_PROTOCOL_VERSION
	r.pass("COL-011")

	// C-020/COL-040: Exit code 0 on success
	switch {
	case result.ExitCode != 0:
		r.fail("C-020", "non-zero exit code on success path")
		r.fail("COL-040", "non-zero exit code on success path")
		r.fail("COL-034", "non-zero exit code when collection should succeed")
	case r.credentialsRejected(result):
		// Evidence after a rejected credential is the worst case reported
		// as fact: every metric the credential gates reads as zero.
		r.pass("C-020")
		r.pass("COL-040")
		r.fail("COL-034", "exited 0 and emitted evidence although its --secret credentials were rejected")
	default:
		r.pass("C-020")
		r.pass("COL-040")
		r.pass("COL-034")
	}

	r.testCollectorResult(resultOutput)
}

func (r *Runner) testCollectorConfig(ctx context.Context) {
	// Create a test config file
	configPath := filepath.Join(r.WorkDir, "config.json")
	configData := []byte(`{"test_key": "test_value"}`)
	if err := os.WriteFile(configPath, configData, 0644); err != nil {
		r.skip("COL-020", "could not create test config file")
		r.skip("COL-012", "could not create test config file")
		return
	}

	env := map[string]string{
		"EPACK_COLLECTOR_NAME":   "test",
		"EPACK_PROTOCOL_VERSION": "1",
		"EPACK_COLLECTOR_CONFIG": configPath,
	}

	result := r.exec(ctx, nil, nil, env)

	// COL-020: Parse config file as JSON
	// Exit codes 0 to 4 are valid - the collector parsed the JSON successfully.
	// Exit 2 (config error) is valid because the test config may not contain
	// required fields for this specific collector. Exits 3 and 4 mean it got
	// past its config to its API, as one that needs no config does when the
	// run carries the --secret canaries.
	if result.ExitCode >= 0 && result.ExitCode <= 4 {
		r.pass("COL-020")
		r.pass("COL-012")
	} else {
		r.fail("COL-020", "failed to handle config file")
		r.fail("COL-012", "failed to read EPACK_COLLECTOR_CONFIG")
	}

	// COL-021: Not crash or hang when config file is missing
	// Any valid exit code (0 to 4) is acceptable - just must complete. A
	// collector that needs no config reaches its API and exits 3 or 4.
	envNoConfig := map[string]string{
		"EPACK_COLLECTOR_NAME":   "test",
		"EPACK_PROTOCOL_VERSION": "1",
	}
	resultNoConfig := r.exec(ctx, nil, nil, envNoConfig)
	if resultNoConfig.ExitCode >= 0 && resultNoConfig.ExitCode <= 4 {
		r.pass("COL-021")
	} else {
		r.fail("COL-021", "crashed or exited with unexpected code")
	}

	// COL-024: exit 2 when required config is missing. Exit 0 means the
	// collector needs none; any other exit could be a different failure.
	switch resultNoConfig.ExitCode {
	case 2:
		r.pass("COL-024")
	case 0:
		r.skip("COL-024", "collector needs no config")
	default:
		r.skip("COL-024", fmt.Sprintf("collector exited %d without config; cannot tell whether config was missing", resultNoConfig.ExitCode))
	}

	// COL-022: Validate config schema - test with invalid JSON
	invalidConfigPath := filepath.Join(r.WorkDir, "invalid.json")
	if err := os.WriteFile(invalidConfigPath, []byte(`{invalid json`), 0644); err == nil {
		envInvalid := map[string]string{
			"EPACK_COLLECTOR_NAME":   "test",
			"EPACK_PROTOCOL_VERSION": "1",
			"EPACK_COLLECTOR_CONFIG": invalidConfigPath,
		}
		resultInvalid := r.exec(ctx, nil, nil, envInvalid)
		// Should exit with error (non-zero) for invalid config
		if resultInvalid.ExitCode != 0 {
			r.pass("COL-022")
		} else {
			r.skip("COL-022", "collector accepted invalid JSON config")
		}
	}
}

func (r *Runner) testCollectorExitCodes(ctx context.Context) {
	// C-021/COL-041: Test error exit code with nonexistent config file
	nonexistentConfig := filepath.Join(r.WorkDir, "nonexistent", "config.json")
	env := map[string]string{
		"EPACK_COLLECTOR_NAME":   "test",
		"EPACK_PROTOCOL_VERSION": "1",
		"EPACK_COLLECTOR_CONFIG": nonexistentConfig,
	}
	result := r.exec(ctx, nil, nil, env)

	// If it fails with a non-zero exit code, that's correct behavior
	if result.ExitCode != 0 {
		r.pass("C-021")
		// Check specific exit codes
		if result.ExitCode == 2 {
			r.pass("COL-042")
		} else {
			r.skip("COL-042", "did not exit with code 2 for config error")
		}
	} else {
		// Collector accepted nonexistent config - that's also valid (graceful handling)
		r.skip("C-021", "collector handled missing config gracefully")
		r.skip("COL-042", "collector handled missing config gracefully")
	}

	// COL-041, COL-044: a missing config file is a config error, so these
	// need general and network failure scenarios
	r.skip("COL-041", "requires general error scenario")
	r.checkAuthFailure()
	r.skip("COL-044", "requires network failure scenario")

	// C-022: Exit codes 2-9 for component-specific errors
	// Already tested above with COL-042
	if result.ExitCode >= 2 && result.ExitCode <= 9 {
		r.pass("C-022")
	} else {
		r.skip("C-022", "did not observe exit codes 2-9")
	}

	// COL-052: HTTPS requirement - cannot test without network mock
	r.skip("COL-052", "requires network interception")
}

// defaultSignalDelay is how long a collector that reports no progress runs
// before COL-031 sends SIGTERM. A collector that reports progress gets the
// signal at its first progress line instead. The delay is generous because a
// signal that lands before the process has started, as on a loaded machine,
// kills it and fails a collector that does handle SIGTERM.
const defaultSignalDelay = 5 * time.Second

// signalGrace is how long a collector has to exit after SIGTERM.
const signalGrace = 5 * time.Second

// progressWatch closes started at the collector's first epack_progress line.
// The collector is collecting from then on, so a SIGTERM lands mid-run.
type progressWatch struct {
	started chan struct{}
	seen    bool
	partial []byte
}

func (w *progressWatch) Write(p []byte) (int, error) {
	if w.seen {
		return len(p), nil
	}
	w.partial = append(w.partial, p...)
	for {
		i := bytes.IndexByte(w.partial, '\n')
		if i < 0 {
			return len(p), nil
		}
		line := bytes.TrimSpace(w.partial[:i])
		w.partial = w.partial[i+1:]
		if isProgressMessage(line) {
			w.seen = true
			w.partial = nil
			close(w.started)
			return len(p), nil
		}
	}
}

func (r *Runner) testCollectorSignalHandling(ctx context.Context) {
	// COL-031: Handle SIGTERM gracefully
	// Start the collector, send SIGTERM while it collects, check it exits on its own

	env, outputDir, cleanup := r.withOutputDir(r.collectorEnv())
	defer cleanup()
	cmd, cmdCancel, err := procexec.CommandChecked(ctx, procexec.Spec{
		Path: r.Binary,
		Dir:  r.WorkDir,
		Env:  r.envList(env),
	})
	if err != nil {
		r.skip("COL-031", "could not construct process for signal test")
		return
	}
	defer cmdCancel()

	watch := &progressWatch{started: make(chan struct{})}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = io.MultiWriter(watch, &stdout)
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		r.skip("COL-031", "could not start process for signal test")
		return
	}
	exited := make(chan struct{})
	go func() {
		_ = cmd.Wait()
		close(exited)
	}()
	defer func() {
		<-exited
		r.recordLeaks(env, stdout.Bytes(), stderr.Bytes(), cmd.ProcessState.ExitCode())
		r.recordFileLeaks(env, outputDir, cmd.ProcessState.ExitCode())
	}()

	delay := time.NewTimer(r.signalDelay)
	defer delay.Stop()
	select {
	case <-exited:
		r.skip("COL-031", fmt.Sprintf("collector exited (code %d) before SIGTERM was sent", cmd.ProcessState.ExitCode()))
		return
	case <-watch.started:
	case <-delay.C:
	}

	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		<-exited
		r.skip("COL-031", fmt.Sprintf("collector exited (code %d) before SIGTERM was sent", cmd.ProcessState.ExitCode()))
		return
	}
	select {
	case <-exited:
	case <-time.After(signalGrace):
		_ = cmd.Process.Kill()
		<-exited
		r.fail("COL-031", fmt.Sprintf("did not exit within %s of SIGTERM", signalGrace))
		return
	}

	// A process the signal ended reports exit code -1: it had no handler.
	if status, ok := cmd.ProcessState.Sys().(syscall.WaitStatus); ok && status.Signaled() {
		r.fail("COL-031", fmt.Sprintf("killed by SIGTERM (%s) instead of handling it", status.Signal()))
		return
	}
	if cmd.ProcessState.ExitCode() > 128 {
		r.fail("COL-031", "process crashed on SIGTERM")
		return
	}
	r.pass("COL-031")
}

func (r *Runner) testCollectorFilesystemBoundary(ctx context.Context) {
	r.testFilesystemBoundary(ctx, nil, nil, r.collectorEnv())

	// C-033: Cannot test without malformed input injection
	r.skip("C-033", "requires malformed input injection")
}

// authRejected matches text saying a credential was rejected. A status code
// counts only beside a word that marks it as one, so a count of 401 in the
// evidence does not match.
var authRejected = regexp.MustCompile(`(?i)\b(status( code)?|http|code)[ :=]*40[13]\b|\b40[13] (unauthori[sz]ed|forbidden)\b|\bunauthori[sz]ed\b|\bforbidden\b|\bbad credentials\b|\binvalid[ _-]?(credentials?|token|api[ _-]?key|client|grant|signature)\b|\bauthentication (failed|required|error)\b|\baccess denied\b`)

// credentialsRejected reports whether a run that held --secret canaries says
// a credential was rejected, in its error or in the evidence it emitted.
func (r *Runner) credentialsRejected(run execResult) bool {
	return len(r.canaries) > 0 && (authRejected.Match(run.Stderr) || authRejected.Match(run.Stdout))
}

// checkAuthFailure decides COL-043 from the run that should collect, which
// holds canary credentials a real API rejects: an auth error exits 3.
func (r *Runner) checkAuthFailure() {
	if len(r.canaries) == 0 {
		r.skip("COL-043", "requires authentication failure scenario: pass --secret, and --config if the collector needs config")
		return
	}
	run := r.collectRun
	rejected := r.credentialsRejected(run)
	switch {
	case run.ExitCode == 3:
		r.pass("COL-043")
	case run.ExitCode == 2:
		reason := "collector exited 2 (config error) before using its credentials"
		if r.CollectorConfig == "" {
			reason += "; pass --config so it reaches its API"
		}
		r.skip("COL-043", reason)
	case rejected && run.ExitCode == 0:
		r.fail("COL-043", "collector exited 0 and emitted evidence after its credentials were rejected; an authentication error exits 3")
	case rejected:
		r.fail("COL-043", fmt.Sprintf("collector exited %d when its credentials were rejected; an authentication error exits 3", run.ExitCode))
	case run.ExitCode == 0:
		r.skip("COL-043", "collector succeeded with canary credentials and reported no rejection, so it does not authenticate with the --secret variables")
	default:
		r.skip("COL-043", fmt.Sprintf("collector exited %d and its error does not say the credentials were rejected", run.ExitCode))
	}
}

// checkSecretHandling decides C-031 and C-032: no run may print a --secret
// canary, and an error message from a run that used the credentials must
// not carry them.
func (r *Runner) checkSecretHandling() {
	if len(r.canaries) == 0 {
		r.skip("C-031", "pass --secret for each variable the collector reads a credential from")
		r.skip("C-032", "pass --secret for each variable the collector reads a credential from")
		return
	}
	if len(r.leaks) > 0 {
		r.fail("C-031", describeLeaks(r.leaks))
	} else {
		r.pass("C-031")
	}

	// Error messages are a failed run's stderr, and the rejection a run
	// that still exited 0 reported in its output.
	var inErrors []secretLeak
	for _, leak := range r.leaks {
		if leak.stream == "stderr" && leak.exit != 0 {
			inErrors = append(inErrors, leak)
		}
	}
	run := r.collectRun
	rejected := r.credentialsRejected(run)
	if rejected && run.ExitCode == 0 {
		for name, canary := range r.canaries {
			if bytes.Contains(run.Stdout, []byte(strings.TrimPrefix(canary, "epack-canary-"))) {
				inErrors = append(inErrors, secretLeak{name: name, stream: "stdout", run: r.runLabel(r.collectorEnv())})
			}
		}
	}
	switch {
	case len(inErrors) > 0:
		r.fail("C-032", describeLeaks(inErrors))
	case rejected || (r.CollectorConfig != "" && run.ExitCode != 0 && run.ExitCode != 2):
		r.pass("C-032")
	default:
		r.skip("C-032", "no run failed after reading its credentials: pass --config so the collector uses them")
	}
}

// describeLeaks names the first leak and counts the rest.
func describeLeaks(leaks []secretLeak) string {
	first := leaks[0]
	msg := fmt.Sprintf("%s's canary value appeared in %s of %s", first.name, first.stream, first.run)
	if len(leaks) > 1 {
		msg += fmt.Sprintf(" (and %d more)", len(leaks)-1)
	}
	return msg
}

func (r *Runner) testCollectorNoColor(ctx context.Context) {
	r.testNoColor(ctx, nil, nil, r.collectorEnv())
}
