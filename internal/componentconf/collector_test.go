//go:build conformance

package componentconf

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/locktivity/epack/internal/componenttypes"
)

// needsConfig exits 2 without a config naming a tenant, and collects with one.
const needsConfig = `if [ -z "$EPACK_COLLECTOR_CONFIG" ]; then echo "tenant_id is required" >&2; exit 2; fi
if ! grep -q '"tenant_id"' "$EPACK_COLLECTOR_CONFIG" 2>/dev/null; then echo "invalid config" >&2; exit 2; fi
echo '{"type":"epack_progress","protocol_version":1,"kind":"status","message":"Collecting"}'
echo '{"type":"epack_result","protocol_version":1,"artifacts":[{"data":{"collector":"'"$EPACK_COLLECTOR_NAME"'"}}]}'
`

// outputChecks need a run that collects.
var outputChecks = []string{"COL-001", "COL-002", "COL-006", "COL-005", "C-020", "COL-040", "COL-034", "C-010", "COL-010", "COL-011"}

func writeCollector(t *testing.T, name, script string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fixture collectors are shell scripts")
	}
	path := filepath.Join(t.TempDir(), "epack-collector-"+name)
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func runCollectorConformance(t *testing.T, runner *Runner) map[string]TestResult {
	t.Helper()
	runner.Timeout = 10 * time.Second
	report, err := runner.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() = %v", err)
	}
	byID := make(map[string]TestResult, len(report.Results))
	for _, result := range report.Results {
		byID[result.ID] = result
	}
	return byID
}

func TestCollectorOutput_ExitTwoWithoutConfigSkipsWhatItCannotCheck(t *testing.T) {
	results := runCollectorConformance(t, NewRunner(writeCollector(t, "needs-config", needsConfig), componenttypes.KindCollector))

	for _, id := range outputChecks {
		got := results[id]
		if got.Status != StatusSkip || !strings.Contains(got.Reason, "--config") {
			t.Errorf("%s = %s (%s), want a skip that names --config", id, got.Status, got.Reason)
		}
	}
	if got := results["COL-024"]; got.Status != StatusPass {
		t.Errorf("COL-024 = %s (%s), want pass: the collector exited 2 without config", got.Status, got.Reason)
	}
	if got := results["COL-031"]; got.Status != StatusSkip {
		t.Errorf("COL-031 = %s, want a skip: the collector exited before SIGTERM", got.Status)
	}
	if got := results["COL-041"]; got.Status != StatusSkip {
		t.Errorf("COL-041 = %s, want a skip: a missing config file is not a general error", got.Status)
	}
	if got := results["COL-030"]; got.Status != StatusPass {
		t.Errorf("COL-030 = %s (%s), want pass", got.Status, got.Message)
	}
	for _, id := range []string{"C-031", "C-032", "COL-043"} {
		if got := results[id]; got.Status != StatusSkip || !strings.Contains(got.Reason, "--secret") {
			t.Errorf("%s = %s (%s), want a skip that asks for --secret", id, got.Status, got.Reason)
		}
	}
}

func TestCollectorTimeout_FailsCOL030(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(configPath, []byte(`{"hang":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	runner := NewRunner(writeCollector(t, "hangs", `if [ -n "$EPACK_COLLECTOR_CONFIG" ] && grep -q hang "$EPACK_COLLECTOR_CONFIG"; then exec sleep 30; fi
exit 2
`), componenttypes.KindCollector)
	runner.CollectorConfig = configPath
	runner.Timeout = 300 * time.Millisecond
	runner.signalDelay = 200 * time.Millisecond
	report, err := runner.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, result := range report.Results {
		if result.ID == "COL-030" {
			if result.Status != StatusFail || !strings.Contains(result.Message, "did not finish within 300ms") {
				t.Errorf("COL-030 = %s (%s), want a failure naming the timeout", result.Status, result.Message)
			}
			return
		}
	}
	t.Fatal("no COL-030 result")
}

func TestCollectorOutput_ConfigRunsTheOutputChecks(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(configPath, []byte(`{"tenant_id":"contoso"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	runner := NewRunner(writeCollector(t, "needs-config", needsConfig), componenttypes.KindCollector)
	runner.CollectorConfig = configPath
	results := runCollectorConformance(t, runner)

	for _, id := range outputChecks {
		if got := results[id]; got.Status != StatusPass {
			t.Errorf("%s = %s (%s%s), want pass", id, got.Status, got.Message, got.Reason)
		}
	}
	if got := results["COL-024"]; got.Status != StatusPass {
		t.Errorf("COL-024 = %s (%s), want pass", got.Status, got.Reason)
	}
}

// With the --secret credentials in place, exit 2 means the collector rejected
// the config it should collect with.
func TestCollectorOutput_RejectedConfigFails(t *testing.T) {
	t.Chdir(t.TempDir())
	if err := os.WriteFile("config.json", []byte(`{"region":"eu"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	runner := NewRunner(writeCollector(t, "needs-config", needsConfig), componenttypes.KindCollector)
	runner.CollectorConfig = "config.json"
	runner.CollectorSecrets = []string{"API_TOKEN"}
	results := runCollectorConformance(t, runner)

	for _, id := range []string{"C-020", "COL-040"} {
		if got := results[id]; got.Status != StatusFail || got.Message != "collector exited 2 (config error) with --config config.json; stderr: invalid config" {
			t.Errorf("%s = %s (%s), want a failure that names the config file", id, got.Status, got.Message)
		}
	}
	for _, id := range append([]string{"COL-001", "COL-034"}, resultIDs...) {
		if got := results[id]; got.Status != StatusSkip || got.Reason != "depends on COL-040" {
			t.Errorf("%s = %s (%s), want a skip that depends on COL-040", id, got.Status, got.Reason)
		}
	}
}

// Without credentials, exit 2 may mean only that they are missing.
func TestCollectorOutput_ExitTwoWithConfigAndNoSecretsSkips(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(configPath, []byte(`{"region":"eu"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	runner := NewRunner(writeCollector(t, "needs-config", needsConfig), componenttypes.KindCollector)
	runner.CollectorConfig = configPath
	results := runCollectorConformance(t, runner)

	for _, id := range outputChecks {
		if got := results[id]; got.Status != StatusSkip || !strings.Contains(got.Reason, "with --config "+configPath+",") || !strings.Contains(got.Reason, "pass --secret") {
			t.Errorf("%s = %s (%s), want a skip that names the config file and asks for --secret", id, got.Status, got.Reason)
		}
	}
}

func TestCollectorOutput_MissingCredentialsSkip(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(configPath, []byte(`{"tenant_id":"contoso"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	runner := NewRunner(writeCollector(t, "needs-token", "echo 'API_TOKEN is not set' >&2\nexit 3\n"), componenttypes.KindCollector)
	runner.CollectorConfig = configPath
	results := runCollectorConformance(t, runner)

	for _, id := range outputChecks {
		if got := results[id]; got.Status != StatusSkip || !strings.Contains(got.Reason, "exited 3 (authentication error)") {
			t.Errorf("%s = %s (%s%s), want a skip naming the auth error", id, got.Status, got.Message, got.Reason)
		}
	}
}

// A collector that needs no config reaches its API in the config runs too,
// with the --secret canaries, and exits as the API answers.
func TestCollectorConfig_AnAPIFailureIsNoCrash(t *testing.T) {
	for _, tt := range []struct {
		name   string
		script string
		status TestStatus
	}{
		{"the canary is rejected", "echo '401 Unauthorized' >&2\nexit 3\n", StatusPass},
		{"the API is unreachable", "echo 'dial tcp: connection refused' >&2\nexit 4\n", StatusPass},
		{"a collector-specific error", "exit 5\n", StatusFail},
	} {
		t.Run(tt.name, func(t *testing.T) {
			runner := NewRunner(writeCollector(t, "no-config", tt.script), componenttypes.KindCollector)
			runner.CollectorSecrets = []string{"API_TOKEN"}
			results := runCollectorConformance(t, runner)
			for _, id := range []string{"COL-020", "COL-021"} {
				if got := results[id]; got.Status != tt.status {
					t.Errorf("%s = %s (%s%s), want %s", id, got.Status, got.Message, got.Reason, tt.status)
				}
			}
		})
	}
}

// authCollector exits 2 without config. With one, it runs failure, unless it
// was handed the real token, which the harness must replace with its canary.
func authCollector(failure string) string {
	return `if [ -z "$EPACK_COLLECTOR_CONFIG" ]; then echo "org is required" >&2; exit 2; fi
if [ "$API_TOKEN" = "real-token-value" ]; then echo "used the real token" >&2; exit 7; fi
` + failure
}

func TestCollectorSecrets(t *testing.T) {
	tests := []struct {
		name    string
		failure string
		c031    TestStatus
		c032    TestStatus
		col043  TestStatus
		col034  TestStatus
		message string
	}{
		{
			name:    "a rejected credential exits 3 without printing it",
			failure: "echo '401 Unauthorized' >&2\nexit 3\n",
			c031:    StatusPass, c032: StatusPass, col043: StatusPass, col034: StatusSkip,
		},
		{
			name:    "the error message prints the token",
			failure: "echo \"401 Unauthorized: token $API_TOKEN rejected\" >&2\nexit 3\n",
			c031:    StatusFail, c032: StatusFail, col043: StatusPass, col034: StatusSkip,
			message: "API_TOKEN's canary value appeared in stderr of the run with --config",
		},
		{
			name:    "a rejected credential exits 4",
			failure: "echo 'GET /orgs/acme: 401 Bad credentials' >&2\nexit 4\n",
			c031:    StatusPass, c032: StatusPass, col043: StatusFail, col034: StatusSkip,
			message: "collector exited 4 when its credentials were rejected; an authentication error exits 3",
		},
		{
			name:    "a network error exits 4",
			failure: "echo 'dial tcp: lookup api.example.com: no such host' >&2\nexit 4\n",
			c031:    StatusPass, c032: StatusPass, col043: StatusSkip, col034: StatusSkip,
			message: "collector exited 4 and its error does not say the credentials were rejected",
		},
		{
			name:    "the evidence prints the token",
			failure: `echo '{"type":"epack_result","protocol_version":1,"artifacts":[{"data":{"token":"'"$API_TOKEN"'","users":401}}]}'` + "\n",
			c031:    StatusFail, c032: StatusSkip, col043: StatusSkip, col034: StatusPass,
			message: "API_TOKEN's canary value appeared in stdout of the run with --config",
		},
		{
			name: "a staged file artifact holds the token",
			failure: `mkdir -p "$EPACK_COLLECTOR_OUTPUT_DIR/docs" && echo "token=$API_TOKEN" > "$EPACK_COLLECTOR_OUTPUT_DIR/docs/token.txt"
echo '{"type":"epack_result","protocol_version":1,"artifacts":[{"file":"docs/token.txt","path":"artifacts/docs/token.txt"}]}'
`,
			c031: StatusFail, c032: StatusSkip, col043: StatusSkip, col034: StatusPass,
			message: "API_TOKEN's canary value appeared in staged file docs/token.txt of the run with --config",
		},
		{
			name:    "a file in the working directory holds the token",
			failure: "echo \"$API_TOKEN\" > debug.log\necho '401 Unauthorized' >&2\nexit 3\n",
			c031:    StatusFail, c032: StatusPass, col043: StatusPass, col034: StatusSkip,
			message: "API_TOKEN's canary value appeared in working-directory file debug.log",
		},
		{
			// A collector that downgrades a rejected credential to a warning:
			// every metric zero, the rejection only in diagnostics.
			name:    "a rejected credential still emits evidence",
			failure: `echo '{"type":"epack_result","protocol_version":1,"artifacts":[{"data":{"mfa_coverage":0,"diagnostics":{"warnings":["users: users API returned status 401"]}}}]}'` + "\n",
			c031:    StatusPass, c032: StatusPass, col043: StatusFail, col034: StatusFail,
			message: "collector exited 0 and emitted evidence after its credentials were rejected",
		},
	}
	configPath := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(configPath, []byte(`{"org":"acme"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("API_TOKEN", "real-token-value")
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runner := NewRunner(writeCollector(t, "auth", authCollector(tt.failure)), componenttypes.KindCollector)
			runner.CollectorConfig = configPath
			runner.CollectorSecrets = []string{"API_TOKEN"}
			results := runCollectorConformance(t, runner)

			if runner.collectRun.ExitCode == 7 {
				t.Fatal("the collector was handed the real token")
			}
			for id, want := range map[string]TestStatus{"C-031": tt.c031, "C-032": tt.c032, "COL-043": tt.col043, "COL-034": tt.col034} {
				if got := results[id]; got.Status != want {
					t.Errorf("%s = %s (%s%s), want %s", id, got.Status, got.Message, got.Reason, want)
				}
			}
			if tt.message == "" {
				return
			}
			for _, id := range []string{"C-031", "C-032", "COL-043"} {
				if got := results[id]; strings.Contains(got.Message+got.Reason, tt.message) {
					return
				}
			}
			t.Errorf("no C-031, C-032, or COL-043 result says %q", tt.message)
		})
	}
}

func TestCollectorSecrets_SkipWithoutConfig(t *testing.T) {
	runner := NewRunner(writeCollector(t, "auth", authCollector("exit 3\n")), componenttypes.KindCollector)
	runner.CollectorSecrets = []string{"API_TOKEN"}
	results := runCollectorConformance(t, runner)

	if got := results["C-031"]; got.Status != StatusPass {
		t.Errorf("C-031 = %s (%s), want pass: no run printed the canary", got.Status, got.Message)
	}
	for _, id := range []string{"C-032", "COL-043"} {
		if got := results[id]; got.Status != StatusSkip || !strings.Contains(got.Reason, "--config") {
			t.Errorf("%s = %s (%s), want a skip that asks for --config", id, got.Status, got.Reason)
		}
	}
}

// progressLine prints a progress message. A fixture prints it once its trap
// is in place, so COL-031 signals a process that is ready, however long the
// machine took to start it.
const progressLine = `echo '{"type":"epack_progress","protocol_version":1,"kind":"status","message":"Scanning"}'` + "\n"

func TestCollectorSignalHandling(t *testing.T) {
	tests := []struct {
		name    string
		script  string
		delay   time.Duration
		status  TestStatus
		message string
	}{
		{
			name:   "exits on SIGTERM",
			script: "trap 'echo stopping >&2; exit 1' TERM\n" + progressLine + "while :; do sleep 0.05; done\n",
			status: StatusPass,
		},
		{
			name:    "ignores SIGTERM",
			script:  "trap '' TERM\n" + progressLine + "exec sleep 30\n",
			status:  StatusFail,
			message: "did not exit within 5s of SIGTERM",
		},
		{
			name:    "exits before the signal",
			script:  "exit 2\n",
			status:  StatusSkip,
			message: "collector exited (code 2) before SIGTERM was sent",
		},
		{
			// It would finish at 300ms, long before the timed signal; only a
			// SIGTERM sent at its first progress line can kill it.
			name:    "signaled at its first progress line",
			script:  progressLine + "exec sleep 0.3\n",
			status:  StatusFail,
			message: "killed by SIGTERM",
		},
		{
			// No progress, so the timed signal; with no handler it dies
			// whether the signal beats its startup or not.
			name:    "killed by the timed SIGTERM",
			script:  "exec sleep 10\n",
			delay:   200 * time.Millisecond,
			status:  StatusFail,
			message: "killed by SIGTERM",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runner := NewRunner(writeCollector(t, "signals", tt.script), componenttypes.KindCollector)
			runner.WorkDir = t.TempDir()
			if tt.delay != 0 {
				runner.signalDelay = tt.delay
			}
			runner.testCollectorSignalHandling(context.Background())

			if len(runner.results) != 1 || runner.results[0].ID != "COL-031" {
				t.Fatalf("results = %+v, want one COL-031 result", runner.results)
			}
			got := runner.results[0]
			if got.Status != tt.status {
				t.Errorf("COL-031 = %s (%s%s), want %s", got.Status, got.Message, got.Reason, tt.status)
			}
			if detail := got.Message + got.Reason; !strings.Contains(detail, tt.message) {
				t.Errorf("COL-031 detail = %q, want it to contain %q", detail, tt.message)
			}
		})
	}
}

// resultCollector writes a collector that prints an envelope holding a data
// artifact and the given result and build file, either of which may be nil,
// and answers --capabilities with sdkCapabilities.
func resultCollector(t *testing.T, result, build map[string]any) string {
	t.Helper()
	return capsCollector(t, sdkCapabilities(), result, build)
}

// capsCollector is resultCollector with the --capabilities answer given, or
// none when caps is nil.
func capsCollector(t *testing.T, caps, result, build map[string]any) string {
	t.Helper()
	artifacts := []map[string]any{{"path": "artifacts/test.json", "data": map[string]any{"ok": true}}}
	if build != nil {
		artifacts = append(artifacts, map[string]any{"path": "artifacts/test.collector-build.json", "schema": "evidencepack/collector-build@v1", "data": build})
	}
	if result != nil {
		artifacts = append(artifacts, map[string]any{"path": "artifacts/test.collector-result.json", "schema": "evidencepack/collector-result@v1", "data": result})
	}
	raw, err := json.Marshal(map[string]any{"type": "epack_result", "protocol_version": 1, "artifacts": artifacts})
	if err != nil {
		t.Fatal(err)
	}
	return writeCollector(t, "results", withCapabilities(t, caps)+"cat <<'EOF'\n"+string(raw)+"\nEOF\n")
}

// withCapabilities returns the shell lines that answer --version and, when
// caps is not nil, --capabilities, as an SDK collector does.
func withCapabilities(t *testing.T, caps map[string]any) string {
	t.Helper()
	script := `case "$1" in --version) echo v0.4.0; exit 0;; esac` + "\n"
	if caps == nil {
		return script
	}
	raw, err := json.Marshal(caps)
	if err != nil {
		t.Fatal(err)
	}
	return script + `case "$1" in --capabilities) cat <<'CAPS'` + "\n" + string(raw) + "\nCAPS\nexit 0;; esac\n"
}

// sdkCapabilities is a --capabilities answer as the SDK writes it, with the
// suites its trace map keeps.
func sdkCapabilities() map[string]any {
	return map[string]any{
		"kind": "collector", "name": "test", "version": "v0.4.0", "protocol_version": 1, "description": "A test collector.",
		"suites": sdkSuites(),
	}
}

// sdkSuites are the suites sdkCapabilities and sdkBuild list: one with the
// sandbox recording and a current waiver, and one built in code.
func sdkSuites() []any {
	return []any{
		map[string]any{"name": "okta", "operations": []any{"okta.logs.list", "okta.users.list"}, "scenarios": 4, "recordings": 1,
			"waivers": []any{map[string]any{"check": "insensitive", "subject": "okta.users.me.get", "reason": "The sign-in feeds no value.", "expires": time.Now().AddDate(0, 3, 0).Format("2006-01-02")}}},
		map[string]any{"name": "okta-oauth", "operations": []any{"okta.logs.list", "okta.token.create", "okta.users.list"}, "scenarios": 2, "recordings": 0},
	}
}

// sdkResult is a result in the shape the SDK writes, with every field
// this epack release adds.
func sdkResult() map[string]any {
	return map[string]any{
		"collector": map[string]any{"name": "test", "version": "v0.4.0", "commit": "abc123"},
		"outcome":   map[string]any{"status": "partial", "code": "permission_denied", "owner": "customer"},
		"gaps": []any{map[string]any{
			"path": "artifacts/test.json", "pointer": "/system_log", "status": "not_collected", "code": "permission_denied", "owner": "customer",
			"vendor_code": "E0000006", "operation": "okta.logs.list", "call": 3, "source": "internal/collector/system_log.go:155",
			"missing_permission": "okta.logs.read",
		}},
		"steps": []any{
			map[string]any{"name": "people", "title": "People", "start_ms": 300, "end_ms": 900, "requests": 3, "calls": 2, "retries": 1, "failed": 1,
				"operations": []any{map[string]any{"name": "okta.users.list", "calls": 2}}},
			map[string]any{"name": "system_log", "title": "Activity log", "start_ms": 900, "end_ms": 950, "requests": 1, "calls": 1, "retries": 0, "failed": 1,
				"operations": []any{map[string]any{"name": "okta.logs.list", "calls": 1}}},
		},
		"calls": map[string]any{
			"operations": []any{
				map[string]any{"name": "okta.users.list", "calls": 2, "attempts": 3, "retries": 1},
				map[string]any{"name": "okta.logs.list", "calls": 1, "attempts": 1, "retries": 0},
			},
		},
		"signed_in_as": map[string]any{"provider": "okta", "kind": "service_app", "auth_method": "private_key_jwt", "requested_scopes": []any{"okta.logs.read"}, "read_only": true},
		"run":          map[string]any{"started_at": "2026-10-20T06:00:00Z", "finished_at": "2026-10-20T06:00:01Z", "proxy": false, "custom_ca": false},
	}
}

// trimmedResult is sdkResult as an SDK that trims counts below the audit
// level writes it at the trust level.
func trimmedResult() map[string]any {
	r := sdkResult()
	delete(r["gaps"].([]any)[0].(map[string]any), "call")
	r["steps"] = []any{
		map[string]any{"name": "people", "title": "People", "any_failed": true, "operations": []any{map[string]any{"name": "okta.users.list"}}},
		map[string]any{"name": "system_log", "title": "Activity log", "any_failed": true, "operations": []any{map[string]any{"name": "okta.logs.list"}}},
	}
	r["calls"] = map[string]any{"operations": []any{
		map[string]any{"name": "okta.users.list", "retried": true, "status_codes": []any{"200", "429"}},
		map[string]any{"name": "okta.logs.list", "retried": false, "status_codes": []any{"403"}, "error_codes": []any{"permission_denied"}},
	}}
	return r
}

// sdkBuild is a build file as the SDK writes it, with a trace map that keeps
// the suites sdkSuites lists.
func sdkBuild() map[string]any {
	return map[string]any{
		"collector": map[string]any{"name": "okta", "version": "v0.4.0", "commit": "abc123"},
		"schemas":   map[string]any{"artifacts/okta.json": map[string]any{"type": "object"}},
		"trace_map": map[string]any{"artifacts": map[string]any{}, "lines": map[string]any{}, "suites": sdkSuites()},
	}
}

// auditRows returns the rows of sdkResult's calls, as an audit run writes
// them.
func auditRows() []any {
	return []any{
		map[string]any{"call": 1, "operation": "okta.users.list", "step": "people", "method": "GET", "host": "a.okta.com", "attempt": 1, "start_ms": 300, "status": 429, "duration_ms": 5},
		map[string]any{"call": 1, "operation": "okta.users.list", "step": "people", "method": "GET", "host": "a.okta.com", "attempt": 2, "start_ms": 1305, "waited_ms": 1000, "status": 200, "duration_ms": 5},
		map[string]any{"call": 2, "operation": "okta.users.list", "step": "people", "method": "GET", "host": "a.okta.com", "attempt": 1, "start_ms": 1310, "status": 200, "duration_ms": 5},
		map[string]any{"call": 3, "operation": "okta.logs.list", "step": "system_log", "method": "GET", "host": "a.okta.com", "attempt": 1, "start_ms": 1400, "status": 403, "vendor_code": "E0000006", "duration_ms": 5},
	}
}

func resultChecks(t *testing.T, result, build map[string]any, config string) map[string]TestResult {
	t.Helper()
	runner := NewRunner(resultCollector(t, result, build), componenttypes.KindCollector)
	if config != "" {
		path := filepath.Join(t.TempDir(), "config.json")
		if err := os.WriteFile(path, []byte(config), 0o600); err != nil {
			t.Fatal(err)
		}
		runner.CollectorConfig = path
	}
	return runCollectorConformance(t, runner)
}

func expectStatuses(t *testing.T, results map[string]TestResult, want map[string]TestStatus) {
	t.Helper()
	for id, status := range want {
		if got := results[id]; got.Status != status {
			t.Errorf("%s = %s (%s%s), want %s", id, got.Status, got.Message, got.Reason, status)
		}
	}
}

func TestCollectorResultChecks_PassANewResult(t *testing.T) {
	results := resultChecks(t, sdkResult(), sdkBuild(), "")
	expectStatuses(t, results, map[string]TestStatus{
		"COL-075": StatusPass, "COL-076": StatusSkip, "COL-077": StatusPass, "COL-078": StatusPass, "COL-079": StatusPass, "COL-080": StatusPass,
		"COL-110": StatusPass, "COL-113": StatusPass, "COL-114": StatusPass,
	})

	audit := sdkResult()
	audit["calls"].(map[string]any)["requests"] = auditRows()
	audit["calls"].(map[string]any)["problem_requests_dropped"] = 0
	audit["gaps"].([]any)[0].(map[string]any)["warning"] = "system log: access denied"
	results = resultChecks(t, audit, sdkBuild(), `{"level": "audit"}`)
	expectStatuses(t, results, map[string]TestStatus{
		"COL-075": StatusPass, "COL-076": StatusPass, "COL-077": StatusPass, "COL-078": StatusPass, "COL-079": StatusPass, "COL-080": StatusSkip,
	})

	results = resultChecks(t, trimmedResult(), sdkBuild(), "")
	expectStatuses(t, results, map[string]TestStatus{
		"COL-075": StatusPass, "COL-076": StatusSkip, "COL-077": StatusPass, "COL-078": StatusPass, "COL-079": StatusPass, "COL-080": StatusPass,
	})
}

func TestCollectorResultChecks_PassAResultFromAnOlderSDK(t *testing.T) {
	old := map[string]any{
		"collector": map[string]any{"name": "test", "version": "v0.3.0"},
		"outcome":   map[string]any{"status": "collected"},
		"gaps":      []any{},
		"calls":     map[string]any{"operations": []any{map[string]any{"name": "okta.users.list", "calls": 1, "attempts": 1, "retries": 0}}},
		"run":       map[string]any{"started_at": "2026-10-20T06:00:00Z", "finished_at": "2026-10-20T06:00:01Z", "proxy": false, "custom_ca": false},
	}
	results := resultChecks(t, old, nil, "")
	expectStatuses(t, results, map[string]TestStatus{
		"COL-075": StatusPass, "COL-076": StatusSkip, "COL-077": StatusSkip, "COL-078": StatusSkip, "COL-079": StatusSkip, "COL-080": StatusPass,
	})
	for _, id := range resultIDs {
		if got := resultChecks(t, nil, nil, "")[id]; got.Status != StatusSkip || !strings.Contains(got.Reason, "no collector result") {
			t.Errorf("without a result, %s = %s (%s), want a skip", id, got.Status, got.Reason)
		}
	}
}

func TestCollectorResultChecks_FailWhatDisagrees(t *testing.T) {
	cases := map[string]struct {
		change func(result, build map[string]any)
		config string
		id     string
		want   string
	}{
		"a field the schema lacks": {func(r, _ map[string]any) { r["calls"].(map[string]any)["requests_kept"] = 3 }, "", "COL-075", "does not match evidencepack/collector-result@v1"},
		"a call whose attempts disagree": {func(r, _ map[string]any) {
			rows := auditRows()
			rows[1].(map[string]any)["operation"] = "okta.apps.list"
			r["calls"].(map[string]any)["requests"] = rows
		}, `{"level": "audit"}`, "COL-076", "the attempts of call 1 name okta.users.list"},
		"a first attempt that waited": {func(r, _ map[string]any) {
			rows := auditRows()
			rows[0].(map[string]any)["waited_ms"] = 250
			r["calls"].(map[string]any)["requests"] = rows
		}, `{"level": "audit"}`, "COL-076", "waited 250ms before its first attempt"},
		"a step that ends before it starts": {func(r, _ map[string]any) {
			r["steps"].([]any)[1].(map[string]any)["end_ms"] = 100
		}, "", "COL-077", "ends at 100ms, before it starts"},
		"steps whose counts disagree": {func(r, _ map[string]any) {
			r["steps"].([]any)[0].(map[string]any)["requests"] = 9
		}, "", "COL-077", "counts 9 requests"},
		"a gap naming an uncounted operation": {func(r, _ map[string]any) {
			r["gaps"].([]any)[0].(map[string]any)["operation"] = "okta.apps.list"
		}, "", "COL-078", "names operation okta.apps.list"},
		"a permission on another code": {func(r, _ map[string]any) {
			g := r["gaps"].([]any)[0].(map[string]any)
			g["code"], g["owner"] = "vendor_error", "vendor"
		}, "", "COL-078", "only a permission_denied gap names one"},
		"a build file for another build": {func(_, b map[string]any) {
			b["collector"].(map[string]any)["commit"] = "def456"
		}, "", "COL-079", `names version "v0.4.0" and commit "def456"`},
		"a build file the schema rejects": {func(_, b map[string]any) { b["run_id"] = "r1" }, "", "COL-079", "does not match evidencepack/collector-build@v1"},
		"rows at trust":                   {func(r, _ map[string]any) { r["calls"].(map[string]any)["requests"] = auditRows() }, "", "COL-080", "holds /calls/requests at the trust level"},
		"a warning at trust": {func(r, _ map[string]any) {
			r["gaps"].([]any)[0].(map[string]any)["warning"] = "user 00u1 cannot read the log"
		}, "", "COL-080", "holds /gaps/0/warning at the trust level"},
		"a gap's scope at trust": {func(r, _ map[string]any) {
			r["gaps"].([]any)[0].(map[string]any)["scope"] = "account 111122223333"
		}, "", "COL-080", "holds /gaps/0/scope at the trust level"},
		"a run warning's message at trust": {func(r, _ map[string]any) {
			r["warnings"] = []any{map[string]any{"message": "bucket northwind-logs is in another account", "fix": "Enroll the log archive account."}}
		}, "", "COL-080", "holds /warnings/0/message at the trust level"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			result, build := sdkResult(), sdkBuild()
			tc.change(result, build)
			got := resultChecks(t, result, build, tc.config)[tc.id]
			if got.Status != StatusFail || !strings.Contains(got.Message, tc.want) {
				t.Errorf("%s = %s (%s%s), want a failure saying %q", tc.id, got.Status, got.Message, got.Reason, tc.want)
			}
		})
	}
}

// capsChecks runs the harness on a collector that answers --capabilities
// with caps and collects nothing it can check.
func capsChecks(t *testing.T, caps map[string]any) map[string]TestResult {
	t.Helper()
	return runCollectorConformance(t, NewRunner(capsCollector(t, caps, nil, nil), componenttypes.KindCollector))
}

// capsSuites returns the suites a capabilities answer lists.
func capsSuites(caps map[string]any) []any {
	return caps["suites"].([]any)
}

func TestCollectorCapabilities_PassAnSDKCollector(t *testing.T) {
	expectStatuses(t, capsChecks(t, sdkCapabilities()), map[string]TestStatus{
		"COL-060": StatusPass, "COL-061": StatusPass, "COL-062": StatusPass, "COL-063": StatusPass,
		"COL-110": StatusPass, "COL-113": StatusPass, "COL-114": StatusPass,
	})
}

func TestCollectorCapabilities_FailWhatIsMissing(t *testing.T) {
	cases := map[string]struct {
		change func(caps map[string]any)
		id     string
		want   string
	}{
		"no kind":             {func(c map[string]any) { delete(c, "kind") }, "COL-060", "did not print one JSON object with a kind"},
		"no name":             {func(c map[string]any) { delete(c, "name") }, "COL-062", "capabilities lack name"},
		"another kind":        {func(c map[string]any) { c["kind"] = "tool" }, "COL-062", `capabilities give kind "tool", want "collector"`},
		"an empty version":    {func(c map[string]any) { c["version"] = "" }, "COL-062", "capabilities lack version"},
		"no description":      {func(c map[string]any) { delete(c, "description") }, "COL-063", "capabilities have no description"},
		"no suites":           {func(c map[string]any) { delete(c, "suites") }, "COL-110", "the capabilities list no test kit suite, so the collector's tests are not on record; run epack sdk map"},
		"an empty suite list": {func(c map[string]any) { c["suites"] = []any{} }, "COL-110", "the capabilities list no test kit suite; run epack sdk map"},
		"a suite with no operations": {func(c map[string]any) {
			capsSuites(c)[1].(map[string]any)["operations"] = []any{}
		}, "COL-110", "suite okta-oauth declares no operations; set Suite.Operations"},
		"a suite with no scenario": {func(c map[string]any) {
			capsSuites(c)[0].(map[string]any)["scenarios"] = 0
		}, "COL-110", "suite okta runs no scenario"},
		"no recording": {func(c map[string]any) {
			capsSuites(c)[0].(map[string]any)["recordings"] = 0
		}, "COL-113", "no test kit suite replays a recording of the test account; record one with collectortest.Record"},
		"an expired waiver": {func(c map[string]any) {
			capsSuites(c)[0].(map[string]any)["waivers"].([]any)[0].(map[string]any)["expires"] = "2026-01-31"
		}, "COL-114", "suite okta waives insensitive okta.users.me.get under a waiver that expired on 2026-01-31"},
		"a waiver without a reason": {func(c map[string]any) {
			capsSuites(c)[0].(map[string]any)["waivers"].([]any)[0].(map[string]any)["reason"] = " "
		}, "COL-114", "suite okta waives insensitive okta.users.me.get with no reason"},
		"a waiver with a loose date": {func(c map[string]any) {
			capsSuites(c)[0].(map[string]any)["waivers"].([]any)[0].(map[string]any)["expires"] = "next spring"
		}, "COL-114", `with the expiry "next spring", which is not a YYYY-MM-DD date`},
		"no recording and a lapsed recording waiver": {func(c map[string]any) {
			capsSuites(c)[0].(map[string]any)["recordings"] = 0
			capsSuites(c)[1].(map[string]any)["waivers"] = []any{recordingWaiver("2026-01-31")}
		}, "COL-113", "no test kit suite replays a recording of the test account; record one"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			caps := sdkCapabilities()
			tc.change(caps)
			got := capsChecks(t, caps)[tc.id]
			if got.Status != StatusFail || !strings.Contains(got.Message, tc.want) {
				t.Errorf("%s = %s (%s%s), want a failure saying %q", tc.id, got.Status, got.Message, got.Reason, tc.want)
			}
		})
	}
}

// recordingWaiver is a waiver of the recording rule for a sandbox that does
// not exist yet, lapsing on expires.
func recordingWaiver(expires string) map[string]any {
	return map[string]any{"check": "recording", "subject": "okta-sandbox", "reason": "No sandbox yet.", "expires": expires}
}

func TestCollectorCapabilities_ARecordingWaiverPassesCOL113AndIsReported(t *testing.T) {
	expires := time.Now().AddDate(0, 3, 0).Format("2006-01-02")
	caps := sdkCapabilities()
	capsSuites(caps)[0].(map[string]any)["recordings"] = 0
	capsSuites(caps)[1].(map[string]any)["waivers"] = []any{recordingWaiver(expires)}
	results := capsChecks(t, caps)
	got := results["COL-113"]
	if got.Status != StatusPass || got.Message != "no test kit suite replays a recording; suite okta-oauth waives the recording of okta-sandbox until "+expires+": No sandbox yet." {
		t.Errorf("COL-113 = %s (%s), want a pass that reports the waiver", got.Status, got.Message)
	}
	if got := results["COL-114"]; got.Status != StatusPass {
		t.Errorf("COL-114 = %s (%s), want a pass: the waiver is current", got.Status, got.Message)
	}

	lapsed := sdkCapabilities()
	capsSuites(lapsed)[0].(map[string]any)["recordings"] = 0
	capsSuites(lapsed)[1].(map[string]any)["waivers"] = []any{recordingWaiver("2026-01-31")}
	results = capsChecks(t, lapsed)
	if got := results["COL-114"]; got.Status != StatusFail || !strings.Contains(got.Message, "suite okta-oauth waives recording okta-sandbox under a waiver that expired on 2026-01-31") {
		t.Errorf("COL-114 = %s (%s), want the lapsed waiver reported", got.Status, got.Message)
	}
}

func TestCollectorCapabilities_ACollectorWithoutThemFailsAndSkipsTheRest(t *testing.T) {
	results := capsChecks(t, nil)
	if got := results["COL-060"]; got.Status != StatusFail || got.Message != "--capabilities did not print one JSON object with a kind" {
		t.Errorf("COL-060 = %s (%s), want a failure: the fixture answers --capabilities with its result", got.Status, got.Message)
	}
	if got := results["COL-061"]; got.Status != StatusPass {
		t.Errorf("COL-061 = %s (%s), want a pass: the fixture answers --version", got.Status, got.Message)
	}
	for _, id := range append([]string{"COL-062", "COL-063"}, suiteIDs...) {
		if got := results[id]; got.Status != StatusSkip || got.Reason != "depends on COL-060" {
			t.Errorf("%s = %s (%s%s), want a skip that depends on COL-060", id, got.Status, got.Message, got.Reason)
		}
	}
}

func TestSuiteRecordChecks_AWaiverExpiresOnItsDate(t *testing.T) {
	today := time.Date(2026, 11, 13, 9, 30, 0, 0, time.UTC)
	for expires, want := range map[string]TestStatus{"2026-11-14": StatusPass, "2026-11-13": StatusFail, "2026-11-12": StatusFail} {
		r := &Runner{}
		raw, err := json.Marshal([]any{
			map[string]any{"name": "demo", "operations": []any{"demo.me.get"}, "scenarios": 1, "recordings": 1,
				"waivers": []any{map[string]any{"check": "faults", "reason": "r", "expires": expires}}},
		})
		if err != nil {
			t.Fatal(err)
		}
		r.testSuiteRecord(raw, today)
		var got TestResult
		for _, res := range r.results {
			if res.ID == "COL-114" {
				got = res
			}
		}
		if got.Status != want {
			t.Errorf("a waiver that expires %s, checked on %s: COL-114 = %s (%s), want %s", expires, today.Format("2006-01-02"), got.Status, got.Message, want)
		}
	}
}

func TestCollectorResultChecks_FailCountsAtTrustFromATrimmingSDK(t *testing.T) {
	cases := map[string]struct {
		change func(result map[string]any)
		want   string
	}{
		"a tenant": {func(r map[string]any) { r["signed_in_as"].(map[string]any)["tenant_id"] = "acme" }, "holds /signed_in_as/tenant_id"},
		"an operation's calls": {func(r map[string]any) {
			r["calls"].(map[string]any)["operations"].([]any)[0].(map[string]any)["calls"] = 2
		}, "holds /calls/operations/0/calls"},
		"a step's times": {func(r map[string]any) {
			r["steps"].([]any)[1].(map[string]any)["start_ms"] = 900
		}, "holds /steps/1/start_ms"},
		"a gap's call": {func(r map[string]any) { r["gaps"].([]any)[0].(map[string]any)["call"] = 3 }, "holds /gaps/0/call"},
		"a count of dropped requests": {func(r map[string]any) {
			r["calls"].(map[string]any)["requests_dropped"] = 3
		}, "holds /calls/requests_dropped"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			result := trimmedResult()
			tc.change(result)
			got := resultChecks(t, result, sdkBuild(), "")["COL-080"]
			if got.Status != StatusFail || !strings.Contains(got.Message, tc.want) {
				t.Errorf("COL-080 = %s (%s%s), want a failure saying %q", got.Status, got.Message, got.Reason, tc.want)
			}
		})
	}
}

func TestCollectorResultChecks_PassCountsAtTrustFromAnOlderSDK(t *testing.T) {
	result := sdkResult()
	result["signed_in_as"].(map[string]any)["tenant_id"] = "acme"
	if got := resultChecks(t, result, sdkBuild(), "")["COL-080"]; got.Status != StatusPass {
		t.Errorf("COL-080 = %s (%s%s), want a pass for a result whose SDK counted calls at every level", got.Status, got.Message, got.Reason)
	}
}
