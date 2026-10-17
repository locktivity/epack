//go:build conformance

package componentconf

import (
	"context"
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

func TestCollectorOutput_RejectedConfigSaysSo(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(configPath, []byte(`{"region":"eu"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	runner := NewRunner(writeCollector(t, "needs-config", needsConfig), componenttypes.KindCollector)
	runner.CollectorConfig = configPath
	results := runCollectorConformance(t, runner)

	if got := results["COL-001"]; got.Status != StatusSkip || got.Reason != "collector exited 2 with the --config file" {
		t.Errorf("COL-001 = %s (%s)", got.Status, got.Reason)
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
