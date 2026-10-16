//go:build components

package cmd

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/locktivity/epack/internal/cli/exitmap"
	"github.com/locktivity/epack/internal/cli/output"
	"github.com/locktivity/epack/internal/updatenotice"
	"github.com/spf13/cobra"
)

func TestNotifiesUpdates_LeavesOutHelpVersionCompletionAndRunnerCommands(t *testing.T) {
	rootCmd.InitDefaultHelpCmd()
	cases := []struct {
		args []string
		want bool
	}{
		{[]string{"inspect", "evidence.epack"}, true},
		{[]string{"run", "northwind-production"}, true},
		{[]string{"remote", "login", "locktivity"}, true},
		{nil, false},
		{[]string{"version"}, false},
		{[]string{"help", "run"}, false},
		{[]string{"completion", "zsh"}, false},
		{[]string{"hooks", "run", "pre-run"}, false},
		{[]string{"context", "build"}, false},
	}
	for _, tc := range cases {
		found, _, err := rootCmd.Find(tc.args)
		if err != nil {
			t.Fatalf("Find(%v): %v", tc.args, err)
		}
		if got := notifiesUpdates(found); got != tc.want {
			t.Errorf("notifiesUpdates(%v) = %v, want %v", tc.args, got, tc.want)
		}
	}

	complete := &cobra.Command{Use: cobra.ShellCompRequestCmd + " [command-line]"}
	(&cobra.Command{Use: "epack"}).AddCommand(complete)
	if notifiesUpdates(complete) {
		t.Error("a shell completion request should not check")
	}
}

func TestUpdateCheck_PrintsAfterTheCommandAndLeavesItsOutcomeAlone(t *testing.T) {
	clearUpdateCheckEnv(t)
	missing := filepath.Join(t.TempDir(), "missing.epack")

	t.Setenv(updatenotice.DisableEnvVar, "1")
	printed, wantErr := inspectWithUpdateCheck(t, "http://127.0.0.1:1", missing, time.Second)
	if wantErr == nil || printed != "" {
		t.Fatalf("baseline: err = %v, printed %q", wantErr, printed)
	}
	_, wantCode := exitmap.ToExit(wantErr)
	t.Setenv(updatenotice.DisableEnvVar, "")

	failing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	defer failing.Close()
	released := make(chan struct{})
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-released:
		}
	}))
	defer slow.Close()
	defer close(released)
	newer := releaseServer(t, "v0.6.0", new(atomic.Int32))

	cases := []struct {
		name    string
		server  string
		timeout time.Duration
		want    string
	}{
		{"failing", failing.URL, 2 * time.Second, ""},
		{"slow", slow.URL, 300 * time.Millisecond, ""},
		{"newer", newer, 2 * time.Second, "epack 0.6.0 is available (you have 0.5.1). Download it from: https://github.com/locktivity/epack/releases/latest\n"},
	}
	for _, tc := range cases {
		printed, err := inspectWithUpdateCheck(t, tc.server, missing, tc.timeout)
		if err == nil || err.Error() != wantErr.Error() {
			t.Errorf("%s: err = %v, want %v", tc.name, err, wantErr)
		}
		if _, code := exitmap.ToExit(err); code != wantCode {
			t.Errorf("%s: exit code = %d, want %d", tc.name, code, wantCode)
		}
		if printed != tc.want {
			t.Errorf("%s: printed %q, want %q", tc.name, printed, tc.want)
		}
	}
}

func TestUpdateCheck_MakesNoRequestInCI(t *testing.T) {
	for _, name := range ciVariables {
		t.Run(name, func(t *testing.T) {
			clearUpdateCheckEnv(t)
			t.Setenv(name, "true")
			hits := new(atomic.Int32)
			server := releaseServer(t, "v0.6.0", hits)
			if printed, _ := inspectWithUpdateCheck(t, server, filepath.Join(t.TempDir(), "missing.epack"), time.Second); printed != "" {
				t.Errorf("printed %q in CI", printed)
			}
			if n := hits.Load(); n != 0 {
				t.Errorf("requests = %d in CI, want none", n)
			}
		})
	}
}

func clearUpdateCheckEnv(t *testing.T) {
	t.Helper()
	for _, name := range append([]string{updatenotice.DisableEnvVar}, ciVariables...) {
		t.Setenv(name, "")
	}
}

func releaseServer(t *testing.T, tag string, hits *atomic.Int32) string {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = fmt.Fprintf(w, `{"tag_name": %q, "assets": []}`, tag)
	}))
	t.Cleanup(server.Close)
	return server.URL
}

// inspectWithUpdateCheck runs inspect on a pack that does not exist, as main
// runs a command, with the update check pointed at baseURL. It returns what
// the check printed and the command's error.
func inspectWithUpdateCheck(t *testing.T, baseURL, pack string, timeout time.Duration) (string, error) {
	t.Helper()
	statePath := filepath.Join(t.TempDir(), updatenotice.StateFileName)
	previous := updateCheckOptions
	updateCheckOptions = func() updatenotice.Options {
		return updatenotice.Options{
			Version:    "0.5.1",
			Terminal:   true,
			StatePath:  statePath,
			BaseURL:    baseURL,
			Executable: filepath.Join(t.TempDir(), "epack"),
			Timeout:    timeout,
		}
	}
	defer func() { updateCheckOptions = previous }()
	previousOut := out
	defer func() { out = previousOut }()

	rootCmd.SetArgs([]string{"inspect", pack})
	defer rootCmd.SetArgs(nil)
	err := rootCmd.Execute()

	var stdout, stderr bytes.Buffer
	out = output.New(&stdout, &stderr, output.Options{})
	finishUpdateCheck()
	return stderr.String(), err
}
