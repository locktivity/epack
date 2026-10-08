//go:build components

package remotecmd

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/spf13/cobra"
)

// rootCommand runs cmd under a root that carries epack's global output flags,
// the way the real binary does, and returns the root with what cmd writes.
func rootCommand(cmd *cobra.Command, args ...string) (root *cobra.Command, stdout, stderr *bytes.Buffer) {
	root = &cobra.Command{Use: "epack", SilenceUsage: true, SilenceErrors: true}
	root.PersistentFlags().BoolP("quiet", "q", false, "suppress non-essential output")
	root.PersistentFlags().Bool("json", false, "output in JSON format")
	root.PersistentFlags().Bool("no-color", false, "disable colored output")
	root.PersistentFlags().BoolP("verbose", "v", false, "verbose output")
	root.AddCommand(cmd)
	root.SetArgs(append([]string{cmd.Name()}, args...))
	stdout, stderr = &bytes.Buffer{}, &bytes.Buffer{}
	root.SetOut(stdout)
	root.SetErr(stderr)
	return root, stdout, stderr
}

func writeRemoteProject(t *testing.T) {
	t.Helper()
	projectDir := t.TempDir()
	configContent := `stream: test/stream
collectors:
  github:
    source: owner/repo@v1.0.0
remotes:
  locktivity:
    source: locktivity/epack-remote-locktivity@v0.1.0
    target:
      workspace: my-workspace
`
	if err := os.WriteFile(filepath.Join(projectDir, "epack.yaml"), []byte(configContent), 0o644); err != nil {
		t.Fatalf("writing config: %v", err)
	}
	oldWd, _ := os.Getwd()
	if err := os.Chdir(projectDir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldWd) })
}

func TestRemoteList_RootJSONFlag(t *testing.T) {
	writeRemoteProject(t)

	cmd, stdout, stderr := rootCommand(newRemoteCommand(), "list", "--json")
	if err := cmd.Execute(); err != nil {
		t.Fatalf("remote list --json: %v", err)
	}

	var result struct {
		Remotes []struct {
			Name string `json:"name"`
		} `json:"remotes"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("stdout is not only JSON: %v\n%s", err, stdout.String())
	}
	if len(result.Remotes) != 1 || result.Remotes[0].Name != "locktivity" {
		t.Errorf("result = %+v", result)
	}
	if stderr.Len() != 0 {
		t.Errorf("stderr = %q", stderr.String())
	}
}

func TestRemoteList_RootQuietFlag(t *testing.T) {
	writeRemoteProject(t)

	cmd, stdout, stderr := rootCommand(newRemoteCommand(), "list", "--quiet")
	if err := cmd.Execute(); err != nil {
		t.Fatalf("remote list --quiet: %v", err)
	}
	if stdout.Len() != 0 || stderr.Len() != 0 {
		t.Errorf("--quiet still printed:\n%s%s", stdout.String(), stderr.String())
	}
}

func TestRemoteLogin_RootJSONFlag(t *testing.T) {
	loginSetup(t)
	port := freePort(t)

	cmd, stdout, stderr := rootCommand(newRemoteCommand(), "login", "mock", "--no-browser", "--port", strconv.Itoa(port), "--json")
	done := make(chan error, 1)
	go func() { done <- cmd.Execute() }()
	visit(t, http.MethodGet, port, "/callback?code=code-789&state=state-123")
	if err := loginResult(t, done); err != nil {
		t.Fatalf("remote login --json: %v (stderr: %s)", err, stderr.String())
	}

	var result struct {
		Remote        string `json:"remote"`
		Authenticated bool   `json:"authenticated"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("stdout is not only JSON: %v\n%s", err, stdout.String())
	}
	if result.Remote != "mock" || !result.Authenticated {
		t.Errorf("result = %+v", result)
	}
	if !bytes.Contains(stderr.Bytes(), []byte("https://app.example.com/oauth/authorize?state=state-123")) {
		t.Errorf("sign-in link missing from stderr:\n%s", stderr.String())
	}
}
