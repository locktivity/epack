//go:build components

package remotecmd

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/locktivity/epack/internal/testutil/testhome"
	"github.com/locktivity/epack/internal/userconfig"
)

// isolateHome points the user-level config at an empty folder so a default
// remote recorded on the developer's machine never leaks into a test.
func isolateHome(t *testing.T) string {
	t.Helper()
	return testhome.Isolate(t)
}

func TestResolveConfigTarget_FlagWins(t *testing.T) {
	isolateHome(t)
	if err := userconfig.SetDefaultRemote("locktivity"); err != nil {
		t.Fatalf("SetDefaultRemote: %v", err)
	}
	target, err := ResolveConfigTarget("northwind-production", "staging")
	if err != nil {
		t.Fatalf("ResolveConfigTarget: %v", err)
	}
	if target.Remote != "staging" || target.Name != "northwind-production" {
		t.Errorf("target = %+v", target)
	}
}

func TestResolveConfigTarget_UsesTheRememberedDefault(t *testing.T) {
	isolateHome(t)
	if err := userconfig.SetDefaultRemote("locktivity"); err != nil {
		t.Fatalf("SetDefaultRemote: %v", err)
	}
	target, err := ResolveConfigTarget("northwind-production", "")
	if err != nil {
		t.Fatalf("ResolveConfigTarget: %v", err)
	}
	if target.Remote != "locktivity" {
		t.Errorf("Remote = %q, want locktivity", target.Remote)
	}
}

func TestResolveConfigTarget_FallsBackToTheProjectsOnlyRemote(t *testing.T) {
	isolateHome(t)
	writeMockAdapterProject(t, configPullAdapter)
	target, err := ResolveConfigTarget("northwind-production", "")
	if err != nil {
		t.Fatalf("ResolveConfigTarget: %v", err)
	}
	if target.Remote != "mock" {
		t.Errorf("Remote = %q, want mock", target.Remote)
	}
}

func TestResolveConfigTarget_RejectsTheColonForm(t *testing.T) {
	isolateHome(t)
	_, err := ResolveConfigTarget("locktivity:northwind-production", "")
	if err == nil || !strings.Contains(err.Error(), "epack run northwind-production --remote locktivity") {
		t.Fatalf("err = %v", err)
	}
}

func TestResolveConfigTarget_RejectsUnsafeNames(t *testing.T) {
	isolateHome(t)
	for _, name := range []string{".ssh", "..", "a/b", "x\x1by", ""} {
		if _, err := ResolveConfigTarget(name, "locktivity"); err == nil {
			t.Errorf("ResolveConfigTarget(%q) accepted an unsafe name", name)
		}
	}
}

func TestRunClone_UsesTheTypedNameForTheFolder(t *testing.T) {
	isolateHome(t)
	projectDir := writeMockAdapterProject(t, strings.Replace(configPullAdapter, `"name":"northwind-production"`, `"name":".ssh"`, 1))
	cmd, _, stderr := rootCommand(newCloneCommand(), "northwind-production", "--remote", "mock")
	if err := cmd.Execute(); err != nil {
		t.Fatalf("clone: %v (stderr: %s)", err, stderr.String())
	}
	if _, err := os.Stat(filepath.Join(projectDir, "northwind-production", "epack.yaml")); err != nil {
		t.Errorf("config not written under the typed name: %v", err)
	}
	if _, err := os.Stat(filepath.Join(projectDir, ".ssh")); !os.IsNotExist(err) {
		t.Errorf("a folder named by the remote was created: %v", err)
	}
}

func TestResolveConfigTarget_NeedsSomeRemote(t *testing.T) {
	isolateHome(t)
	dir := t.TempDir()
	oldWd, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	defer func() { _ = os.Chdir(oldWd) }()

	_, err := ResolveConfigTarget("northwind-production", "")
	if err == nil || !strings.Contains(err.Error(), "epack remote login") {
		t.Fatalf("err = %v", err)
	}
}

// writeMockAdapterProject writes a project whose remote "mock" is an external
// adapter script pinned in the lockfile, and makes it the working directory.
func writeMockAdapterProject(t *testing.T, script string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell script adapters are not available on Windows")
	}
	projectDir := t.TempDir()
	adapterPath := filepath.Join(projectDir, "mock-adapter")
	if err := os.WriteFile(adapterPath, []byte(script), 0o755); err != nil {
		t.Fatalf("writing adapter: %v", err)
	}
	sum := sha256.Sum256([]byte(script))
	digest := "sha256:" + hex.EncodeToString(sum[:])

	configContent := fmt.Sprintf(`stream: test/stream
collectors:
  github:
    source: owner/repo@v1.0.0
remotes:
  mock:
    binary: %s
    adapter: mock
`, adapterPath)
	if err := os.WriteFile(filepath.Join(projectDir, "epack.yaml"), []byte(configContent), 0o644); err != nil {
		t.Fatalf("writing config: %v", err)
	}
	lockContent := fmt.Sprintf(`schema_version: 1
remotes:
  mock:
    kind: external
    platforms:
      %s/%s:
        digest: %s
`, runtime.GOOS, runtime.GOARCH, digest)
	if err := os.WriteFile(filepath.Join(projectDir, "epack.lock.yaml"), []byte(lockContent), 0o644); err != nil {
		t.Fatalf("writing lockfile: %v", err)
	}

	oldWd, _ := os.Getwd()
	if err := os.Chdir(projectDir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldWd) })
	return projectDir
}

const configPullAdapter = `#!/bin/sh
case "$1" in
  --capabilities)
    echo '{"name":"mock","kind":"remote_adapter","deploy_protocol_version":1,"version":"1.0.0","features":{"prepare_finalize":true,"config_pull":true}}'
    ;;
  config.pull)
    printf '%s\n' '{"ok":true,"type":"config.pull.result","config":{"name":"northwind-production","title":"Northwind production","stream":"northwind/production","revision":3,"files":{"epack.yaml":"stream: northwind/production\ncollectors:\n  tls:\n    source: locktivity/epack-collector-tls@^0.1.0\n",".epack/hooks/pre-collect.sh":"#!/bin/sh\n"},"shas":{"epack.yaml":"abc"},"lockfile":"schema_version: 1\n"}}'
    ;;
  *)
    echo '{"ok":false,"error":{"code":"unknown_command","message":"unknown command"}}'
    exit 1
    ;;
esac
`

func TestRunClone_WritesConfigFromAdapter(t *testing.T) {
	isolateHome(t)
	projectDir := writeMockAdapterProject(t, configPullAdapter)
	dest := filepath.Join(projectDir, "cloned")
	cmd, stdout, stderr := rootCommand(newCloneCommand(), "northwind-production", dest, "--remote", "mock")
	if err := cmd.Execute(); err != nil {
		t.Fatalf("clone: %v (stderr: %s)", err, stderr.String())
	}

	data, err := os.ReadFile(filepath.Join(dest, "epack.yaml"))
	if err != nil || !strings.HasPrefix(string(data), "stream: northwind/production\n") {
		t.Errorf("epack.yaml = %q, %v", data, err)
	}
	if _, err := os.Stat(filepath.Join(dest, "epack.lock.yaml")); err != nil {
		t.Errorf("lockfile not written: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dest, ".epack", "remote-config.json")); err != nil {
		t.Errorf("state not written: %v", err)
	}
	if !strings.Contains(stdout.String(), "Cloned Northwind production (revision 3)") {
		t.Errorf("unexpected output: %s", stdout.String())
	}
	for _, want := range []string{"Collects with", "Hooks", "pre-collect.sh is the remote's template", "Lock"} {
		if !strings.Contains(stdout.String(), want) {
			t.Errorf("summary missing %q:\n%s", want, stdout.String())
		}
	}
}

func TestRunClone_JSONOutput(t *testing.T) {
	isolateHome(t)
	projectDir := writeMockAdapterProject(t, configPullAdapter)
	cmd, stdout, _ := rootCommand(newCloneCommand(), "northwind-production", filepath.Join(projectDir, "cloned"), "--json")
	if err := cmd.Execute(); err != nil {
		t.Fatalf("clone: %v", err)
	}
	var result struct {
		Revision int      `json:"revision"`
		Created  bool     `json:"created"`
		Written  []string `json:"written"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("parsing JSON: %v (%s)", err, stdout.String())
	}
	if result.Revision != 3 || !result.Created || len(result.Written) != 3 {
		t.Errorf("result = %+v", result)
	}
}

func TestRunClone_AdapterWithoutConfigPull(t *testing.T) {
	isolateHome(t)
	writeMockAdapterProject(t, `#!/bin/sh
echo '{"name":"mock","kind":"remote_adapter","deploy_protocol_version":1,"version":"1.0.0","features":{"prepare_finalize":true}}'
`)
	cmd, _, _ := rootCommand(newCloneCommand(), "northwind-production")
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "cannot hand over configurations") {
		t.Fatalf("err = %v", err)
	}
}
