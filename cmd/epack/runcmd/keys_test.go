//go:build components

package runcmd

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/locktivity/epack/internal/cli/output"
	"github.com/locktivity/epack/internal/remote"
	"github.com/locktivity/epack/internal/safefile"
	"github.com/locktivity/epack/internal/testutil/testhome"
	"github.com/locktivity/epack/sign"
)

// writeKeyProject gives a fresh HOME this machine's key for the remote
// "mock" and writes a project whose pinned mock adapter lists that key with
// status, or lists no keys when status is empty. It returns the project
// folder and the key file.
func writeKeyProject(t *testing.T, status string) (dir, keyPath string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell script adapters are not available on Windows")
	}
	home := testhome.Isolate(t)
	key, err := sign.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	pemBytes, err := sign.MarshalPrivateKeyPEM(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := safefile.MkdirAllPrivate(home, filepath.Join(home, ".epack")); err != nil {
		t.Fatal(err)
	}
	keyPath = filepath.Join(home, ".epack", "keys", "mock.pem")
	if err := sign.SavePrivateKey(keyPath, pemBytes); err != nil {
		t.Fatal(err)
	}
	fingerprint, err := sign.Fingerprint(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	keys := ""
	if status != "" {
		keys = fmt.Sprintf(`{"id":"key_123","name":"laptop","fingerprint":"%s","status":"%s"}`, fingerprint, status)
	}
	response := `{"ok":true,"type":"key.list.result","keys":[` + keys + `]}`
	if code, ok := strings.CutPrefix(status, "error:"); ok {
		response = fmt.Sprintf(`{"ok":false,"error":{"code":"%s","message":"key status unavailable"}}`, code)
	}
	script := `#!/bin/sh
case "$1" in
  --capabilities)
    echo '{"name":"mock","kind":"remote_adapter","deploy_protocol_version":1,"version":"1.0.0","features":{"prepare_finalize":true,"keys":true}}'
    ;;
  key.list)
    cat > /dev/null
    echo '` + response + `'
    ;;
  *)
    echo '{"ok":false,"error":{"code":"unknown_command","message":"unknown command"}}'
    exit 1
    ;;
esac
`
	dir = t.TempDir()
	adapterPath := filepath.Join(dir, "mock-adapter")
	sum := sha256.Sum256([]byte(script))
	files := map[string]string{
		"mock-adapter": script,
		"epack.yaml": fmt.Sprintf("stream: test/stream\ncollectors:\n  github:\n    source: owner/repo@v1.0.0\nremotes:\n  mock:\n    binary: %s\n    adapter: mock\n",
			adapterPath),
		"epack.lock.yaml": fmt.Sprintf("schema_version: 1\nremotes:\n  mock:\n    kind: external\n    platforms:\n      %s/%s:\n        digest: sha256:%s\n",
			runtime.GOOS, runtime.GOARCH, hex.EncodeToString(sum[:])),
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return dir, keyPath
}

func TestResolveRunKey_SignsOnlyWithAUsableKey(t *testing.T) {
	for _, tc := range []struct {
		status   string
		want     func(keyPath string) runSigning
		warning  string
		errorHas string
	}{
		{status: remote.KeyStatusUsable, want: func(keyPath string) runSigning { return runSigning{keyPath: keyPath} }},
		{status: remote.KeyStatusPending, errorHas: "is waiting for approval"},
		{status: remote.KeyStatusLapsed, errorHas: "approval window has closed"},
		{status: remote.KeyStatusDenied, errorHas: "as denied for this configuration; replace it with 'epack key rotate mock', or pass --browser"},
		{status: remote.KeyStatusRetired, errorHas: "as retired for this configuration; replace it with 'epack key rotate mock'"},
		{status: remote.KeyStatusRevoked, errorHas: "as revoked for this configuration"},
		{status: "", errorHas: "is not registered for this configuration; run 'epack key create mock', or pass --browser"},
	} {
		name := tc.status
		if name == "" {
			name = "not listed"
		}
		t.Run(name, func(t *testing.T) {
			dir, keyPath := writeKeyProject(t, tc.status)
			var stdout, stderr bytes.Buffer
			out := output.New(&stdout, &stderr, output.Options{})

			signing, err := resolveRunKey(context.Background(), out, newStageUI(out), dir, "")
			if tc.errorHas != "" {
				if err == nil || !strings.Contains(err.Error(), tc.errorHas) {
					t.Fatalf("err = %v, want it to say %q", err, tc.errorHas)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolveRunKey: %v", err)
			}
			if want := tc.want(keyPath); signing != want {
				t.Errorf("signing = %+v, want %+v", signing, want)
			}
			if tc.warning == "" && stderr.Len() != 0 {
				t.Errorf("unexpected warning: %s", stderr.String())
			}
			if !strings.Contains(stderr.String(), tc.warning) {
				t.Errorf("warning = %q, want it to say %q", stderr.String(), tc.warning)
			}
		})
	}
}

func TestMachineKeyRegister_AsksOnlyInATerminal(t *testing.T) {
	signer, err := sign.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	out := output.New(&stdout, &stderr, output.Options{})

	_, registered, err := newMachineKey("mock.pem", "", "mock", "").register(context.Background(), out, nil, signer, "")
	if err != nil || registered || stdout.Len() != 0 {
		t.Fatalf("registered %v, err %v, stdout %q; want no question and no registration without a terminal", registered, err, stdout.String())
	}
}

func TestRun_PendingKeyStopsBeforeCollectionEvenWithYes(t *testing.T) {
	dir, _ := writeKeyProject(t, remote.KeyStatusPending)
	t.Chdir(dir)
	defer NewCommand()
	cmd := NewCommand()
	cmd.SetArgs([]string{"--yes"})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "is waiting for approval") {
		t.Fatalf("err = %v, want pending-key recovery", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "evidence.epack")); !os.IsNotExist(err) {
		t.Fatalf("run created a pack before approval: %v", err)
	}
}

func TestResolveRunKey_UnsignedMustBeExplicit(t *testing.T) {
	dir, _ := writeKeyProject(t, remote.KeyStatusPending)
	defer NewCommand()
	cmd := NewCommand()
	if err := cmd.ParseFlags([]string{"--unsigned"}); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	out := output.New(&stdout, &stderr, output.Options{})
	signing, err := resolveRunKey(context.Background(), out, newStageUI(out), dir, "")
	if err != nil || signing != (runSigning{unsigned: true}) {
		t.Fatalf("signing = %+v, err = %v", signing, err)
	}
	if key, _ := localRunKey(dir, ""); key != "" {
		t.Fatalf("unsigned check selected key %q", key)
	}
}

func TestRun_StopsWhenAutomaticKeyApprovalCannotBeChecked(t *testing.T) {
	for _, status := range []string{"missing lock", "error:auth_required", "error:server_error"} {
		t.Run(status, func(t *testing.T) {
			dir, _ := writeKeyProject(t, status)
			t.Chdir(dir)
			if status == "missing lock" {
				if err := os.Remove(filepath.Join(dir, "epack.lock.yaml")); err != nil {
					t.Fatal(err)
				}
			}
			defer NewCommand()
			cmd := NewCommand()
			cmd.SetArgs([]string{"--yes"})
			err := cmd.Execute()
			if err == nil || !strings.Contains(err.Error(), "checking this machine's signing key") {
				t.Fatalf("err = %v, want key-status failure before collection", err)
			}
			if _, err := os.Stat(filepath.Join(dir, "evidence.epack")); !os.IsNotExist(err) {
				t.Fatalf("run created a pack without verifying approval: %v", err)
			}
		})
	}
}

func TestMachineKeyCommand_NamesTheConfigurationWhenThereIsOne(t *testing.T) {
	named := machineKey{remoteName: "mock", config: "northwind-production"}
	if got := named.command("create"); got != "epack key create mock --for northwind-production" {
		t.Errorf("command = %q", got)
	}
	if got := (machineKey{remoteName: "mock"}).command("rotate"); got != "epack key rotate mock" {
		t.Errorf("command without a configuration name = %q", got)
	}
}
