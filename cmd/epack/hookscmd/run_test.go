//go:build components

package hookscmd

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/locktivity/epack/internal/remoteconfig"
)

func TestRun_SkipsAHookThatIsStillTheRemotesTemplate(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell hooks are not available on Windows")
	}
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "epack.yaml"), []byte("stream: t/s\ncollectors:\n  tls:\n    source: owner/repo@v1.0.0\n"), 0o644); err != nil {
		t.Fatalf("config: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(dir, ".epack", "hooks"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	marker := filepath.Join(dir, "ran")
	template := "#!/bin/sh\ntouch " + marker + "\n"
	hook := filepath.Join(dir, ".epack", "hooks", "pre-collect.sh")
	if err := os.WriteFile(hook, []byte(template), 0o755); err != nil {
		t.Fatalf("hook: %v", err)
	}
	sum := sha256.Sum256([]byte(template))
	state := remoteconfig.State{Remote: "mock", Name: "cfg", Revision: 1, Files: map[string]string{}, Templates: map[string]string{".epack/hooks/pre-collect.sh": hex.EncodeToString(sum[:])}}
	data, _ := json.Marshal(state)
	if err := os.WriteFile(filepath.Join(dir, remoteconfig.StateFile), data, 0o644); err != nil {
		t.Fatalf("state: %v", err)
	}

	oldWd, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	defer func() { _ = os.Chdir(oldWd) }()

	cmd := newRunCommand()
	cmd.SetArgs([]string{"pre-collect"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("run: %v", err)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("the remote's template hook ran")
	}

	if err := os.WriteFile(hook, []byte(template+"echo edited\n"), 0o755); err != nil {
		t.Fatalf("editing hook: %v", err)
	}
	cmd = newRunCommand()
	cmd.SetArgs([]string{"pre-collect"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("run after edit: %v", err)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatal("the edited hook did not run")
	}
}
