//go:build components

package runcmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/locktivity/epack/cmd/epack/remotecmd"
	"github.com/locktivity/epack/internal/cli/output"
	"github.com/locktivity/epack/internal/component/config"
	"github.com/locktivity/epack/internal/project"
	"github.com/locktivity/epack/internal/remote"
	"github.com/locktivity/epack/internal/runflow"
	"github.com/locktivity/epack/internal/userconfig"
	"github.com/locktivity/epack/sign"
)

// localRunKey is the key a run signs with when nothing was said: --key
// wins, --browser means none, otherwise this machine's key for the remote
// the run pushes to, if 'epack key create' made one.
func localRunKey(workDir, remoteFlag string) (keyPath, remoteName string) {
	if runKey != "" {
		return runKey, ""
	}
	if runBrowser {
		return "", ""
	}
	cfg, err := config.Load(filepath.Join(workDir, project.ConfigFileName))
	if err != nil {
		return "", ""
	}
	remoteName, err = runflow.ResolveRemote(cfg, remoteFlag)
	if err != nil || remoteName == "" {
		return "", ""
	}
	path, err := userconfig.KeyPath(remoteName)
	if err != nil {
		return "", ""
	}
	if _, err := os.Stat(path); err != nil {
		return "", ""
	}
	return path, remoteName
}

// runSigning is how a run signs: with keyPath, keyless when keyPath is
// empty, or not at all when unsigned.
type runSigning struct {
	keyPath  string
	unsigned bool
}

// resolveRunKey picks the key and asks the remote how it holds the key for
// this configuration. The run signs with the machine key only once the
// remote says it is usable, and goes unsigned while it waits for approval.
// An unregistered machine key is offered for registration in a terminal and
// stops the run otherwise, since the pack would land as unsigned.
func resolveRunKey(ctx context.Context, out *output.Writer, ui *stageUI, workDir, remoteFlag string) (runSigning, error) {
	keyPath, remoteName := localRunKey(workDir, remoteFlag)
	withKey := runSigning{keyPath: keyPath}
	if keyPath == "" || remoteName == "" {
		return withKey, nil
	}
	configRef, configName, err := runflow.ConfigReference(workDir)
	if err != nil {
		return withKey, nil
	}
	label := configName
	if label == "" {
		label = "this configuration"
	}
	key, err := sign.LoadPrivateKey(keyPath)
	if err != nil {
		return runSigning{}, fmt.Errorf("reading this machine's signing key: %w", err)
	}
	fingerprint, err := sign.Fingerprint(key.Public())
	if err != nil {
		return runSigning{}, err
	}

	cfg, err := config.Load(filepath.Join(workDir, project.ConfigFileName))
	if err != nil {
		return withKey, nil
	}
	remoteCfg, err := remote.ResolveRemoteConfig(cfg, remoteName, "")
	if err != nil {
		return withKey, nil
	}
	exec, caps, err := remote.PrepareAdapterExecutor(ctx, workDir, remoteName, cfg, remoteCfg, remote.AdapterExecutorOptions{
		PromptInstall: func(remoteName, adapterName string) bool {
			return ui.promptInstallAdapter(remoteName, adapterName, !runYes)
		},
		Step:   ui.onStep,
		Stderr: os.Stderr,
		Verification: remote.VerificationOptions{
			Unsafe: remote.VerificationUnsafeOverrides{AllowUnverifiedSource: runInsecureAllowUnpinned},
		},
	})
	if err != nil {
		return withKey, nil
	}
	defer exec.Close()
	if !caps.SupportsKeys() {
		return withKey, nil
	}
	list, err := exec.KeyList(ctx, configRef)
	if err != nil {
		var adapterErr *remote.AdapterError
		if errors.As(err, &adapterErr) && adapterErr.IsAuthRequired() {
			return withKey, nil
		}
		return withKey, nil
	}
	machine := machineKey{path: keyPath, fingerprint: fingerprint, remoteName: remoteName, config: configName, label: label}
	registered, found := runflow.FindKey(list.Keys, fingerprint)
	ui.stopSpinner()
	if found {
		return machine.signing(out, registered.Status)
	}
	if runYes || !out.PromptConfirm("This machine's signing key is not registered for %s yet. Register it now?", label) {
		return runSigning{}, fmt.Errorf("this machine's signing key %s is not registered for %s; run '%s', or pass --browser to sign in the browser",
			fingerprint[:8], label, machine.command("create"))
	}
	publicPEM, err := sign.MarshalPublicKeyPEM(key.Public())
	if err != nil {
		return runSigning{}, err
	}
	resp, err := exec.KeyRegister(ctx, &remote.KeyRegisterRequest{
		Config: configRef, PublicKeyPEM: string(publicPEM), Name: remote.MachineName(), ExpiresInDays: 365,
	})
	if err != nil {
		return runSigning{}, fmt.Errorf("registering this machine's key: %w", err)
	}
	out.Success("Registered this machine's key for %s as %q", label, resp.Key.Name)
	status := resp.Key.Status
	if status == remote.KeyStatusPending && resp.Key.Approval != nil {
		status, err = remotecmd.AwaitKeyApproval(ctx, out, remotecmd.PendingKey{
			Remote: remoteName, Config: configRef, Key: resp.Key, Lister: exec,
			Resume: fmt.Sprintf("run '%s'", machine.command("create")),
		})
		if err != nil {
			return runSigning{}, err
		}
	}
	return machine.signing(out, status)
}

// machineKey is this machine's key for the remote a run pushes to. config
// names the configuration for --for, empty when the folder has no name.
type machineKey struct {
	path        string
	fingerprint string
	remoteName  string
	config      string
	label       string
}

// command is the epack key command that works on this key, as in
// "epack key create myremote --for northwind-production".
func (k machineKey) command(verb string) string {
	if k.config == "" {
		return fmt.Sprintf("epack key %s %s", verb, k.remoteName)
	}
	return fmt.Sprintf("epack key %s %s --for %s", verb, k.remoteName, k.config)
}

// signing decides how the run signs from the key's status on the remote:
// with the key once it is usable, unsigned while it waits for approval, and
// not at all once the remote has turned it down.
func (k machineKey) signing(out *output.Writer, status string) (runSigning, error) {
	switch status {
	case remote.KeyStatusUsable:
		return runSigning{keyPath: k.path}, nil
	case remote.KeyStatusPending, remote.KeyStatusLapsed:
		out.Warning("this machine's signing key %s is waiting for approval on %s, so this run sends its pack unsigned. To approve it, run '%s'.",
			k.fingerprint[:8], k.remoteName, k.command("create"))
		return runSigning{unsigned: true}, nil
	}
	return runSigning{}, fmt.Errorf("%s holds this machine's signing key %s as %s for %s; replace it with '%s', or pass --browser to sign in the browser",
		k.remoteName, k.fingerprint[:8], output.Printable(status), k.label, k.command("rotate"))
}
