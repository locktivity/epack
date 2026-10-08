//go:build components

package remotecmd

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/locktivity/epack/internal/cli/output"
	"github.com/locktivity/epack/internal/component/config"
	"github.com/locktivity/epack/internal/componenttypes"
	"github.com/locktivity/epack/internal/project"
	"github.com/locktivity/epack/internal/remote"
	"github.com/locktivity/epack/internal/runflow"
	"github.com/locktivity/epack/internal/userconfig"
	"github.com/locktivity/epack/sign"
	"github.com/spf13/cobra"
)

const defaultKeyLifetimeDays = 365

var (
	keyFor                   string
	keyOut                   string
	keyName                  string
	keyExpiresDays           int
	keyNoBrowser             bool
	keyInsecureAllowUnpinned bool
)

// NewKeyCommand returns the 'key' command group.
func NewKeyCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "key",
		Short: "Signing keys for runs from this machine",
		Long: `Signing keys for runs from this machine.

A run from a terminal signs its pack in your browser, as you. A key signs it
with nobody at the keyboard, which a scheduled run needs, and keeps your email
out of the signature. 'epack key create' makes one, keeps the private half in
~/.epack/keys/<remote>.pem readable only by you, and registers the public half
with the remote. Once the remote accepts it, runs from this machine sign with
it on their own.`,
	}
	cmd.AddCommand(newKeyCreateCommand(), newKeyListCommand(), newKeyRotateCommand())
	return cmd
}

func newKeyCreateCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "create [remote]",
		Short: "Make a signing key for this machine and register it",
		Long: `Make a signing key for this machine and register its public half.

The private key is written to ~/.epack/keys/<remote>.pem, readable only by
you, and never leaves this machine. Only the public half is sent. Running the
command again registers the same key, so it is safe to repeat.

The remote may hold a new key until someone approves it. The command then
shows a code, opens the approval page in your browser, and waits; enter the
code there. With --no-browser, it prints the link instead. Runs sign with the
key only once it is approved. If nobody approves it in time, run the command
again for a new code.

Inside a fetched configuration the key is registered for that configuration.
Elsewhere, name one with --for. With --out, the key is written there for a
runner you manage instead, and runs on this machine do not pick it up.

Examples:
  epack key create
  epack key create locktivity --for northwind-production
  epack key create --for northwind-production --out ./epack-signing-key.pem`,
		Args: cobra.MaximumNArgs(1),
		RunE: runKeyCreate,
	}
	addKeyFlags(cmd, true)
	return cmd
}

func newKeyListCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list [remote]",
		Short: "Show the keys a configuration accepts",
		Long: `Show the keys a configuration accepts, and which one is this machine's.

Examples:
  epack key list
  epack key list locktivity --for northwind-production`,
		Args: cobra.MaximumNArgs(1),
		RunE: runKeyList,
	}
	addKeyFlags(cmd, false)
	return cmd
}

func newKeyRotateCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rotate [remote]",
		Short: "Replace this machine's key and retire the old one",
		Long: `Replace this machine's signing key.

A new key is made and registered first; the old one is retired only once the
new one is accepted, so a failed rotation leaves the old key working. A retired
key signs nothing new, and packs already signed with it stay trusted. When the
remote asks for approval, the command waits for it as 'epack key create' does,
and running it again picks up the same new key.

Examples:
  epack key rotate
  epack key rotate locktivity --for northwind-production`,
		Args: cobra.MaximumNArgs(1),
		RunE: runKeyRotate,
	}
	addKeyFlags(cmd, true)
	return cmd
}

func addKeyFlags(cmd *cobra.Command, create bool) {
	cmd.Flags().StringVar(&keyFor, "for", "", "the configuration the key is for (default: the fetched configuration in this folder)")
	if create {
		cmd.Flags().StringVar(&keyName, "name", "", "how the key is listed (default: this machine's name)")
		cmd.Flags().IntVar(&keyExpiresDays, "expires-days", defaultKeyLifetimeDays, "days until the key stops being accepted; 0 for no expiry")
		cmd.Flags().BoolVar(&keyNoBrowser, "no-browser", false, "print the link instead of opening a browser")
		if cmd.Name() == "create" {
			cmd.Flags().StringVar(&keyOut, "out", "", "write the key to this path for a runner you manage, instead of this machine's key")
		}
	}
	keyInsecureAllowUnpinned = componenttypes.InsecureAllowUnpinnedFromEnv()
	cmd.Flags().BoolVar(&keyInsecureAllowUnpinned, "insecure-allow-unpinned", keyInsecureAllowUnpinned,
		"allow using adapters not pinned in lockfile (NOT RECOMMENDED)")
}

// keyTarget is the remote and configuration a key command works on.
type keyTarget struct {
	remoteName string
	config     string
	label      string
}

// resolveKeyTarget picks the remote (the argument, the project's only
// remote, or the one last signed in to) and the configuration (--for, or
// the folder's own).
func resolveKeyTarget(args []string) (keyTarget, error) {
	remoteName := ""
	if len(args) > 0 {
		remoteName = strings.TrimSpace(args[0])
	}
	projectRoot, cfg := currentProject()
	if remoteName == "" && cfg != nil {
		remoteName, _ = runflow.ResolveRemote(cfg, "")
	}
	if remoteName == "" {
		remoteName, _ = userconfig.DefaultRemote()
	}
	if remoteName == "" {
		return keyTarget{}, exitError("say which remote, as in: epack key create locktivity")
	}
	target := keyTarget{remoteName: remoteName, config: strings.TrimSpace(keyFor), label: strings.TrimSpace(keyFor)}
	if target.config == "" && projectRoot != "" {
		id, label, err := runflow.ConfigReference(projectRoot)
		if err != nil {
			return keyTarget{}, exitError("%v", err)
		}
		target.config, target.label = id, label
	}
	if target.label == "" {
		target.label = "this folder's configuration"
	}
	return target, nil
}

func currentProject() (string, *config.JobConfig) {
	projectRoot, err := project.FindRoot("")
	if err != nil {
		return "", nil
	}
	cfg, err := config.Load(filepath.Join(projectRoot, project.ConfigFileName))
	if err != nil {
		return projectRoot, nil
	}
	return projectRoot, cfg
}

// keyFile is where the key goes: this machine's key for the remote, or
// the path --out names for a runner elsewhere.
func keyFile(remoteName string) (path string, machineKey bool, err error) {
	if keyOut != "" {
		abs, err := filepath.Abs(keyOut)
		return abs, false, err
	}
	path, err = userconfig.KeyPath(remoteName)
	return path, true, err
}

type generatedKey struct {
	signer      crypto.Signer
	privatePEM  []byte
	publicPEM   string
	fingerprint string
}

func generateKey() (*generatedKey, error) {
	key, err := sign.GenerateKey()
	if err != nil {
		return nil, err
	}
	privatePEM, err := sign.MarshalPrivateKeyPEM(key)
	if err != nil {
		return nil, err
	}
	return describeSigner(key, privatePEM)
}

func loadKey(path string) (*generatedKey, error) {
	signer, err := sign.LoadPrivateKey(path)
	if err != nil {
		return nil, err
	}
	return describeSigner(signer, nil)
}

func describeSigner(signer crypto.Signer, privatePEM []byte) (*generatedKey, error) {
	publicPEM, err := sign.MarshalPublicKeyPEM(signer.Public())
	if err != nil {
		return nil, err
	}
	fingerprint, err := sign.Fingerprint(signer.Public())
	if err != nil {
		return nil, err
	}
	return &generatedKey{signer: signer, privatePEM: privatePEM, publicPEM: string(publicPEM), fingerprint: fingerprint}, nil
}

type keyRegistration struct {
	key         remote.SigningKey
	created     bool
	pipelineURL string
	// adapter stays open so a key waiting for approval can be checked on.
	// The caller closes it.
	adapter *PreparedRemote
}

// registerKey hands the public half to the remote. A reason comes back,
// instead of an error, when the key is fine but could not be registered
// from here, so the caller can print the public key for the page.
func registerKey(ctx context.Context, ui *commandUI, target keyTarget, publicPEM, name string, expiresDays int) (*keyRegistration, string, error) {
	prepared, err := PrepareRemote(ctx, target.remoteName, PrepareOptions{
		AllowUnpinned: keyInsecureAllowUnpinned,
		Step:          ui.onStep,
		PromptInstall: func(remoteName, adapterName string) bool {
			return ui.promptInstallAdapter(remoteName, adapterName, true)
		},
		Stderr: os.Stderr,
	})
	if err != nil {
		return nil, fmt.Sprintf("the %s adapter could not be started (%v)", target.remoteName, err), nil
	}
	if !prepared.Caps.SupportsKeys() {
		prepared.Close()
		return nil, fmt.Sprintf("the %s adapter cannot register keys", target.remoteName), nil
	}
	resp, err := prepared.Exec.KeyRegister(ctx, &remote.KeyRegisterRequest{
		Config: target.config, PublicKeyPEM: publicPEM, Name: name, ExpiresInDays: expiresDays,
	})
	if err != nil {
		prepared.Close()
		var adapterErr *remote.AdapterError
		if errors.As(err, &adapterErr) && adapterErr.IsAuthRequired() {
			return nil, fmt.Sprintf("you are not signed in to %s", target.remoteName), nil
		}
		if target.config == "" {
			return nil, "no configuration was named; run this inside a fetched configuration or add --for <name>", nil
		}
		return nil, "", exitError("registering the key: %v", adapterMessage(err))
	}
	return &keyRegistration{key: resp.Key, created: resp.Created, pipelineURL: resp.PipelineURL, adapter: prepared}, "", nil
}

// approve waits for a person to approve the key when the remote holds it as
// pending, then fails if the key can no longer become usable. A remote that
// approves keys some other way returns no approval to wait on. resume says
// how to pick the request up again, as in "run 'epack key create' again".
func (r *keyRegistration) approve(ctx context.Context, out *output.Writer, target keyTarget, resume string) error {
	if r.key.Status == remote.KeyStatusPending && r.key.Approval != nil {
		status, err := AwaitKeyApproval(ctx, out, PendingKey{
			Remote: target.remoteName, Config: target.config, Key: r.key,
			Lister: r.adapter.Exec, NoBrowser: keyNoBrowser, Resume: resume,
		})
		if err != nil {
			return err
		}
		r.key.Status = status
	}
	switch r.key.Status {
	case remote.KeyStatusDenied:
		return exitError("the key was denied on %s, so runs will not sign with it", target.remoteName)
	case remote.KeyStatusLapsed:
		return exitError("the key was not approved in time; %s for a new code", resume)
	case remote.KeyStatusExpired, remote.KeyStatusRetired, remote.KeyStatusRevoked:
		return exitError("%s holds this key as %s, so runs will not sign with it", target.remoteName, r.key.Status)
	}
	return nil
}

func runKeyCreate(cmd *cobra.Command, args []string) error {
	out := getOutput(cmd)
	ctx := cmdContext(cmd)
	ui := newCommandUI(out, "", "", "Registration failed")

	target, err := resolveKeyTarget(args)
	if err != nil {
		return err
	}
	path, machineKey, err := keyFile(target.remoteName)
	if err != nil {
		return exitError("%v", err)
	}

	var key *generatedKey
	created := false
	if _, statErr := os.Stat(path); statErr == nil {
		if key, err = loadKey(path); err != nil {
			return exitError("reading %s: %v", displayPath(path), err)
		}
	} else {
		if key, err = generateKey(); err != nil {
			return exitError("%v", err)
		}
		if err := sign.SavePrivateKey(path, key.privatePEM); err != nil {
			return exitError("%v", err)
		}
		created = true
	}

	name := strings.TrimSpace(keyName)
	if name == "" {
		name = remote.MachineName()
	}
	registration, reason, err := registerKey(ctx, ui, target, key.publicPEM, name, keyExpiresDays)
	if err != nil {
		ui.fail()
		return err
	}
	if registration == nil {
		if out.IsJSON() {
			return out.JSON(keyCreateJSON(target, path, key, nil, reason, created))
		}
		printKeyFile(out, path, key, created)
		printUnregisteredKey(out, target, key.publicPEM, reason)
		return nil
	}
	defer registration.adapter.Close()

	if !out.IsJSON() {
		printKeyFile(out, path, key, created)
		if registration.created {
			out.Print("Registered its public key with %s for %s\n  as %q, %s (fingerprint %s)\n",
				target.remoteName, target.label, registration.key.Name, expiryPhrase(registration.key.ExpiresAt), shortFingerprint(registration.key.Fingerprint))
		} else {
			out.Print("%s already holds this key for %s as %q, %s (fingerprint %s)\n",
				target.remoteName, target.label, registration.key.Name, expiryPhrase(registration.key.ExpiresAt), shortFingerprint(registration.key.Fingerprint))
		}
	}
	if err := registration.approve(ctx, out, target, fmt.Sprintf("run '%s' again", cmd.CommandPath())); err != nil {
		return err
	}
	if out.IsJSON() {
		return out.JSON(keyCreateJSON(target, path, key, registration, reason, created))
	}
	switch {
	case !machineKey:
		out.Print("Store %s where the runner keeps secrets and hand it to the run as EPACK_SIGNING_KEY.\n", displayPath(path))
	case registration.key.Status == remote.KeyStatusUsable:
		out.Print("Runs from this machine now sign with it. No browser needed.\n")
	default:
		out.Print("Runs from this machine sign with it once %s approves it.\n", target.remoteName)
	}
	if registration.key.Status == remote.KeyStatusUsable {
		PrintPipelinePage(out, registration.pipelineURL)
	}
	return nil
}

func printKeyFile(out *output.Writer, path string, key *generatedKey, created bool) {
	if created {
		out.Print("Generated %s (ECDSA P-256, readable only by you)\n", displayPath(path))
	} else {
		out.Print("Using the key at %s (fingerprint %s)\n", displayPath(path), shortFingerprint(key.fingerprint))
	}
}

func keyCreateJSON(target keyTarget, path string, key *generatedKey, registration *keyRegistration, reason string, created bool) map[string]interface{} {
	result := map[string]interface{}{
		"remote":      target.remoteName,
		"config":      target.config,
		"path":        path,
		"fingerprint": key.fingerprint,
		"generated":   created,
		"registered":  registration != nil,
	}
	if registration != nil {
		result["created"] = registration.created
		result["name"] = registration.key.Name
		result["status"] = registration.key.Status
		result["expires_at"] = registration.key.ExpiresAt
		if page := PipelinePage(registration.pipelineURL); page != "" && registration.key.Status == remote.KeyStatusUsable {
			result["pipeline_url"] = page
		}
	} else {
		result["reason"] = reason
		result["public_key_pem"] = key.publicPEM
	}
	return result
}

func printUnregisteredKey(out *output.Writer, target keyTarget, publicPEM, reason string) {
	out.Warning("The key was not registered: %s.", reason)
	out.Print("\nIts public half, to register by hand:\n\n%s\n", publicPEM)
	if strings.HasPrefix(reason, "you are not signed in") {
		out.Print("Or sign in with: epack remote login %s\nThen run this command again.\n", target.remoteName)
	}
}

func runKeyList(cmd *cobra.Command, args []string) error {
	out := getOutput(cmd)
	ctx := cmdContext(cmd)
	ui := newCommandUI(out, "", "", "Listing failed")

	target, err := resolveKeyTarget(args)
	if err != nil {
		return err
	}
	keys, err := listKeys(ctx, ui, target)
	if err != nil {
		ui.fail()
		return err
	}
	local := ""
	if path, err := userconfig.KeyPath(target.remoteName); err == nil {
		if key, err := loadKey(path); err == nil {
			local = key.fingerprint
		}
	}

	if out.IsJSON() {
		return out.JSON(map[string]interface{}{"remote": target.remoteName, "config": target.config, "keys": keys, "this_machine": local})
	}
	if len(keys) == 0 {
		out.Print("%s accepts no keys yet. Make one with: epack key create\n", target.label)
		return nil
	}
	out.Print("Keys %s accepts:\n", target.label)
	for _, key := range keys {
		from := ""
		if key.Machine != "" && key.Machine != key.Name {
			from = "  from " + output.Printable(key.Machine)
		}
		marker := ""
		if key.Fingerprint == local {
			marker = "  (this machine)"
		}
		out.Print("  %-28s %-8s %s  %s%s%s\n", keyDisplayName(key), output.Printable(key.Status), shortFingerprint(key.Fingerprint), expiryPhrase(key.ExpiresAt), from, marker)
	}
	return nil
}

func listKeys(ctx context.Context, ui *commandUI, target keyTarget) ([]remote.SigningKey, error) {
	prepared, err := PrepareRemote(ctx, target.remoteName, PrepareOptions{
		AllowUnpinned: keyInsecureAllowUnpinned,
		Step:          ui.onStep,
		PromptInstall: func(remoteName, adapterName string) bool {
			return ui.promptInstallAdapter(remoteName, adapterName, true)
		},
		Stderr: os.Stderr,
	})
	if err != nil {
		return nil, exitError("%v", err)
	}
	defer prepared.Close()
	if !prepared.Caps.SupportsKeys() {
		return nil, exitError("the %s adapter cannot list keys", target.remoteName)
	}
	resp, err := prepared.Exec.KeyList(ctx, target.config)
	if err != nil {
		return nil, exitError("listing keys: %v", adapterMessage(err))
	}
	return resp.Keys, nil
}

func runKeyRotate(cmd *cobra.Command, args []string) error {
	out := getOutput(cmd)
	ctx := cmdContext(cmd)
	ui := newCommandUI(out, "", "", "Rotation failed")

	target, err := resolveKeyTarget(args)
	if err != nil {
		return err
	}
	path, err := userconfig.KeyPath(target.remoteName)
	if err != nil {
		return exitError("%v", err)
	}
	old, err := loadKey(path)
	if err != nil {
		return exitError("no key for %s on this machine yet; make one with: epack key create", target.remoteName)
	}
	nextPath := nextKeyPath(path)
	fresh, err := loadKey(nextPath)
	if err != nil {
		if fresh, err = generateKey(); err != nil {
			return exitError("%v", err)
		}
		if err := sign.SavePrivateKey(nextPath, fresh.privatePEM); err != nil {
			return exitError("%v", err)
		}
	}
	name := strings.TrimSpace(keyName)
	if name == "" {
		name = remote.MachineName()
	}
	registration, reason, err := registerKey(ctx, ui, target, fresh.publicPEM, name, keyExpiresDays)
	if err != nil {
		ui.fail()
		return err
	}
	if registration == nil {
		return exitError("the new key was not registered (%s), so the old one stays", reason)
	}
	defer registration.adapter.Close()
	if err := registration.approve(ctx, out, target, fmt.Sprintf("run '%s' again", cmd.CommandPath())); err != nil {
		switch registration.key.Status {
		case remote.KeyStatusDenied, remote.KeyStatusExpired, remote.KeyStatusRetired, remote.KeyStatusRevoked:
			_ = os.Remove(nextPath)
		}
		return exitError("%v. The old key stays.", err)
	}
	if registration.key.Status != remote.KeyStatusUsable {
		return exitError("the new key is not usable on %s yet, so the old one stays; once it is approved, run '%s' again to finish", target.remoteName, cmd.CommandPath())
	}
	if err := os.Rename(nextPath, path); err != nil {
		return exitError("%v", err)
	}

	retired := retireKeyByFingerprint(ctx, ui, target, old.fingerprint)
	if out.IsJSON() {
		result := map[string]interface{}{
			"remote": target.remoteName, "config": target.config, "path": path,
			"fingerprint": fresh.fingerprint, "name": registration.key.Name, "expires_at": registration.key.ExpiresAt,
			"retired": retired, "previous_fingerprint": old.fingerprint,
		}
		if page := PipelinePage(registration.pipelineURL); page != "" {
			result["pipeline_url"] = page
		}
		return out.JSON(result)
	}
	out.Print("Registered a new key with %s for %s as %q, %s (fingerprint %s)\nSaved to %s\n",
		target.remoteName, target.label, registration.key.Name, expiryPhrase(registration.key.ExpiresAt), shortFingerprint(fresh.fingerprint), displayPath(path))
	if retired {
		out.Print("Retired the old key %s. Packs it already signed stay trusted.\n", shortFingerprint(old.fingerprint))
	} else {
		out.Print("The old key %s was not in use there, so there was nothing to retire.\n", shortFingerprint(old.fingerprint))
	}
	PrintPipelinePage(out, registration.pipelineURL)
	return nil
}

// retireKeyByFingerprint retires the key a rotation replaced, so it signs
// nothing new while the packs it signed stay trusted.
func retireKeyByFingerprint(ctx context.Context, ui *commandUI, target keyTarget, fingerprint string) bool {
	keys, err := listKeys(ctx, ui, target)
	if err != nil {
		return false
	}
	for _, key := range keys {
		if key.Fingerprint != fingerprint || key.Status != remote.KeyStatusUsable {
			continue
		}
		prepared, err := PrepareRemote(ctx, target.remoteName, PrepareOptions{AllowUnpinned: keyInsecureAllowUnpinned, Stderr: os.Stderr})
		if err != nil {
			return false
		}
		_, err = prepared.Exec.KeyRetire(ctx, target.config, key.ID)
		prepared.Close()
		return err == nil
	}
	return false
}

// nextKeyPath is where a rotation keeps the new key until the remote accepts
// it, so running the rotation again picks up the same key. Key files end in
// .pem, so it cannot be another remote's key.
func nextKeyPath(path string) string {
	return path + ".next"
}

func keyDisplayName(key remote.SigningKey) string {
	if key.Name != "" {
		return output.Printable(key.Name)
	}
	return shortFingerprint(key.Fingerprint)
}

func shortFingerprint(fingerprint string) string {
	if len(fingerprint) > 8 {
		return fingerprint[:8]
	}
	return fingerprint
}

// expiryPhrase reads an expiry as the terminal shows it: "expiring
// 2027-10-01" or "with no expiry".
func expiryPhrase(expiresAt string) string {
	if expiresAt == "" {
		return "with no expiry"
	}
	expires, err := time.Parse(time.RFC3339, expiresAt)
	if err != nil {
		return "expiring " + output.Printable(expiresAt)
	}
	return "expiring " + expires.Local().Format("2006-01-02")
}

func displayPath(path string) string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" || !strings.HasPrefix(path, home+string(os.PathSeparator)) {
		return path
	}
	return "~" + strings.TrimPrefix(path, home)
}
