package runflow

import (
	"context"
	"errors"
	"fmt"
	"github.com/locktivity/epack/sign"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/locktivity/epack/internal/component/config"
	"github.com/locktivity/epack/internal/component/lockfile"
	"github.com/locktivity/epack/internal/credentials"
	"github.com/locktivity/epack/internal/lockprovenance"
	"github.com/locktivity/epack/internal/platform"
	"github.com/locktivity/epack/internal/project"
	"github.com/locktivity/epack/internal/redact"
	"github.com/locktivity/epack/internal/remote"
	"github.com/locktivity/epack/internal/remoteconfig"
	"github.com/locktivity/epack/internal/trustedpublishers"
)

// FailureCheck is the failure code a check reports when it found something.
const FailureCheck = "check_failed"

// CredentialCheck is one Locktivity-managed credential the check tried to resolve.
type CredentialCheck struct {
	Component string
	Resolved  bool
	Error     string
}

// CheckResult is what a check found. Findings is empty when the run would
// have everything it needs.
type CheckResult struct {
	Remote      string
	SignedInAs  string
	LockPresent bool
	LockCurrent bool
	EnvPresent  int
	EnvTotal    int
	EnvMissing  []string
	// EnvCovered are variables only the remote reads, left out of the count
	// because the run is signed in and the remote will not need them.
	EnvCovered []string
	// Signing says how the run would sign: in the browser, or with which key.
	Signing           string
	Credentials       []CredentialCheck
	PublishersTrusted bool
	Findings          []string
	Reported          bool
	// PipelineURL is the pipeline page the remote linked the report to, as
	// the remote sent it.
	PipelineURL string
}

// Check does everything a run does before collecting and nothing after:
// trusts publishers, locks a fetched configuration and checks a committed
// one's lock, installs the locked components, checks the variables the
// configuration reads, resolves the credentials the broker provides, signs in
// to the remote, and reports what it found so the pipeline page can show it.
func Check(ctx context.Context, opts Options) (*CheckResult, error) {
	opts, err := withDefaults(opts)
	if err != nil {
		return nil, err
	}
	if err := os.Chdir(opts.WorkDir); err != nil {
		return nil, fmt.Errorf("entering %s: %w", opts.WorkDir, err)
	}
	cfg, err := config.Load(filepath.Join(opts.WorkDir, project.ConfigFileName))
	if err != nil {
		return nil, fmt.Errorf("loading config: %w", err)
	}
	state, err := remoteconfig.LoadState(opts.WorkDir)
	if err != nil {
		return nil, fmt.Errorf("reading the pull record: %w", err)
	}
	if err := exportPipelineID(opts.WorkDir, state); err != nil {
		return nil, err
	}

	result := &CheckResult{PublishersTrusted: true}
	result.Remote, err = ResolveRemote(cfg, opts.Remote)
	if err != nil {
		return nil, err
	}

	checkTrust(cfg, state, opts, result)
	fetched := state != nil
	if fetched && result.PublishersTrusted {
		lockFetched(ctx, cfg, opts, result)
	}
	checkLock(cfg, opts.WorkDir, fetched, result)
	if result.PublishersTrusted && result.LockPresent && result.LockCurrent {
		installLocked(ctx, cfg, opts, result)
	}
	var session *remoteSession
	if result.Remote != "" {
		session = openRemote(ctx, cfg, opts, result)
		if session != nil {
			defer session.exec.Close()
		}
	}
	checkEnv(cfg, opts.WorkDir, result)
	checkCredentials(ctx, cfg, result)
	checkSigning(ctx, session, opts, result)
	if session != nil {
		session.report(ctx, opts, result)
	}
	return result, nil
}

// checkSigning says how the pack would be signed. A key the remote does not
// accept for this configuration is a finding, since the pack would land as
// unsigned; that includes a key still waiting for approval.
func checkSigning(ctx context.Context, session *remoteSession, opts Options, result *CheckResult) {
	path := strings.TrimSpace(opts.Sign.KeyPath)
	if path == "" {
		result.Signing = "in your browser, as you"
		return
	}
	signer, err := sign.LoadPrivateKey(path)
	if err != nil {
		result.Findings = append(result.Findings, fmt.Sprintf("signing key: %v", err))
		return
	}
	fingerprint, err := sign.Fingerprint(signer.Public())
	if err != nil {
		result.Findings = append(result.Findings, fmt.Sprintf("signing key: %v", err))
		return
	}
	result.Signing = "with the key " + filepath.Base(path)
	if session == nil || !session.caps.SupportsKeys() || result.SignedInAs == "" {
		return
	}
	config := strings.TrimSpace(os.Getenv(PipelineIDEnvVar))
	list, err := session.exec.KeyList(ctx, config)
	if err != nil {
		return
	}
	key, found := FindKey(list.Keys, fingerprint)
	switch {
	case !found:
		result.Findings = append(result.Findings, fmt.Sprintf("the signing key %s is not registered for this configuration; run epack key create", fingerprint[:8]))
	case key.Status == remote.KeyStatusUsable:
		result.Signing = "with the key " + DescribeKey(key)
	case key.Status == remote.KeyStatusPending || key.Status == remote.KeyStatusLapsed:
		result.Signing = "unsigned; the key " + keyName(key) + " is waiting for approval"
		result.Findings = append(result.Findings, fmt.Sprintf("the signing key %s is waiting for approval; run epack key create and approve it in the browser", fingerprint[:8]))
	default:
		result.Findings = append(result.Findings, fmt.Sprintf("the signing key %s is no longer accepted for this configuration; replace it with epack key rotate", fingerprint[:8]))
	}
}

// FindKey picks the remote's entry for a key's fingerprint, a usable one
// first.
func FindKey(keys []remote.SigningKey, fingerprint string) (remote.SigningKey, bool) {
	var match remote.SigningKey
	found := false
	for _, key := range keys {
		if key.Fingerprint != fingerprint {
			continue
		}
		if key.Status == remote.KeyStatusUsable {
			return key, true
		}
		if !found {
			match, found = key, true
		}
	}
	return match, found
}

func keyName(key remote.SigningKey) string {
	if key.Name == "" && len(key.Fingerprint) >= 8 {
		return key.Fingerprint[:8]
	}
	return key.Name
}

// DescribeKey names a registered key and how long it has left.
func DescribeKey(key remote.SigningKey) string {
	name := keyName(key)
	if key.ExpiresAt == "" {
		return name
	}
	expires, err := time.Parse(time.RFC3339, key.ExpiresAt)
	if err != nil {
		return name
	}
	days := int(time.Until(expires).Hours() / 24)
	switch {
	case days < 0:
		return name + ", expired"
	case days == 0:
		return name + ", expires today"
	case days == 1:
		return name + ", 1 day left"
	default:
		return fmt.Sprintf("%s, %d days left", name, days)
	}
}

func checkTrust(cfg *config.JobConfig, state *remoteconfig.State, opts Options, result *CheckResult) {
	err := checkPublishers(cfg, state, opts)
	if err == nil {
		return
	}
	result.PublishersTrusted = false
	var trustErr *trustedpublishers.Error
	if errors.As(err, &trustErr) {
		names := make([]string, 0, len(trustErr.Missing))
		for _, req := range trustErr.Missing {
			names = append(names, "github.com/"+req.Publisher)
		}
		result.Findings = append(result.Findings, fmt.Sprintf("publishers not trusted: %s (set %s)", strings.Join(names, ", "), trustedpublishers.EnvVar))
		return
	}
	result.Findings = append(result.Findings, err.Error())
}

// lockFetched locks a fetched configuration the way its first run would.
// Nobody commits the lock of a folder epack fetched, so the check makes it
// rather than asking for it.
func lockFetched(ctx context.Context, cfg *config.JobConfig, opts Options, result *CheckResult) {
	if _, _, err := lockIfNeeded(ctx, cfg, opts); err != nil {
		result.Findings = append(result.Findings, err.Error())
	}
}

// installLocked installs the locked components the way a run does before
// collecting, so the check signs in through the adapter the run will use.
func installLocked(ctx context.Context, cfg *config.JobConfig, opts Options, result *CheckResult) {
	opts.OnStep("Installing dependencies", true)
	if _, err := syncLocked(ctx, cfg, opts); err != nil {
		result.Findings = append(result.Findings, err.Error())
		return
	}
	opts.OnStep("Installed dependencies", false)
}

func checkLock(cfg *config.JobConfig, workDir string, fetched bool, result *CheckResult) {
	platformKey := platform.Key(runtime.GOOS, runtime.GOARCH)
	_, statErr := os.Stat(filepath.Join(workDir, lockfile.FileName))
	result.LockPresent = statErr == nil
	needsLock, err := lockNeeded(cfg, workDir, platformKey)
	if err != nil {
		result.Findings = append(result.Findings, fmt.Sprintf("lock: %v", err))
		return
	}
	result.LockCurrent = !needsLock
	if fetched {
		return
	}
	lockCommand := "epack lock"
	if len(cfg.Platforms) > 0 {
		lockCommand += " --all-platforms"
	}
	if !result.LockPresent {
		result.Findings = append(result.Findings, fmt.Sprintf("no epack.lock.yaml; run %s and commit it", lockCommand))
	} else if needsLock {
		result.Findings = append(result.Findings, fmt.Sprintf("epack.lock.yaml is behind epack.yaml; run %s and commit it", lockCommand))
	}
}

func checkEnv(cfg *config.JobConfig, workDir string, result *CheckResult) {
	summary, err := remoteconfig.Summarize(workDir, os.Getenv)
	if err != nil {
		result.Findings = append(result.Findings, fmt.Sprintf("reading the configuration: %v", err))
		return
	}
	for _, env := range summary.Env {
		if coveredBySignIn(cfg, result.SignedInAs, env) {
			result.EnvCovered = append(result.EnvCovered, env.Name)
			continue
		}
		result.EnvTotal++
		if env.Set {
			result.EnvPresent++
		} else {
			result.EnvMissing = append(result.EnvMissing, env.Name)
		}
	}
	sort.Strings(result.EnvCovered)
	sort.Strings(result.EnvMissing)
	if len(result.EnvMissing) > 0 {
		result.Findings = append(result.Findings, "not set: "+strings.Join(result.EnvMissing, ", "))
	}
}

// coveredBySignIn reports whether a variable is read only by remotes and the
// run is signed in. Such a variable is the remote's fallback credential; a
// signed-in session is the credential, so the run will not read the
// variable, and the page agrees that there is nothing to add.
func coveredBySignIn(cfg *config.JobConfig, signedInAs string, env remoteconfig.EnvVar) bool {
	if signedInAs == "" || len(env.UsedBy) == 0 {
		return false
	}
	for _, user := range env.UsedBy {
		if _, isRemote := cfg.Remotes[user]; !isRemote {
			return false
		}
	}
	return true
}

func checkCredentials(ctx context.Context, cfg *config.JobConfig, result *CheckResult) {
	resolver := credentials.Resolver{}
	try := func(component string, refs []string) {
		if len(refs) == 0 {
			return
		}
		check := CredentialCheck{Component: component}
		if _, err := resolver.ResolveComponentEnv(ctx, cfg, refs); err != nil {
			check.Error = redact.Error(err.Error())
			result.Findings = append(result.Findings, fmt.Sprintf("%s credentials: %s", component, check.Error))
		} else {
			check.Resolved = true
		}
		result.Credentials = append(result.Credentials, check)
	}
	for _, name := range sortedNames(cfg.Collectors) {
		try("collector "+name, cfg.Collectors[name].Credentials)
	}
	for _, name := range sortedNames(cfg.Tools) {
		try("tool "+name, cfg.Tools[name].Credentials)
	}
	for _, name := range sortedNames(cfg.Remotes) {
		try("remote "+name, cfg.Remotes[name].Credentials)
	}
}

// remoteSession is the adapter the check signed in through, kept open so
// the report at the end goes through the same process.
type remoteSession struct {
	exec      *remote.Executor
	caps      *remote.Capabilities
	remoteCfg *config.RemoteConfig
}

// openRemote starts the adapter and asks who the run is, before the
// variables are counted: a signed-in session covers the remote's own
// fallback credential.
func openRemote(ctx context.Context, cfg *config.JobConfig, opts Options, result *CheckResult) *remoteSession {
	remoteCfg, err := remote.ResolveRemoteConfig(cfg, result.Remote, "")
	if err != nil {
		result.Findings = append(result.Findings, fmt.Sprintf("remote %s: %v", result.Remote, err))
		return nil
	}
	exec, caps, err := remote.PrepareAdapterExecutor(ctx, opts.WorkDir, result.Remote, cfg, remoteCfg, remote.AdapterExecutorOptions{
		PromptInstall: opts.PromptInstallAdapter,
		Step:          opts.OnStep,
		Stderr:        opts.Stderr,
		Verification: remote.VerificationOptions{
			Unsafe: remote.VerificationUnsafeOverrides{AllowUnverifiedSource: opts.AllowUnpinned},
		},
	})
	if err != nil {
		result.Findings = append(result.Findings, fmt.Sprintf("remote %s: %v", result.Remote, err))
		return nil
	}

	if caps.SupportsWhoami() {
		identity, err := exec.AuthWhoami(ctx)
		switch {
		case err != nil:
			result.Findings = append(result.Findings, fmt.Sprintf("sign-in to %s: %v", result.Remote, err))
		case !identity.Identity.Authenticated:
			result.Findings = append(result.Findings, fmt.Sprintf("not signed in to %s", result.Remote))
		default:
			result.SignedInAs = identity.Identity.Subject
		}
	}
	return &remoteSession{exec: exec, caps: caps, remoteCfg: remoteCfg}
}

func (s *remoteSession) report(ctx context.Context, opts Options, result *CheckResult) {
	if !s.caps.SupportsLockReport() {
		return
	}
	provenance, err := lockprovenance.Build(checkProvenanceOptions(opts.WorkDir, result))
	if err != nil {
		_, _ = fmt.Fprintf(opts.Stderr, "Warning: could not report the check to %s: %v\n", result.Remote, err)
		return
	}
	resp, err := s.exec.ReportLock(ctx, &remote.LockReportRequest{
		Remote:         result.Remote,
		Target:         remote.TargetConfig{Workspace: s.remoteCfg.Target.Workspace, Environment: s.remoteCfg.Target.Environment},
		LockProvenance: *provenance,
	})
	if err != nil {
		_, _ = fmt.Fprintf(opts.Stderr, "Warning: could not report the check to %s: %v\n", result.Remote, err)
		return
	}
	result.Reported = true
	result.PipelineURL = resp.PipelineURL
}

func checkProvenanceOptions(workDir string, result *CheckResult) lockprovenance.Options {
	credentials := make([]map[string]any, 0, len(result.Credentials))
	for _, c := range result.Credentials {
		entry := map[string]any{"component": c.Component, "resolved": c.Resolved}
		if c.Error != "" {
			entry["error"] = c.Error
		}
		credentials = append(credentials, entry)
	}
	details := map[string]any{
		"signed_in_as":       result.SignedInAs,
		"lock_present":       result.LockPresent,
		"lock_current":       result.LockCurrent,
		"env_present":        result.EnvPresent,
		"env_total":          result.EnvTotal,
		"env_missing":        result.EnvMissing,
		"env_covered":        result.EnvCovered,
		"signing":            result.Signing,
		"credentials":        credentials,
		"publishers_trusted": result.PublishersTrusted,
		"findings":           result.Findings,
	}
	opts := lockprovenance.Options{
		ProjectRoot: workDir,
		TriggerKind: lockprovenance.TriggerCheck,
		Metadata:    map[string]any{"check": details},
	}
	if len(result.Findings) == 0 && result.LockPresent {
		opts.Outcome = lockprovenance.OutcomeSuccess
	} else {
		opts.Outcome = lockprovenance.OutcomeFailure
		opts.FailureCode = FailureCheck
		opts.FailureMessage = strings.Join(result.Findings, "; ")
	}
	return opts
}

// OK reports whether the run would have everything it needs.
func (r *CheckResult) OK() bool {
	return len(r.Findings) == 0
}
