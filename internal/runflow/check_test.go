package runflow

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"github.com/locktivity/epack/internal/remote"
	"github.com/locktivity/epack/internal/testutil/testhome"
	"github.com/locktivity/epack/sign"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/locktivity/epack/internal/component/config"
	"github.com/locktivity/epack/internal/component/sync"
	"github.com/locktivity/epack/internal/remoteconfig"
	"github.com/locktivity/epack/internal/trustedpublishers"
)

func writeCheckProject(t *testing.T, config string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "epack.yaml"), []byte(config), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestCheck_NamesWhatTheRunWouldMiss(t *testing.T) {
	testhome.Isolate(t)
	t.Setenv(trustedpublishers.EnvVar, "")
	t.Setenv("OKTA_PRIVATE_KEY", "")
	t.Setenv("SENTRY_AUTH_TOKEN", "set")
	oldWd, _ := os.Getwd()
	defer func() { _ = os.Chdir(oldWd) }()

	dir := writeCheckProject(t, "stream: northwind/production\ncollectors:\n  okta:\n    source: locktivity/epack-collector-okta@^0.1\n    secrets: [OKTA_PRIVATE_KEY, SENTRY_AUTH_TOKEN]\n")

	result, err := Check(context.Background(), Options{WorkDir: dir, NonInteractive: true})
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if result.OK() {
		t.Fatalf("expected findings, got none: %+v", result)
	}
	if result.LockPresent || result.LockCurrent {
		t.Errorf("lock should be reported missing: %+v", result)
	}
	if result.EnvTotal != 2 || result.EnvPresent != 1 || strings.Join(result.EnvMissing, ",") != "OKTA_PRIVATE_KEY" {
		t.Errorf("env = %d/%d missing %v", result.EnvPresent, result.EnvTotal, result.EnvMissing)
	}
	joined := strings.Join(result.Findings, "\n")
	for _, want := range []string{"no epack.lock.yaml; run epack lock and commit it", "not set: OKTA_PRIVATE_KEY"} {
		if !strings.Contains(joined, want) {
			t.Errorf("findings missing %q:\n%s", want, joined)
		}
	}
	if result.Reported {
		t.Error("nothing to report to without a remote")
	}
}

func TestCheck_StopsAtUntrustedPublishersInAFetchedFolder(t *testing.T) {
	testhome.Isolate(t)
	t.Setenv(trustedpublishers.EnvVar, "")
	oldWd, _ := os.Getwd()
	defer func() { _ = os.Chdir(oldWd) }()

	dir := writeCheckProject(t, "stream: northwind/production\ncollectors:\n  tls:\n    source: locktivity/epack-collector-tls@^0.1\n")
	if err := os.MkdirAll(filepath.Join(dir, ".epack"), 0o755); err != nil {
		t.Fatal(err)
	}
	record := `{"remote":"locktivity","id":"pipe_1","name":"n","revision":1,"pulled_at":"2026-09-30T12:00:00Z","files":{}}`
	if err := os.WriteFile(filepath.Join(dir, ".epack", "remote-config.json"), []byte(record), 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := Check(context.Background(), Options{WorkDir: dir, NonInteractive: true})
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if result.PublishersTrusted {
		t.Fatal("locktivity is not trusted in this HOME")
	}
	joined := strings.Join(result.Findings, "\n")
	if !strings.Contains(joined, "publishers not trusted: github.com/locktivity (set EPACK_TRUSTED_PUBLISHERS)") {
		t.Errorf("findings = %v", result.Findings)
	}
	if strings.Contains(joined, "epack.lock.yaml") {
		t.Errorf("a fetched folder is locked by its run, never committed:\n%s", joined)
	}
}

func TestCheck_InstallsTheLockedComponentsAsTheRunWould(t *testing.T) {
	testhome.Isolate(t)
	t.Setenv(trustedpublishers.EnvVar, "")
	oldWd, _ := os.Getwd()
	defer func() { _ = os.Chdir(oldWd) }()

	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(dir, "epack-collector-local")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "epack.yaml"), []byte("stream: northwind/production\ncollectors:\n  local:\n    binary: "+binary+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(filepath.Join(dir, "epack.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sync.NewLocker(dir).Lock(context.Background(), cfg, sync.LockOpts{}); err != nil {
		t.Fatalf("Lock: %v", err)
	}

	result, err := Check(context.Background(), Options{WorkDir: dir, NonInteractive: true})
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if !result.OK() {
		t.Fatalf("a current lock whose components install should pass: %v", result.Findings)
	}

	if err := os.WriteFile(binary, []byte("#!/bin/sh\necho changed\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	result, err = Check(context.Background(), Options{WorkDir: dir, NonInteractive: true})
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if !strings.Contains(strings.Join(result.Findings, "\n"), "installing dependencies") {
		t.Errorf("a component that no longer matches its lock should stop the check: %v", result.Findings)
	}
}

func TestCheckProvenanceOptions_ReportsTheOutcome(t *testing.T) {
	ok := &CheckResult{LockPresent: true, LockCurrent: true, PublishersTrusted: true, SignedInAs: "dana@example.com"}
	opts := checkProvenanceOptions(t.TempDir(), ok)
	if opts.TriggerKind != "check" || opts.Outcome != "success" || opts.FailureCode != "" {
		t.Fatalf("ok options = %+v", opts)
	}
	check := opts.Metadata["check"].(map[string]any)
	if check["signed_in_as"] != "dana@example.com" || check["lock_current"] != true {
		t.Fatalf("details = %v", check)
	}

	bad := &CheckResult{LockPresent: true, Findings: []string{"not set: OKTA_PRIVATE_KEY"}}
	opts = checkProvenanceOptions(t.TempDir(), bad)
	if opts.Outcome != "failure" || opts.FailureCode != FailureCheck || opts.FailureMessage != "not set: OKTA_PRIVATE_KEY" {
		t.Fatalf("failing options = %+v", opts)
	}
}

func TestCoveredBySignIn_OnlyTheRemotesOwnVariablesAndOnlyWhenSignedIn(t *testing.T) {
	cfg := &config.JobConfig{
		Remotes:    map[string]config.RemoteConfig{"locktivity": {}},
		Collectors: map[string]config.CollectorConfig{"okta": {}},
	}
	remoteOnly := remoteconfig.EnvVar{Name: "LOCKTIVITY_CLIENT_ID", UsedBy: []string{"locktivity"}}
	shared := remoteconfig.EnvVar{Name: "SHARED_TOKEN", UsedBy: []string{"locktivity", "okta"}}
	collectorOnly := remoteconfig.EnvVar{Name: "OKTA_PRIVATE_KEY", UsedBy: []string{"okta"}}

	if !coveredBySignIn(cfg, "dana@example.com", remoteOnly) {
		t.Error("a signed-in session should cover the remote's own fallback credential")
	}
	for name, env := range map[string]remoteconfig.EnvVar{"shared": shared, "collector": collectorOnly} {
		if coveredBySignIn(cfg, "dana@example.com", env) {
			t.Errorf("%s variable must still be counted", name)
		}
	}
	if coveredBySignIn(cfg, "", remoteOnly) {
		t.Error("nothing is covered without a sign-in")
	}
}

func TestCheck_NamesAllPlatformsWhenTheConfigListsThem(t *testing.T) {
	testhome.Isolate(t)
	t.Setenv(trustedpublishers.EnvVar, "")
	oldWd, _ := os.Getwd()
	defer func() { _ = os.Chdir(oldWd) }()

	dir := writeCheckProject(t, "stream: northwind/production\nplatforms: [linux/amd64, darwin/arm64]\ncollectors:\n  tls:\n    source: locktivity/epack-collector-tls@^0.1\n")

	result, err := Check(context.Background(), Options{WorkDir: dir, NonInteractive: true})
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	joined := strings.Join(result.Findings, "\n")
	if !strings.Contains(joined, "run epack lock --all-platforms and commit it") {
		t.Errorf("finding should name --all-platforms:\n%s", joined)
	}
}

func TestCheck_SaysHowItWouldSign(t *testing.T) {
	testhome.Isolate(t)
	t.Setenv(trustedpublishers.EnvVar, "")
	oldWd, _ := os.Getwd()
	defer func() { _ = os.Chdir(oldWd) }()
	dir := writeCheckProject(t, "stream: northwind/production\ncollectors:\n  tls:\n    source: locktivity/epack-collector-tls@^0.1\n")

	browser, err := Check(context.Background(), Options{WorkDir: dir, NonInteractive: true})
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if browser.Signing != "in your browser, as you" {
		t.Fatalf("Signing = %q", browser.Signing)
	}

	key, err := sign.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	pemBytes, _ := sign.MarshalPrivateKeyPEM(key)
	keyPath := filepath.Join(dir, "signing-key.pem")
	if err := sign.SavePrivateKey(keyPath, pemBytes); err != nil {
		t.Fatal(err)
	}
	withKey, err := Check(context.Background(), Options{WorkDir: dir, NonInteractive: true, Sign: sign.SignPackOptions{KeyPath: keyPath}})
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if withKey.Signing != "with the key signing-key.pem" {
		t.Fatalf("Signing = %q", withKey.Signing)
	}

	if got := DescribeKey(remote.SigningKey{Name: "laptop", ExpiresAt: time.Now().Add(72 * time.Hour).UTC().Format(time.RFC3339)}); got != "laptop, 2 days left" && got != "laptop, 3 days left" {
		t.Fatalf("DescribeKey = %q", got)
	}
	if got := DescribeKey(remote.SigningKey{Fingerprint: "9f14322ec5"}); got != "9f14322e" {
		t.Fatalf("DescribeKey without a name = %q", got)
	}
}

func TestCheckSigning_SaysWhenTheKeyWaitsForApproval(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell script adapters are not available on Windows")
	}
	t.Setenv(PipelineIDEnvVar, "")
	key, err := sign.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	pemBytes, _ := sign.MarshalPrivateKeyPEM(key)
	keyPath := filepath.Join(t.TempDir(), "signing-key.pem")
	if err := sign.SavePrivateKey(keyPath, pemBytes); err != nil {
		t.Fatal(err)
	}
	fingerprint, _ := sign.Fingerprint(key.Public())

	for status, want := range map[string]struct{ signing, finding string }{
		remote.KeyStatusUsable:  {signing: "with the key laptop"},
		remote.KeyStatusPending: {signing: "unsigned; the key laptop is waiting for approval", finding: "the signing key " + fingerprint[:8] + " is waiting for approval; run epack key create and approve it in the browser"},
		remote.KeyStatusLapsed:  {signing: "unsigned; the key laptop is waiting for approval", finding: "is waiting for approval"},
		remote.KeyStatusDenied:  {signing: "with the key signing-key.pem", finding: "is no longer accepted for this configuration; replace it with epack key rotate"},
	} {
		adapter := filepath.Join(t.TempDir(), "adapter")
		list := fmt.Sprintf(`{"ok":true,"type":"key.list.result","keys":[{"id":"key_123","name":"laptop","fingerprint":"%s","status":"%s"}]}`, fingerprint, status)
		if err := os.WriteFile(adapter, []byte("#!/bin/sh\ncat > /dev/null\necho '"+list+"'\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		session := &remoteSession{exec: remote.NewExecutor(adapter, "mock"), caps: &remote.Capabilities{Features: remote.CapabilityFeatures{Keys: true}}}
		result := &CheckResult{SignedInAs: "dana@example.com"}
		opts := Options{
			Sign: sign.SignPackOptions{KeyPath: keyPath},
			RegisterKey: func(context.Context, *remote.Executor, crypto.Signer, string) (remote.SigningKey, bool, error) {
				t.Errorf("%s: offered to register a key the remote already holds", status)
				return remote.SigningKey{}, false, nil
			},
		}

		checkSigning(context.Background(), session, opts, result)
		findings := strings.Join(result.Findings, "\n")
		if result.Signing != want.signing || (want.finding == "") != (findings == "") || !strings.Contains(findings, want.finding) {
			t.Errorf("%s: signing %q, findings %q; want %q and %q", status, result.Signing, findings, want.signing, want.finding)
		}
	}
}

func TestCheckSigning_OffersToRegisterAKeyTheRemoteDoesNotHold(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell script adapters are not available on Windows")
	}
	t.Setenv(PipelineIDEnvVar, "pipe-123")
	key, err := sign.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	pemBytes, _ := sign.MarshalPrivateKeyPEM(key)
	keyPath := filepath.Join(t.TempDir(), "signing-key.pem")
	if err := sign.SavePrivateKey(keyPath, pemBytes); err != nil {
		t.Fatal(err)
	}
	fingerprint, _ := sign.Fingerprint(key.Public())
	adapter := filepath.Join(t.TempDir(), "adapter")
	if err := os.WriteFile(adapter, []byte("#!/bin/sh\ncat > /dev/null\necho '{\"ok\":true,\"type\":\"key.list.result\",\"keys\":[]}'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	unregistered := "the signing key " + fingerprint[:8] + " is not registered for this configuration; run epack key create, or pass --browser to sign in the browser"

	for name, tc := range map[string]struct {
		register         func() (remote.SigningKey, bool, error)
		signing, finding string
	}{
		"not offered": {signing: "with the key signing-key.pem", finding: unregistered},
		"declined": {
			register: func() (remote.SigningKey, bool, error) { return remote.SigningKey{}, false, nil },
			signing:  "with the key signing-key.pem", finding: unregistered,
		},
		"approved": {
			register: func() (remote.SigningKey, bool, error) {
				return remote.SigningKey{Name: "laptop", Status: remote.KeyStatusUsable}, true, nil
			},
			signing: "with the key laptop",
		},
		"waiting": {
			register: func() (remote.SigningKey, bool, error) {
				return remote.SigningKey{Name: "laptop", Status: remote.KeyStatusPending}, true, nil
			},
			signing: "unsigned; the key laptop is waiting for approval", finding: "is waiting for approval",
		},
		"failed": {
			register: func() (remote.SigningKey, bool, error) {
				return remote.SigningKey{}, false, errors.New("adapter crashed")
			},
			signing: "with the key signing-key.pem", finding: "registering the signing key " + fingerprint[:8] + ": adapter crashed",
		},
	} {
		opts := Options{Sign: sign.SignPackOptions{KeyPath: keyPath}}
		if tc.register != nil {
			opts.RegisterKey = func(_ context.Context, _ *remote.Executor, signer crypto.Signer, config string) (remote.SigningKey, bool, error) {
				if got, _ := sign.Fingerprint(signer.Public()); got != fingerprint || config != "pipe-123" {
					t.Errorf("%s: asked to register %s for %q", name, got, config)
				}
				return tc.register()
			}
		}
		session := &remoteSession{exec: remote.NewExecutor(adapter, "mock"), caps: &remote.Capabilities{Features: remote.CapabilityFeatures{Keys: true}}}
		result := &CheckResult{SignedInAs: "dana@example.com"}

		checkSigning(context.Background(), session, opts, result)
		findings := strings.Join(result.Findings, "\n")
		if result.Signing != tc.signing || (tc.finding == "") != (findings == "") || !strings.Contains(findings, tc.finding) {
			t.Errorf("%s: signing %q, findings %q; want %q and %q", name, result.Signing, findings, tc.signing, tc.finding)
		}
	}
}

func TestCheckReport_KeepsThePipelinePageTheRemoteLinked(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell script adapters are not available on Windows")
	}
	for _, link := range []string{"https://app.locktivity.com/evidence_packs/pipelines/9b2f", ""} {
		answer := `{"ok":true,"type":"lock.report.result","status":"accepted"}`
		if link != "" {
			answer = `{"ok":true,"type":"lock.report.result","status":"accepted","pipeline_url":"` + link + `"}`
		}
		adapter := filepath.Join(t.TempDir(), "adapter")
		if err := os.WriteFile(adapter, []byte("#!/bin/sh\ncat > /dev/null\necho '"+answer+"'\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		session := &remoteSession{
			exec:      remote.NewExecutor(adapter, "mock"),
			caps:      &remote.Capabilities{Features: remote.CapabilityFeatures{LockReport: true}},
			remoteCfg: &config.RemoteConfig{},
		}
		result := &CheckResult{Remote: "mock", Findings: []string{"not set: OKTA_PRIVATE_KEY"}}
		var stderr strings.Builder

		session.report(context.Background(), Options{WorkDir: t.TempDir(), Stderr: &stderr}, result)
		if !result.Reported || result.PipelineURL != link {
			t.Errorf("reported %v with pipeline page %q, want %q (stderr: %s)", result.Reported, result.PipelineURL, link, stderr.String())
		}
	}
}

func TestFindKey_PrefersAUsableEntry(t *testing.T) {
	keys := []remote.SigningKey{
		{ID: "key_1", Fingerprint: "aa", Status: remote.KeyStatusRevoked},
		{ID: "key_2", Fingerprint: "bb", Status: remote.KeyStatusPending},
		{ID: "key_3", Fingerprint: "aa", Status: remote.KeyStatusUsable},
	}
	if key, found := FindKey(keys, "aa"); !found || key.ID != "key_3" {
		t.Errorf("FindKey(aa) = %+v, %v", key, found)
	}
	if key, found := FindKey(keys, "bb"); !found || key.ID != "key_2" {
		t.Errorf("FindKey(bb) = %+v, %v", key, found)
	}
	if _, found := FindKey(keys, "cc"); found {
		t.Error("FindKey(cc) found a key that is not listed")
	}
}

func TestConfigReference_FromTheRecordOrTheEnvironment(t *testing.T) {
	t.Setenv(PipelineIDEnvVar, "")
	dir := t.TempDir()
	if id, label, err := ConfigReference(dir); err != nil || id != "" || label != "" {
		t.Fatalf("empty folder: %q %q %v", id, label, err)
	}

	if err := os.MkdirAll(filepath.Join(dir, ".epack"), 0o755); err != nil {
		t.Fatal(err)
	}
	state := `{"remote":"locktivity","id":"pipe_1","name":"northwind-production","revision":1,"pulled_at":"2026-09-30T12:00:00Z","files":{}}`
	if err := os.WriteFile(filepath.Join(dir, ".epack", "remote-config.json"), []byte(state), 0o644); err != nil {
		t.Fatal(err)
	}
	if id, label, _ := ConfigReference(dir); id != "pipe_1" || label != "northwind-production" {
		t.Fatalf("record: %q %q", id, label)
	}

	t.Setenv(PipelineIDEnvVar, "pipe_env")
	if id, _, _ := ConfigReference(dir); id != "pipe_env" {
		t.Fatalf("env: %q", id)
	}
}
