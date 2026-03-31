//go:build components

package remotecmd

import (
	"bytes"
	"io"
	"strings"
	"sync"
	"testing"

	"github.com/locktivity/epack/internal/component/config"
	"github.com/locktivity/epack/internal/securityaudit"
	"github.com/locktivity/epack/internal/securitypolicy"
)

type remoteAuditSink struct {
	mu     sync.Mutex
	events []securityaudit.Event
}

func (s *remoteAuditSink) HandleSecurityEvent(evt securityaudit.Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, evt)
}

func (s *remoteAuditSink) Snapshot() []securityaudit.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]securityaudit.Event, len(s.events))
	copy(out, s.events)
	return out
}

func TestValidatePullFlags_StrictProductionBlocksInsecure(t *testing.T) {
	t.Setenv(securitypolicy.StrictProductionEnvVar, "1")

	orig := pullInsecureAllowUnpinned
	pullInsecureAllowUnpinned = true
	defer func() { pullInsecureAllowUnpinned = orig }()

	err := validatePullFlags(io.Discard, &config.RemoteConfig{})
	if err == nil {
		t.Fatal("expected strict production enforcement error")
	}
	if !strings.Contains(err.Error(), "strict production mode forbids insecure execution overrides") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidatePushFlags_StrictProductionBlocksInsecure(t *testing.T) {
	t.Setenv(securitypolicy.StrictProductionEnvVar, "1")

	orig := pushInsecureAllowUnpinned
	pushInsecureAllowUnpinned = true
	defer func() { pushInsecureAllowUnpinned = orig }()

	err := validatePushFlags(io.Discard, &config.RemoteConfig{})
	if err == nil {
		t.Fatal("expected strict production enforcement error")
	}
	if !strings.Contains(err.Error(), "strict production mode forbids insecure execution overrides") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRemoteFlags_AllowsSecureMode(t *testing.T) {
	t.Setenv(securitypolicy.StrictProductionEnvVar, "1")

	origPull := pullInsecureAllowUnpinned
	origPush := pushInsecureAllowUnpinned
	pullInsecureAllowUnpinned = false
	pushInsecureAllowUnpinned = false
	defer func() {
		pullInsecureAllowUnpinned = origPull
		pushInsecureAllowUnpinned = origPush
	}()

	if err := validatePullFlags(io.Discard, &config.RemoteConfig{}); err != nil {
		t.Fatalf("validatePullFlags unexpected error: %v", err)
	}
	if err := validatePushFlags(io.Discard, &config.RemoteConfig{}); err != nil {
		t.Fatalf("validatePushFlags unexpected error: %v", err)
	}
}

func TestValidateRemoteFlags_EmitInsecureBypassWhenAllowed(t *testing.T) {
	t.Setenv(securitypolicy.StrictProductionEnvVar, "")

	origPull := pullInsecureAllowUnpinned
	origPush := pushInsecureAllowUnpinned
	t.Cleanup(func() {
		pullInsecureAllowUnpinned = origPull
		pushInsecureAllowUnpinned = origPush
		securityaudit.SetSink(nil)
	})

	sink := &remoteAuditSink{}
	securityaudit.SetSink(sink)

	pullInsecureAllowUnpinned = true
	if err := validatePullFlags(io.Discard, &config.RemoteConfig{}); err != nil {
		t.Fatalf("validatePullFlags() error = %v", err)
	}
	pushInsecureAllowUnpinned = true
	if err := validatePushFlags(io.Discard, &config.RemoteConfig{}); err != nil {
		t.Fatalf("validatePushFlags() error = %v", err)
	}

	events := sink.Snapshot()
	var sawPull, sawPush bool
	for _, evt := range events {
		if evt.Type != securityaudit.EventInsecureBypass {
			continue
		}
		if evt.Component == "pull" {
			sawPull = true
		}
		if evt.Component == "push" {
			sawPush = true
		}
	}
	if !sawPull || !sawPush {
		t.Fatalf("expected pull+push insecure bypass events, got: %+v", events)
	}
}

func TestValidatePushFlags_CustomEndpointsEmitWarningAndAudit(t *testing.T) {
	t.Setenv(securitypolicy.StrictProductionEnvVar, "")

	origPush := pushInsecureAllowUnpinned
	t.Cleanup(func() {
		pushInsecureAllowUnpinned = origPush
		securityaudit.SetSink(nil)
	})

	sink := &remoteAuditSink{}
	securityaudit.SetSink(sink)

	stderr := &bytes.Buffer{}
	err := validatePushFlags(stderr, &config.RemoteConfig{
		InsecureEndpoint: "https://api.dev.example",
	})
	if err != nil {
		t.Fatalf("validatePushFlags() error = %v", err)
	}
	if !strings.Contains(stderr.String(), "custom remote endpoint") {
		t.Fatalf("expected custom endpoint warning, got %q", stderr.String())
	}

	events := sink.Snapshot()
	for _, evt := range events {
		if evt.Type == securityaudit.EventInsecureBypass && evt.Component == "push" && evt.Attrs["remote_endpoint_host"] == "api.dev.example" {
			return
		}
	}
	t.Fatalf("expected remote endpoint audit event, got: %+v", events)
}

func TestValidateWhoamiFlags_StrictProductionBlocksInsecure(t *testing.T) {
	t.Setenv(securitypolicy.StrictProductionEnvVar, "1")

	err := validateWhoamiFlags(io.Discard, map[string]*config.RemoteConfig{
		"locktivity": {
			InsecureEndpoint: "https://api.dev.example",
		},
	})
	if err == nil {
		t.Fatal("expected strict production enforcement error")
	}
	if !strings.Contains(err.Error(), "strict production mode forbids insecure execution overrides") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateWhoamiFlags_IgnoresInvalidEndpointUntilPerRemoteExecution(t *testing.T) {
	t.Setenv(securitypolicy.StrictProductionEnvVar, "")

	err := validateWhoamiFlags(io.Discard, map[string]*config.RemoteConfig{
		"locktivity": {
			InsecureEndpoint: "http://api.dev.example",
		},
	})
	if err != nil {
		t.Fatalf("validateWhoamiFlags() error = %v", err)
	}
}
