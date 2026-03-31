package credentials

import (
	"bytes"
	"io"
	"strings"
	"sync"
	"testing"

	"github.com/locktivity/epack/internal/broker"
	"github.com/locktivity/epack/internal/securityaudit"
	"github.com/locktivity/epack/internal/securitypolicy"
)

type brokerPolicyAuditSink struct {
	mu     sync.Mutex
	events []securityaudit.Event
}

func (s *brokerPolicyAuditSink) HandleSecurityEvent(evt securityaudit.Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, evt)
}

func (s *brokerPolicyAuditSink) Snapshot() []securityaudit.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]securityaudit.Event, len(s.events))
	copy(out, s.events)
	return out
}

func TestValidateManagedCredentialBrokerOverride_IgnoresOverrideWithoutManagedRefs(t *testing.T) {
	t.Setenv(securitypolicy.StrictProductionEnvVar, "1")
	t.Setenv(broker.InsecureCredentialBrokerURLEnvVar, "http://invalid.example.com")

	if err := ValidateManagedCredentialBrokerOverride(io.Discard, nil, BrokerOverridePolicy{}); err != nil {
		t.Fatalf("ValidateManagedCredentialBrokerOverride() error = %v", err)
	}
}

func TestValidateManagedCredentialBrokerOverride_StrictProductionBlocksActiveOverride(t *testing.T) {
	t.Setenv(securitypolicy.StrictProductionEnvVar, "1")
	t.Setenv(broker.InsecureCredentialBrokerURLEnvVar, "https://broker.example.com")

	err := ValidateManagedCredentialBrokerOverride(io.Discard, []string{"github_repo"}, BrokerOverridePolicy{
		StrictProductionComponent: "dispatch_cli",
	})
	if err == nil {
		t.Fatal("expected strict production enforcement error")
	}
	if !strings.Contains(err.Error(), "strict production mode forbids insecure execution overrides") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateManagedCredentialBrokerOverride_EmitsWarningAndAudit(t *testing.T) {
	t.Setenv(securitypolicy.StrictProductionEnvVar, "")
	t.Setenv(broker.InsecureCredentialBrokerURLEnvVar, "https://broker.example.com/base")

	sink := &brokerPolicyAuditSink{}
	securityaudit.SetSink(sink)
	t.Cleanup(func() { securityaudit.SetSink(nil) })

	stderr := &bytes.Buffer{}
	err := ValidateManagedCredentialBrokerOverride(stderr, []string{"github_repo"}, BrokerOverridePolicy{
		StrictProductionComponent: "dispatch_cli",
		AuditComponent:            "dispatch",
		AuditName:                 "dispatch",
		AuditDescription:          "dispatch command running with insecure custom credential broker override",
	})
	if err != nil {
		t.Fatalf("ValidateManagedCredentialBrokerOverride() error = %v", err)
	}
	if !strings.Contains(stderr.String(), "custom credential broker") {
		t.Fatalf("expected warning, got %q", stderr.String())
	}

	events := sink.Snapshot()
	for _, evt := range events {
		if evt.Type == securityaudit.EventInsecureBypass && evt.Component == "dispatch" && evt.Attrs["credential_broker_host"] == "broker.example.com" {
			return
		}
	}
	t.Fatalf("expected insecure bypass audit event, got: %+v", events)
}
