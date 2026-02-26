//go:build components

package componentcmd

import (
	"strings"
	"sync"
	"testing"

	"github.com/locktivity/epack/internal/securityaudit"
	"github.com/locktivity/epack/internal/securitypolicy"
)

type syncAuditSink struct {
	mu     sync.Mutex
	events []securityaudit.Event
}

func (s *syncAuditSink) HandleSecurityEvent(evt securityaudit.Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, evt)
}

func (s *syncAuditSink) Snapshot() []securityaudit.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]securityaudit.Event, len(s.events))
	copy(out, s.events)
	return out
}

func TestValidateSyncFlags(t *testing.T) {
	origFrozen := syncFrozen
	origInsecure := syncInsecureSkipVerify
	t.Cleanup(func() {
		syncFrozen = origFrozen
		syncInsecureSkipVerify = origInsecure
	})

	syncFrozen = true
	syncInsecureSkipVerify = true
	if err := validateSyncFlags(); err == nil {
		t.Fatal("expected frozen+insecure combination error")
	}

	syncFrozen = false
	syncInsecureSkipVerify = false
	if err := validateSyncFlags(); err != nil {
		t.Fatalf("expected secure flags to pass, got %v", err)
	}
}

func TestValidateSyncFlags_StrictProductionBlocksInsecure(t *testing.T) {
	t.Setenv(securitypolicy.StrictProductionEnvVar, "1")

	origFrozen := syncFrozen
	origInsecure := syncInsecureSkipVerify
	t.Cleanup(func() {
		syncFrozen = origFrozen
		syncInsecureSkipVerify = origInsecure
	})

	syncFrozen = false
	syncInsecureSkipVerify = true

	err := validateSyncFlags()
	if err == nil {
		t.Fatal("expected strict production enforcement error")
	}
	if !strings.Contains(err.Error(), "strict production mode forbids insecure execution overrides") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateSyncFlags_EmitsInsecureBypassWhenAllowed(t *testing.T) {
	t.Setenv(securitypolicy.StrictProductionEnvVar, "")

	origFrozen := syncFrozen
	origInsecure := syncInsecureSkipVerify
	t.Cleanup(func() {
		syncFrozen = origFrozen
		syncInsecureSkipVerify = origInsecure
		securityaudit.SetSink(nil)
	})

	sink := &syncAuditSink{}
	securityaudit.SetSink(sink)

	syncFrozen = false
	syncInsecureSkipVerify = true
	if err := validateSyncFlags(); err != nil {
		t.Fatalf("validateSyncFlags() error = %v", err)
	}

	for _, evt := range sink.Snapshot() {
		if evt.Type == securityaudit.EventInsecureBypass && evt.Component == "component_sync" {
			return
		}
	}
	t.Fatalf("expected insecure bypass event, got: %+v", sink.Snapshot())
}
