//go:build components

package collectorcmd

import (
	"strings"
	"sync"
	"testing"

	"github.com/locktivity/epack/internal/securityaudit"
	"github.com/locktivity/epack/internal/securitypolicy"
)

type runAuditSink struct {
	mu     sync.Mutex
	events []securityaudit.Event
}

func (s *runAuditSink) HandleSecurityEvent(evt securityaudit.Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, evt)
}

func (s *runAuditSink) Snapshot() []securityaudit.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]securityaudit.Event, len(s.events))
	copy(out, s.events)
	return out
}

func TestValidateRunFlags(t *testing.T) {
	origFrozen := runFrozen
	origUnpinned := runInsecureAllowUnpinned
	t.Cleanup(func() {
		runFrozen = origFrozen
		runInsecureAllowUnpinned = origUnpinned
	})

	tests := []struct {
		name      string
		frozen    bool
		unpinned  bool
		shouldErr bool
	}{
		{
			name:      "frozen with pinned adapters",
			frozen:    true,
			unpinned:  false,
			shouldErr: false,
		},
		{
			name:      "non-frozen with unpinned adapters",
			frozen:    false,
			unpinned:  true,
			shouldErr: false,
		},
		{
			name:      "frozen with unpinned adapters",
			frozen:    true,
			unpinned:  true,
			shouldErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runFrozen = tt.frozen
			runInsecureAllowUnpinned = tt.unpinned

			err := validateRunFlags()
			if tt.shouldErr && err == nil {
				t.Fatal("expected error, got nil")
			}
			if !tt.shouldErr && err != nil {
				t.Fatalf("expected no error, got %v", err)
			}
		})
	}
}

func TestValidateRunFlags_StrictProductionBlocksInsecure(t *testing.T) {
	t.Setenv(securitypolicy.StrictProductionEnvVar, "1")

	origFrozen := runFrozen
	origUnverified := runInsecureAllowUnverified
	origUnpinned := runInsecureAllowUnpinned
	t.Cleanup(func() {
		runFrozen = origFrozen
		runInsecureAllowUnverified = origUnverified
		runInsecureAllowUnpinned = origUnpinned
	})

	runFrozen = false
	runInsecureAllowUnverified = true
	runInsecureAllowUnpinned = false

	err := validateRunFlags()
	if err == nil {
		t.Fatal("expected strict production enforcement error")
	}
	if !strings.Contains(err.Error(), "strict production mode forbids insecure execution overrides") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRunFlags_EmitsInsecureBypassWhenAllowed(t *testing.T) {
	t.Setenv(securitypolicy.StrictProductionEnvVar, "")

	origFrozen := runFrozen
	origUnverified := runInsecureAllowUnverified
	origUnpinned := runInsecureAllowUnpinned
	t.Cleanup(func() {
		runFrozen = origFrozen
		runInsecureAllowUnverified = origUnverified
		runInsecureAllowUnpinned = origUnpinned
		securityaudit.SetSink(nil)
	})

	sink := &runAuditSink{}
	securityaudit.SetSink(sink)

	runFrozen = false
	runInsecureAllowUnverified = true
	runInsecureAllowUnpinned = false
	if err := validateRunFlags(); err != nil {
		t.Fatalf("validateRunFlags() error = %v", err)
	}

	for _, evt := range sink.Snapshot() {
		if evt.Type == securityaudit.EventInsecureBypass && evt.Component == "collector_run" {
			return
		}
	}
	t.Fatalf("expected insecure bypass event, got: %+v", sink.Snapshot())
}
