package cmd

import (
	"strings"
	"sync"
	"testing"

	"github.com/locktivity/epack/internal/securityaudit"
	"github.com/locktivity/epack/internal/securitypolicy"
)

type testAuditSink struct {
	mu     sync.Mutex
	events []securityaudit.Event
}

func (s *testAuditSink) HandleSecurityEvent(evt securityaudit.Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, evt)
}

func (s *testAuditSink) Snapshot() []securityaudit.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]securityaudit.Event, len(s.events))
	copy(out, s.events)
	return out
}

func TestValidateMergeFlags_StrictProductionBlocksInsecure(t *testing.T) {
	t.Setenv(securitypolicy.StrictProductionEnvVar, "1")

	origSkipAttest := mergeInsecureSkipAttestationVerify
	origSkipIdentity := mergeInsecureSkipIdentityCheck
	t.Cleanup(func() {
		mergeInsecureSkipAttestationVerify = origSkipAttest
		mergeInsecureSkipIdentityCheck = origSkipIdentity
	})

	mergeInsecureSkipAttestationVerify = true
	mergeInsecureSkipIdentityCheck = false
	err := validateMergeFlags()
	if err == nil {
		t.Fatal("expected strict production enforcement error")
	}
	if !strings.Contains(err.Error(), "strict production mode forbids insecure execution overrides") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateMergeFlags_EmitsInsecureBypassWhenAllowed(t *testing.T) {
	t.Setenv(securitypolicy.StrictProductionEnvVar, "")

	origSkipAttest := mergeInsecureSkipAttestationVerify
	origSkipIdentity := mergeInsecureSkipIdentityCheck
	t.Cleanup(func() {
		mergeInsecureSkipAttestationVerify = origSkipAttest
		mergeInsecureSkipIdentityCheck = origSkipIdentity
		securityaudit.SetSink(nil)
	})

	sink := &testAuditSink{}
	securityaudit.SetSink(sink)

	mergeInsecureSkipAttestationVerify = true
	mergeInsecureSkipIdentityCheck = false
	if err := validateMergeFlags(); err != nil {
		t.Fatalf("validateMergeFlags() error = %v", err)
	}

	for _, evt := range sink.Snapshot() {
		if evt.Type == securityaudit.EventInsecureBypass && evt.Component == "merge" {
			return
		}
	}
	t.Fatalf("expected insecure bypass event, got: %+v", sink.Snapshot())
}

func TestValidateVerifyFlags_StrictProductionBlocksInsecure(t *testing.T) {
	t.Setenv(securitypolicy.StrictProductionEnvVar, "1")

	origSkipIdentity := verifyInsecureSkipIdentityCheck
	origSkipEmbedded := verifyInsecureSkipEmbeddedVerify
	t.Cleanup(func() {
		verifyInsecureSkipIdentityCheck = origSkipIdentity
		verifyInsecureSkipEmbeddedVerify = origSkipEmbedded
	})

	verifyInsecureSkipIdentityCheck = true
	verifyInsecureSkipEmbeddedVerify = false
	err := validateVerifyFlags()
	if err == nil {
		t.Fatal("expected strict production enforcement error")
	}
	if !strings.Contains(err.Error(), "strict production mode forbids insecure execution overrides") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateVerifyFlags_EmitsInsecureBypassWhenAllowed(t *testing.T) {
	t.Setenv(securitypolicy.StrictProductionEnvVar, "")

	origSkipIdentity := verifyInsecureSkipIdentityCheck
	origSkipEmbedded := verifyInsecureSkipEmbeddedVerify
	t.Cleanup(func() {
		verifyInsecureSkipIdentityCheck = origSkipIdentity
		verifyInsecureSkipEmbeddedVerify = origSkipEmbedded
		securityaudit.SetSink(nil)
	})

	sink := &testAuditSink{}
	securityaudit.SetSink(sink)

	verifyInsecureSkipIdentityCheck = true
	verifyInsecureSkipEmbeddedVerify = false
	if err := validateVerifyFlags(); err != nil {
		t.Fatalf("validateVerifyFlags() error = %v", err)
	}

	for _, evt := range sink.Snapshot() {
		if evt.Type == securityaudit.EventInsecureBypass && evt.Component == "verify" {
			return
		}
	}
	t.Fatalf("expected insecure bypass event, got: %+v", sink.Snapshot())
}

func TestValidateSignFlags_StrictProductionBlocksInsecure(t *testing.T) {
	t.Setenv(securitypolicy.StrictProductionEnvVar, "1")

	origAllowCustom := signInsecureAllowCustomEndpoints
	t.Cleanup(func() {
		signInsecureAllowCustomEndpoints = origAllowCustom
	})

	signInsecureAllowCustomEndpoints = true
	err := validateSignFlags()
	if err == nil {
		t.Fatal("expected strict production enforcement error")
	}
	if !strings.Contains(err.Error(), "strict production mode forbids insecure execution overrides") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateSignFlags_EmitsInsecureBypassWhenAllowed(t *testing.T) {
	t.Setenv(securitypolicy.StrictProductionEnvVar, "")

	origAllowCustom := signInsecureAllowCustomEndpoints
	t.Cleanup(func() {
		signInsecureAllowCustomEndpoints = origAllowCustom
		securityaudit.SetSink(nil)
	})

	sink := &testAuditSink{}
	securityaudit.SetSink(sink)

	signInsecureAllowCustomEndpoints = true
	if err := validateSignFlags(); err != nil {
		t.Fatalf("validateSignFlags() error = %v", err)
	}

	for _, evt := range sink.Snapshot() {
		if evt.Type == securityaudit.EventInsecureBypass && evt.Component == "sign" {
			return
		}
	}
	t.Fatalf("expected insecure bypass event, got: %+v", sink.Snapshot())
}

func TestInsecureCLIFlagsEmitAuditEvent_Matrix(t *testing.T) {
	t.Setenv(securitypolicy.StrictProductionEnvVar, "")

	cases := []struct {
		name      string
		component string
		setFlags  func()
		reset     func()
		validate  func() error
	}{
		{
			name:      "merge",
			component: "merge",
			setFlags: func() {
				mergeInsecureSkipAttestationVerify = true
				mergeInsecureSkipIdentityCheck = false
			},
			reset: func() {
				mergeInsecureSkipAttestationVerify = false
				mergeInsecureSkipIdentityCheck = false
			},
			validate: validateMergeFlags,
		},
		{
			name:      "verify",
			component: "verify",
			setFlags: func() {
				verifyInsecureSkipIdentityCheck = true
				verifyInsecureSkipEmbeddedVerify = false
			},
			reset: func() {
				verifyInsecureSkipIdentityCheck = false
				verifyInsecureSkipEmbeddedVerify = false
			},
			validate: validateVerifyFlags,
		},
		{
			name:      "sign",
			component: "sign",
			setFlags: func() {
				signInsecureAllowCustomEndpoints = true
			},
			reset: func() {
				signInsecureAllowCustomEndpoints = false
			},
			validate: validateSignFlags,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.reset()
			t.Cleanup(tc.reset)

			sink := &testAuditSink{}
			securityaudit.SetSink(sink)
			t.Cleanup(func() { securityaudit.SetSink(nil) })

			tc.setFlags()
			if err := tc.validate(); err != nil {
				t.Fatalf("validate() error = %v", err)
			}

			for _, evt := range sink.Snapshot() {
				if evt.Type == securityaudit.EventInsecureBypass && evt.Component == tc.component {
					return
				}
			}
			t.Fatalf("expected insecure bypass event for %s, got: %+v", tc.component, sink.Snapshot())
		})
	}
}
