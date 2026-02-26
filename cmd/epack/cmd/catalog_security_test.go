//go:build components

package cmd

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/locktivity/epack/internal/securityaudit"
)

type unifiedCatalogAuditSink struct {
	mu     sync.Mutex
	events []securityaudit.Event
}

func (s *unifiedCatalogAuditSink) HandleSecurityEvent(evt securityaudit.Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, evt)
}

func (s *unifiedCatalogAuditSink) Snapshot() []securityaudit.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]securityaudit.Event, len(s.events))
	copy(out, s.events)
	return out
}

func TestUnifiedCatalogRefreshInsecureHTTPEmitsAuditEvent(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", tmpDir)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"schema_version": 1, "generated_at": "", "source": {}, "tools": []}`))
	}))
	defer server.Close()

	sink := &unifiedCatalogAuditSink{}
	securityaudit.SetSink(sink)
	t.Cleanup(func() { securityaudit.SetSink(nil) })

	cmd := newCatalogCommand()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetArgs([]string{"refresh", "--url", server.URL, "--insecure-allow-http"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	for _, evt := range sink.Snapshot() {
		if evt.Type == securityaudit.EventInsecureBypass && evt.Component == "catalog" && evt.Name == "refresh" {
			return
		}
	}
	t.Fatalf("expected insecure bypass audit event, got: %+v", sink.Snapshot())
}
