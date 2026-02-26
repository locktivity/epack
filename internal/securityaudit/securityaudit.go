package securityaudit

import (
	"sync"
	"time"
)

// EventType identifies a security-relevant event category.
type EventType string

const (
	EventUnpinnedExecution EventType = "unpinned_execution"
	EventInsecureBypass    EventType = "insecure_bypass"
	EventVerificationFail  EventType = "verification_failure"
	EventSSRFBlockedURL    EventType = "ssrf_blocked_url"
	EventResultBackfilled  EventType = "result_backfilled"
)

// Event is a structured security audit event.
type Event struct {
	At          time.Time         `json:"at"`
	Type        EventType         `json:"type"`
	Component   string            `json:"component,omitempty"`
	Name        string            `json:"name,omitempty"`
	Description string            `json:"description,omitempty"`
	Attrs       map[string]string `json:"attrs,omitempty"`
}

// Sink receives emitted audit events.
type Sink interface {
	HandleSecurityEvent(Event)
}

type noopSink struct{}

func (noopSink) HandleSecurityEvent(Event) {}

var (
	sinkMu sync.RWMutex
	sink   Sink = noopSink{}
)

// SetSink installs a sink for security events.
// Passing nil restores the no-op sink.
func SetSink(s Sink) {
	sinkMu.Lock()
	defer sinkMu.Unlock()
	if s == nil {
		sink = noopSink{}
		return
	}
	sink = s
}

// Emit sends a security event to the configured sink.
// Emission is best-effort and never panics.
func Emit(evt Event) {
	if evt.At.IsZero() {
		evt.At = time.Now().UTC()
	}

	sinkMu.RLock()
	current := sink
	sinkMu.RUnlock()

	defer func() {
		_ = recover()
	}()
	current.HandleSecurityEvent(evt)
}
