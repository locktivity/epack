package securityaudit

import "testing"

type captureSink struct {
	events []Event
}

func (c *captureSink) HandleSecurityEvent(evt Event) {
	c.events = append(c.events, evt)
}

func TestEmit_WithConfiguredSink(t *testing.T) {
	t.Cleanup(func() { SetSink(nil) })

	c := &captureSink{}
	SetSink(c)

	Emit(Event{
		Type:        EventInsecureBypass,
		Component:   "collector",
		Name:        "demo",
		Description: "test event",
	})

	if len(c.events) != 1 {
		t.Fatalf("events = %d, want 1", len(c.events))
	}
	if c.events[0].Type != EventInsecureBypass {
		t.Fatalf("type = %q, want %q", c.events[0].Type, EventInsecureBypass)
	}
	if c.events[0].At.IsZero() {
		t.Fatal("expected event timestamp to be set")
	}
}

func TestSetSinkNil_RestoresNoop(t *testing.T) {
	SetSink(nil)
	Emit(Event{Type: EventUnpinnedExecution})
}
