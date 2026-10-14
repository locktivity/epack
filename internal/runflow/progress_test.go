package runflow

import (
	"bytes"
	"context"
	"errors"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/locktivity/epack/internal/collector"
	"github.com/locktivity/epack/internal/remote"
)

type fakeSender struct {
	mu     sync.Mutex
	events []remote.ProgressEvent
	closed bool
}

func (f *fakeSender) Send(_ context.Context, event remote.ProgressEvent) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, event)
	return nil
}

func (f *fakeSender) Close() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
}

func (f *fakeSender) sent() []remote.ProgressEvent {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]remote.ProgressEvent(nil), f.events...)
}

func testReporter(open func(ctx context.Context) (progressSender, error)) (*progressReporter, *bytes.Buffer) {
	stderr := &bytes.Buffer{}
	clock := time.Date(2026, 10, 14, 15, 2, 11, 0, time.UTC)
	return &progressReporter{
		runID:    "run-1",
		open:     open,
		stderr:   stderr,
		now:      func() time.Time { clock = clock.Add(time.Second); return clock },
		events:   make(chan remote.ProgressEvent, progressQueue),
		done:     make(chan struct{}),
		lastNote: map[string]time.Time{},
	}, stderr
}

func TestProgressReporter_QueuesUntilStartAndSendsInOrder(t *testing.T) {
	sender := &fakeSender{}
	reporter, stderr := testReporter(func(context.Context) (progressSender, error) { return sender, nil })

	reporter.stage(StageInstall, ProgressStarted)
	reporter.stage(StageInstall, ProgressFinished)
	if len(sender.sent()) != 0 {
		t.Fatal("nothing may be sent before start")
	}
	reporter.start(context.Background())
	reporter.collector(collector.CollectorEvent{Type: collector.CollectorEventStart, Collector: "okta", Index: 1, Total: 5})
	reporter.collector(collector.CollectorEvent{Type: collector.CollectorEventFinish, Collector: "okta", Index: 1, Total: 5, Success: false, Error: errors.New("collector exited with code 1: 401 Unauthorized")})
	reporter.step(StageTools, "validate", 1, 1, ProgressFinished, "")
	reporter.close()

	events := sender.sent()
	want := []string{"install/started", "install/finished", "collect okta 2/5/started", "collect okta 2/5/failed", "tools validate 1/1/finished"}
	var got []string
	for _, event := range events {
		if event.Step == "" {
			got = append(got, event.Stage+"/"+event.State)
		} else {
			got = append(got, strings.Join([]string{event.Stage, event.Step, itoa(event.Index) + "/" + itoa(event.Total) + "/" + event.State}, " "))
		}
	}
	if strings.Join(got, "; ") != strings.Join(want, "; ") {
		t.Errorf("events = %v, want %v", got, want)
	}
	if events[3].Note != "exited with code 1: 401 Unauthorized" {
		t.Errorf("failed note = %q", events[3].Note)
	}
	if events[0].At == "" || events[0].At >= events[1].At {
		t.Errorf("events must carry rising timestamps: %q then %q", events[0].At, events[1].At)
	}
	if !sender.closed {
		t.Error("close must close the sender")
	}
	if stderr.Len() != 0 {
		t.Errorf("unexpected stderr: %s", stderr)
	}
}

func TestProgressReporter_ThrottlesStatusNotes(t *testing.T) {
	sender := &fakeSender{}
	reporter, _ := testReporter(func(context.Context) (progressSender, error) { return sender, nil })
	reporter.start(context.Background())
	for i := 0; i < 5; i++ {
		reporter.collector(collector.CollectorEvent{Type: collector.CollectorEventStatus, Collector: "okta", Index: 0, Total: 1, Message: "page " + itoa(i)})
	}
	reporter.close()
	events := sender.sent()
	if len(events) != 1 || events[0].Note != "page 0" {
		t.Errorf("status notes within a few seconds must collapse to one, got %+v", events)
	}
}

func TestProgressReporter_DropsEverythingWhenTheAdapterCannotTakeIt(t *testing.T) {
	opens := 0
	reporter, stderr := testReporter(func(context.Context) (progressSender, error) { opens++; return nil, nil })
	reporter.start(context.Background())
	reporter.stage(StageInstall, ProgressStarted)
	reporter.stage(StageCollect, ProgressStarted)
	reporter.close()
	if opens != 1 {
		t.Errorf("the adapter was opened %d times, want once", opens)
	}
	if stderr.Len() != 0 {
		t.Errorf("a remote without the feature must stay silent, got %s", stderr)
	}

	reporter, stderr = testReporter(func(context.Context) (progressSender, error) { return nil, errors.New("adapter not installed") })
	reporter.start(context.Background())
	reporter.stage(StageInstall, ProgressStarted)
	reporter.close()
	if !strings.Contains(stderr.String(), "not reporting progress to the remote: adapter not installed") {
		t.Errorf("stderr = %q", stderr.String())
	}
}

func TestProgressReporter_NilIsSafeAndCloseWithoutStartReturns(t *testing.T) {
	var reporter *progressReporter
	reporter.stage(StageInstall, ProgressStarted)
	reporter.collector(collector.CollectorEvent{})
	reporter.start(context.Background())
	reporter.close()

	sender := &fakeSender{}
	started, _ := testReporter(func(context.Context) (progressSender, error) { return sender, nil })
	started.stage(StageInstall, ProgressStarted)
	done := make(chan struct{})
	go func() { started.close(); close(done) }()
	select {
	case <-done:
	case <-time.After(progressFlushWait + time.Second):
		t.Fatal("close without start must not hang")
	}
	if len(sender.sent()) != 0 {
		t.Error("nothing is sent when the run never reached the install stage")
	}
}

func TestNewRunID(t *testing.T) {
	at := time.Date(2026, 10, 14, 15, 2, 11, 0, time.UTC)
	id := newRunID(at)
	if !strings.HasPrefix(id, "20261014T150211Z-") || len(id) != len("20261014T150211Z-")+8 {
		t.Errorf("run id = %q", id)
	}
	if newRunID(at) == id {
		t.Error("two runs in the same second must get different ids")
	}
}

func itoa(n int) string {
	return strconv.Itoa(n)
}
