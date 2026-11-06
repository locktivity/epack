//go:build components

package collectorcmd

import (
	"bytes"
	"context"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/locktivity/epack/internal/cli/output"
	"github.com/locktivity/epack/internal/collector"
)

func TestStartCollectionProgress_PlainHeartbeatAndCollectorStatus(t *testing.T) {
	prev := collectHeartbeatInterval
	collectHeartbeatInterval = 10 * time.Millisecond
	t.Cleanup(func() { collectHeartbeatInterval = prev })

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	out := output.New(&stdout, &stderr, output.Options{})

	p := startCollectionProgress(context.Background(), out, false, progressModePlain)
	p.OnCollectorEvent(collector.CollectorEvent{Type: collector.CollectorEventStart, Collector: "github", Index: 2, Total: 7})
	p.OnCollectorEvent(collector.CollectorEvent{
		Type:      collector.CollectorEventFinish,
		Collector: "github",
		Index:     2,
		Total:     7,
		Success:   true,
		Duration:  18 * time.Second,
	})
	time.Sleep(30 * time.Millisecond)
	p.Done(true)

	got := stdout.String()
	if !strings.Contains(got, "Collecting evidence (this can take a few minutes)...") {
		t.Fatalf("missing start message in output: %q", got)
	}
	if !strings.Contains(got, "[2/7] github started") {
		t.Fatalf("missing collector start event in output: %q", got)
	}
	if !strings.Contains(got, "[2/7] github done (18.0s)") {
		t.Fatalf("missing collector finish event in output: %q", got)
	}
	if !strings.Contains(got, "still collecting... elapsed") {
		t.Fatalf("missing heartbeat in output: %q", got)
	}
	if !strings.Contains(got, "Collected evidence in") {
		t.Fatalf("missing completion message in output: %q", got)
	}
}

func TestStartCollectionProgress_PlainNamesTheCollectorThatSentEachLine(t *testing.T) {
	var stdout bytes.Buffer
	out := output.New(&stdout, io.Discard, output.Options{})

	p := startCollectionProgress(context.Background(), out, false, progressModePlain)
	p.OnCollectorEvent(collector.CollectorEvent{Type: collector.CollectorEventStart, Collector: "aws", Index: 1, Total: 2})
	p.OnCollectorEvent(collector.CollectorEvent{Type: collector.CollectorEventStart, Collector: "github", Index: 2, Total: 2})
	p.OnCollectorEvent(collector.CollectorEvent{Type: collector.CollectorEventStatus, Collector: "aws", Index: 1, Total: 2, Message: "Listing IAM users"})
	p.OnCollectorEvent(collector.CollectorEvent{Type: collector.CollectorEventProgress, Collector: "aws", Index: 1, Total: 2, Message: "Reading accounts", ProgressCurrent: 1, ProgressTotal: 4})

	var wg sync.WaitGroup
	for _, name := range []string{"aws", "github"} {
		wg.Add(1)
		go func(name string) {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				p.OnCollectorEvent(collector.CollectorEvent{Type: collector.CollectorEventStatus, Collector: name, Message: "page from " + name})
			}
		}(name)
	}
	wg.Wait()
	p.Done(true)

	got := stdout.String()
	for _, want := range []string{"  aws: Listing IAM users\n", "  aws: Reading accounts (25%)\n"} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %q in output: %q", want, got)
		}
	}
	for _, line := range strings.Split(got, "\n") {
		if strings.HasPrefix(line, "  github: page from aws") || strings.HasPrefix(line, "  aws: page from github") {
			t.Fatalf("line labeled with the wrong collector: %q", line)
		}
	}
}

func TestStartCollectionProgress_JSONEmitsToStderr(t *testing.T) {
	prev := collectHeartbeatInterval
	collectHeartbeatInterval = 10 * time.Millisecond
	t.Cleanup(func() { collectHeartbeatInterval = prev })

	oldStderr := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe() error: %v", err)
	}
	os.Stderr = w
	t.Cleanup(func() {
		os.Stderr = oldStderr
		_ = w.Close()
	})

	var stdout bytes.Buffer
	out := output.New(&stdout, io.Discard, output.Options{})

	p := startCollectionProgress(context.Background(), out, true, progressModeJSON)
	p.OnCollectorEvent(collector.CollectorEvent{Type: collector.CollectorEventStart, Collector: "aws", Index: 1, Total: 2})
	p.OnCollectorEvent(collector.CollectorEvent{Type: collector.CollectorEventFinish, Collector: "aws", Index: 1, Total: 2, Success: true})
	time.Sleep(25 * time.Millisecond)
	p.Done(true)
	_ = w.Close()

	data, _ := io.ReadAll(r)
	got := string(data)
	if !strings.Contains(got, "\"event\":\"start\"") {
		t.Fatalf("missing json start event: %q", got)
	}
	if !strings.Contains(got, "\"event\":\"heartbeat\"") {
		t.Fatalf("missing json heartbeat event: %q", got)
	}
	if !strings.Contains(got, "\"event\":\"finish\"") {
		t.Fatalf("missing json finish event: %q", got)
	}
	if !strings.Contains(got, "\"event\":\"done\"") {
		t.Fatalf("missing json done event: %q", got)
	}
}

func TestValidateProgressMode(t *testing.T) {
	valid := []string{"auto", "tty", "plain", "json", "quiet", "  Auto "}
	for _, m := range valid {
		if err := validateProgressMode(m); err != nil {
			t.Fatalf("validateProgressMode(%q) unexpected error: %v", m, err)
		}
	}
	if err := validateProgressMode("bad"); err == nil {
		t.Fatal("validateProgressMode(bad) expected error")
	}
}
