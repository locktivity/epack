package componentsdk

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"
)

func TestWaitMovesAKitRunsClock(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	var slept []time.Duration
	var beforeRetry, afterRetry, afterWait time.Time
	script := newScript().on("api.example.com/report", respond(503, "", nil), respond(200, "{}", nil))
	res := RunInProcess(CollectorSpec{Name: "demo"}, func(ctx CollectorContext) error {
		beforeRetry = Now(ctx)
		client := NewHTTPClient(ctx, HTTPOptions{})
		req, err := http.NewRequestWithContext(ctx.Context(), http.MethodGet, "https://api.example.com/report", nil)
		if err != nil {
			return err
		}
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		_ = resp.Body.Close()
		afterRetry = Now(ctx)
		for i := 0; i < 3; i++ {
			if err := Wait(ctx, 10*time.Second); err != nil {
				return err
			}
		}
		afterWait = Now(ctx)
		return ctx.Emit([]CollectedArtifact{{Data: map[string]any{"ok": true}}})
	}, InProcessOptions{
		Transport: script,
		Clock:     func() time.Time { return start },
		Sleep: func(ctx context.Context, d time.Duration) error {
			slept = append(slept, d)
			return ctx.Err()
		},
	})
	if res.ExitCode != 0 {
		t.Fatalf("exit = %d: %s", res.ExitCode, res.Stderr)
	}
	if !afterRetry.Equal(beforeRetry) {
		t.Errorf("a retry moved the clock by %s; only Wait may", afterRetry.Sub(beforeRetry))
	}
	if got := afterWait.Sub(afterRetry); got != 30*time.Second {
		t.Errorf("three waits of 10s moved the clock by %s, want 30s", got)
	}
	if len(slept) != 4 {
		t.Errorf("sleeps = %v, want one retry delay and three waits", slept)
	}
}

func TestWaitStopsWhenItsSleepFails(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	var waitErr error
	var after time.Time
	res := RunInProcess(CollectorSpec{Name: "demo"}, func(ctx CollectorContext) error {
		waitErr = Wait(ctx, time.Minute)
		after = Now(ctx)
		return ctx.Emit([]CollectedArtifact{{Data: map[string]any{"ok": true}}})
	}, InProcessOptions{
		Clock: func() time.Time { return start },
		Sleep: func(context.Context, time.Duration) error { return context.Canceled },
	})
	if res.ExitCode != 0 {
		t.Fatalf("exit = %d: %s", res.ExitCode, res.Stderr)
	}
	if !errors.Is(waitErr, context.Canceled) {
		t.Errorf("Wait = %v, want context.Canceled", waitErr)
	}
	if !after.Equal(start) {
		t.Errorf("a cancelled wait moved the clock to %s", after)
	}
}
