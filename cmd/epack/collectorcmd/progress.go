//go:build components

package collectorcmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/locktivity/epack/internal/cli/output"
	"github.com/locktivity/epack/internal/collector"
)

const (
	progressModeAuto  = "auto"
	progressModeTTY   = "tty"
	progressModePlain = "plain"
	progressModeJSON  = "json"
	progressModeQuiet = "quiet"
)

var collectHeartbeatInterval = 30 * time.Second

type collectionProgress struct {
	Done             func(success bool)
	OnCollectorEvent func(evt collector.CollectorEvent)
}

type jsonProgressEvent struct {
	Type      string `json:"type"`
	Event     string `json:"event"`
	Collector string `json:"collector,omitempty"`
	Index     int    `json:"index,omitempty"`
	Total     int    `json:"total,omitempty"`
	Success   bool   `json:"success,omitempty"`
	Error     string `json:"error,omitempty"`
	Frozen    bool   `json:"frozen,omitempty"`
	ElapsedMS int64  `json:"elapsed_ms,omitempty"`
	Timestamp string `json:"timestamp"`
}

// startCollectionProgress shows collection progress while the workflow runs.
func startCollectionProgress(ctx context.Context, out *output.Writer, frozen bool, mode string) collectionProgress {
	mode = normalizeProgressMode(mode)
	started := time.Now()

	if out.IsJSON() && mode != progressModeJSON && mode != progressModeQuiet {
		mode = progressModeQuiet
	}
	if out.IsQuiet() && mode != progressModeJSON {
		mode = progressModeQuiet
	}
	if mode == progressModeAuto {
		mode = autoProgressMode(out)
	}

	switch mode {
	case progressModeQuiet:
		return collectionProgress{
			Done:             func(bool) {},
			OnCollectorEvent: func(collector.CollectorEvent) {},
		}
	case progressModeJSON:
		return startJSONProgress(ctx, frozen, started)
	case progressModeTTY:
		return startTTYProgress(ctx, out, frozen, started)
	default:
		return startPlainProgress(ctx, out, frozen, started)
	}
}

func startTTYProgress(ctx context.Context, out *output.Writer, frozen bool, started time.Time) collectionProgress {
	message := collectMessage(frozen)
	spinner := out.StartSpinnerWithContext(ctx, message)
	var mu sync.Mutex

	return collectionProgress{
		Done: func(success bool) {
			mu.Lock()
			defer mu.Unlock()
			finalMsg := fmt.Sprintf("Collected evidence in %s", formatDuration(time.Since(started)))
			if success {
				spinner.Success(finalMsg)
			} else {
				spinner.Fail(finalMsg)
			}
		},
		OnCollectorEvent: func(evt collector.CollectorEvent) {
			mu.Lock()
			defer mu.Unlock()

			// Pause spinner to keep per-collector lines readable in interactive terminals.
			spinner.Stop()
			switch evt.Type {
			case collector.CollectorEventStart:
				out.Print("[%d/%d] %s started\n", evt.Index, evt.Total, evt.Collector)
			case collector.CollectorEventFinish:
				if evt.Success {
					out.Print("[%d/%d] %s done (%s)\n", evt.Index, evt.Total, evt.Collector, formatDuration(evt.Duration))
				} else {
					out.Print("[%d/%d] %s failed (%s)\n", evt.Index, evt.Total, evt.Collector, formatDuration(evt.Duration))
				}
			}
			spinner = out.StartSpinnerWithContext(ctx, message)
		},
	}
}

func startPlainProgress(ctx context.Context, out *output.Writer, frozen bool, started time.Time) collectionProgress {
	interval := collectHeartbeatInterval
	var printMu sync.Mutex
	print := func(format string, args ...interface{}) {
		printMu.Lock()
		defer printMu.Unlock()
		out.Print(format, args...)
	}

	print("%s\n", collectMessage(frozen))
	done := make(chan struct{})
	var doneOnce sync.Once
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ctx.Done():
				return
			case <-ticker.C:
				elapsed := formatDuration(time.Since(started))
				if out.IsCI() {
					print("[%s] still collecting... elapsed %s\n", time.Now().Format("15:04:05"), elapsed)
				} else {
					print("still collecting... elapsed %s\n", elapsed)
				}
			}
		}
	}()

	return collectionProgress{
		Done: func(success bool) {
			doneOnce.Do(func() { close(done) })
			wg.Wait()
			if !success {
				print("collection failed after %s\n", formatDuration(time.Since(started)))
				return
			}
			print("Collected evidence in %s\n", formatDuration(time.Since(started)))
		},
		OnCollectorEvent: func(evt collector.CollectorEvent) {
			switch evt.Type {
			case collector.CollectorEventStart:
				print("[%d/%d] %s started\n", evt.Index, evt.Total, evt.Collector)
			case collector.CollectorEventFinish:
				if evt.Success {
					print("[%d/%d] %s done (%s)\n", evt.Index, evt.Total, evt.Collector, formatDuration(evt.Duration))
					return
				}
				print("[%d/%d] %s failed (%s)\n", evt.Index, evt.Total, evt.Collector, formatDuration(evt.Duration))
			}
		},
	}
}

func startJSONProgress(ctx context.Context, frozen bool, started time.Time) collectionProgress {
	interval := collectHeartbeatInterval
	done := make(chan struct{})
	var doneOnce sync.Once
	var wg sync.WaitGroup
	emitJSONProgress(jsonProgressEvent{
		Type:      "collect_progress",
		Event:     "start",
		Frozen:    frozen,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	})

	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ctx.Done():
				return
			case <-ticker.C:
				emitJSONProgress(jsonProgressEvent{
					Type:      "collect_progress",
					Event:     "heartbeat",
					Frozen:    frozen,
					ElapsedMS: time.Since(started).Milliseconds(),
					Timestamp: time.Now().UTC().Format(time.RFC3339),
				})
			}
		}
	}()

	return collectionProgress{
		Done: func(success bool) {
			doneOnce.Do(func() { close(done) })
			wg.Wait()
			emitJSONProgress(jsonProgressEvent{
				Type:      "collect_progress",
				Event:     "done",
				Frozen:    frozen,
				Success:   success,
				ElapsedMS: time.Since(started).Milliseconds(),
				Timestamp: time.Now().UTC().Format(time.RFC3339),
			})
		},
		OnCollectorEvent: func(evt collector.CollectorEvent) {
			j := jsonProgressEvent{
				Type:      "collect_progress",
				Event:     string(evt.Type),
				Collector: evt.Collector,
				Index:     evt.Index,
				Total:     evt.Total,
				Success:   evt.Success,
				ElapsedMS: evt.Duration.Milliseconds(),
				Timestamp: time.Now().UTC().Format(time.RFC3339),
			}
			if evt.Error != nil {
				j.Error = evt.Error.Error()
			}
			emitJSONProgress(j)
		},
	}
}

func emitJSONProgress(evt jsonProgressEvent) {
	data, err := json.Marshal(evt)
	if err != nil {
		return
	}
	_, _ = fmt.Fprintln(os.Stderr, string(data))
}

func autoProgressMode(out *output.Writer) string {
	if out.IsTTY() && !out.IsCI() {
		return progressModeTTY
	}
	return progressModePlain
}

func collectMessage(frozen bool) string {
	if frozen {
		return "Collecting evidence (frozen mode, this can take a few minutes)..."
	}
	return "Collecting evidence (this can take a few minutes)..."
}

func defaultProgressMode() string {
	env := normalizeProgressMode(os.Getenv("EPACK_PROGRESS"))
	if isValidProgressMode(env) {
		return env
	}
	return progressModeAuto
}

func validateProgressMode(mode string) error {
	mode = normalizeProgressMode(mode)
	if isValidProgressMode(mode) {
		return nil
	}
	return fmt.Errorf("invalid --progress mode %q (expected: auto, tty, plain, json, quiet)", mode)
}

func normalizeProgressMode(mode string) string {
	return strings.ToLower(strings.TrimSpace(mode))
}

func isValidProgressMode(mode string) bool {
	switch mode {
	case progressModeAuto, progressModeTTY, progressModePlain, progressModeJSON, progressModeQuiet:
		return true
	default:
		return false
	}
}
