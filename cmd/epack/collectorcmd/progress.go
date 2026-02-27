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

	// Progress-specific fields (for status/progress events)
	Message         string `json:"message,omitempty"`
	ProgressCurrent int64  `json:"progress_current,omitempty"`
	ProgressTotal   int64  `json:"progress_total,omitempty"`
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
	activeCollectors := make(map[string]struct{}) // Track which collectors are running

	// updateSpinnerForActive updates the spinner message based on active collectors.
	updateSpinnerForActive := func() {
		count := len(activeCollectors)
		switch count {
		case 0:
			spinner.UpdateMessage(message)
		case 1:
			// Show single collector name
			for name := range activeCollectors {
				spinner.UpdateMessage(fmt.Sprintf("%s: %s", message, name))
			}
		default:
			// Show count when multiple running in parallel
			spinner.UpdateMessage(fmt.Sprintf("%s (%d running)", message, count))
		}
	}

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

			switch evt.Type {
			case collector.CollectorEventStart:
				activeCollectors[evt.Collector] = struct{}{}
				// In parallel mode, don't print start lines (too noisy)
				// Just update the spinner
				updateSpinnerForActive()

			case collector.CollectorEventStatus:
				// Update spinner with status from the reporting collector
				if len(activeCollectors) == 1 {
					spinner.UpdateMessage(fmt.Sprintf("%s: %s", evt.Collector, evt.Message))
				}
				// In parallel mode with multiple collectors, status updates would be confusing

			case collector.CollectorEventProgress:
				// Update spinner with progress from the reporting collector
				if len(activeCollectors) == 1 {
					if evt.ProgressTotal > 0 {
						pct := float64(evt.ProgressCurrent) / float64(evt.ProgressTotal) * 100
						spinner.UpdateMessage(fmt.Sprintf("%s: %s (%.0f%%)", evt.Collector, evt.Message, pct))
					} else {
						spinner.UpdateMessage(fmt.Sprintf("%s: %s (%d)", evt.Collector, evt.Message, evt.ProgressCurrent))
					}
				}
				// In parallel mode with multiple collectors, progress updates would be confusing

			case collector.CollectorEventFinish:
				delete(activeCollectors, evt.Collector)
				// Print completion line
				spinner.Stop()
				if evt.Success {
					out.Print("%s %s done (%s)\n", out.Palette().Success(""), evt.Collector, formatDuration(evt.Duration))
				} else {
					out.Print("%s %s failed (%s)\n", out.Palette().Failure(""), evt.Collector, formatDuration(evt.Duration))
				}
				spinner = out.StartSpinnerWithContext(ctx, message)
				updateSpinnerForActive()
			}
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

	var currentCollector string

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
				currentCollector = evt.Collector
				print("[%d/%d] %s started\n", evt.Index, evt.Total, evt.Collector)

			case collector.CollectorEventStatus:
				print("  %s: %s\n", currentCollector, evt.Message)

			case collector.CollectorEventProgress:
				if evt.ProgressTotal > 0 {
					pct := float64(evt.ProgressCurrent) / float64(evt.ProgressTotal) * 100
					print("  %s: %s (%.0f%%)\n", currentCollector, evt.Message, pct)
				} else {
					print("  %s: %s (%d)\n", currentCollector, evt.Message, evt.ProgressCurrent)
				}

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
			// Add progress-specific fields for status/progress events
			if evt.Type == collector.CollectorEventStatus || evt.Type == collector.CollectorEventProgress {
				j.Message = evt.Message
				j.ProgressCurrent = evt.ProgressCurrent
				j.ProgressTotal = evt.ProgressTotal
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
