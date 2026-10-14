package runflow

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/locktivity/epack/internal/collector"
	"github.com/locktivity/epack/internal/component/config"
	"github.com/locktivity/epack/internal/redact"
	"github.com/locktivity/epack/internal/remote"
)

// Progress states.
const (
	ProgressStarted  = "started"
	ProgressFinished = "finished"
	ProgressFailed   = "failed"
)

const (
	progressSendTimeout = 2 * time.Second
	progressFlushWait   = 3 * time.Second
	progressQueue       = 64
	progressNoteLength  = 200
	progressNoteGap     = 10 * time.Second
)

// progressSender delivers one event to the remote.
type progressSender interface {
	Send(ctx context.Context, event remote.ProgressEvent) error
	Close()
}

// adapterProgress sends events through the remote adapter.
type adapterProgress struct {
	exec   *remote.Executor
	remote string
	target remote.TargetConfig
	run    remote.ProgressRun
}

func (a *adapterProgress) Send(ctx context.Context, event remote.ProgressEvent) error {
	return a.exec.RunProgress(ctx, &remote.RunProgressRequest{Remote: a.remote, Target: a.target, Run: a.run, Event: event})
}

func (a *adapterProgress) Close() { a.exec.Close() }

// progressReporter turns the run's callbacks into run.progress events and
// sends them in the background, so the run never waits on the remote.
// Events queue until start, which the run calls once the adapter is
// installed; a remote that cannot take them is found out once and then
// everything is dropped quietly.
type progressReporter struct {
	runID     string
	startedAt time.Time
	open      func(ctx context.Context) (progressSender, error)
	stderr    io.Writer
	now       func() time.Time

	events    chan remote.ProgressEvent
	done      chan struct{}
	startOnce sync.Once
	closeOnce sync.Once
	mu        sync.Mutex
	closed    bool
	lastNote  map[string]time.Time
}

// newRunID names a run: when it started, plus a few random bytes so two
// runs in the same second stay apart.
func newRunID(now time.Time) string {
	var suffix [4]byte
	_, _ = rand.Read(suffix[:])
	return now.UTC().Format("20060102T150405Z") + "-" + hex.EncodeToString(suffix[:])
}

// newProgressReporter wires a reporter to the configured remote. A
// configuration without one gets nil, and every method accepts nil.
func newProgressReporter(cfg *config.JobConfig, opts Options, remoteName, runID string, startedAt time.Time) *progressReporter {
	if remoteName == "" {
		return nil
	}
	reporter := &progressReporter{
		runID:     runID,
		startedAt: startedAt,
		stderr:    opts.Stderr,
		now:       time.Now,
		events:    make(chan remote.ProgressEvent, progressQueue),
		done:      make(chan struct{}),
		lastNote:  map[string]time.Time{},
	}
	reporter.open = func(ctx context.Context) (progressSender, error) {
		remoteCfg, err := remote.ResolveRemoteConfig(cfg, remoteName, "")
		if err != nil {
			return nil, err
		}
		exec, caps, err := remote.PrepareAdapterExecutor(ctx, opts.WorkDir, remoteName, cfg, remoteCfg, remote.AdapterExecutorOptions{
			Stderr:       io.Discard,
			Verification: remote.VerificationOptions{Unsafe: remote.VerificationUnsafeOverrides{AllowUnverifiedSource: opts.AllowUnpinned}},
		})
		if err != nil {
			return nil, err
		}
		if !caps.SupportsRunProgress() {
			exec.Close()
			return nil, nil
		}
		return &adapterProgress{
			exec:   exec,
			remote: remoteName,
			target: remote.TargetConfig{Workspace: remoteCfg.Target.Workspace, Environment: remoteCfg.Target.Environment},
			run:    remote.ProgressRun{ID: runID, StartedAt: startedAt.UTC().Format(time.RFC3339)},
		}, nil
	}
	return reporter
}

// stage records a stage starting, finishing, or failing.
func (r *progressReporter) stage(name, state string) {
	r.report(remote.ProgressEvent{Stage: name, State: state})
}

// step records a collector or tool inside a stage.
func (r *progressReporter) step(stage, step string, index, total int, state, note string) {
	r.report(remote.ProgressEvent{Stage: stage, Step: step, Index: index, Total: total, State: state, Note: note})
}

// collector maps a collector event. Status lines become notes, at most
// one every few seconds per collector, since some collectors print many.
func (r *progressReporter) collector(event collector.CollectorEvent) {
	if r == nil {
		return
	}
	switch event.Type {
	case collector.CollectorEventStart:
		r.step(StageCollect, event.Collector, event.Index+1, event.Total, ProgressStarted, "")
	case collector.CollectorEventFinish:
		state, note := ProgressFinished, ""
		if !event.Success {
			state = ProgressFailed
			if event.Error != nil {
				note = progressNote(strings.TrimPrefix(event.Error.Error(), "collector "))
			}
		}
		r.step(StageCollect, event.Collector, event.Index+1, event.Total, state, note)
	case collector.CollectorEventStatus:
		if event.Message == "" || !r.noteDue(event.Collector) {
			return
		}
		r.step(StageCollect, event.Collector, event.Index+1, event.Total, ProgressStarted, progressNote(event.Message))
	}
}

func (r *progressReporter) noteDue(step string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	if last, ok := r.lastNote[step]; ok && now.Sub(last) < progressNoteGap {
		return false
	}
	r.lastNote[step] = now
	return true
}

func progressNote(text string) string {
	text = redact.Error(strings.TrimSpace(text))
	if len(text) > progressNoteLength {
		text = text[:progressNoteLength]
	}
	return text
}

func (r *progressReporter) report(event remote.ProgressEvent) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return
	}
	event.At = r.now().UTC().Format(time.RFC3339)
	select {
	case r.events <- event:
	default:
	}
}

// start begins sending. The adapter is opened on the first event; a remote
// that cannot take progress, or an adapter that cannot be opened, ends the
// sending with everything after it dropped.
func (r *progressReporter) start(ctx context.Context) {
	if r == nil {
		return
	}
	r.startOnce.Do(func() { go r.run(ctx) })
}

func (r *progressReporter) run(ctx context.Context) {
	defer close(r.done)
	var sender progressSender
	opened := false
	for event := range r.events {
		if !opened {
			opened = true
			var err error
			sender, err = r.open(ctx)
			if err != nil {
				_, _ = fmt.Fprintf(r.stderr, "Note: not reporting progress to the remote: %v\n", err)
			}
		}
		if sender == nil {
			continue
		}
		sendCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), progressSendTimeout)
		_ = sender.Send(sendCtx, event)
		cancel()
	}
	if sender != nil {
		sender.Close()
	}
}

// close stops taking events and waits briefly for the queue to drain, so
// the last event of a run is not lost to the process ending.
func (r *progressReporter) close() {
	if r == nil {
		return
	}
	r.closeOnce.Do(func() {
		r.mu.Lock()
		r.closed = true
		r.mu.Unlock()
		close(r.events)
		r.startOnce.Do(func() { close(r.done) })
		select {
		case <-r.done:
		case <-time.After(progressFlushWait):
		}
	})
}
