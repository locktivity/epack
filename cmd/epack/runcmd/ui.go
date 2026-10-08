//go:build components

package runcmd

import (
	"fmt"
	"strings"

	"github.com/locktivity/epack/cmd/epack/remotecmd"
	"github.com/locktivity/epack/internal/cli/output"
	"github.com/locktivity/epack/internal/collector"
	"github.com/locktivity/epack/internal/runflow"
	"github.com/locktivity/epack/internal/trustedpublishers"
)

// stageUI shows one line per stage. Stages whose work prints on its own
// (hooks and tools) get plain lines; the others get a spinner.
type stageUI struct {
	out      *output.Writer
	spinner  *output.Spinner
	progress *output.ProgressBar
	stage    string
}

func newStageUI(out *output.Writer) *stageUI {
	return &stageUI{out: out}
}

func (u *stageUI) quiet() bool {
	return u.out.IsQuiet() || u.out.IsJSON()
}

func (u *stageUI) onStage(stage string, started bool) {
	if u.quiet() {
		return
	}
	// A run goes on to the post-collect hook after a failed collect, so the
	// spinner of a stage that never finished is closed as that stage's
	// failure before the next stage prints.
	if started {
		u.fail()
	}
	u.stage = stage
	label := stageLabel(stage, started)
	if plainStage(stage) {
		if started {
			u.out.Print("%s...\n", label)
		} else {
			u.out.Print("%s\n", u.out.Palette().Success(label))
		}
		return
	}
	if started {
		u.stopSpinner()
		u.spinner = u.out.StartSpinner(label)
		return
	}
	if u.progress != nil {
		u.progress.Done(label)
		u.progress = nil
		return
	}
	if u.spinner != nil {
		u.spinner.Success(label)
		u.spinner = nil
	}
}

func (u *stageUI) onStep(step string, started bool) {
	if u.quiet() {
		return
	}
	if plainStage(u.stage) {
		if started {
			u.out.Print("  %s...\n", step)
		}
		return
	}
	if u.spinner != nil {
		if started {
			u.spinner.UpdateMessage(step)
		}
		return
	}
	if started {
		u.spinner = u.out.StartSpinner(step)
	}
}

func (u *stageUI) onCollectorEvent(event collector.CollectorEvent) {
	if u.quiet() || u.spinner == nil {
		return
	}
	switch event.Type {
	case collector.CollectorEventStart:
		u.spinner.UpdateMessage(fmt.Sprintf("Collecting %s (%d/%d)", event.Collector, event.Index+1, event.Total))
	case collector.CollectorEventStatus:
		if event.Message != "" {
			u.spinner.UpdateMessage(fmt.Sprintf("Collecting %s: %s", event.Collector, event.Message))
		}
	}
}

func (u *stageUI) onProgress(written, total int64) {
	if u.quiet() {
		return
	}
	if u.spinner != nil {
		u.spinner.Stop()
		u.spinner = nil
		u.progress = u.out.StartProgress("Uploading", total)
	}
	if u.progress != nil {
		u.progress.Update(written)
	}
}

func (u *stageUI) promptInstallAdapter(remoteName, adapterName string, allowPrompt bool) bool {
	if !allowPrompt || u.quiet() || !u.out.IsTTY() {
		return false
	}
	u.stopSpinner()
	return u.out.PromptConfirm("Adapter %q for remote %q is not installed. Install now?", adapterName, remoteName)
}

// promptTrustPublisher offers a publisher the fetched configuration needs.
// Only a person at a terminal can say yes; a job gets the variable instead.
func (u *stageUI) promptTrustPublisher(req trustedpublishers.Requirement, allowPrompt bool) bool {
	if !allowPrompt || u.quiet() || !u.out.IsTTY() {
		return false
	}
	u.stopSpinner()
	return u.out.PromptConfirm("This configuration runs %s from github.com/%s. Trust github.com/%s on this machine?",
		strings.Join(req.Repositories, ", "), req.Publisher, req.Publisher)
}

func (u *stageUI) fetched(clone *remotecmd.CloneResult) {
	if u.quiet() {
		return
	}
	u.stopSpinner()
	p := u.out.Palette()
	title := output.Printable(clone.Config.Title)
	if title == "" {
		title = output.Printable(clone.Config.Name)
	}
	switch {
	case clone.Created:
		u.out.Print("%s\n", p.Success(fmt.Sprintf("Fetched %s (revision %d) into %s", title, clone.Config.Revision, clone.Dir)))
	case clone.Current():
		u.out.Print("%s\n", p.Success(fmt.Sprintf("%s is current (revision %d) in %s", title, clone.Config.Revision, clone.Dir)))
	default:
		u.out.Print("%s\n", p.Success(fmt.Sprintf("Updated %s to revision %d in %s", title, clone.Config.Revision, clone.Dir)))
	}
	remotecmd.PrintFetched(u.out, clone)
}

func (u *stageUI) onNote(note string) {
	if u.quiet() {
		return
	}
	u.out.Print("  %s\n", note)
}

func (u *stageUI) fail() {
	if u.progress != nil {
		u.progress.Fail(stageLabel(u.stage, true) + " failed")
		u.progress = nil
		return
	}
	if u.spinner != nil {
		u.spinner.Fail(stageLabel(u.stage, true) + " failed")
		u.spinner = nil
	}
}

func (u *stageUI) stopSpinner() {
	if u.spinner != nil {
		u.spinner.Stop()
		u.spinner = nil
	}
}

func plainStage(stage string) bool {
	switch stage {
	case runflow.StagePreCollect, runflow.StagePostCollect, runflow.StageTools:
		return true
	}
	return false
}

func stageLabel(stage string, started bool) string {
	labels := map[string][2]string{
		runflow.StageInstall:     {"Installing dependencies", "Dependencies installed"},
		runflow.StagePreCollect:  {"Running pre-collect hook", "Pre-collect hook done"},
		runflow.StageCollect:     {"Collecting evidence", "Evidence collected"},
		runflow.StagePostCollect: {"Running post-collect hook", "Post-collect hook done"},
		runflow.StageTools:       {"Running tools", "Tools done"},
		runflow.StageSign:        {"Signing pack", "Pack signed"},
		runflow.StagePush:        {"Pushing pack", "Pack pushed"},
	}
	pair, ok := labels[stage]
	if !ok {
		return stage
	}
	if started {
		return pair[0]
	}
	return pair[1]
}
