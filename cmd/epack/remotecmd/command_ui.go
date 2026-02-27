//go:build components

package remotecmd

import "github.com/locktivity/epack/internal/cli/output"

type commandUI struct {
	out           *output.Writer
	spinner       *output.Spinner
	progressBar   *output.ProgressBar
	progressLabel string
	progressFail  string
	spinnerFail   string
}

func newCommandUI(out *output.Writer, progressLabel, progressFail, spinnerFail string) *commandUI {
	return &commandUI{
		out:           out,
		progressLabel: progressLabel,
		progressFail:  progressFail,
		spinnerFail:   spinnerFail,
	}
}

func (u *commandUI) onStep(step string, started bool) {
	if u.out.IsQuiet() || u.out.IsJSON() {
		return
	}
	if started {
		if u.progressBar != nil {
			u.progressBar = nil
		}
		u.spinner = u.out.StartSpinner(step)
		return
	}
	if u.spinner != nil {
		u.spinner.Success(step)
		u.spinner = nil
	}
}

func (u *commandUI) onProgress(written, total int64) {
	if u.out.IsQuiet() || u.out.IsJSON() {
		return
	}
	if u.spinner != nil {
		u.spinner.Stop()
		u.spinner = nil
		u.progressBar = u.out.StartProgress(u.progressLabel, total)
	}
	if u.progressBar != nil {
		u.progressBar.Update(written)
	}
}

func (u *commandUI) promptInstallAdapter(remoteName, adapterName string, allowPrompt bool) bool {
	if !allowPrompt || u.out.IsQuiet() || u.out.IsJSON() || !u.out.IsTTY() {
		return false
	}
	if u.spinner != nil {
		u.spinner.Stop()
		u.spinner = nil
	}
	return u.out.PromptConfirm(
		"Adapter %q for remote %q is not installed. Install now?",
		adapterName, remoteName,
	)
}

func (u *commandUI) fail() {
	if u.progressBar != nil {
		u.progressBar.Fail(u.progressFail)
		return
	}
	if u.spinner != nil {
		u.spinner.Fail(u.spinnerFail)
	}
}

func (u *commandUI) done(doneLabel string) {
	if u.progressBar != nil {
		u.progressBar.Done(doneLabel)
	}
}
