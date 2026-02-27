//go:build components

package remotecmd

import (
	"bytes"
	"testing"

	"github.com/locktivity/epack/internal/cli/output"
)

func TestNewCommandUI(t *testing.T) {
	out := output.New(&bytes.Buffer{}, &bytes.Buffer{}, output.Options{})
	ui := newCommandUI(out, "Downloading", "Download failed", "Pull failed")

	if ui.out != out {
		t.Fatal("newCommandUI() did not retain writer")
	}
	if ui.progressLabel != "Downloading" || ui.progressFail != "Download failed" || ui.spinnerFail != "Pull failed" {
		t.Fatalf("newCommandUI() labels not set: %+v", ui)
	}
}

func TestCommandUI_PromptInstallAdapter_Disabled(t *testing.T) {
	out := output.New(&bytes.Buffer{}, &bytes.Buffer{}, output.Options{})
	ui := newCommandUI(out, "Uploading", "Upload failed", "Push failed")

	if ok := ui.promptInstallAdapter("locktivity", "adapter", false); ok {
		t.Fatal("promptInstallAdapter() = true, want false when prompting disabled")
	}
}

func TestCommandUI_StepAndProgressTransitions(t *testing.T) {
	out := output.New(&bytes.Buffer{}, &bytes.Buffer{}, output.Options{})
	ui := newCommandUI(out, "Downloading", "Download failed", "Pull failed")

	ui.onStep("Resolving", true)
	if ui.spinner == nil {
		t.Fatal("onStep(started=true) did not start spinner")
	}

	ui.onStep("Resolving", false)
	if ui.spinner != nil {
		t.Fatal("onStep(started=false) did not clear spinner")
	}

	ui.onStep("Downloading", true)
	ui.onProgress(5, 10)
	if ui.spinner != nil {
		t.Fatal("onProgress() should stop spinner when progress starts")
	}
	if ui.progressBar == nil {
		t.Fatal("onProgress() should create progress bar")
	}

	ui.done("Downloaded")
	ui.fail()
}

func TestCommandUI_QuietModeNoInteractiveUI(t *testing.T) {
	out := output.New(&bytes.Buffer{}, &bytes.Buffer{}, output.Options{Quiet: true})
	ui := newCommandUI(out, "Downloading", "Download failed", "Pull failed")

	ui.onStep("Resolving", true)
	ui.onProgress(1, 2)

	if ui.spinner != nil || ui.progressBar != nil {
		t.Fatalf("quiet mode should not create UI elements, got spinner=%v progress=%v", ui.spinner != nil, ui.progressBar != nil)
	}
}
