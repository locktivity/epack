//go:build components

package runcmd

import (
	"bytes"
	"strings"
	"testing"

	"github.com/locktivity/epack/internal/cli/output"
	"github.com/locktivity/epack/internal/runflow"
	"github.com/locktivity/epack/internal/trustedpublishers"
)

func TestStageUI_ClosesAFailedStageBeforeTheNextOnePrints(t *testing.T) {
	var stdout bytes.Buffer
	ui := newStageUI(output.New(&stdout, &bytes.Buffer{}, output.Options{NoColor: true}))

	ui.onStage(runflow.StageCollect, true)
	ui.onStage(runflow.StagePostCollect, true)
	ui.onStage(runflow.StagePostCollect, false)
	ui.fail()

	got := stdout.String()
	failed := strings.Index(got, "Collecting evidence failed")
	hook := strings.Index(got, "Running post-collect hook...")
	if failed < 0 || hook < 0 || failed > hook {
		t.Fatalf("the collect failure should close its line before the hook prints:\n%s", got)
	}
	if strings.Contains(got, "post-collect hook failed") {
		t.Errorf("the hook did not fail:\n%s", got)
	}
}

func TestStageUI_NobodyAnswersPromptsWithJSONOutput(t *testing.T) {
	out := output.New(&bytes.Buffer{}, &bytes.Buffer{}, output.Options{JSON: true})
	ui := newStageUI(out)

	if ui.attended() {
		t.Fatal("JSON output has nobody to answer a prompt")
	}
	if !installPolicy(ui)("locktivity", "locktivity", "locktivity", trustedpublishers.NewSet("locktivity")) {
		t.Error("with nobody to ask, the pinned adapter from a trusted publisher installs")
	}
	if installPolicy(ui)("locktivity", "locktivity", "someone", trustedpublishers.NewSet("locktivity")) {
		t.Error("an adapter from an untrusted publisher never installs unasked")
	}
}
