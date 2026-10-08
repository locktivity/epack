//go:build components

package runcmd

import (
	"bytes"
	"strings"
	"testing"

	"github.com/locktivity/epack/internal/cli/output"
	"github.com/locktivity/epack/internal/runflow"
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
