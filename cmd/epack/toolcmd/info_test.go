//go:build components

package toolcmd

import (
	"testing"

	"github.com/spf13/cobra"
)

func TestRunInfo_NilCommandContext_DoesNotPanic(t *testing.T) {
	cmd := &cobra.Command{}

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("runInfo panicked with nil command context: %v", r)
		}
	}()

	// Unknown tool is fine for this test; we only care that nil context
	// doesn't panic in ProbeCapabilities path.
	_ = runInfo(cmd, "definitely-not-a-real-tool", false)
}
