package componentsdk

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// TestRunTool_ExitCodes checks C-020 and C-021 for a tool built on the SDK: a
// run that succeeds exits 0, one whose handler fails exits 1, and one that
// requires a pack and gets none exits 1 without running the handler, with
// result.json saying why each time.
func TestRunTool_ExitCodes(t *testing.T) {
	t.Setenv("EPACK_PACK_PATH", "")
	t.Setenv("EPACK_PACK_DIGEST", "")
	spec := ToolSpec{Name: "demo", Version: "dev"}
	for _, tc := range []struct {
		name       string
		spec       ToolSpec
		handler    ToolHandler
		wantCode   int
		wantStatus string
		wantError  string
	}{
		{"success", spec, func(ToolContext) error { return nil }, 0, "success", ""},
		{"handler error", spec, func(ToolContext) error { return errors.New("boom") }, 1, "failure", "TOOL_ERROR"},
		{"pack required", ToolSpec{Name: "demo", Version: "dev", RequiresPack: true}, func(ToolContext) error {
			t.Error("the handler ran without a pack")
			return nil
		}, 1, "failure", "PACK_REQUIRED"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runDir := t.TempDir()
			t.Setenv("EPACK_RUN_DIR", runDir)
			if code := runToolInternal(tc.spec, tc.handler); code != tc.wantCode {
				t.Errorf("exit code = %d, want %d", code, tc.wantCode)
			}
			data, err := os.ReadFile(filepath.Join(runDir, "result.json"))
			if err != nil {
				t.Fatal(err)
			}
			var result toolResult
			if err := json.Unmarshal(data, &result); err != nil {
				t.Fatal(err)
			}
			if result.Status != tc.wantStatus {
				t.Errorf("status = %q, want %q", result.Status, tc.wantStatus)
			}
			if tc.wantError != "" && (len(result.Errors) != 1 || result.Errors[0].Code != tc.wantError) {
				t.Errorf("errors = %+v, want one %s", result.Errors, tc.wantError)
			}
		})
	}
}
