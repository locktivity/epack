//go:build components

package remotecmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/locktivity/epack/internal/cli/exitmap"
	"github.com/locktivity/epack/internal/lockprovenance"
)

func TestReportLockMetadata_ListsTheCollectorsTheErrorFileNames(t *testing.T) {
	path := filepath.Join(t.TempDir(), "epack-error.txt")
	content := "code=collect_failed\nexit=3\nsummary=okta: exited with code 3: 401 Unauthorized\n" +
		"collector=okta code=auth_failed exit=3 code_source=exit_code\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	getenv := func(key string) string {
		if key == exitmap.ErrorFileEnv {
			return path
		}
		return ""
	}

	provenance, err := lockprovenance.Build(lockprovenance.Options{
		ProjectRoot:    t.TempDir(),
		TriggerKind:    lockprovenance.TriggerFrozenCheck,
		Outcome:        lockprovenance.OutcomeFailure,
		FailureCode:    "collect_failed",
		FailureMessage: "okta: exited with code 3: 401 Unauthorized",
		Getenv:         getenv,
		Metadata:       reportLockMetadata(lockprovenance.OutcomeFailure, "collect_failed", getenv),
	})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(provenance.Metadata)
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"collect":{"failures":[{"collector":"okta","code":"auth_failed","exit":3,"code_source":"exit_code"}]}}`; string(encoded) != want {
		t.Errorf("metadata = %s, want %s", encoded, want)
	}

	if got := reportLockMetadata(lockprovenance.OutcomeFailure, "workflow_failed", getenv); got != nil {
		t.Errorf("failure the file does not describe = %v, want nil", got)
	}
	if got := reportLockMetadata(lockprovenance.OutcomeSuccess, "", getenv); got != nil {
		t.Errorf("success = %v, want nil", got)
	}
	if got := reportLockMetadata(lockprovenance.OutcomeFailure, "collect_failed", func(string) string { return "" }); got != nil {
		t.Errorf("no error file = %v, want nil", got)
	}
}
