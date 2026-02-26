package exec

import (
	"testing"

	"github.com/locktivity/epack/internal/testutil/importguard"
)

// TestNoRawExecImport ensures collector exec uses internal/procexec wrappers.
func TestNoRawExecImport(t *testing.T) {
	importguard.AssertNoImport(t, "os/exec",
		"Use internal/procexec for subprocess execution in collector exec.")
}
