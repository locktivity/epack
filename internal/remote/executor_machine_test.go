package remote

import (
	"strings"
	"testing"
)

func TestPrintableMachineNameDropsControlCharactersAndBounds(t *testing.T) {
	if got := printableMachineName("  mnipper-mbp\x00\n\u200b "); got != "mnipper-mbp" {
		t.Fatalf("printableMachineName = %q", got)
	}
	long := strings.Repeat("m", 100)
	if got := printableMachineName(long); len(got) != 64 {
		t.Fatalf("printableMachineName length = %d, want 64", len(got))
	}
	if got := printableMachineName(""); got != "" {
		t.Fatalf("printableMachineName(\"\") = %q", got)
	}
}
