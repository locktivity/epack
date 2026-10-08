package exec

import "testing"

func TestSanitizeStderr_DropsTheTrailingNewline(t *testing.T) {
	if got := SanitizeStderr("error: no credentials\n"); got != "error: no credentials" {
		t.Errorf("SanitizeStderr = %q", got)
	}
	if got := SanitizeStderr("first\nsecond\n"); got != `first\nsecond` {
		t.Errorf("inner newlines stay escaped: %q", got)
	}
	if got := SanitizeStderr("\n"); got != "(no stderr)" {
		t.Errorf("only whitespace is no stderr: %q", got)
	}
}
