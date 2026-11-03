package collectortest

import "testing"

func TestThePermissionsCheckHoldsAHintToTheDeclaredPermission(t *testing.T) {
	if got := violationsOf(checkDemo(t, demo{callErrors: true, declares: true}), "permissions"); len(got) != 0 {
		t.Errorf("a gap with the declared permission: %+v", got)
	}
	expectViolation(t, checkDemo(t, demo{callErrors: true, declares: true, wrongHint: true}), "permissions",
		"has missing permission scores.write, but demo.score.get declares scores.read")
	if got := violationsOf(checkDemo(t, demo{callErrors: true, wrongHint: true}), "permissions"); len(got) != 0 {
		t.Errorf("the check skips an operation that declares no permission: %+v", got)
	}
}
