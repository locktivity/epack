package collectortest

import "testing"

func TestRedactionFlagsAnIdentifierHiddenAsASecret(t *testing.T) {
	expectViolation(t, checkDemo(t, demo{longCode: "ScoreConfigurationVersion20240101NotFoundError"}), "redaction",
		`"ScoreConfigurationVersion20240101NotFoundError" hidden as a possible secret`)
	if got := violationsOf(checkDemo(t, demo{longCode: "ScoreConfigurationNotFoundForThisAccountError"}), "redaction"); len(got) != 0 {
		t.Errorf("an error code that reads as words is reported: %v", got)
	}
}
