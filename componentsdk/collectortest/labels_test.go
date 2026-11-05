package collectortest

import "testing"

// labelSuite is methodSuite's probe with a detailed schema that gives
// two_factor the annotations in extra, a JSON fragment.
func labelSuite(extra string) Suite {
	s := methodSuite(methodsProbe{mirror: true, method: true})
	detailed := `{"type": "object", "properties": {"name": {"type": "string"}, "two_factor": {"type": "boolean", ` +
		`"x-epack-method": "Reads whether the organization requires two-factor authentication."` + extra + `}}}`
	s.Spec.Schemas = map[string][]byte{"artifacts/probe.json": []byte(detailed)}
	return s
}

func TestTheLabelsCheckWantsALabelAndASummaryOnEachValue(t *testing.T) {
	want := "artifacts/probe.json has no x-epack-label or x-epack-summary for /two_factor"
	expectViolation(t, checkSuite(t, labelSuite("")), "labels", want)
	expectViolation(t, checkSuite(t, labelSuite(`, "x-epack-label": "Two-factor required"`)), "labels", want)
	labeled := labelSuite(`, "x-epack-label": "Two-factor required", "x-epack-summary": "Whether every member must use two-factor authentication.", "x-epack-goal": true`)
	if got := violationsOf(checkSuite(t, labeled), "labels"); len(got) != 0 {
		t.Errorf("a labeled value, and a normalized artifact the SDK's schema labels: %+v", got)
	}
}

func TestTheLabelsCheckReportsAGoalThatDoesNotFit(t *testing.T) {
	s := labelSuite(`, "x-epack-label": "Two-factor required", "x-epack-summary": "Whether every member must use two-factor authentication.", "x-epack-goal": "higher"`)
	expectViolation(t, checkSuite(t, s), "labels", "artifacts/probe.json /two_factor: x-epack-goal \"higher\" on a true-or-false value, want true or false")
}

func TestTheLabelsCheckCanBeSkipped(t *testing.T) {
	s := labelSuite("")
	s.SkipChecks = append(s.SkipChecks, "labels")
	if got := violationsOf(checkSuite(t, s), "labels"); len(got) != 0 {
		t.Errorf("a skipped check: %+v", got)
	}
}
