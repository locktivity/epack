package collectortest

import "testing"

func TestTheWritesCheckWantsEverySchemaIDListed(t *testing.T) {
	s := methodSuite(methodsProbe{mirror: true, method: true})
	expectViolation(t, checkSuite(t, s), "writes",
		"artifacts/probe.vcs-posture.json has schema evidencepack/vcs-posture@v1, which CollectorSpec.Writes does not list")
	s.Spec.Writes = []string{"evidencepack/vcs-posture@v1"}
	if got := violationsOf(checkSuite(t, s), "writes"); len(got) != 0 {
		t.Errorf("a collector that lists what it writes: %+v", got)
	}
}
