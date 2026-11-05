package collectortest

import "testing"

func TestTheWritesCheckWantsEverySchemaIDListed(t *testing.T) {
	s := methodSuite(methodsProbe{mirror: true, method: true})
	expectViolation(t, checkSuite(t, s), "writes",
		"artifacts/probe.access-posture.json has schema evidencepack/access-posture@v1, which CollectorSpec.Writes does not list")
	s.Spec.Writes = []string{"evidencepack/access-posture@v1"}
	if got := violationsOf(checkSuite(t, s), "writes"); len(got) != 0 {
		t.Errorf("a collector that lists what it writes: %+v", got)
	}
}
