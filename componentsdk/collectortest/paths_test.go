package collectortest

import "testing"

func TestThePathsCheck(t *testing.T) {
	for _, name := range []string{"", "probe-prod"} {
		s := methodSuite(methodsProbe{mirror: true, method: true})
		s.Name = name
		report, err := Check(s)
		if err != nil {
			t.Fatal(err)
		}
		got := violationsOf(report, "paths")
		want := map[string]string{
			"":           `artifacts/probe.json is a details artifact, which belongs at artifacts/probe.details.json. Name it with componentsdk.ArtifactPath("probe", "")`,
			"probe-prod": `artifacts/probe-prod.json is a details artifact, which belongs at artifacts/probe-prod.details.json. Name it with componentsdk.ArtifactPath("probe", "")`,
		}[name]
		if len(got) != 1 || got[0].Message != want {
			t.Errorf("name %q: paths violations = %+v, want one for the details file and none for the vcs-posture one at its kind's path", name, got)
		}
	}
}
