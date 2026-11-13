package collectortest

import (
	"strings"
	"testing"
	"time"

	"github.com/locktivity/epack/internal/tracemap"
)

func TestAnOldSuiteFieldSaysWhichWaiverToAdd(t *testing.T) {
	for name, set := range map[string]func(*Suite){
		"SkipChecks":    func(s *Suite) { s.SkipChecks = []string{"faults"} },
		"SkipFaults":    func(s *Suite) { s.SkipFaults = []string{"timeout"} },
		"Insensitive":   func(s *Suite) { s.Insensitive = []string{"demo.me.get"} },
		"Capped":        func(s *Suite) { s.Capped = []string{"demo.users.list"} },
		"Ordered":       func(s *Suite) { s.Ordered = []string{"demo.users.list"} },
		"Ignore":        func(s *Suite) { s.Ignore = map[string][]string{"artifacts/demo.json": {"/diagnostics"}} },
		"IgnoredFields": func(s *Suite) { s.IgnoredFields = map[string][]string{"demo.users.list": {"/*/status"}} },
	} {
		t.Run(name, func(t *testing.T) {
			s := demoSuite(demo{})
			set(&s)
			_, err := Check(s)
			if err == nil || !strings.Contains(err.Error(), "Suite."+name+" is no longer read") || !strings.Contains(err.Error(), "collectortest.Waiver{Check:") || !strings.Contains(err.Error(), `Expires: "`) {
				t.Errorf("Check() = %v, want an error naming Suite.%s and the waiver to add", err, name)
			}
		})
	}
	s := demoSuite(demo{})
	s.Ignore = map[string][]string{"artifacts/demo.json": {"/diagnostics"}}
	s.SkipChecks = []string{"faults"}
	_, err := Check(s)
	if err == nil || strings.Count(err.Error(), "is no longer read") != 2 || !strings.Contains(err.Error(), `Subject: "artifacts/demo.json /diagnostics"`) {
		t.Errorf("Check() = %v, want one line per field, with the Ignore entry as a subject", err)
	}
}

func TestFieldFaultsIsReadButDoesNothing(t *testing.T) {
	s := demoSuite(demo{})
	s.FieldFaults = true
	if _, err := Check(s); err != nil {
		t.Errorf("a suite that still sets FieldFaults: %v", err)
	}
}

func TestWaiversNeedAReasonAnExpiryAndAKnownCheck(t *testing.T) {
	soon := time.Now().AddDate(0, 1, 0).Format(tracemap.WaiverDate)
	for name, tc := range map[string]struct {
		waiver Waiver
		want   string
	}{
		"no check":          {Waiver{Reason: "r", Expires: soon}, "names no check"},
		"unknown check":     {Waiver{Check: "faultz", Reason: "r", Expires: soon}, "names no check: the checks are"},
		"no reason":         {Waiver{Check: "faults", Expires: soon}, "has no Reason"},
		"blank reason":      {Waiver{Check: "faults", Reason: "  ", Expires: soon}, "has no Reason"},
		"no expiry":         {Waiver{Check: "faults", Reason: "r"}, "has no Expires"},
		"bad date":          {Waiver{Check: "faults", Reason: "r", Expires: "next spring"}, "write the date as YYYY-MM-DD"},
		"too far out":       {Waiver{Check: "faults", Reason: "r", Expires: time.Now().AddDate(2, 0, 0).Format(tracemap.WaiverDate)}, "more than a year"},
		"subject on check":  {Waiver{Check: "faults", Subject: "demo.me.get", Reason: "r", Expires: soon}, "takes no Subject"},
		"no subject":        {Waiver{Check: WaiveInsensitive, Reason: "r", Expires: soon}, "needs a Subject of one operation name"},
		"two subjects":      {Waiver{Check: WaiveFault, Subject: "timeout reset", Reason: "r", Expires: soon}, "needs a Subject of one fault name"},
		"ignore pointer":    {Waiver{Check: WaiveIgnore, Subject: "artifacts/demo.json diagnostics", Reason: "r", Expires: soon}, "an artifact path and a pointer prefix"},
		"ignored field":     {Waiver{Check: WaiveIgnoredField, Subject: "demo.users.list", Reason: "r", Expires: soon}, "an operation and a field pattern"},
		"recording":         {Waiver{Check: WaiveRecording, Reason: "no sandbox yet", Expires: soon}, "needs a Subject of one sandbox name"},
		"the waivers check": {Waiver{Check: "waivers", Reason: "r", Expires: soon}, "cannot be waived"},
	} {
		t.Run(name, func(t *testing.T) {
			s := demoSuite(demo{})
			s.Waivers = append(s.Waivers, tc.waiver)
			_, err := Check(s)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("Check() = %v, want an error saying %q", err, tc.want)
			}
		})
	}
	s := demoSuite(demo{})
	s.Waivers = append(s.Waivers, waive("faults"), waive("faults"))
	if _, err := Check(s); err == nil || !strings.Contains(err.Error(), "lists faults twice") {
		t.Errorf("Check() = %v, want an error about the repeated waiver", err)
	}
}

func TestAnExpiredWaiverRunsItsCheckAndIsReported(t *testing.T) {
	s := demoSuite(demo{firstPage: true})
	current := waive("pages")
	s.Waivers = append(s.Waivers, current)
	if got := violationsOf(checkSuite(t, s), "pages"); len(got) != 0 {
		t.Errorf("a current waiver turns the check off: %+v", got)
	}

	expired := current
	expired.Expires = time.Now().AddDate(0, 0, -1).Format(tracemap.WaiverDate)
	s.Waivers[len(s.Waivers)-1] = expired
	report := checkSuite(t, s)
	if got := violationsOf(report, "pages"); len(got) == 0 {
		t.Error("an expired waiver no longer turns the check off")
	}
	expectViolation(t, report, "waivers", "the waiver on pages expired on "+expired.Expires)
	expectViolation(t, report, "waivers", "renew it with a date within a year if its reason still holds: the kit's own test")

	today := current
	today.Expires = time.Now().Format(tracemap.WaiverDate)
	s.Waivers[len(s.Waivers)-1] = today
	expectViolation(t, checkSuite(t, s), "waivers", "expired on "+today.Expires)
}

func TestARecordingWaiverStandsUntilTheSuiteReplaysOne(t *testing.T) {
	s := demoSuite(demo{})
	s.Waivers = append(s.Waivers, waive(WaiveRecording, "demo-sandbox"))
	report := checkSuite(t, s)
	if got := violationsOf(report, "waivers"); len(got) != 0 {
		t.Errorf("a suite with no recording may waive it: %+v", got)
	}
	traces := suiteTraces(t, s)
	if len(traces) != 1 || traces[0].Summary == nil || traces[0].Summary.Recordings != 0 {
		t.Fatalf("traces = %+v, want a summary with no recording", traces)
	}
	found := false
	for _, w := range traces[0].Summary.Waivers {
		found = found || (w.Check == WaiveRecording && w.Subject == "demo-sandbox")
	}
	if !found {
		t.Errorf("the summary's waivers lack the recording waiver: %+v", traces[0].Summary.Waivers)
	}

	// The clean scenario stands in for a recording, as LoadScenario marks
	// one, so the waiver has nothing left to excuse.
	s.Scenarios[0].source = "testdata/recordings/demo.json"
	expectViolation(t, checkSuite(t, s), "waivers", "the suite waives the recording of demo-sandbox but replays 1; remove the waiver")
}

func TestFieldFaultsRunsUnlessWaived(t *testing.T) {
	// The admin probe has the bug the check exists to catch, and its suite
	// turns nothing off but the checks it is not about.
	report := checkSuite(t, adminSuite(adminProbe{}))
	if got := violationsOf(report, "field_faults"); len(got) == 0 {
		t.Error("the field_faults check is on in a suite that does not mention it")
	}
	s := adminSuite(adminProbe{})
	s.Waivers = append(s.Waivers, waive("field_faults"))
	if got := violationsOf(checkSuite(t, s), "field_faults"); len(got) != 0 {
		t.Errorf("a waiver turns the check off: %+v", got)
	}
}

func TestCoverageWantsTheOperationsListed(t *testing.T) {
	s := demoSuite(demo{})
	s.Operations = nil
	expectViolation(t, checkSuite(t, s), "coverage", "Suite.Operations lists no operations")
	if got := violationsOf(checkDemo(t, demo{}), "coverage"); len(got) != 0 {
		t.Errorf("a suite that lists its operations: %+v", got)
	}
}

func TestTheSuiteTraceSummarizesTheSuite(t *testing.T) {
	s := demoSuite(demo{})
	s.Name = "demo-token"
	s.Waivers = append(s.Waivers, waive(WaiveCapped, "demo.users.list"))
	traces := suiteTraces(t, s)
	if len(traces) != 1 || traces[0].Summary == nil {
		t.Fatalf("traces = %+v, want one with a summary", traces)
	}
	got := traces[0].Summary
	if got.Name != "demo-token" || strings.Join(got.Operations, ",") != "demo.me.get,demo.score.get,demo.users.list" || got.Scenarios != 3 || got.Recordings != 0 {
		t.Errorf("summary = %+v", got)
	}
	var kinds []string
	for _, w := range got.Waivers {
		kinds = append(kinds, waiverLabel(w))
		if w.Reason == "" || w.Expires == "" {
			t.Errorf("the trace drops a waiver's reason or expiry: %+v", w)
		}
	}
	if strings.Join(kinds, ", ") != "capped demo.users.list, field_faults, insensitive demo.me.get, paths" {
		t.Errorf("waivers = %v, want them sorted by check and subject", kinds)
	}
	if strings.Join(traces[0].Insensitive, ",") != "demo.me.get" {
		t.Errorf("insensitive = %v, want the waived operation", traces[0].Insensitive)
	}
}
