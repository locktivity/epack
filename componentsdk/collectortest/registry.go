package collectortest

import (
	"os"

	"github.com/locktivity/epack/componentsdk"
	"github.com/locktivity/epack/internal/tracemap"
)

// kitCheck is one of the kit's checks. It holds the check's name, which
// Suite.SkipChecks uses to turn it off, and the hooks the check runs at. At
// each hook, the checks run in the order kitChecks lists them. To add a
// check, add an entry to kitChecks.
type kitCheck struct {
	name string
	// on reports whether the suite turns on a check that is off by default.
	// Nil means the check is on by default.
	on func(Suite) bool
	// eachRun runs on every run's result. It gets the check and name the run
	// was made under.
	eachRun func(k *kit, check, name string, res componentsdk.InProcessResult)
	// eachScenario runs on each scenario's run, whether it succeeded or
	// failed as its scenario expects.
	eachScenario func(k *kit, label string, sc Scenario, res componentsdk.InProcessResult, n *network)
	// eachSuccess runs on each scenario's run that succeeded.
	eachSuccess func(k *kit, label string, sc Scenario, res componentsdk.InProcessResult, n *network)
	// afterBaseline runs after the clean scenario's run is set as the
	// baseline.
	afterBaseline func(k *kit)
}

// kitChecks lists the kit's checks in the order they run at each hook. The
// output checks come last. They run in the SDK and in checkOutput, and are
// listed here so SkipChecks can name them. init fills kitChecks because the
// checks call back into the hooks that read it.
var kitChecks []kitCheck

func init() {
	kitChecks = []kitCheck{
		{name: "determinism", afterBaseline: (*kit).checkDeterminism},
		{name: "coverage", afterBaseline: (*kit).checkCoverage},
		{name: "levels", afterBaseline: (*kit).checkLevels},
		{name: "methods", afterBaseline: (*kit).checkMethods},
		{name: "writes", eachSuccess: func(k *kit, label string, _ Scenario, res componentsdk.InProcessResult, _ *network) {
			k.checkWrites(label, res)
		}},
		{name: "permissions", eachRun: (*kit).checkPermissions},
		{name: "credentials",
			eachRun:       func(k *kit, _, _ string, res componentsdk.InProcessResult) { k.checkHostLists(res) },
			afterBaseline: (*kit).checkCredentials},
		{name: "faults", afterBaseline: (*kit).runFaultMatrix},
		{name: "responses", eachScenario: func(k *kit, label string, sc Scenario, _ componentsdk.InProcessResult, n *network) {
			k.checkResponses(label, sc, n)
		}},
		{name: "guidance", eachScenario: func(k *kit, label string, sc Scenario, res componentsdk.InProcessResult, _ *network) {
			k.checkGuidanceText(label, sc, k.adviceAsWritten(label, sc, res))
		}},
		{name: "pages",
			eachSuccess: func(k *kit, label string, _ Scenario, _ componentsdk.InProcessResult, n *network) {
				for _, msg := range n.replay.unreadPages(k.suite.Capped) {
					k.violate("pages", label, "%s", msg)
				}
			},
			afterBaseline: (*kit).checkPageFaults},
		{name: "vocabulary", eachSuccess: func(k *kit, label string, _ Scenario, res componentsdk.InProcessResult, _ *network) {
			k.checkUnrecognized(label, res)
		}},
		{name: "order", afterBaseline: (*kit).checkOrder},
		{name: "variants", afterBaseline: (*kit).checkVariants},
		{name: "fields", on: func(s Suite) bool { return s.FieldSensitivity }, afterBaseline: (*kit).checkFields},
		{name: "sensitivity", afterBaseline: (*kit).checkSensitivity},
		{name: "tracemap", afterBaseline: func(k *kit) {
			if k.trace != nil && os.Getenv(tracemap.Env) == "" {
				k.checkTraceMap()
			}
		}},
		{name: "population"},
		{name: "nulls"},
		{name: "rollups"},
		{name: "ratios"},
	}
}

// CheckNames returns the names of the kit's checks in the order they run.
// Suite.SkipChecks and Violation.Check use these names.
func CheckNames() []string {
	names := make([]string, len(kitChecks))
	for i, c := range kitChecks {
		names[i] = c.name
	}
	return names
}

// enabled reports whether the suite runs c.
func (k *kit) enabled(c kitCheck) bool {
	return !k.skipped(c.name) && (c.on == nil || c.on(k.suite))
}

func (k *kit) runEachRun(check, name string, res componentsdk.InProcessResult) {
	for _, c := range kitChecks {
		if c.eachRun != nil && k.enabled(c) {
			c.eachRun(k, check, name, res)
		}
	}
}

func (k *kit) runEachScenario(label string, sc Scenario, res componentsdk.InProcessResult, n *network) {
	for _, c := range kitChecks {
		if c.eachScenario != nil && k.enabled(c) {
			c.eachScenario(k, label, sc, res, n)
		}
	}
}

func (k *kit) runEachSuccess(label string, sc Scenario, res componentsdk.InProcessResult, n *network) {
	for _, c := range kitChecks {
		if c.eachSuccess != nil && k.enabled(c) {
			c.eachSuccess(k, label, sc, res, n)
		}
	}
}

func (k *kit) runAfterBaseline() {
	for _, c := range kitChecks {
		if c.afterBaseline != nil && k.enabled(c) {
			c.afterBaseline(k)
		}
	}
}
