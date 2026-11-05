package collectortest

import (
	"fmt"
	"strings"

	"github.com/locktivity/epack/internal/outputcheck"
)

// The labels check requires a label and a summary on each number and
// true-or-false value an artifact holds, so a reviewer reading the pack can
// tell what the value means. The label is the value's x-epack-label, a few
// words such as "Disk encryption". The summary is its x-epack-summary, one or
// two plain sentences on what the value counts or says. Both go in the schema
// the kit checks the artifact against. The SDK's normalized schemas carry
// both for every value, so a normalized artifact needs none of its own. The
// check also reports an x-epack-goal that does not fit its value.

// maxLabelFields is the most fields one artifact's report names.
const maxLabelFields = 5

func (k *kit) checkLabels() {
	byPath := artifactsByPath(k.baseline.Artifacts)
	for _, path := range sortedKeys(byPath) {
		a := byPath[path]
		sch := k.levelSchema(a.Path, a.Schema)
		doc, err := outputcheck.Decode(a.Data)
		if sch == nil || err != nil {
			continue
		}
		missing := map[string]bool{}
		goals := map[string]string{}
		for _, v := range outputcheck.MeasuredValues(sch, doc) {
			field := anyIndex(v.Pointer)
			if v.Label == "" || v.Summary == "" {
				missing[field] = true
			}
			if problem := outputcheck.GoalProblem(v); problem != "" {
				goals[field] = problem
			}
		}
		if len(missing) > 0 {
			fields := sortedKeys(missing)
			shown := fields[:min(len(fields), maxLabelFields)]
			more := ""
			if len(fields) > len(shown) {
				more = fmt.Sprintf(", and %d more", len(fields)-len(shown))
			}
			k.violate("labels", path, "%s has no x-epack-label or x-epack-summary for %s%s. Add a label of a few words and "+
				"one or two plain sentences on what each value means to the collector's schema", path, strings.Join(shown, ", "), more)
		}
		for _, field := range sortedKeys(goals) {
			k.violate("labels", path, "%s %s: %s", path, field, goals[field])
		}
	}
}
