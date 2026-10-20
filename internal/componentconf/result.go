//go:build conformance

package componentconf

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/locktivity/epack/componentsdk"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

// resultIDs are the checks of the collector result and build file an SDK
// collector adds to its output, which run on the run that collects.
// decodedResultIDs are those that read the decoded result, after COL-075
// checks it against its schema.
var (
	decodedResultIDs = []string{"COL-076", "COL-077", "COL-078", "COL-079", "COL-080"}
	resultIDs        = append([]string{"COL-075"}, decodedResultIDs...)
)

// emitted is the part of an artifact the result checks read.
type emitted struct {
	Path   string          `json:"path"`
	Schema string          `json:"schema"`
	Data   json.RawMessage `json:"data"`
}

// testCollectorResult checks the collector result and the build file in a
// run's output. Each check skips what the collector does not write, so a
// collector on an SDK that predates a field still passes.
func (r *Runner) testCollectorResult(output []byte) {
	var envelope struct {
		Artifacts []emitted `json:"artifacts"`
	}
	_ = json.Unmarshal(output, &envelope)
	var resultRaw, buildRaw json.RawMessage
	for _, a := range envelope.Artifacts {
		switch a.Schema {
		case componentsdk.ResultSchema:
			resultRaw = a.Data
		case componentsdk.BuildSchema:
			buildRaw = a.Data
		}
	}
	if resultRaw == nil {
		for _, id := range resultIDs {
			r.skip(id, "the collector writes no collector result")
		}
		return
	}

	// COL-075: the result matches evidencepack/collector-result@v1
	if problem := validateAgainst(componentsdk.ResultSchemaJSON(), resultRaw); problem != "" {
		r.fail("COL-075", "the collector result does not match "+componentsdk.ResultSchema+": "+problem)
	} else {
		r.pass("COL-075")
	}
	var result componentsdk.CollectorResult
	if err := json.Unmarshal(resultRaw, &result); err != nil {
		for _, id := range decodedResultIDs {
			r.skip(id, "the collector result does not decode: "+err.Error())
		}
		return
	}
	for _, c := range []struct {
		id, skip string
		check    func(componentsdk.CollectorResult) (string, bool)
	}{
		{"COL-076", "no request row carries a call number", checkRows},
		{"COL-077", "the collector result lists no steps", checkSteps},
		{"COL-078", "no gap names a call or a missing permission", checkGapCalls},
	} {
		problem, applies := c.check(result)
		r.report(c.id, problem, applies, c.skip)
	}
	r.testBuildFile(buildRaw, result)
	r.testTrustLevelResult(result)
}

// report skips id with skip when its check does not apply, since the
// collector writes nothing it reads, and otherwise passes it, or fails it
// with problem when there is one.
func (r *Runner) report(id, problem string, applies bool, skip string) {
	switch {
	case !applies:
		r.skip(id, skip)
	case problem == "":
		r.pass(id)
	default:
		r.fail(id, problem)
	}
}

// validateAgainst returns why doc does not match the schema, or "".
func validateAgainst(schemaJSON, doc []byte) string {
	schemaDoc, err := jsonschema.UnmarshalJSON(bytes.NewReader(schemaJSON))
	if err != nil {
		return err.Error()
	}
	c := jsonschema.NewCompiler()
	if err := c.AddResource("mem:///schema.json", schemaDoc); err != nil {
		return err.Error()
	}
	sch, err := c.Compile("mem:///schema.json")
	if err != nil {
		return err.Error()
	}
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(doc))
	if err != nil {
		return err.Error()
	}
	if err := sch.Validate(inst); err != nil {
		return firstLines(err.Error(), 3)
	}
	return ""
}

func firstLines(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[:n]
	}
	return strings.Join(lines, " ")
}

// checkRows checks the rows that carry call numbers: the attempts of one
// call share its operation and step, number up from 1 in order and never
// start before an earlier one, and only a retry waited before it was sent.
// It does not apply when no row carries a call number.
func checkRows(result componentsdk.CollectorResult) (string, bool) {
	byCall := map[int]componentsdk.CallRow{}
	numbered := false
	for _, row := range result.Calls.Requests {
		if row.Call == 0 {
			continue
		}
		numbered = true
		if row.WaitedMS > 0 && row.Attempt <= 1 {
			return fmt.Sprintf("call %d waited %dms before its first attempt; only a retry waits", row.Call, row.WaitedMS), true
		}
		prior, seen := byCall[row.Call]
		byCall[row.Call] = row
		if !seen {
			continue
		}
		switch {
		case row.Operation != prior.Operation || row.Step != prior.Step:
			return fmt.Sprintf("the attempts of call %d name %s in step %q and %s in step %q; one call has one operation and step", row.Call, prior.Operation, prior.Step, row.Operation, row.Step), true
		case row.Attempt <= prior.Attempt:
			return fmt.Sprintf("call %d lists attempt %d after attempt %d", row.Call, row.Attempt, prior.Attempt), true
		case row.StartMS < prior.StartMS:
			return fmt.Sprintf("call %d's attempt %d started at %dms, before attempt %d at %dms", row.Call, row.Attempt, row.StartMS, prior.Attempt, prior.StartMS), true
		}
	}
	if !numbered {
		return "", false
	}
	return "", true
}

// checkSteps checks the steps: each named once, listed in the order it
// started, ending no earlier, with counts that agree, and every row's step
// among them. It does not apply when the result lists no steps.
func checkSteps(result componentsdk.CollectorResult) (string, bool) {
	if len(result.Steps) == 0 {
		return "", false
	}
	names := map[string]bool{}
	for i, st := range result.Steps {
		ops := 0
		for _, op := range st.Operations {
			ops += op.Calls
		}
		switch {
		case st.Name == "":
			return fmt.Sprintf("step %d has no name", i), true
		case names[st.Name]:
			return fmt.Sprintf("step %s is listed twice; a step's name is part of the collector's contract, so each step needs its own", st.Name), true
		case st.EndMS < st.StartMS:
			return fmt.Sprintf("step %s ends at %dms, before it starts at %dms", st.Name, st.EndMS, st.StartMS), true
		case i > 0 && st.StartMS < result.Steps[i-1].StartMS:
			return fmt.Sprintf("step %s starts at %dms, before step %s listed ahead of it", st.Name, st.StartMS, result.Steps[i-1].Name), true
		case st.Requests != st.Calls+st.Retries || st.Failed > st.Requests:
			return fmt.Sprintf("step %s counts %d requests, %d calls, %d retries, and %d failed; requests are its calls and retries, and failures are among them", st.Name, st.Requests, st.Calls, st.Retries, st.Failed), true
		case ops != st.Calls:
			return fmt.Sprintf("step %s counts %d calls, but its operations count %d", st.Name, st.Calls, ops), true
		}
		names[st.Name] = true
	}
	for _, row := range result.Calls.Requests {
		if row.Step != "" && !names[row.Step] {
			return fmt.Sprintf("call %d names step %s, which the result does not list", row.Call, row.Step), true
		}
	}
	return "", true
}

// checkGapCalls checks the gaps that name a call or a missing permission:
// the operation is one the result counts, its call has rows wherever the
// result says no failed row was dropped, and a missing permission sits on a
// permission_denied gap. It does not apply when no gap names a call or a
// missing permission.
func checkGapCalls(result componentsdk.CollectorResult) (string, bool) {
	called := map[string]bool{}
	for _, op := range result.Calls.Operations {
		called[op.Name] = true
	}
	rowCalls := map[int]string{}
	for _, row := range result.Calls.Requests {
		if row.Call > 0 {
			rowCalls[row.Call] = row.Operation
		}
	}
	allRows := result.Calls.ProblemRequestsDropped != nil && *result.Calls.ProblemRequestsDropped == 0
	checked := false
	for _, g := range result.Gaps {
		if g.Operation == "" && g.Call == 0 && g.MissingPermission == "" {
			continue
		}
		checked = true
		at := g.Path + " " + g.Pointer
		switch {
		case g.MissingPermission != "" && g.Code != componentsdk.CodePermissionDenied:
			return fmt.Sprintf("the gap at %s names a missing permission but has code %s; only a permission_denied gap names one", at, g.Code), true
		case g.Call > 0 && g.Operation == "":
			return fmt.Sprintf("the gap at %s names call %d but no operation", at, g.Call), true
		case g.Operation != "" && !called[g.Operation]:
			return fmt.Sprintf("the gap at %s names operation %s, which the result's calls do not count", at, g.Operation), true
		case g.Call > 0 && allRows && rowCalls[g.Call] != g.Operation:
			return fmt.Sprintf("the gap at %s names call %d of %s, which has no row although no failed row was left out", at, g.Call, g.Operation), true
		}
	}
	if !checked {
		return "", false
	}
	return "", true
}

// testBuildFile checks the build file, when the collector writes one: it
// matches evidencepack/collector-build@v1 and names the result's version and
// commit (COL-079).
func (r *Runner) testBuildFile(raw json.RawMessage, result componentsdk.CollectorResult) {
	if raw == nil {
		r.skip("COL-079", "the collector writes no build file")
		return
	}
	if problem := validateAgainst(componentsdk.BuildSchemaJSON(), raw); problem != "" {
		r.fail("COL-079", "the build file does not match "+componentsdk.BuildSchema+": "+problem)
		return
	}
	var build componentsdk.CollectorBuild
	if err := json.Unmarshal(raw, &build); err != nil {
		r.fail("COL-079", "the build file does not decode: "+err.Error())
		return
	}
	if build.Collector.Version != result.Collector.Version || build.Collector.Commit != result.Collector.Commit {
		r.fail("COL-079", fmt.Sprintf("the build file names version %q and commit %q, but the collector result names %q and %q", build.Collector.Version, build.Collector.Commit, result.Collector.Version, result.Collector.Commit))
		return
	}
	r.pass("COL-079")
}

// testTrustLevelResult checks that a run at the trust level kept out of its
// result what only the audit and internal levels hold: request rows, the
// gaps' warnings and error text, and the principal's ID (COL-080).
func (r *Runner) testTrustLevelResult(result componentsdk.CollectorResult) {
	if level := r.collectLevel(); level != componentsdk.LevelTrust {
		r.skip("COL-080", "the --config file collects at "+string(level))
		return
	}
	switch {
	case len(result.Calls.Requests) > 0:
		r.fail("COL-080", fmt.Sprintf("the result holds %d request rows at the trust level", len(result.Calls.Requests)))
	case result.SignedInAs != nil && result.SignedInAs.ID != "":
		r.fail("COL-080", "the result holds the principal's ID at the trust level")
	default:
		for _, g := range result.Gaps {
			if g.Warning != "" || g.Detail != "" {
				r.fail("COL-080", "the gap at "+g.Path+" "+g.Pointer+" holds its warning or error text at the trust level")
				return
			}
		}
		r.pass("COL-080")
	}
}

// collectLevel is the level the run that collects asks for: the --config
// file's level, or trust.
func (r *Runner) collectLevel() componentsdk.Level {
	if r.CollectorConfig == "" {
		return componentsdk.LevelTrust
	}
	raw, err := os.ReadFile(r.CollectorConfig)
	if err != nil {
		return componentsdk.LevelTrust
	}
	var config map[string]any
	_ = json.Unmarshal(raw, &config)
	return componentsdk.LevelOf(config)
}
