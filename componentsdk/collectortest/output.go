package collectortest

import (
	"github.com/locktivity/epack/componentsdk"
	"github.com/locktivity/epack/componentsdk/internal/outputcheck"
)

// valueChecksApply reports whether the population, nulls, rollups, and
// ratios checks apply to a run. Sensitivity runs change responses on purpose, which makes
// rows and rollups disagree, and determinism runs repeat the clean scenario.
func valueChecksApply(check string) bool {
	switch check {
	case "scenario", "levels", "faults", "credentials":
		return true
	}
	return false
}

// violateFinding reports one output check finding from a run under the
// finding's own check name. A schema that does not compile fails the same way
// in every run, so it is reported once, outside any run.
func (k *kit) violateFinding(check, name, finding, path, pointer, message string) {
	if finding == outputcheck.CheckSchemaUnusable {
		k.violate(finding, "", "%s", message)
		return
	}
	if finding != outputcheck.CheckSchema && (!valueChecksApply(check) || k.skipped(finding)) {
		return
	}
	k.violate(finding, check+"/"+name, "%s %s: %s", path, pointerLabel(pointer), message)
}

// checkOutput reports the output check findings in a run's result, and runs
// the same checks on artifacts whose schema only Suite.Schemas gives, at the
// level the run collected at. When the result dropped findings past its
// limit, the kit checks the SDK's artifacts again, so none go unreported.
func (k *kit) checkOutput(check, name string, res componentsdk.InProcessResult, level componentsdk.Level) {
	if res.Result == nil {
		return
	}
	for _, f := range res.Result.Checks {
		k.violateFinding(check, name, f.Check, f.Path, f.Pointer, f.Message)
	}
	gaps := make([]outputcheck.Gap, len(res.Result.Gaps))
	for i, g := range res.Result.Gaps {
		gaps[i] = outputcheck.Gap{Path: g.Path, Pointer: g.Pointer}
	}
	recheck := res.Result.ChecksDropped > 0
	for _, a := range res.Artifacts {
		if a.File != "" || sdkArtifact(a) {
			continue
		}
		sch, fromSDK := k.sdkSchema(a.Path, a.Schema)
		if fromSDK && !recheck {
			continue
		}
		if !fromSDK {
			sch = k.suiteSchema(a.Path, a.Schema)
		}
		if sch == nil {
			continue
		}
		doc, err := outputcheck.Decode(a.Data)
		if err != nil {
			continue
		}
		var findings []outputcheck.Finding
		if fromSDK {
			findings = outputcheck.Validate(sch, a.Path, doc)
		}
		if valueChecksApply(check) {
			findings = append(findings, outputcheck.Check(sch, a.Path, doc, gaps, string(level))...)
		}
		for _, f := range findings {
			k.violateFinding(check, name, f.Check, f.Path, f.Pointer, f.Message)
		}
	}
}

func (k *kit) suiteSchema(path, schemaID string) *outputcheck.Schema {
	if sch := k.schemas[path]; sch != nil {
		return sch
	}
	if schemaID != "" {
		return k.schemas[schemaID]
	}
	return nil
}

// sdkSchema returns the schema Emit checks an artifact against, picked the
// way Emit picks it, and whether Emit has one. A schema that does not compile
// counts as one, so the artifact is left to the result's findings.
func (k *kit) sdkSchema(path, schemaID string) (*outputcheck.Schema, bool) {
	raw, ok := k.suite.Spec.Schemas[path]
	if !ok && schemaID != "" {
		raw, ok = k.suite.Spec.Schemas[schemaID]
	}
	if !ok && schemaID != "" {
		raw = componentsdk.NormalizedSchemaJSON(schemaID)
		ok = raw != nil
	}
	if !ok {
		return nil, false
	}
	sch, err := outputcheck.Compile(raw)
	if err != nil {
		return nil, true
	}
	return sch, true
}

// levelSchema returns the schema the levels check reads annotations from:
// Suite.Schemas, then Spec.Schemas, then the SDK's normalized schemas.
func (k *kit) levelSchema(path, schemaID string) *outputcheck.Schema {
	if sch := k.suiteSchema(path, schemaID); sch != nil {
		return sch
	}
	sch, _ := k.sdkSchema(path, schemaID)
	return sch
}

// sdkArtifact reports whether the SDK added an artifact itself: the result
// artifact or the build file, which say how the run went and what built it
// rather than holding evidence.
func sdkArtifact(a componentsdk.EmittedArtifact) bool {
	return a.Schema == componentsdk.ResultSchema || a.Schema == componentsdk.BuildSchema
}
