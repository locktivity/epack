package collectortest

import (
	"fmt"
	"sort"

	"github.com/locktivity/epack/componentsdk"
	"github.com/locktivity/epack/componentsdk/internal/outputcheck"
)

// checkLevels runs the clean scenario at each collection level. What one
// level emits, every higher level must emit too, though values may differ.
// A value whose schema gives it a level with x-epack-level must be absent,
// not even null, below that level.
func (k *kit) checkLevels() {
	type levelRun struct {
		level componentsdk.Level
		res   componentsdk.InProcessResult
	}
	var runs []levelRun
	for _, level := range []componentsdk.Level{componentsdk.LevelTrust, componentsdk.LevelAudit, componentsdk.LevelInternal} {
		config := k.configFor(k.suite.Scenarios[0])
		if config == nil {
			config = map[string]any{}
		}
		config["level"] = string(level)
		res, _ := k.runWith("levels", string(level), k.suite.Scenarios[0], nil, config)
		if res.ExitCode != 0 {
			k.violate("levels", string(level), "the run failed with exit %d and %s", res.ExitCode, failureLabel(res))
			continue
		}
		k.checkLevelAnnotations(level, res)
		runs = append(runs, levelRun{level: level, res: res})
	}
	for i, lower := range runs {
		for _, higher := range runs[i+1:] {
			for _, p := range levelLosses(lower.level, higher.level, lower.res, higher.res, k.ignore) {
				k.violate("levels", string(lower.level)+"/"+string(higher.level), "%s", p)
			}
		}
	}
}

func (k *kit) checkLevelAnnotations(level componentsdk.Level, res componentsdk.InProcessResult) {
	for _, a := range res.Artifacts {
		if a.File != "" || sdkArtifact(a) {
			continue
		}
		sch := k.levelSchema(a.Path, a.Schema)
		if sch == nil {
			continue
		}
		doc, err := outputcheck.Decode(a.Data)
		if err != nil {
			continue
		}
		for _, f := range outputcheck.AboveLevel(sch, a.Path, doc, string(level)) {
			k.violate("levels", string(level), "%s %s: %s", f.Path, pointerLabel(f.Pointer), f.Message)
		}
	}
}

// levelLosses lists what the lower level's run emitted that the higher
// level's run did not: whole artifacts, and leaf values by pointer. A value
// the higher run left out with a gap still counts as emitted.
func levelLosses(lower, higher componentsdk.Level, low, high componentsdk.InProcessResult, ignore ignoreSet) []string {
	var problems []string
	emitted := map[string]bool{}
	for _, a := range high.Artifacts {
		emitted[a.Path] = true
	}
	for _, a := range low.Artifacts {
		if !sdkArtifact(a) && !emitted[a.Path] {
			problems = append(problems, fmt.Sprintf("%s: emitted at %s but missing at %s", a.Path, lower, higher))
		}
	}
	lowData, highData := artifactsByPath(low.Artifacts), artifactsByPath(high.Artifacts)
	paths := make([]string, 0, len(lowData))
	for path := range lowData {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	gaps := gapsOf(high.Result)
	for _, path := range paths {
		h, ok := highData[path]
		if !ok {
			continue
		}
		leaves, err := flatten(lowData[path].Data)
		if err != nil {
			continue
		}
		doc, err := outputcheck.Decode(h.Data)
		if err != nil {
			continue
		}
		pointers := make([]string, 0, len(leaves))
		for p := range leaves {
			pointers = append(pointers, p)
		}
		sort.Strings(pointers)
		for _, p := range pointers {
			if ignore.has(path, p) || covered(gaps, path, p) {
				continue
			}
			if _, ok := outputcheck.Resolve(doc, p); !ok {
				problems = append(problems, fmt.Sprintf("%s %s: present at %s but missing at %s", path, pointerLabel(p), lower, higher))
			}
		}
	}
	return problems
}
