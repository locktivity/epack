package collectortest

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/locktivity/epack/componentsdk"
	"github.com/locktivity/epack/internal/outputcheck"
)

// The methods check requires one plain sentence on how the collector
// measures each number and true-or-false value that a profile can test. The
// sentence is the value's x-epack-method in the collector's own schema, or
// for a normalized artifact, its entry in CollectorSpec.Methods.
// Profiles test every such value in a normalized artifact. They also test a
// detailed artifact's values that a trust run writes, since most collectors
// have no normalized artifact yet. A normalized value that Recorder.Mirror
// records as a copy uses the method of the value it copies, found in the
// schema of the artifact it copies from, so a collector that fills its
// normalized artifact from its detailed one writes each method once. That
// holds when the detailed artifact is marked for a higher level than the run
// and so is not written.

// maxMethodFields is the most fields one artifact's report names.
const maxMethodFields = 5

func (k *kit) checkMethods() {
	res := k.baseline
	byPath := artifactsByPath(res.Artifacts)
	copied := map[string]componentsdk.Location{}
	for _, mirror := range res.Mirrors {
		if to, ok := locate(mirror.To, res.Artifacts); ok {
			copied[to+mirror.To.Pointer] = mirror.From
		}
	}
	sourceMethod := func(from componentsdk.Location) string {
		path, _ := locate(from, res.Artifacts)
		schemaID := from.Schema
		if a, ok := byPath[path]; ok {
			schemaID = a.Schema
		}
		sch := k.levelSchema(path, schemaID)
		if sch == nil {
			return ""
		}
		return outputcheck.MethodAt(sch, from.Pointer)
	}
	for _, path := range sortedKeys(byPath) {
		a := byPath[path]
		sch := k.levelSchema(a.Path, a.Schema)
		doc, err := outputcheck.Decode(a.Data)
		if sch == nil || err != nil {
			continue
		}
		normalized := componentsdk.NormalizedSchemaJSON(a.Schema) != nil
		var aboveTrust []string
		if !normalized {
			if outputcheck.WholeAbove(sch, string(componentsdk.LevelTrust)) {
				continue
			}
			for _, f := range outputcheck.AboveLevel(sch, a.Path, doc, string(componentsdk.LevelTrust)) {
				aboveTrust = append(aboveTrust, f.Pointer)
			}
		}
		missing := map[string]bool{}
		for _, v := range outputcheck.MeasuredValues(sch, doc) {
			if v.Method != "" || within(aboveTrust, v.Pointer) {
				continue
			}
			if from, ok := copied[path+v.Pointer]; ok && sourceMethod(from) != "" {
				continue
			}
			missing[anyIndex(v.Pointer)] = true
		}
		if len(missing) == 0 {
			continue
		}
		fields := sortedKeys(missing)
		shown := fields[:min(len(fields), maxMethodFields)]
		more := ""
		if len(fields) > len(shown) {
			more = fmt.Sprintf(", and %d more", len(fields)-len(shown))
		}
		if normalized {
			k.violate("methods", path, "%s has no x-epack-method for %s%s. Add one plain sentence on how the collector measures "+
				"each value to CollectorSpec.Methods under %s, or record the detailed value it copies with Recorder.Mirror",
				path, strings.Join(shown, ", "), more, a.Schema)
			continue
		}
		k.violate("methods", path, "%s has no x-epack-method for %s%s, which a trust run writes and a profile can test. Add one "+
			"plain sentence on how the collector measures each value to the collector's schema, or mark the field, or the whole "+
			"artifact when a normalized artifact carries what profiles read, for the audit level with x-epack-level",
			path, strings.Join(shown, ", "), more)
	}
}

// within reports whether pointer is one of pointers or inside one.
func within(pointers []string, pointer string) bool {
	for _, p := range pointers {
		if p == "" || pointer == p || strings.HasPrefix(pointer, p+"/") {
			return true
		}
	}
	return false
}

// anyIndex replaces each array index in a JSON pointer with *, so the fields
// of every row read as one.
func anyIndex(pointer string) string {
	tokens := strings.Split(pointer, "/")
	for i, t := range tokens {
		if _, err := strconv.Atoi(t); err == nil {
			tokens[i] = "*"
		}
	}
	return strings.Join(tokens, "/")
}
