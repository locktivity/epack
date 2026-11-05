package collectortest

import (
	"strings"

	"github.com/locktivity/epack/componentsdk"
)

// The normalized check holds a collector to the SDK's normalized schemas. A
// collector gives the x-epack-method sentences for a normalized artifact in
// CollectorSpec.Methods, and the SDK adds them to its own schema. A copy of
// a normalized schema in CollectorSpec.Schemas would replace the SDK's and
// fall behind it, so the check reports one, by schema ID or by the path of
// an artifact of that type. It also reports a Methods entry for a type the
// SDK has no schema for, and one it could not place on a field.

func (k *kit) checkNormalized() {
	byPath := artifactsByPath(k.baseline.Artifacts)
	for _, key := range sortedKeys(k.suite.Spec.Schemas) {
		schemaID := key
		if a, ok := byPath[k.runPath(key)]; ok {
			schemaID = a.Schema
		}
		if componentsdk.NormalizedSchemaJSON(schemaID) == nil {
			continue
		}
		subject := "its own copy of the SDK's " + schemaID + " schema"
		if key != schemaID {
			subject = "its own schema for " + key + ", an " + schemaID + " artifact"
		}
		k.violate("normalized", key, "CollectorSpec.Schemas holds %s. A copy replaces the SDK's schema and falls behind it. "+
			"Give the collector's x-epack-method sentences in CollectorSpec.Methods instead", subject)
	}
	for _, schemaID := range sortedKeys(k.suite.Spec.Methods) {
		raw, problems := componentsdk.NormalizedSchemaWithMethods(schemaID, k.suite.Spec.Methods[schemaID])
		if raw == nil {
			k.violate("normalized", schemaID, "CollectorSpec.Methods names %s, which is not one of the SDK's normalized types", schemaID)
			continue
		}
		if len(problems) > 0 {
			k.violate("normalized", schemaID, "CollectorSpec.Methods for %s: %s", schemaID, strings.Join(problems, "; "))
		}
	}
}
