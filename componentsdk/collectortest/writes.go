package collectortest

import (
	"slices"

	"github.com/locktivity/epack/componentsdk"
)

// The writes check requires CollectorSpec.Writes to list every schema ID a
// run writes. --capabilities and the build file publish the list, so a
// reader can learn what a release writes without running it, and a schema
// ID missing from it would go unannounced.

func (k *kit) checkWrites(label string, res componentsdk.InProcessResult) {
	declared := k.suite.Spec.Writes
	for _, a := range res.Artifacts {
		if a.Schema == "" || sdkArtifact(a) || slices.Contains(declared, a.Schema) {
			continue
		}
		k.violate("writes", label, "%s has schema %s, which CollectorSpec.Writes does not list. List every schema ID the collector "+
			"writes, so --capabilities and the build file announce each kind of evidence and its version", a.Path, a.Schema)
	}
}
