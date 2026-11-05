package collectortest

import "github.com/locktivity/epack/componentsdk"

// The paths check holds each data artifact the clean scenario writes to the
// path componentsdk.ArtifactPath gives it: artifacts/<collector>.<kind>.json,
// with the kind from its schema ID, or details for the one with no schema
// ID. A reader can then find any collector's artifacts by kind, and two
// collectors in one pack, or two runs of one under other configured names,
// never write the same path. The check leaves file artifacts alone.

func (k *kit) checkPaths() {
	for _, a := range k.baseline.Artifacts {
		if sdkArtifact(a) || a.File != "" {
			continue
		}
		want := k.runPath(componentsdk.ArtifactPath(k.suite.Spec.Name, a.Schema))
		if a.Path == want {
			continue
		}
		kind := componentsdk.KindOf(a.Schema)
		k.violate("paths", a.Path, "%s is a %s artifact, which belongs at %s. Name it with componentsdk.ArtifactPath(%q, %q)",
			a.Path, kind, want, k.suite.Spec.Name, a.Schema)
	}
}
