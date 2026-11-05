package componentsdk

import (
	"encoding/json"
	"strings"

	"github.com/locktivity/epack/internal/tracemap"
)

// ArtifactPath returns the path a collector named collector gives its
// artifact with schema ID schemaID: artifacts/<collector>.<kind>.json, such
// as artifacts/okta.idp-posture.json, or artifacts/okta.details.json for the
// detailed file, which has no schema ID. A run configured under another name
// writes the artifact under that name instead, as RunPath says.
func ArtifactPath(collector, schemaID string) string {
	return "artifacts/" + collector + "." + KindOf(schemaID) + ".json"
}

// RunPath returns the path at which a run of the collector named collector,
// configured as name, writes the artifact the collector names path. A path
// that starts with artifacts/<collector>. or artifacts/<collector>/ starts
// with artifacts/<name>. or artifacts/<name>/ instead, so two runs of one
// collector in a pack write different files. Other paths are kept.
//
// The SDK moves every path in the run's output. A collector that writes an
// artifact's path into another artifact's data, such as an index that points
// at files, moves it with RunPath(spec name, ctx.Name(), path).
func RunPath(collector, name, path string) string {
	if collector == "" || name == "" || collector == name {
		return path
	}
	for _, sep := range []string{".", "/"} {
		if rest, ok := strings.CutPrefix(path, "artifacts/"+collector+sep); ok {
			return "artifacts/" + name + sep + rest
		}
	}
	return path
}

// path is RunPath for the run.
func (r *run) path(p string) string {
	return RunPath(r.collector, r.name, p)
}

// located returns a copy of artifacts with each path as the run writes it.
func (r *run) located(artifacts []CollectedArtifact) []CollectedArtifact {
	out := make([]CollectedArtifact, len(artifacts))
	for i, a := range artifacts {
		a.Path = r.path(a.Path)
		out[i] = a
	}
	return out
}

// runSchemas returns schemas with each key that is an artifact path renamed
// as the run writes the path. A schema ID is kept.
func runSchemas(schemas map[string][]byte, rename func(string) string) map[string][]byte {
	out := make(map[string][]byte, len(schemas))
	for key, raw := range schemas {
		out[rename(key)] = raw
	}
	return out
}

// runTraceMap returns the trace map with each artifact path, and each path a
// copied field names, renamed as the run writes the path. A map that does
// not decode is returned as it is.
func runTraceMap(raw []byte, rename func(string) string) []byte {
	var m tracemap.Map
	if err := json.Unmarshal(raw, &m); err != nil || m.Artifacts == nil {
		return raw
	}
	changed := false
	artifacts := make(map[string]map[string]*tracemap.Field, len(m.Artifacts))
	for path, fields := range m.Artifacts {
		renamed := rename(path)
		changed = changed || renamed != path
		for _, f := range fields {
			for i, c := range f.Copies {
				if p := rename(c.Path); p != c.Path {
					f.Copies[i].Path, changed = p, true
				}
			}
		}
		artifacts[renamed] = fields
	}
	if !changed {
		return raw
	}
	m.Artifacts = artifacts
	out, err := tracemap.Encode(&m)
	if err != nil {
		return raw
	}
	return out
}
