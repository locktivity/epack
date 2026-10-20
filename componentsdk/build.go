package componentsdk

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
)

// BuildSchema is the schema of the build file the SDK adds to every
// collector's output at Emit.
const BuildSchema = "evidencepack/collector-build@v1"

// CollectorBuild is the build file: the collector's build, the schemas it
// checks its artifacts against, and its trace map. It describes the build
// rather than the run, so every run of one build writes the same bytes at
// every level, and a reader can store it once per build.
type CollectorBuild struct {
	// Collector names the build, by the name its spec declares.
	Collector ResultCollector `json:"collector"`
	// Schemas holds CollectorSpec.Schemas, keyed as it keys them, by
	// artifact path or schema ID. An artifact of a normalized type with no
	// schema here was checked against the SDK's own, which
	// NormalizedSchemaJSON returns.
	Schemas map[string]json.RawMessage `json:"schemas"`
	// TraceMap is CollectorSpec.TraceMap. It is absent for a collector
	// without one.
	TraceMap json.RawMessage `json:"trace_map,omitempty"`
}

func buildPath(name string) string {
	return "artifacts/" + name + ".collector-build.json"
}

// newBuild makes the build file from the spec. A schema that is not JSON,
// which also fails to compile, is left out, and so is a trace map that is
// not a JSON object, with a warning on stderr.
func newBuild(spec CollectorSpec, stderr io.Writer) CollectorBuild {
	b := CollectorBuild{
		Collector: ResultCollector{Name: spec.Name, Version: spec.Version, Commit: spec.Commit},
		Schemas:   make(map[string]json.RawMessage, len(spec.Schemas)),
	}
	for key, raw := range spec.Schemas {
		if raw = bytes.TrimSpace(raw); json.Valid(raw) {
			b.Schemas[key] = raw
		}
	}
	if len(spec.TraceMap) > 0 {
		if raw := bytes.TrimSpace(spec.TraceMap); json.Valid(raw) && raw[0] == '{' {
			b.TraceMap = raw
		} else {
			_, _ = fmt.Fprintln(stderr, "warning: CollectorSpec.TraceMap is not a JSON object, so the build file leaves it out")
		}
	}
	return b
}

//go:embed schema/collector-build.v1.json
var buildSchemaJSON []byte

// BuildSchemaJSON returns the JSON Schema of the build file, which holds the
// trace map's schema under $defs.
func BuildSchemaJSON() []byte {
	return append([]byte(nil), buildSchemaJSON...)
}
