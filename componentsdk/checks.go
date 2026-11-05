package componentsdk

import (
	"embed"
	"fmt"
	"io"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/locktivity/epack/internal/outputcheck"
)

// Output check names, as CheckFinding.Check carries them.
const (
	// CheckSchema reports a value that does not match the artifact's schema.
	CheckSchema = outputcheck.CheckSchema
	// CheckSchemaUnusable reports a schema in CollectorSpec.Schemas that does
	// not compile, so the artifacts it covers went unchecked.
	CheckSchemaUnusable = outputcheck.CheckSchemaUnusable
	// CheckPopulation reports a value whose x-epack-denominator is 0 or was
	// not read. It also reports a value whose x-epack-present is false or was
	// not read.
	CheckPopulation = outputcheck.CheckPopulation
	// CheckNulls reports a null number or boolean that no gap, x-epack-null
	// note, or population annotation accounts for. A population annotation
	// accounts for a null when the denominator is 0 or unread, or when
	// x-epack-present is false or unread.
	CheckNulls = outputcheck.CheckNulls
	// CheckRollups reports an x-epack-rollup its rows do not give.
	CheckRollups = outputcheck.CheckRollups
	// CheckRatios reports a percentage or boolean that does not follow from
	// its x-epack-numerator and x-epack-denominator, rounded as its
	// x-epack-rounding says.
	CheckRatios = outputcheck.CheckRatios
	// CheckGuidance reports a gap or run warning that has more than one of
	// Fix, NoAction, and Decide. It also reports a Decide with fewer than two
	// options. The SDK keeps the first advice given.
	CheckGuidance = "guidance"
	// CheckLevels reports a value the collector wrote that its schema places
	// above the run's level with x-epack-level. The SDK leaves the value out.
	CheckLevels = outputcheck.CheckLevels
)

// CheckFinding is one problem the output checks found when the collector
// emitted. Findings never fail a run or change its outcome.
type CheckFinding struct {
	Check string `json:"check"`
	// Path is the artifact's path in the pack. A schema_unusable finding has
	// none; its message names the schema.
	Path    string `json:"path,omitempty"`
	Pointer string `json:"pointer"`
	Message string `json:"message"`
}

const (
	maxCheckFindings = 100
	maxCheckMessage  = 300
)

//go:embed schema/normalized/*.json
var normalizedFS embed.FS

var normalizedFiles = map[string]string{
	"evidencepack/idp-posture@v1":      "schema/normalized/idp-posture.v1.json",
	"evidencepack/cloud-posture@v1":    "schema/normalized/cloud-posture.v1.json",
	"evidencepack/vcs-posture@v1":      "schema/normalized/vcs-posture.v1.json",
	"evidencepack/email-dns@v1":        "schema/normalized/email-dns.v1.json",
	"evidencepack/tls@v1":              "schema/normalized/tls.v1.json",
	"evidencepack/endpoint-posture@v1": "schema/normalized/endpoint-posture.v1.json",
	"evidencepack/access-posture@v1":   "schema/normalized/access-posture.v1.json",
	"evidencepack/vuln-scanning@v1":    "schema/normalized/vuln-scanning.v1.json",
}

// NormalizedSchemaJSON returns the SDK's JSON Schema for a normalized artifact
// type, such as "evidencepack/idp-posture@v1", or nil for a type it has none
// for. These schemas require only the fields that say what was collected and
// allow null on every metric, so a collector can leave out what it could not
// read. Emit checks artifacts of these types against them, with the
// collector's CollectorSpec.Methods added, unless CollectorSpec.Schemas has
// a schema for the type or the path.
func NormalizedSchemaJSON(schemaID string) []byte {
	file, ok := normalizedFiles[schemaID]
	if !ok {
		return nil
	}
	raw, err := normalizedFS.ReadFile(file)
	if err != nil {
		return nil
	}
	return raw
}

// NormalizedSchemaWithMethods returns the SDK's schema for a normalized type
// with methods written as each field's x-epack-method, keyed by JSON pointer
// with * for any array index. It also returns a problem for each pointer it
// could not place, which it skips. It returns nil for a type the SDK has no
// schema for.
func NormalizedSchemaWithMethods(schemaID string, methods map[string]string) ([]byte, []string) {
	raw := NormalizedSchemaJSON(schemaID)
	if raw == nil {
		return nil, nil
	}
	if len(methods) == 0 {
		return raw, nil
	}
	out, problems, err := outputcheck.AddMethods(raw, methods)
	if err != nil {
		return raw, []string{err.Error()}
	}
	return out, problems
}

// ArtifactSchemas returns the schemas Emit checks the collector's artifacts
// against and the build file carries. They are Schemas, and for each type in
// Methods that Schemas has no schema for, the SDK's schema for the type with
// those methods added.
func (spec CollectorSpec) ArtifactSchemas() map[string][]byte {
	out := make(map[string][]byte, len(spec.Schemas)+len(spec.Methods))
	for key, raw := range spec.Schemas {
		out[key] = raw
	}
	for _, schemaID := range sortedKeys(spec.Methods) {
		if _, ok := out[schemaID]; ok {
			continue
		}
		if raw, _ := NormalizedSchemaWithMethods(schemaID, spec.Methods[schemaID]); raw != nil {
			out[schemaID] = raw
		}
	}
	return out
}

// artifactSchema is one schema Emit checks artifacts against.
type artifactSchema struct {
	schema *outputcheck.Schema
	err    error
}

// compileSchemas compiles the spec's schemas when a run starts. A schema that
// does not compile gets one warning on stderr and a schema_unusable finding,
// and never fails the run.
func compileSchemas(schemas map[string][]byte, stderr io.Writer) map[string]*artifactSchema {
	out := make(map[string]*artifactSchema, len(schemas))
	for _, key := range sortedKeys(schemas) {
		s, err := outputcheck.Compile(schemas[key])
		out[key] = &artifactSchema{schema: s, err: err}
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "warning: %s\n", unusableMessage(key, err))
		}
	}
	return out
}

func unusableMessage(key string, err error) string {
	return fmt.Sprintf("the schema for %s in CollectorSpec.Schemas does not compile, so the artifacts it covers are not checked: %s",
		key, strings.Join(strings.Fields(err.Error()), " "))
}

// schemaFor picks an artifact's schema: CollectorSpec.Schemas by path, then by
// schema ID, then the SDK's normalized schema for the ID.
func schemaFor(spec map[string]*artifactSchema, path, schemaID string) *outputcheck.Schema {
	if s, ok := spec[path]; ok {
		return s.schema
	}
	if schemaID == "" {
		return nil
	}
	if s, ok := spec[schemaID]; ok {
		return s.schema
	}
	raw := NormalizedSchemaJSON(schemaID)
	if raw == nil {
		return nil
	}
	s, err := outputcheck.Compile(raw)
	if err != nil {
		return nil
	}
	return s
}

// outputChecks runs the schema, population, nulls, rollups, and ratios checks
// on each data artifact that has a schema, as emitted at level. It keeps the
// first maxCheckFindings findings and counts the rest. Messages are redacted
// like gap details.
func outputChecks(set *emittedSet, spec map[string]*artifactSchema, gaps []Gap, secrets []string, level Level) ([]CheckFinding, int) {
	var found []outputcheck.Finding
	for _, key := range sortedKeys(spec) {
		if err := spec[key].err; err != nil {
			found = append(found, outputcheck.Finding{Check: CheckSchemaUnusable, Message: unusableMessage(key, err)})
		}
	}
	located := make([]outputcheck.Gap, len(gaps))
	for i, g := range gaps {
		located[i] = outputcheck.Gap{Path: g.Path, Pointer: g.Pointer}
	}
	for _, e := range set.list {
		if e.art.File != "" {
			continue
		}
		s := schemaFor(spec, e.path, e.art.Schema)
		if s == nil {
			continue
		}
		doc, err := set.doc(e)
		if err != nil {
			continue
		}
		found = append(found, outputcheck.Validate(s, e.path, doc)...)
		found = append(found, outputcheck.Check(s, e.path, doc, located, string(level))...)
	}
	dropped := 0
	if len(found) > maxCheckFindings {
		dropped = len(found) - maxCheckFindings
		found = found[:maxCheckFindings]
	}
	var out []CheckFinding
	for _, f := range found {
		message := redactDetail(f.Message, secrets)
		if len(message) > maxCheckMessage {
			cut := maxCheckMessage
			for cut > 0 && !utf8.RuneStart(message[cut]) {
				cut--
			}
			message = message[:cut] + "..."
		}
		out = append(out, CheckFinding{Check: f.Check, Path: f.Path, Pointer: f.Pointer, Message: message})
	}
	return out, dropped
}

func sortedKeys[K ~string, V any](m map[K]V) []K {
	keys := make([]K, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}
