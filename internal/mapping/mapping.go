// Package mapping loads, checks, and emits control mapping documents
// (evidencepack/control-mapping@v1). A mapping records the publisher's
// assertions that specific evidence in a pack supports specific profile
// requirements. Mappings never affect verification or validation outcomes;
// every problem this package reports is a warning, not a failure.
package mapping

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/locktivity/epack/internal/limits"
	"github.com/locktivity/epack/internal/safefile"
	"github.com/locktivity/epack/internal/safeyaml"
)

// Schema is the artifact schema identifier for control mapping documents.
const Schema = "evidencepack/control-mapping@v1"

// SchemaVersion is the document schema version this package understands.
const SchemaVersion = "1.0.0"

// Document is a control mapping document.
type Document struct {
	SchemaVersion string  `yaml:"schema_version" json:"schema_version"`
	CapturedAt    string  `yaml:"captured_at" json:"captured_at"`
	Profile       Profile `yaml:"profile" json:"profile"`
	Mappings      []Entry `yaml:"mappings" json:"mappings"`
}

// Profile pins the profile a mapping asserts against.
type Profile struct {
	ID     string `yaml:"id" json:"id"`
	Digest string `yaml:"digest,omitempty" json:"digest,omitempty"`
}

// Entry links one piece of evidence to one profile requirement.
type Entry struct {
	Requirement string   `yaml:"requirement,omitempty" json:"requirement,omitempty"`
	Control     string   `yaml:"control,omitempty" json:"control,omitempty"`
	Type        string   `yaml:"type,omitempty" json:"type,omitempty"`
	Evidence    Evidence `yaml:"evidence" json:"evidence"`
	Label       string   `yaml:"label,omitempty" json:"label,omitempty"`
	Note        string   `yaml:"note,omitempty" json:"note,omitempty"`
	MappedAt    string   `yaml:"mapped_at,omitempty" json:"mapped_at,omitempty"`
	MappedBy    string   `yaml:"mapped_by,omitempty" json:"mapped_by,omitempty"`
}

// Evidence references the cited evidence: exactly one of Artifact or
// DocumentID, with optional anchors.
type Evidence struct {
	Artifact   string `yaml:"artifact,omitempty" json:"artifact,omitempty"`
	Pointer    string `yaml:"pointer,omitempty" json:"pointer,omitempty"`
	DocumentID string `yaml:"document_id,omitempty" json:"document_id,omitempty"`
	Quote      *Quote `yaml:"quote,omitempty" json:"quote,omitempty"`
	Table      *Table `yaml:"table,omitempty" json:"table,omitempty"`
}

// Quote anchors a citation to a passage in a document's extracted text.
type Quote struct {
	Exact  string `yaml:"exact" json:"exact"`
	Prefix string `yaml:"prefix,omitempty" json:"prefix,omitempty"`
	Suffix string `yaml:"suffix,omitempty" json:"suffix,omitempty"`
}

// Table anchors a citation to a row in a document's tabular extraction.
type Table struct {
	Sheet   string         `yaml:"sheet,omitempty" json:"sheet,omitempty"`
	Where   map[string]any `yaml:"where" json:"where"`
	Columns []string       `yaml:"columns,omitempty" json:"columns,omitempty"`
	Range   string         `yaml:"range,omitempty" json:"range,omitempty"`
}

// Load reads a mapping file with the same path hardening the sync layer
// applies to profile files: containment within workDir, symlink rejection,
// and bounded reads.
func Load(workDir, key, filePath string) (*Document, []byte, error) {
	validatedPath, err := resolvePath(workDir, key, filePath)
	if err != nil {
		return nil, nil, fmt.Errorf("mapping %s: %w", key, err)
	}
	data, err := safefile.ReadFile(validatedPath, limits.ProfileFile)
	if err != nil {
		return nil, nil, fmt.Errorf("reading mapping %s: %w", key, err)
	}
	doc, err := Parse(data)
	if err != nil {
		return nil, nil, fmt.Errorf("mapping %s: %w", key, err)
	}
	return doc, data, nil
}

func resolvePath(workDir, key, filePath string) (string, error) {
	if !filepath.IsAbs(filePath) {
		return safefile.ValidateRegularFile(workDir, key)
	}
	return safefile.ValidateAbsoluteFile(workDir, filePath)
}

// Parse parses a mapping document from YAML or JSON bytes.
// JSON is a subset of YAML, so one parser covers both.
func Parse(data []byte) (*Document, error) {
	var doc Document
	if err := safeyaml.Unmarshal(data, limits.ProfileFile, &doc); err != nil {
		return nil, fmt.Errorf("parsing mapping document: %w", err)
	}
	return &doc, nil
}

// Check returns warnings for a parsed mapping document. Warnings never fail
// a build; malformed entries are reported and carried as-is.
func (d *Document) Check() []string {
	var warnings []string

	if d.SchemaVersion != SchemaVersion {
		warnings = append(warnings, fmt.Sprintf("schema_version %q is not %q", d.SchemaVersion, SchemaVersion))
	}
	if d.Profile.ID == "" {
		warnings = append(warnings, "profile.id is empty")
	}

	for i, entry := range d.Mappings {
		warnings = append(warnings, entry.check(i)...)
	}
	return warnings
}

func (e Entry) check(index int) []string {
	var warnings []string

	joins := 0
	for _, v := range []string{e.Requirement, e.Control, e.Type} {
		if v != "" {
			joins++
		}
	}
	if joins != 1 {
		warnings = append(warnings, fmt.Sprintf("mappings[%d]: exactly one of requirement, control, or type must be set", index))
	}

	targets := 0
	for _, v := range []string{e.Evidence.Artifact, e.Evidence.DocumentID} {
		if v != "" {
			targets++
		}
	}
	if targets != 1 {
		warnings = append(warnings, fmt.Sprintf("mappings[%d]: evidence must set exactly one of artifact or document_id", index))
	}

	if e.Evidence.Pointer != "" && e.Evidence.Artifact == "" {
		warnings = append(warnings, fmt.Sprintf("mappings[%d]: pointer requires an artifact reference", index))
	}
	if (e.Evidence.Quote != nil || e.Evidence.Table != nil) && e.Evidence.DocumentID == "" {
		warnings = append(warnings, fmt.Sprintf("mappings[%d]: quote and table anchors require a document_id reference", index))
	}
	if e.Evidence.Quote != nil && e.Evidence.Table != nil {
		warnings = append(warnings, fmt.Sprintf("mappings[%d]: quote and table anchors are mutually exclusive", index))
	}
	if e.Evidence.Quote != nil && e.Evidence.Quote.Exact == "" {
		warnings = append(warnings, fmt.Sprintf("mappings[%d]: quote.exact is empty", index))
	}
	return warnings
}

// CheckArtifactRefs returns warnings for entries whose artifact reference is
// not among packPaths. Document references are not checked here: resolving a
// document_id requires reading the pack's document index, which is validator
// territory.
func (d *Document) CheckArtifactRefs(packPaths map[string]bool) []string {
	var warnings []string
	for i, entry := range d.Mappings {
		if entry.Evidence.Artifact == "" {
			continue
		}
		if !packPaths[entry.Evidence.Artifact] {
			warnings = append(warnings, fmt.Sprintf("mappings[%d]: cites artifact %q, which this pack does not carry", i, entry.Evidence.Artifact))
		}
	}
	return warnings
}

// CheckProfileDigest warns when the document pins a profile digest that
// matches none of the locked profile digests.
func (d *Document) CheckProfileDigest(lockedDigests []string) []string {
	if d.Profile.Digest == "" {
		return nil
	}
	for _, digest := range lockedDigests {
		if digest == d.Profile.Digest {
			return nil
		}
	}
	return []string{fmt.Sprintf("profile.digest %s matches no locked profile; the mapping may be stale", d.Profile.Digest)}
}

// EmitJSON returns the document as JSON bytes for sealing into a pack.
// JSON input is embedded verbatim so publisher-authored fields this package
// does not model survive. YAML input is converted through a generic tree;
// encoding/json sorts map keys, so the output is deterministic.
func EmitJSON(source []byte) ([]byte, error) {
	trimmed := bytes.TrimLeft(source, " \t\r\n")
	if len(trimmed) > 0 && trimmed[0] == '{' {
		var checkTarget any
		if err := json.Unmarshal(source, &checkTarget); err != nil {
			return nil, fmt.Errorf("mapping document is not valid JSON: %w", err)
		}
		return source, nil
	}

	var tree any
	if err := safeyaml.Unmarshal(source, limits.ProfileFile, &tree); err != nil {
		return nil, fmt.Errorf("parsing mapping document: %w", err)
	}
	out, err := json.MarshalIndent(normalizeTree(tree), "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encoding mapping document: %w", err)
	}
	return append(out, '\n'), nil
}

// normalizeTree converts YAML map keys to strings so the tree is JSON-encodable.
func normalizeTree(node any) any {
	switch v := node.(type) {
	case map[string]any:
		out := make(map[string]any, len(v))
		for key, value := range v {
			out[key] = normalizeTree(value)
		}
		return out
	case map[any]any:
		out := make(map[string]any, len(v))
		for key, value := range v {
			out[fmt.Sprint(key)] = normalizeTree(value)
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, value := range v {
			out[i] = normalizeTree(value)
		}
		return out
	default:
		return v
	}
}

// ArtifactPath derives the in-pack path for a mapping file from its config key.
// The basename keeps its identity; the extension becomes .json because the
// emitted form is always JSON.
func ArtifactPath(key string) string {
	base := filepath.Base(key)
	if ext := filepath.Ext(base); ext != "" {
		base = strings.TrimSuffix(base, ext)
	}
	return "artifacts/" + base + ".json"
}
