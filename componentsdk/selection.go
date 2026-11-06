package componentsdk

import (
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"sync"

	"github.com/locktivity/epack/internal/componenttypes"
	"github.com/locktivity/epack/internal/jsonpointer"
	"github.com/locktivity/epack/internal/outputcheck"
)

// The collect config key lists the kinds of evidence a run collects, so a
// pack's epack.yaml says what each collector contributes. A kind is the name
// in a schema ID such as evidencepack/vuln-scanning@v1. A collector's own
// detailed file has no schema ID and is the kind details, for every
// collector. The key applies at every level, and the level still decides
// what a kind holds. With no key, a run collects every kind its level
// allows.
const collectKey = componenttypes.CollectKey

// CollectOf returns the kinds a config's collect key lists. set is false when
// the key is absent. err is set when the key holds anything but a list of
// non-empty strings.
func CollectOf(config map[string]any) (kinds []string, set bool, err error) {
	return componenttypes.CollectOf(config)
}

// DetailsKind is the kind of a collector's own detailed file, the one
// artifact with no schema ID. The collect config key lists it as details.
const DetailsKind = componenttypes.DetailsKind

// KindOf returns the kind of an artifact with schema ID schemaID: the name
// in the schema ID, or details for an artifact with no schema ID.
func KindOf(schemaID string) string {
	return componenttypes.KindOf(schemaID)
}

// kindName matches a kind as collect lists it: a schema ID's kind, or
// details.
var kindName = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*$`)

// checkCollect reports a collect key that is not a list of kinds. It does
// not check that the collector writes each kind, since some, such as a
// documents collector, learn their kinds only as they run. The result
// artifact lists a kind the run never wrote as unmatched instead.
func (c *collectorContext) checkCollect() error {
	kinds, _, err := CollectOf(c.config)
	if err != nil {
		return NewConfigError("%v", err)
	}
	for _, kind := range kinds {
		if !kindName.MatchString(kind) {
			return NewConfigError("collect lists %q, which is not a kind of evidence such as cloud-posture", kind)
		}
	}
	return nil
}

// Selected reports whether the run collects the artifact that at names by
// its Schema or Path. Its Pointer is ignored. It is false when the
// artifact's schema sets x-epack-level on the whole artifact above the run's
// level, and when the collect config key leaves its kind out. In that second
// case the run records the kind as not shared, with a not_shared gap. Check
// Selected before the calls that feed only that artifact. Emit leaves out an
// artifact that Selected rules out even when the collector passes it. When
// that artifact is normalized, Emit removes each value Recorder.Mirror copied
// from it and each Recorder.Moved placed beside it, whether or not the
// collector passes it.
func Selected(ctx CollectorContext, at Location) bool {
	r := runOf(ctx)
	at.Path = r.path(at.Path)
	switch r.verdict(at.Path, at.Schema, LevelOf(ctx.Config()), collectListOf(ctx.Config())) {
	case notListed:
		r.leaveOut(at.Schema, at.Path)
		return false
	case aboveLevel:
		return false
	}
	return true
}

// verdict is what a run does with an artifact.
type verdict int

const (
	// write is an artifact the run writes.
	write verdict = iota
	// aboveLevel is an artifact whose schema sets x-epack-level above the
	// run's level on the whole artifact. The run leaves it out with no gap,
	// as it does a field marked for a higher level.
	aboveLevel
	// notListed is an artifact whose kind the collect config key leaves
	// out. The run leaves it out with a not_shared gap.
	notListed
)

// verdict decides what the run does with the artifact with schema ID
// schemaID at path, and notes its kind as one the run met.
func (r *run) verdict(path, schemaID string, level Level, list collectList) verdict {
	r.collect.saw(KindOf(schemaID))
	switch {
	case wholeAbove(r.schemas, path, schemaID, level):
		return aboveLevel
	case !r.collects(list, schemaID):
		return notListed
	}
	return write
}

// leaveOut records that the collect config key left out the artifact with
// schema ID schemaID at path: its kind, and a not_shared gap on it.
func (r *run) leaveOut(schemaID, path string) {
	r.collect.leaveOut(KindOf(schemaID), Location{Schema: schemaID, Path: path})
	r.records.leaveOut(schemaID, path)
}

// collectList is what the collect config key lists. all is true when the
// key is absent, and the run collects every kind its level allows. It is
// also true for a key that is not a list of kinds, which the config check
// rejects before the handler runs.
type collectList struct {
	all   bool
	kinds []string
}

func collectListOf(config map[string]any) collectList {
	kinds, set, err := CollectOf(config)
	return collectList{all: !set || err != nil, kinds: kinds}
}

// collects reports whether list names the kind of an artifact with schema
// ID schemaID.
func (r *run) collects(list collectList, schemaID string) bool {
	return list.all || slices.Contains(list.kinds, KindOf(schemaID))
}

// collectState is what the collect config key did in a run: the kinds it
// listed, the kinds the run wrote or asked about, and the kinds it left out.
// unshared holds the normalized artifacts it left out.
type collectState struct {
	mu       sync.Mutex
	listed   []string
	set      bool
	seen     []string
	leftOut  []string
	unshared []Location
}

// list notes the kinds the key listed, which the run's result reports.
func (s *collectState) list(kinds []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.listed, s.set = kinds, true
}

// saw notes a kind the run wrote or asked about, so the result can list
// the kinds the key names that the run never met.
func (s *collectState) saw(kind string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !slices.Contains(s.seen, kind) {
		s.seen = append(s.seen, kind)
	}
}

// leaveOut notes a kind the key left out, and the artifact at when it is
// normalized.
func (s *collectState) leaveOut(kind string, at Location) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !slices.Contains(s.leftOut, kind) {
		s.leftOut = append(s.leftOut, kind)
	}
	if NormalizedSchemaJSON(at.Schema) != nil && !slices.Contains(s.unshared, at) {
		s.unshared = append(s.unshared, at)
	}
}

// unsharedArtifacts returns the normalized artifacts the key left out, those
// Selected ruled out included.
func (s *collectState) unsharedArtifacts() []Location {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.unshared)
}

// leftAnyOut reports whether the key left out any kind.
func (s *collectState) leftAnyOut() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.leftOut) > 0
}

// result is the collect record for the run's result, or nil when the key
// listed nothing. Unmatched holds the kinds listed that the run never wrote
// or asked about. The collector, configured under name, may list its own
// file by its published name, collector.
func (s *collectState) result(name, collector string) *ResultCollect {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.set {
		return nil
	}
	out := &ResultCollect{Listed: s.listed, LeftOut: append([]string(nil), s.leftOut...)}
	for _, kind := range s.listed {
		own := kind == collector && slices.Contains(s.seen, name)
		if !own && !slices.Contains(s.seen, kind) {
			out.Unmatched = append(out.Unmatched, kind)
		}
	}
	return out
}

// wholeAbove reports whether an artifact's schema sets x-epack-level on the
// whole artifact above level.
func wholeAbove(schemas map[string]*artifactSchema, path, schemaID string, level Level) bool {
	s := schemaFor(schemas, path, schemaID)
	if s == nil {
		return false
	}
	return outputcheck.WholeAbove(s, string(level))
}

// names reports whether at names the artifact with path and schemaID: by
// path when at has one, and otherwise by schema.
func (at Location) names(path, schemaID string) bool {
	if at.Path != "" {
		return at.Path == path
	}
	return at.Schema != "" && at.Schema == schemaID
}

// share applies the run's level and the collect config key to the artifacts
// passed to Emit, and returns the ones the run writes. When it leaves any
// out, it sets each remaining artifact's path, so the runner's default paths
// do not shift.
//
// An artifact whose schema sets a level above the run's on the whole
// artifact is left out with no gap, as a field marked for a higher level is.
// An artifact whose kind the key leaves out is recorded as not shared. When
// that artifact is normalized, each value Recorder.Mirror copied from it into
// an artifact the run writes is removed and recorded as not shared too, and
// so is each value Recorder.Moved placed beside it. That holds for one
// Selected ruled out that the collector did not pass. A value copied from a
// detailed artifact stays, since leaving out a detailed artifact leaves out
// only that file. Gaps inside an artifact left out are dropped, since the
// pack does not hold it.
func (r *run) share(artifacts []CollectedArtifact, config map[string]any) ([]CollectedArtifact, error) {
	level, list := LevelOf(config), collectListOf(config)
	if !list.all {
		r.collect.list(list.kinds)
	}
	var kept []CollectedArtifact
	var dropped []Location
	for i, a := range artifacts {
		path := artifactPath(a, r.name, i)
		switch r.verdict(path, a.Schema, level, list) {
		case aboveLevel:
			dropped = append(dropped, Location{Schema: a.Schema, Path: path})
		case notListed:
			r.leaveOut(a.Schema, path)
			dropped = append(dropped, Location{Schema: a.Schema, Path: path})
		default:
			a.Path = path
			kept = append(kept, a)
		}
	}
	unshared := r.collect.unsharedArtifacts()
	if len(dropped) == 0 && len(unshared) == 0 {
		return artifacts, nil
	}
	r.dropGapsInside(append(dropped, unshared...))
	if err := r.removeMirrored(kept, unshared); err != nil {
		return nil, err
	}
	return kept, nil
}

// trimAbove removes from each artifact the values its schema places above
// level with x-epack-level, as the result artifact's own are removed. It
// returns a levels finding for each value removed, since the collector
// should not have collected it at this level. A staged file is written as
// it is.
func (r *run) trimAbove(artifacts []CollectedArtifact, level Level) ([]CollectedArtifact, []CheckFinding, error) {
	out, cloned := artifacts, false
	var findings []CheckFinding
	for i, a := range artifacts {
		path := artifactPath(a, r.name, i)
		s := schemaFor(r.schemas, path, a.Schema)
		if s == nil || a.File != "" {
			continue
		}
		raw, err := json.Marshal(a.Data)
		if err != nil {
			return nil, nil, fmt.Errorf("artifact %s: %w", path, err)
		}
		doc, err := outputcheck.Decode(raw)
		if err != nil {
			return nil, nil, fmt.Errorf("artifact %s: %w", path, err)
		}
		above := outputcheck.AboveLevel(s, path, doc, string(level))
		if len(above) == 0 {
			continue
		}
		pruned, err := outputcheck.Prune(s, raw, string(level))
		if err != nil {
			return nil, nil, fmt.Errorf("artifact %s: %w", path, err)
		}
		if !cloned {
			out, cloned = slices.Clone(artifacts), true
		}
		out[i].Data = json.RawMessage(pruned)
		for _, f := range above {
			findings = append(findings, CheckFinding{Check: CheckLevels, Path: path, Pointer: f.Pointer, Message: f.Message + ", so the SDK left it out"})
		}
	}
	return out, findings, nil
}

// dropGapsInside removes the gaps inside the artifacts the run left out,
// since the pack does not hold them. It keeps each not_shared gap on a
// whole artifact.
func (r *run) dropGapsInside(dropped []Location) {
	r.records.dropInside(func(g Gap) bool {
		if g.Code == CodeNotShared && g.Pointer == "" {
			return false
		}
		return slices.ContainsFunc(dropped, func(d Location) bool { return g.names(d.Path, d.Schema) })
	})
}

// removeMirrored removes from the artifacts the run writes each value that
// Recorder.Mirror copied from an artifact in unshared, and each that
// Recorder.Moved placed beside one, and records it as not shared. A moved
// value's gaps go with it.
func (r *run) removeMirrored(out []CollectedArtifact, unshared []Location) error {
	left := func(at Location) bool {
		return slices.ContainsFunc(unshared, func(u Location) bool { return at.names(u.Path, u.Schema) || u.names(at.Path, at.Schema) })
	}
	for _, m := range r.records.mirrored() {
		if left(m.From) {
			if err := r.remove(out, m.To, false); err != nil {
				return err
			}
		}
	}
	for _, m := range r.records.movedValues() {
		if left(m.From) {
			if err := r.remove(out, m.To, true); err != nil {
				return err
			}
		}
	}
	return nil
}

// remove removes the value at at from the artifact in out that has it, and
// records it as not shared. inside drops the gaps inside the value too.
func (r *run) remove(out []CollectedArtifact, at Location, inside bool) error {
	i := slices.IndexFunc(out, func(a CollectedArtifact) bool { return at.names(a.Path, a.Schema) })
	if i < 0 || out[i].File != "" || at.Pointer == "" {
		return nil
	}
	doc, err := decodeData(out[i].Data)
	if err != nil {
		return fmt.Errorf("artifact %s: %w", out[i].Path, err)
	}
	out[i].Data = removePointer(doc, at.Pointer)
	at = Location{Schema: out[i].Schema, Path: out[i].Path, Pointer: at.Pointer}
	if inside {
		r.records.dropInside(func(g Gap) bool { return g.names(at.Path, at.Schema) && covers(at.Pointer, g.Pointer) })
	}
	r.records.notShared(at)
	return nil
}

// removePointer returns doc with the value at pointer removed: a member is
// deleted, and an array item is set to null so the items after it keep their
// indexes. A pointer to nothing leaves doc as it is.
func removePointer(doc any, pointer string) any {
	if pointer == "" {
		return nil
	}
	tokens := jsonpointer.Tokens(pointer)
	cur := doc
	for i, token := range tokens {
		last := i == len(tokens)-1
		switch node := cur.(type) {
		case map[string]any:
			if last {
				delete(node, token)
				return doc
			}
			cur = node[token]
		case []any:
			idx, ok := jsonpointer.Index(token)
			if !ok || idx >= len(node) {
				return doc
			}
			if last {
				node[idx] = nil
				return doc
			}
			cur = node[idx]
		default:
			return doc
		}
	}
	return doc
}
