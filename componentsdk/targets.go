package componentsdk

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/locktivity/epack/internal/outputcheck"
)

// TargetKind names what a run was pointed at. A run declares its
// container, the organization, tenant, customer, workspace, or group it
// signed in to or was configured for, and the resources it assessed in
// it. Users, apps, groups of people, and devices are populations, not
// targets: the counts and checks on them cover them.
type TargetKind string

// Target kinds.
const (
	TargetOrganization TargetKind = "organization"
	TargetTenant       TargetKind = "tenant"
	TargetCustomer     TargetKind = "customer"
	TargetWorkspace    TargetKind = "workspace"
	TargetGroup        TargetKind = "group"
	TargetAccount      TargetKind = "account"
	TargetSubscription TargetKind = "subscription"
	TargetRegion       TargetKind = "region"
	TargetRepository   TargetKind = "repository"
	TargetProject      TargetKind = "project"
	TargetService      TargetKind = "service"
	TargetEnvironment  TargetKind = "environment"
	TargetEndpoint     TargetKind = "endpoint"
	TargetDomain       TargetKind = "domain"
)

var targetKinds = []TargetKind{
	TargetOrganization, TargetTenant, TargetCustomer, TargetWorkspace, TargetGroup, TargetAccount, TargetSubscription,
	TargetRegion, TargetRepository, TargetProject, TargetService, TargetEnvironment, TargetEndpoint, TargetDomain,
}

// TargetChoice says how a run chose its targets, which tells a reader how
// far the list's completeness can be relied on.
type TargetChoice string

// Target choices.
const (
	// ChosenByConfig means a person listed the targets in the config, so
	// the list is as complete as they made it.
	ChosenByConfig TargetChoice = "config_list"
	// ChosenByDiscovery means the collector found every target its
	// credential can see.
	ChosenByDiscovery TargetChoice = "discovery"
	// ChosenByFilter means the collector found the targets its credential
	// can see, then the config narrowed them, such as with patterns.
	ChosenByFilter TargetChoice = "discovery_filtered"
	// ChosenByGrant means the collector found every target its credential
	// can see, and the credential was given only some of them, such as a
	// GitHub App installed on selected repositories, so others may exist.
	ChosenByGrant TargetChoice = "granted"
	// ChosenByGrantFilter means the credential was given only some targets,
	// as with ChosenByGrant, and the config then narrowed them.
	ChosenByGrantFilter TargetChoice = "granted_filtered"
	// ChosenByCollector means the collector picked the targets itself, such
	// as a default region, and the config doesn't name them.
	ChosenByCollector TargetChoice = "collector"
)

var targetChoices = []TargetChoice{ChosenByConfig, ChosenByDiscovery, ChosenByFilter, ChosenByGrant, ChosenByGrantFilter, ChosenByCollector}

// ResultTarget is one entry in the result artifact's targets: a kind of
// target the run declared, how it chose them, and where they and the
// values about them sit in the pack. It points into the artifacts and
// copies no names, so the names follow their own fields' levels. A
// location the run's level or the collect config key left out of the pack
// is dropped, with the parts that read it. Count and Complete are the
// SDK's: Count is how many targets the artifact holds, written from the
// audit level, and Complete says whether every one was reached with no gap
// that makes the run partial, written at every level. For, when present,
// narrows the declaration to the values read in these targets alone.
type ResultTarget struct {
	Kind      TargetKind   `json:"kind"`
	ChosenBy  TargetChoice `json:"chosen_by"`
	ConfigKey string       `json:"config_key,omitempty"`
	At        *Location    `json:"at,omitempty"`
	Name      []string     `json:"name,omitempty"`
	Label     string       `json:"label,omitempty"`
	Reached   string       `json:"reached,omitempty"`
	Found     *Location    `json:"found,omitempty"`
	Assessed  *Location    `json:"assessed,omitempty"`
	Coverage  *Location    `json:"coverage,omitempty"`
	Include   *Location    `json:"include,omitempty"`
	Exclude   *Location    `json:"exclude,omitempty"`
	For       []Location   `json:"for,omitempty"`
	Count     *int         `json:"count,omitempty"`
	Complete  *bool        `json:"complete,omitempty"`
}

// Targets is a declaration Recorder.Targets started. Its methods add to it
// and return it, so a declaration reads as one chain.
type Targets struct {
	r     *Recorder
	index int
}

// Targets declares the targets of one kind the run was pointed at. at
// names them in an artifact:
//   - an array, each item one target, such as /endpoints;
//   - a single value, for a container, such as /tenant_id or /organization;
//   - the whole artifact, with the pointer "", for a container the artifact
//     describes, such as a tenant whose ID and domain sit at its top;
//   - an array inside each item of another array, written with one "*"
//     token, such as /accounts/*/regions.
//
// name gives pointers inside each item whose values, joined with ":", name
// a target, such as /host and /port. Give none when the item is itself the
// name, as a string is, or for a single value. Declare each kind once, and
// again with For for values the run read in fewer of them.
func (r *Recorder) Targets(kind TargetKind, at Location, name ...string) *Targets {
	at = r.located(at)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.targets = append(r.targets, ResultTarget{Kind: kind, At: &at, Name: slices.Clone(name)})
	return &Targets{r: r, index: len(r.targets) - 1}
}

func (t *Targets) set(f func(*ResultTarget)) *Targets {
	t.r.mu.Lock()
	defer t.r.mu.Unlock()
	f(&t.r.targets[t.index])
	return t
}

// ChosenBy says how the run chose the targets, and the config key that
// listed or narrowed them, if any.
func (t *Targets) ChosenBy(how TargetChoice, configKey string) *Targets {
	return t.set(func(d *ResultTarget) { d.ChosenBy, d.ConfigKey = how, configKey })
}

// Label gives a pointer inside each item to the name people know a target
// by, such as /account_label or /org_domain, for a reader to show beside
// the name, or alone when the run's level leaves the name out.
func (t *Targets) Label(pointer string) *Targets {
	return t.set(func(d *ResultTarget) { d.Label = pointer })
}

// Reached gives a pointer inside each item to a boolean that is false when
// the target did not answer, such as an endpoint that refused the
// connection. A target that did not answer is not complete.
func (t *Targets) Reached(pointer string) *Targets {
	return t.set(func(d *ResultTarget) { d.Reached = pointer })
}

// Found points at a count of the targets the collector found, before the
// config narrowed them.
func (t *Targets) Found(at Location) *Targets {
	at = t.r.located(at)
	return t.set(func(d *ResultTarget) { d.Found = &at })
}

// Assessed points at a count of the targets the run assessed.
func (t *Targets) Assessed(at Location) *Targets {
	at = t.r.located(at)
	return t.set(func(d *ResultTarget) { d.Assessed = &at })
}

// Coverage points at the share of the found targets the run assessed, as
// a percentage the artifact holds.
func (t *Targets) Coverage(at Location) *Targets {
	at = t.r.located(at)
	return t.set(func(d *ResultTarget) { d.Coverage = &at })
}

// Patterns points at the include and exclude patterns the config narrowed
// the targets by. Pass a zero Location for one the artifact doesn't hold.
func (t *Targets) Patterns(include, exclude Location) *Targets {
	include, exclude = t.r.located(include), t.r.located(exclude)
	return t.set(func(d *ResultTarget) {
		if include.Pointer != "" {
			d.Include = &include
		}
		if exclude.Pointer != "" {
			d.Exclude = &exclude
		}
	})
}

// For narrows the declaration to the values the run read in these targets
// alone, when it read its other values in more of them, such as the
// security services a collector reads in one region of the several it
// scans. Declare the kind again without For for the targets the rest of the
// run read. A pointer may use one "*" token, as at does.
func (t *Targets) For(values ...Location) *Targets {
	located := make([]Location, len(values))
	for i, v := range values {
		located[i] = t.r.located(v)
	}
	return t.set(func(d *ResultTarget) { d.For = located })
}

// targetList returns a copy of the declarations made so far.
func (r *Recorder) targetList() []ResultTarget {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.targets)
}

// target is one target read from an artifact: where it sits and its value.
type target struct {
	pointer string
	value   any
}

// resolveTargets fills in each declaration's artifact paths, reads its
// targets from the emitted artifacts, and sets Count and Complete. A
// location whose artifact the run didn't write, or whose value the schema
// places above the run's level, is dropped, with the parts that read it. A
// location a gap covers holds no targets and is incomplete. A location the
// artifact should otherwise hold and doesn't, and a target missing a name it
// should have, are targets findings. A declaration narrowed with For whose
// values the pack holds none of is dropped. A declaration that names no
// known kind or choice, or a malformed pointer, is the collector's mistake,
// so it fails Emit.
func (s *emittedSet) resolveTargets(decls []ResultTarget, gaps []Gap, spec map[string]*artifactSchema, level Level) ([]ResultTarget, []CheckFinding, error) {
	var out []ResultTarget
	var findings []CheckFinding
	for _, d := range decls {
		if !slices.Contains(targetKinds, d.Kind) {
			return nil, nil, fmt.Errorf("targets at %s name the kind %q, which is not a target kind", d.At.Pointer, d.Kind)
		}
		if !slices.Contains(targetChoices, d.ChosenBy) {
			return nil, nil, fmt.Errorf("%s targets at %s say how they were chosen with %q; call ChosenBy with a TargetChoice", d.Kind, d.At.Pointer, d.ChosenBy)
		}
		if err := checkTargetPointers(d); err != nil {
			return nil, nil, err
		}
		at := *d.At
		d.At = &at
		if len(d.For) > 0 {
			kept, err := s.resolveFor(d.For, spec, level)
			if err != nil {
				return nil, nil, err
			}
			if len(kept) == 0 {
				continue
			}
			d.For = kept
		}
		for _, loc := range []**Location{&d.Found, &d.Assessed, &d.Coverage, &d.Include, &d.Exclude} {
			resolved, err := s.resolveValue(*loc)
			if err != nil {
				return nil, nil, err
			}
			*loc = resolved
		}
		e, err := s.find(*d.At)
		if err != nil {
			return nil, nil, err
		}
		var doc any
		if e != nil {
			if doc, err = s.doc(e); err != nil {
				return nil, nil, fmt.Errorf("artifact %s: %w", e.path, err)
			}
		}
		if e == nil || doc == nil {
			out = append(out, withoutTargets(d))
			continue
		}
		d.At.Path = e.path
		if d.At.Schema == "" {
			d.At.Schema = e.art.Schema
		}
		schema := schemaFor(spec, e.path, e.art.Schema)
		above := func(ptr string) bool {
			return schema != nil && outputcheck.PointerAbove(schema, ptr, string(level))
		}
		targets, holders, held, err := readTargets(doc, d.At.Pointer)
		if err != nil {
			return nil, nil, fmt.Errorf("%s targets in %s: %w", d.Kind, e.path, err)
		}
		if !held {
			holder, _, _ := strings.Cut(d.At.Pointer, "/*")
			switch {
			case above(d.At.Pointer), anyGapCovers(gaps, e.path, holder, false):
				// The level, or a gap on a value left out on purpose, such
				// as one the collector doesn't read, leaves the targets out.
				out = append(out, withoutTargets(d))
			case anyGapCovers(gaps, e.path, holder, true):
				// A value the run couldn't read is a target set it read
				// none of, not a declaration the artifact fails to bear out.
				count, complete := 0, false
				d.Count, d.Complete = &count, &complete
				out = append(out, d)
			default:
				findings = append(findings, CheckFinding{Check: CheckTargets, Path: e.path, Pointer: d.At.Pointer,
					Message: fmt.Sprintf("declares %s targets here, but the artifact holds no value at it", d.Kind)})
				out = append(out, withoutTargets(d))
			}
			continue
		}
		// Before a "*", only a gap on the outer array or above it bears on
		// the targets: a gap elsewhere inside an outer item, such as one
		// account's password policy, is not about its regions.
		outer, _, nested := strings.Cut(d.At.Pointer, "/*")
		complete := !nested || !anyGapCovers(gaps, e.path, outer, true)
		for _, holder := range holders {
			if gapCovers(gaps, e.path, holder) {
				complete = false
			}
		}
		for _, t := range targets {
			// A target a gap covers may lack its name, such as an account
			// whose role was refused.
			for _, part := range d.Name {
				if _, ok, _ := resolvePointer(t.value, part); !ok && !above(t.pointer+part) && !gapCovers(gaps, e.path, t.pointer) {
					findings = append(findings, CheckFinding{Check: CheckTargets, Path: e.path, Pointer: t.pointer,
						Message: fmt.Sprintf("has no value at %s to name this %s target", part, d.Kind)})
				}
			}
			if d.Reached != "" {
				if v, ok, _ := resolvePointer(t.value, d.Reached); ok && v == false {
					complete = false
				}
			}
		}
		count := len(targets)
		// A list cut short, such as at a collector's row cap, holds fewer
		// targets than the run says it assessed.
		if assessed, ok := s.number(d.Assessed); ok && assessed > count {
			complete = false
		}
		d.Count, d.Complete = &count, &complete
		out = append(out, d)
	}
	return out, findings, nil
}

// withoutTargets returns d without the location of its targets and the
// parts that read them, for a run whose pack doesn't hold them.
func withoutTargets(d ResultTarget) ResultTarget {
	d.At, d.Name, d.Label, d.Reached = nil, nil, "", ""
	return d
}

// checkTargetPointers checks that each of d's pointers is a JSON pointer,
// with at "" for the whole artifact, and that at and each For value hold at
// most one "*" token.
func checkTargetPointers(d ResultTarget) error {
	pointers := append([]string{d.Label, d.Reached}, d.Name...)
	wildcards := []string{d.At.Pointer}
	if d.At.Pointer != "" {
		pointers = append(pointers, d.At.Pointer)
	}
	for _, v := range d.For {
		if v.Pointer == "" {
			return fmt.Errorf("%s targets are for the whole artifact; give the pointer of the value read in them", d.Kind)
		}
		pointers = append(pointers, v.Pointer)
		wildcards = append(wildcards, v.Pointer)
	}
	for _, p := range pointers {
		if p != "" && !strings.HasPrefix(p, "/") {
			return fmt.Errorf("%s targets use the pointer %q, which must start with /", d.Kind, p)
		}
	}
	for _, p := range wildcards {
		if strings.Count(p+"/", "/*/") > 1 {
			return fmt.Errorf("%s targets at %s use more than one * token", d.Kind, p)
		}
	}
	return nil
}

// resolveFor returns the For values the pack holds, with their artifact
// paths filled in: those whose artifact the run wrote, at a pointer the
// schema doesn't place above the run's level.
func (s *emittedSet) resolveFor(values []Location, spec map[string]*artifactSchema, level Level) ([]Location, error) {
	var kept []Location
	for _, v := range values {
		e, err := s.find(v)
		if err != nil {
			return nil, err
		}
		if e == nil {
			continue
		}
		if schema := schemaFor(spec, e.path, e.art.Schema); schema != nil && outputcheck.PointerAbove(schema, v.Pointer, string(level)) {
			continue
		}
		v.Path = e.path
		if v.Schema == "" {
			v.Schema = e.art.Schema
		}
		kept = append(kept, v)
	}
	return kept, nil
}

// readTargets returns the targets at pointer in doc: each item of an
// array, or the value itself for a single target. A "*" token reads the
// array or value after it in each item of the array before it. holders are
// the pointers of the values that hold the targets, after the "*" when
// there is one, where a gap at, above or inside leaves the set incomplete. held is false when doc has no value at pointer, or no
// array before a "*". A null value holds no targets.
func readTargets(doc any, pointer string) (targets []target, holders []string, held bool, err error) {
	prefix, suffix, nested := strings.Cut(pointer, "/*")
	if !nested {
		value, ok, err := resolvePointer(doc, pointer)
		if err != nil || !ok {
			return nil, nil, false, err
		}
		return expand(pointer, value), []string{pointer}, true, nil
	}
	value, ok, err := resolvePointer(doc, prefix)
	if err != nil || !ok {
		return nil, nil, false, err
	}
	items, isArray := value.([]any)
	if !isArray {
		return nil, nil, value == nil, nil
	}
	for i, item := range items {
		at := prefix + "/" + strconv.Itoa(i) + suffix
		holders = append(holders, at)
		inner, ok, err := resolvePointer(item, suffix)
		if err != nil {
			return nil, nil, false, err
		}
		if ok {
			targets = append(targets, expand(at, inner)...)
		}
	}
	return targets, holders, true, nil
}

// expand returns each item of an array value as a target, a single value
// as one, and null as none.
func expand(pointer string, value any) []target {
	switch v := value.(type) {
	case nil:
		return nil
	case []any:
		out := make([]target, len(v))
		for i, item := range v {
			out[i] = target{pointer: pointer + "/" + strconv.Itoa(i), value: item}
		}
		return out
	default:
		return []target{{pointer: pointer, value: v}}
	}
}

// gapCovers reports whether a gap that makes the run partial sits at
// pointer in the artifact at path, inside it, or on a value that holds it.
func gapCovers(gaps []Gap, path, pointer string) bool {
	for _, g := range gaps {
		if g.Path == path && g.Code.makesPartial() && (covers(g.Pointer, pointer) || covers(pointer, g.Pointer)) {
			return true
		}
	}
	return false
}

// anyGapCovers reports whether a gap sits at pointer in the artifact at
// path or on a value that holds it, among the gaps that make the run
// partial or, with partial false, among those that don't.
func anyGapCovers(gaps []Gap, path, pointer string, partial bool) bool {
	for _, g := range gaps {
		if g.Path == path && g.Code.makesPartial() == partial && covers(g.Pointer, pointer) {
			return true
		}
	}
	return false
}

// number returns the integer at a resolved location, if it holds one.
func (s *emittedSet) number(at *Location) (int, bool) {
	if at == nil {
		return 0, false
	}
	e, err := s.find(*at)
	if err != nil || e == nil {
		return 0, false
	}
	doc, err := s.doc(e)
	if err != nil {
		return 0, false
	}
	value, ok, _ := resolvePointer(doc, at.Pointer)
	if !ok {
		return 0, false
	}
	n, err := strconv.Atoi(fmt.Sprint(value))
	return n, err == nil
}

// resolveValue returns at with its artifact path filled in, or nil when the
// pack doesn't hold a value at it.
func (s *emittedSet) resolveValue(at *Location) (*Location, error) {
	if at == nil {
		return nil, nil
	}
	if at.Pointer != "" && !strings.HasPrefix(at.Pointer, "/") {
		return nil, fmt.Errorf("a target value at %q must use a pointer that starts with /", at.Pointer)
	}
	e, err := s.find(*at)
	if err != nil || e == nil {
		return nil, err
	}
	doc, err := s.doc(e)
	if err != nil {
		return nil, fmt.Errorf("artifact %s: %w", e.path, err)
	}
	if _, ok, err := resolvePointer(doc, at.Pointer); err != nil || !ok || doc == nil {
		return nil, err
	}
	out := *at
	out.Path = e.path
	if out.Schema == "" {
		out.Schema = e.art.Schema
	}
	return &out, nil
}

// find returns the emitted artifact at names, by its path or its schema,
// or nil when the run wrote no such artifact.
func (s *emittedSet) find(at Location) (*emitted, error) {
	var found *emitted
	switch {
	case at.Path != "":
		for _, e := range s.list {
			if e.path == at.Path {
				return e, nil
			}
		}
	case at.Schema != "":
		for _, e := range s.list {
			if e.art.Schema != at.Schema {
				continue
			}
			if found != nil {
				return nil, fmt.Errorf("the location %s names schema %s, which several artifacts share; give its path", at.Pointer, at.Schema)
			}
			found = e
		}
	default:
		return nil, fmt.Errorf("the location %s names neither a schema nor a path", at.Pointer)
	}
	return found, nil
}
