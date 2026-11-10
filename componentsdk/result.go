package componentsdk

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/locktivity/epack/internal/jsonpointer"
	"github.com/locktivity/epack/internal/outputcheck"
	"github.com/locktivity/epack/internal/redact"
)

// ResultSchema is the schema of the result artifact the SDK adds to every
// collector's output at Emit.
const ResultSchema = "evidencepack/collector-result@v1"

// Outcome statuses. A collector that fails emits no artifacts, so "failed"
// appears only in its failure record, never in a result artifact.
const (
	OutcomeCollected = "collected"
	OutcomePartial   = "partial"
	OutcomeFailed    = "failed"
)

// CollectorResult is the result artifact: what the collector could not
// measure and why, what the output checks found, the calls it made, the
// identity it signed in as, and when it ran. Below the audit level it holds
// no counts or times, because those grow with the size of the account. It
// also holds no tenant. The run leaves out each value that the result
// schema's x-epack-level places above the run's level.
type CollectorResult struct {
	Collector ResultCollector `json:"collector"`
	Outcome   ResultOutcome   `json:"outcome"`
	Gaps      []Gap           `json:"gaps"`
	// Checks lists the first 100 findings of the output checks, and
	// ChecksDropped counts the rest.
	Checks        []CheckFinding `json:"checks,omitempty"`
	ChecksDropped int            `json:"checks_dropped,omitempty"`
	// Steps lists the run's steps in the order they started, at every
	// level. See StartStep.
	Steps      []ResultStep `json:"steps,omitempty"`
	Calls      ResultCalls  `json:"calls"`
	SignedInAs *Principal   `json:"signed_in_as,omitempty"`
	// Unrecognized lists the values the run read that are not in the
	// collector's vocabularies, grouped by vocabulary. See Vocabulary.Seen.
	Unrecognized []Unrecognized `json:"unrecognized,omitempty"`
	// Warnings lists the run's warnings and the advice for each. See
	// Recorder.Warn.
	Warnings []RunWarning `json:"warnings,omitempty"`
	// Collect is what the collect config key listed and what it left out,
	// at every level. It is absent when the key is.
	Collect *ResultCollect `json:"collect,omitempty"`
	// Targets says what the run was pointed at. See Recorder.Targets.
	Targets []ResultTarget `json:"targets,omitempty"`
	Run     ResultRun      `json:"run"`
}

// ResultCollect records the collect config key of a run.
type ResultCollect struct {
	// Listed is the kinds the key named.
	Listed []string `json:"listed"`
	// LeftOut is each kind the collector could write that the key left out.
	LeftOut []string `json:"left_out,omitempty"`
	// Unmatched is each kind the key named that the run never wrote, such
	// as a misspelled one.
	Unmatched []string `json:"unmatched,omitempty"`
}

// ResultCollector identifies the collector build.
type ResultCollector struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	Commit  string `json:"commit,omitempty"`
}

// ResultOutcome summarizes the run. Code and owner come from the first gap
// when the outcome is partial. A not_shared gap does not make a run partial,
// since the customer chose to leave the value out. An unsupported gap does
// not either, since no run could read the value, and neither does a not_read
// gap, since every run of the collector has it.
type ResultOutcome struct {
	Status string `json:"status"`
	Code   Code   `json:"code,omitempty"`
	Owner  Owner  `json:"owner,omitempty"`
}

// ResultCalls holds the call ledger. Per-request rows appear at the audit and
// internal levels only. They keep the first 1,000 requests and, after those,
// up to 1,000 more whose attempt failed or was a retry. RequestsDropped
// counts every row left out, and ProblemRequestsDropped the failed and
// retried rows among them, so 0 there means every problem has a row. It is
// set wherever the rows are.
type ResultCalls struct {
	Operations             []OperationCalls `json:"operations"`
	Requests               []CallRow        `json:"requests,omitempty"`
	RequestsDropped        int              `json:"requests_dropped,omitempty"`
	ProblemRequestsDropped *int             `json:"problem_requests_dropped,omitempty"`
}

// ResultRun records when the collector ran and whether a proxy or a custom
// certificate authority could have stood between it and the vendor.
type ResultRun struct {
	RunID      string `json:"run_id,omitempty"`
	StartedAt  string `json:"started_at"`
	FinishedAt string `json:"finished_at"`
	// Level is the level the run collected at, written at every level. A
	// reader uses it to tell a value the level left out from one the
	// collector could not read, for every artifact the run wrote.
	Level    Level `json:"level,omitempty"`
	Proxy    bool  `json:"proxy"`
	CustomCA bool  `json:"custom_ca"`
}

func resultPath(name string) string {
	return "artifacts/" + name + ".collector-result.json"
}

type resultInput struct {
	run       *run
	level     Level
	artifacts []CollectedArtifact
	// trimmed holds a levels finding for each value Emit left out because
	// its schema places it above the run's level.
	trimmed []CheckFinding
	// config is the run's config, whose values can name the account.
	config   map[string]any
	getenv   func(string) string
	finished time.Time
}

// resultSchema is the result artifact's schema, compiled once.
var resultSchema = sync.OnceValues(func() (*outputcheck.Schema, error) {
	return outputcheck.Compile(resultSchemaJSON)
})

// resultData returns the run's result artifact as the run writes it. It
// takes the result from buildResult and removes each value that the result
// schema places above the run's level.
func resultData(in resultInput) (json.RawMessage, error) {
	result, err := buildResult(in)
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(result)
	if err != nil {
		return nil, err
	}
	s, err := resultSchema()
	if err != nil {
		return nil, err
	}
	return outputcheck.Prune(s, raw, string(in.level))
}

// buildResult builds the run's result as the internal level writes it. It
// passes the run's level only to the output checks.
func buildResult(in resultInput) (CollectorResult, error) {
	r := in.run
	set := newEmittedSet(in.artifacts, r.name)
	gaps, err := set.resolveGaps(r.records.Gaps())
	if err != nil {
		return CollectorResult{}, err
	}
	secrets := r.secrets.list()
	checks, checksDropped := outputChecks(set, r.schemas, gaps, secrets, in.level)
	for _, f := range in.trimmed {
		if len(checks) >= maxCheckFindings {
			checksDropped++
			continue
		}
		checks = append(checks, f)
	}
	for i := range gaps {
		if gaps[i].guidanceConflict {
			checks = append(checks, guidanceConflictFinding("the gap", gaps[i].Location))
		}
		r.noteHidden("the gap at "+gaps[i].Path+" "+gaps[i].Pointer, secrets, gaps[i].texts()...)
		gaps[i].redact(secrets)
	}
	warnings := r.records.Warnings()
	for i := range warnings {
		if warnings[i].guidanceConflict {
			checks = append(checks, guidanceConflictFinding("a run warning", Location{}))
		}
		r.noteHidden("a run warning", secrets, warnings[i].texts()...)
		warnings[i].redact(secrets)
	}
	// Advice appears at every level, so below audit it leaves out the
	// identifiers that level leaves out everywhere else.
	if !in.level.AtLeast(LevelAudit) {
		ids := accountIdentifiers(r.records.signedIn(), gaps, warnings, in.config)
		for i := range gaps {
			gaps[i].Guidance = redactGuidance(gaps[i].Guidance, ids)
		}
		for i := range warnings {
			warnings[i].Guidance = redactGuidance(warnings[i].Guidance, ids)
		}
	}
	sort.SliceStable(gaps, func(i, j int) bool {
		if gaps[i].Path != gaps[j].Path {
			return gaps[i].Path < gaps[j].Path
		}
		return gaps[i].Pointer < gaps[j].Pointer
	})

	r.calls.endOpenSteps(r.sinceStart(in.finished))
	calls := ResultCalls{Operations: r.calls.operations()}
	var problemsDropped int
	calls.Requests, calls.RequestsDropped, problemsDropped = r.calls.requests()
	calls.ProblemRequestsDropped = &problemsDropped
	result := CollectorResult{
		Collector:     ResultCollector{Name: r.name, Version: r.version, Commit: r.commit},
		Outcome:       ResultOutcome{Status: OutcomeCollected},
		Gaps:          gaps,
		Checks:        checks,
		ChecksDropped: checksDropped,
		Steps:         r.calls.resultSteps(),
		Calls:         calls,
		SignedInAs:    r.records.signedIn(),
		Unrecognized:  r.unrecognized.list(),
		Warnings:      warnings,
		Run: ResultRun{
			RunID:      r.runID,
			StartedAt:  r.started.UTC().Format(time.RFC3339Nano),
			FinishedAt: in.finished.UTC().Format(time.RFC3339Nano),
			Level:      in.level,
			Proxy:      anySet(in.getenv, "HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"),
			CustomCA:   anySet(in.getenv, "SSL_CERT_FILE", "SSL_CERT_DIR"),
		},
	}
	result.Collect = r.collect.result(r.name, r.collector)
	targets, targetFindings, err := set.resolveTargets(r.records.targetList(), gaps, r.schemas, in.level)
	if err != nil {
		return CollectorResult{}, err
	}
	result.Targets = targets
	for _, f := range targetFindings {
		if len(result.Checks) >= maxCheckFindings {
			result.ChecksDropped++
			continue
		}
		result.Checks = append(result.Checks, f)
	}
	for _, g := range gaps {
		if g.Code.makesPartial() {
			result.Outcome = ResultOutcome{Status: OutcomePartial, Code: g.Code, Owner: g.Owner}
			break
		}
	}
	return result, nil
}

// emittedSet holds the artifacts passed to Emit, each decoded once for the
// gap and output checks that read it.
type emittedSet struct {
	list []*emitted
}

type emitted struct {
	path string
	art  CollectedArtifact
	doc  any
	err  error
	done bool
}

func newEmittedSet(artifacts []CollectedArtifact, name string) *emittedSet {
	set := &emittedSet{list: make([]*emitted, len(artifacts))}
	for i, a := range artifacts {
		set.list[i] = &emitted{path: artifactPath(a, name, i), art: a}
	}
	return set
}

// doc returns a data artifact's decoded content, or nil for a file artifact.
func (s *emittedSet) doc(e *emitted) (any, error) {
	if !e.done {
		e.done = true
		if e.art.File == "" {
			e.doc, e.err = decodeData(e.art.Data)
		}
	}
	return e.doc, e.err
}

// resolveGaps fills in each gap's artifact path and checks that the value it
// names is absent or null, so no field carries both a value and a gap. A
// partial gap may name a list or object that holds the items that were read.
func resolveGaps(gaps []Gap, artifacts []CollectedArtifact, name string) ([]Gap, error) {
	return newEmittedSet(artifacts, name).resolveGaps(gaps)
}

func container(value any) bool {
	switch value.(type) {
	case map[string]any, []any:
		return true
	}
	return false
}

func (s *emittedSet) resolveGaps(gaps []Gap) ([]Gap, error) {
	out := make([]Gap, len(gaps))
	for i, g := range gaps {
		if g.Pointer != "" && !strings.HasPrefix(g.Pointer, "/") {
			return nil, fmt.Errorf("gap pointer %q must start with /", g.Pointer)
		}
		var target *emitted
		switch {
		case g.Path != "":
			for _, e := range s.list {
				if e.path == g.Path {
					target = e
					break
				}
			}
		case g.Schema != "":
			for _, e := range s.list {
				if e.art.Schema != g.Schema {
					continue
				}
				if target != nil {
					return nil, fmt.Errorf("gap at %s names schema %s, which several artifacts share; give its path", g.Pointer, g.Schema)
				}
				target = e
			}
		default:
			return nil, fmt.Errorf("gap at %s names neither a schema nor a path", g.Pointer)
		}
		if target != nil {
			g.Path = target.path
			if g.Schema == "" {
				g.Schema = target.art.Schema
			}
			doc, err := s.doc(target)
			if err != nil {
				return nil, fmt.Errorf("artifact %s: %w", target.path, err)
			}
			if doc != nil {
				value, found, err := resolvePointer(doc, g.Pointer)
				if err != nil {
					return nil, fmt.Errorf("gap at %s in %s: %w", g.Pointer, target.path, err)
				}
				readInPart := g.Status == GapPartial && container(value)
				if found && value != nil && !readInPart {
					return nil, fmt.Errorf("artifact %s has a value at %s, which is recorded as %s", target.path, g.Pointer, g.Status)
				}
			}
		}
		out[i] = g
	}
	return out, nil
}

// artifactPath is the path the runner gives an artifact, matching its
// default for artifacts that name none.
func artifactPath(a CollectedArtifact, name string, index int) string {
	if a.Path != "" {
		return a.Path
	}
	return defaultArtifactPath(name, index)
}

// defaultArtifactPath is the path the runner gives the artifact at index in
// the output of the collector configured as name when the artifact names
// none.
func defaultArtifactPath(name string, index int) string {
	if index == 0 {
		return fmt.Sprintf("artifacts/%s.json", name)
	}
	return fmt.Sprintf("artifacts/%s_%d.json", name, index)
}

func decodeData(data any) (any, error) {
	raw, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var doc any
	if err := dec.Decode(&doc); err != nil {
		return nil, err
	}
	return doc, nil
}

// resolvePointer returns the value at an RFC 6901 pointer and whether it
// exists. A pointer through a missing or null value does not exist.
func resolvePointer(doc any, pointer string) (any, bool, error) {
	if pointer == "" {
		return doc, true, nil
	}
	cur := doc
	for _, token := range jsonpointer.Tokens(pointer) {
		switch node := cur.(type) {
		case map[string]any:
			next, ok := node[token]
			if !ok {
				return nil, false, nil
			}
			cur = next
		case []any:
			idx, ok := jsonpointer.Index(token)
			if !ok {
				return nil, false, fmt.Errorf("array index %q is not a number", token)
			}
			if idx >= len(node) {
				return nil, false, nil
			}
			cur = node[idx]
		case nil:
			return nil, false, nil
		default:
			return nil, false, nil
		}
	}
	return cur, true, nil
}

// accountIdentifiers returns the run's values that name something in the
// account and that the trust level leaves out: the principal's ID and
// tenant, and the identifiers in each gap's and warning's scope and in the
// config's own values. An identifier there is a word that holds a digit or
// a separator such as . or @, so plain words in advice stay.
func accountIdentifiers(p *Principal, gaps []Gap, warnings []RunWarning, config map[string]any) []string {
	var out []string
	if p != nil {
		out = append(out, p.ID, p.TenantID)
	}
	words := func(text string) {
		for _, w := range strings.Fields(text) {
			if w = strings.Trim(w, ",;()[]\"'"); strings.ContainsAny(w, "0123456789.@:/-_") {
				out = append(out, w)
			}
		}
	}
	for _, g := range gaps {
		words(g.Scope)
	}
	for _, w := range warnings {
		words(w.Scope)
	}
	var walk func(v any)
	walk = func(v any) {
		switch v := v.(type) {
		case string:
			words(v)
		case []string:
			for _, s := range v {
				words(s)
			}
		case []any:
			for _, item := range v {
				walk(item)
			}
		case map[string]any:
			for _, item := range v {
				walk(item)
			}
		}
	}
	for key, v := range config {
		if key != "level" && key != collectKey {
			walk(v)
		}
	}
	return out
}

// guidanceConflictFinding is the guidance check's finding for advice given
// more than one way, on what, at at.
func guidanceConflictFinding(what string, at Location) CheckFinding {
	return CheckFinding{Check: CheckGuidance, Path: at.Path, Pointer: at.Pointer,
		Message: what + " was given more than one of fix, no_action, and choice, or a choice with fewer than two options, so the SDK kept only the first valid advice"}
}

// texts returns the gap's text and advice, which redact scans.
func (g *Gap) texts() []string {
	return append([]string{g.Detail, g.Warning}, g.Guidance.texts()...)
}

// texts returns the warning's message and advice, which redact scans.
func (w *RunWarning) texts() []string {
	return append([]string{w.Message}, w.Guidance.texts()...)
}

// texts returns the advice's text.
func (g Guidance) texts() []string {
	out := []string{g.Fix, g.Scope}
	if g.Choice != nil {
		out = append(out, g.Choice.Question)
		for _, o := range g.Choice.Options {
			out = append(out, o.Label, o.Consequence)
		}
	}
	return out
}

// redact removes the run's secrets from the gap's text and advice.
func (g *Gap) redact(secrets []string) {
	g.Guidance = redactGuidance(g.Guidance, secrets)
	g.Detail = redactDetail(g.Detail, secrets)
	g.Warning = redactDetail(g.Warning, secrets)
}

// redact removes the run's secrets from the warning's message and advice.
func (w *RunWarning) redact(secrets []string) {
	w.Guidance = redactGuidance(w.Guidance, secrets)
	w.Message = redactDetail(w.Message, secrets)
}

// redactGuidance removes the run's secrets from a gap's or warning's advice.
// The advice appears at every level.
func redactGuidance(g Guidance, secrets []string) Guidance {
	g.Fix = redactDetail(g.Fix, secrets)
	g.Scope = redactDetail(g.Scope, secrets)
	if g.Choice != nil {
		c := &Choice{Question: redactDetail(g.Choice.Question, secrets)}
		for _, o := range g.Choice.Options {
			c.Options = append(c.Options, ChoiceOption{Label: redactDetail(o.Label, secrets), Consequence: redactDetail(o.Consequence, secrets)})
		}
		g.Choice = c
	}
	return g
}

func redactDetail(detail string, secrets []string) string {
	if detail == "" {
		return ""
	}
	return redact.SensitiveAlways(redact.Values(detail, secrets...))
}

func anySet(getenv func(string) string, names ...string) bool {
	if getenv == nil {
		return false
	}
	for _, n := range names {
		if getenv(n) != "" {
			return true
		}
	}
	return false
}

//go:embed schema/collector-result.v1.json
var resultSchemaJSON []byte

// ResultSchemaJSON returns the JSON Schema of the result artifact.
func ResultSchemaJSON() []byte {
	return append([]byte(nil), resultSchemaJSON...)
}
