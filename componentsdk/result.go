package componentsdk

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

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
// identity it signed in as, and when it ran.
type CollectorResult struct {
	Collector ResultCollector `json:"collector"`
	Outcome   ResultOutcome   `json:"outcome"`
	Gaps      []Gap           `json:"gaps"`
	// Checks lists the first 100 findings of the output checks, and
	// ChecksDropped counts the rest.
	Checks        []CheckFinding `json:"checks,omitempty"`
	ChecksDropped int            `json:"checks_dropped,omitempty"`
	Calls         ResultCalls    `json:"calls"`
	SignedInAs    *Principal     `json:"signed_in_as,omitempty"`
	Run           ResultRun      `json:"run"`
}

// ResultCollector identifies the collector build.
type ResultCollector struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	Commit  string `json:"commit,omitempty"`
}

// ResultOutcome summarizes the run. Code and owner come from the first gap
// when the outcome is partial.
type ResultOutcome struct {
	Status string `json:"status"`
	Code   Code   `json:"code,omitempty"`
	Owner  Owner  `json:"owner,omitempty"`
}

// ResultCalls holds the call ledger. Per-request rows appear at the audit and
// internal levels only.
type ResultCalls struct {
	Operations      []OperationCalls `json:"operations"`
	Requests        []CallRow        `json:"requests,omitempty"`
	RequestsDropped int              `json:"requests_dropped,omitempty"`
}

// ResultRun records when the collector ran and whether a proxy or a custom
// certificate authority could have stood between it and the vendor.
type ResultRun struct {
	RunID      string `json:"run_id,omitempty"`
	StartedAt  string `json:"started_at"`
	FinishedAt string `json:"finished_at"`
	Proxy      bool   `json:"proxy"`
	CustomCA   bool   `json:"custom_ca"`
}

func resultPath(name string) string {
	return "artifacts/" + name + ".collector-result.json"
}

type resultInput struct {
	run       *run
	level     Level
	artifacts []CollectedArtifact
	getenv    func(string) string
	finished  time.Time
}

func buildResult(in resultInput) (CollectorResult, error) {
	r := in.run
	set := newEmittedSet(in.artifacts, r.name)
	gaps, err := set.resolveGaps(r.records.Gaps())
	if err != nil {
		return CollectorResult{}, err
	}
	audit := in.level.AtLeast(LevelAudit)
	secrets := r.secrets.list()
	checks, checksDropped := outputChecks(set, r.schemas, gaps, secrets)
	for i := range gaps {
		if audit {
			gaps[i].Detail = redactDetail(gaps[i].Detail, secrets)
		} else {
			gaps[i].Detail = ""
		}
	}
	sort.SliceStable(gaps, func(i, j int) bool {
		if gaps[i].Path != gaps[j].Path {
			return gaps[i].Path < gaps[j].Path
		}
		return gaps[i].Pointer < gaps[j].Pointer
	})

	result := CollectorResult{
		Collector:     ResultCollector{Name: r.name, Version: r.version, Commit: r.commit},
		Outcome:       ResultOutcome{Status: OutcomeCollected},
		Gaps:          gaps,
		Checks:        checks,
		ChecksDropped: checksDropped,
		Calls:         ResultCalls{Operations: r.calls.operations()},
		Run: ResultRun{
			RunID:      r.runID,
			StartedAt:  r.started.UTC().Format(time.RFC3339Nano),
			FinishedAt: in.finished.UTC().Format(time.RFC3339Nano),
			Proxy:      anySet(in.getenv, "HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"),
			CustomCA:   anySet(in.getenv, "SSL_CERT_FILE", "SSL_CERT_DIR"),
		},
	}
	if len(gaps) > 0 {
		result.Outcome = ResultOutcome{Status: OutcomePartial, Code: gaps[0].Code, Owner: gaps[0].Owner}
	}
	if audit {
		result.Calls.Requests, result.Calls.RequestsDropped = r.calls.requests()
	}
	if p := r.records.signedIn(); p != nil {
		if !audit {
			p.ID = ""
		}
		result.SignedInAs = p
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
	for _, token := range strings.Split(pointer[1:], "/") {
		token = strings.ReplaceAll(strings.ReplaceAll(token, "~1", "/"), "~0", "~")
		switch node := cur.(type) {
		case map[string]any:
			next, ok := node[token]
			if !ok {
				return nil, false, nil
			}
			cur = next
		case []any:
			idx, err := strconv.Atoi(token)
			if err != nil || idx < 0 || (len(token) > 1 && token[0] == '0') {
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
