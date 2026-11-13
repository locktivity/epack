// Package surface compares the vendor API calls a collector's recordings
// hold against the vendor's OpenAPI description, so what the collector
// reads, and what it leaves out, comes from the vendor rather than from
// memory. A reviewed surface.yaml gives each operation the collector does
// not read a verdict, and the collector's Not Collected documentation is
// rendered from those verdicts.
package surface

import (
	"encoding/json"
	"fmt"
	"net/url"
	"path/filepath"
	"sort"
	"strings"

	"github.com/locktivity/epack/internal/limits"
	"github.com/locktivity/epack/internal/safefile"
	"github.com/locktivity/epack/internal/safeyaml"
)

// Operation is one method on one path of the vendor's API description.
type Operation struct {
	// ID is the description's operationId, when it has one.
	ID          string
	Method      string
	Path        string
	Tags        []string
	Summary     string
	Deprecated  bool
	Category    string
	Subcategory string

	segments []string
	literals int
}

// Key names the operation: its operationId, or "METHOD /path" when the
// description gives none. surface.yaml names operations by their keys.
func (o *Operation) Key() string {
	if o.ID != "" {
		return o.ID
	}
	return o.Method + " " + o.Path
}

// Spec is the part of an OpenAPI description the surface check reads: its
// servers' base paths and its operations.
type Spec struct {
	Servers    []string
	Operations []*Operation
	byKey      map[string]*Operation
}

var methods = []string{"get", "put", "post", "delete", "options", "head", "patch", "trace"}

// LoadSpec reads an OpenAPI 3 description from a JSON or YAML file.
func LoadSpec(path string) (*Spec, error) {
	data, err := safefile.ReadFile(path, limits.Artifact)
	if err != nil {
		return nil, err
	}
	return ParseSpec(data, strings.ToLower(filepath.Ext(path)) == ".json")
}

// ParseSpec parses an OpenAPI 3 description. JSON documents decode with
// encoding/json, which is far quicker on large descriptions than YAML.
func ParseSpec(data []byte, isJSON bool) (*Spec, error) {
	var doc map[string]any
	if isJSON {
		if err := json.Unmarshal(data, &doc); err != nil {
			return nil, fmt.Errorf("parsing the API description: %w", err)
		}
	} else if err := safeyaml.UnmarshalDocument(data, limits.Artifact, &doc); err != nil {
		return nil, fmt.Errorf("parsing the API description: %w", err)
	}
	paths, ok := doc["paths"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("the API description has no paths")
	}
	s := &Spec{byKey: map[string]*Operation{}}
	for _, server := range asSlice(doc["servers"]) {
		m, _ := server.(map[string]any)
		raw, _ := m["url"].(string)
		if u, err := url.Parse(raw); err == nil && strings.Trim(u.Path, "/") != "" {
			s.Servers = append(s.Servers, "/"+strings.Trim(u.Path, "/"))
		}
	}
	for path, item := range paths {
		ops, ok := item.(map[string]any)
		if !ok {
			continue
		}
		for _, method := range methods {
			raw, ok := ops[method].(map[string]any)
			if !ok {
				continue
			}
			op := &Operation{Method: strings.ToUpper(method), Path: path}
			op.ID, _ = raw["operationId"].(string)
			op.Summary, _ = raw["summary"].(string)
			op.Deprecated, _ = raw["deprecated"].(bool)
			for _, tag := range asSlice(raw["tags"]) {
				if t, ok := tag.(string); ok {
					op.Tags = append(op.Tags, t)
				}
			}
			if x, ok := raw["x-github"].(map[string]any); ok {
				op.Category, _ = x["category"].(string)
				op.Subcategory, _ = x["subcategory"].(string)
			}
			op.segments = splitPath(path)
			for _, seg := range op.segments {
				if !isParam(seg) {
					op.literals++
				}
			}
			s.Operations = append(s.Operations, op)
		}
	}
	sort.Slice(s.Operations, func(i, j int) bool {
		if s.Operations[i].Path != s.Operations[j].Path {
			return s.Operations[i].Path < s.Operations[j].Path
		}
		return s.Operations[i].Method < s.Operations[j].Method
	})
	for _, op := range s.Operations {
		s.byKey[op.Key()] = op
		s.byKey[op.Method+" "+op.Path] = op
	}
	return s, nil
}

// Lookup finds an operation by its key, or by "METHOD /path".
func (s *Spec) Lookup(key string) (*Operation, bool) {
	op, ok := s.byKey[key]
	return op, ok
}

// SpanningParams names the path parameters that may span several segments
// when no template has the request's number of segments, such as GitHub's
// {path} in a contents URL. Scope.SpanningParams adds to it.
var SpanningParams = []string{"path"}

// Match finds the operation a recorded request exercised. A template
// segment such as {userId} matches one path segment. When no template has
// the request's number of segments, a template whose last segment is one
// of the spanning parameters absorbs the rest of the path. Among the
// templates that match, the one with the most literal segments wins.
func (s *Spec) Match(method, rawURL string) (*Operation, bool) {
	return s.MatchSpanning(method, rawURL, nil)
}

// MatchSpanning is Match with more spanning parameter names.
func (s *Spec) MatchSpanning(method, rawURL string, spanning []string) (*Operation, bool) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, false
	}
	path := u.Path
	for _, base := range s.Servers {
		if strings.HasPrefix(path, base+"/") || path == base {
			path = strings.TrimPrefix(path, base)
			break
		}
	}
	segs := splitPath(path)
	method = strings.ToUpper(method)
	if method == "" {
		method = "GET"
	}
	var best *Operation
	for _, greedy := range []bool{false, true} {
		for _, op := range s.Operations {
			if op.Method != method || !matchSegments(op.segments, segs, greedy && spans(op.segments, spanning)) {
				continue
			}
			if best == nil || op.literals > best.literals {
				best = op
			}
		}
		if best != nil {
			return best, true
		}
	}
	return nil, false
}

func matchSegments(tmpl, got []string, greedy bool) bool {
	if !greedy && len(tmpl) != len(got) {
		return false
	}
	for i, t := range tmpl {
		if i >= len(got) {
			return false
		}
		if isParam(t) {
			if greedy && i == len(tmpl)-1 {
				return true
			}
			continue
		}
		if t != got[i] {
			return false
		}
	}
	return len(tmpl) == len(got)
}

func spans(tmpl, extra []string) bool {
	if len(tmpl) == 0 {
		return false
	}
	last := tmpl[len(tmpl)-1]
	if !isParam(last) {
		return false
	}
	name := strings.Trim(last, "{}")
	for _, list := range [][]string{SpanningParams, extra} {
		for _, n := range list {
			if n == name {
				return true
			}
		}
	}
	return false
}

func splitPath(path string) []string {
	path = strings.Trim(path, "/")
	if path == "" {
		return nil
	}
	return strings.Split(path, "/")
}

func isParam(segment string) bool {
	return strings.HasPrefix(segment, "{") && strings.HasSuffix(segment, "}")
}

func asSlice(v any) []any {
	s, _ := v.([]any)
	return s
}
