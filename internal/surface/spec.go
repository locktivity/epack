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
	"os"
	"path/filepath"
	"slices"
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
	origin   *Spec
}

// Description names the description the operation came from.
func (o *Operation) Description() string {
	if o.origin == nil {
		return ""
	}
	return o.origin.Name
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
// servers' hosts and base paths and its operations.
type Spec struct {
	// Name says which description this is when several are checked, such
	// as the file's name.
	Name string
	// Servers holds the servers' base paths, such as /v1.0.
	Servers []string
	// Hosts holds the servers' fixed host names. A templated host, such as
	// {yourOktaDomain}, is left out, and a description with no fixed host
	// matches a request on any host.
	Hosts      []string
	Operations []*Operation
	// Parts holds the descriptions a combined Spec was made from.
	Parts []*Spec
	byKey map[string]*Operation
}

var methods = []string{"get", "put", "post", "delete", "options", "head", "patch", "trace"}

// LoadSpec reads an OpenAPI 3 or Swagger 2 description from a JSON or YAML
// file, named after the file. A directory is one description made of every
// JSON and YAML file in it, as Azure publishes a resource provider's API
// version as a folder of files.
func LoadSpec(path string) (*Spec, error) {
	files, err := DescriptionFiles(path)
	if err != nil {
		return nil, err
	}
	var parts []*Spec
	for _, file := range files {
		data, err := safefile.ReadFile(file, limits.Artifact)
		if err != nil {
			return nil, err
		}
		spec, err := ParseSpec(data, strings.ToLower(filepath.Ext(file)) == ".json")
		if err != nil {
			return nil, fmt.Errorf("%s: %w", file, err)
		}
		spec.Name = filepath.Base(file)
		parts = append(parts, spec)
	}
	if len(parts) == 1 {
		return parts[0], nil
	}
	spec := Combine(parts...)
	spec.Name = filepath.Base(path)
	spec.Parts = nil
	for _, part := range parts {
		part.Name = spec.Name
	}
	return spec, nil
}

// Rename names a description, and every operation it holds, in reports.
func (s *Spec) Rename(name string) {
	s.Name = name
	for _, op := range s.Operations {
		if op.origin != nil {
			op.origin.Name = name
		}
	}
}

// DescriptionFiles lists the files a description path names: the file
// itself, or every .json, .yaml and .yml file in a directory, in name
// order.
func DescriptionFiles(path string) ([]string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return []string{path}, nil
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, err
	}
	var files []string
	for _, entry := range entries {
		ext := strings.ToLower(filepath.Ext(entry.Name()))
		if !entry.IsDir() && (ext == ".json" || ext == ".yaml" || ext == ".yml") {
			files = append(files, filepath.Join(path, entry.Name()))
		}
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("%s holds no .json or .yaml description", path)
	}
	return files, nil
}

// LoadSpecs reads several descriptions and combines them: a request
// matches an operation of whichever description names its host, and every
// operation of every description is in scope for a verdict.
func LoadSpecs(paths []string) (*Spec, error) {
	specs := make([]*Spec, 0, len(paths))
	for _, path := range paths {
		spec, err := LoadSpec(path)
		if err != nil {
			return nil, err
		}
		specs = append(specs, spec)
	}
	return Combine(specs...), nil
}

// Combine joins descriptions into one. Each operation keeps the hosts and
// base paths of the description it came from.
func Combine(specs ...*Spec) *Spec {
	if len(specs) == 1 {
		return specs[0]
	}
	out := &Spec{byKey: map[string]*Operation{}}
	seen := map[string]bool{}
	for _, spec := range specs {
		out.Parts = append(out.Parts, spec)
		for _, op := range spec.Operations {
			// Azure's files describe some paths more than once; one copy is
			// enough, or the other would want a verdict of its own. The same
			// path on another host is another operation.
			var hosts []string
			if op.origin != nil {
				hosts = op.origin.Hosts
			}
			key := strings.Join(hosts, ",") + " " + op.Method + " " + op.Path
			if seen[key] {
				continue
			}
			seen[key] = true
			out.Operations = append(out.Operations, op)
		}
	}
	sort.SliceStable(out.Operations, func(i, j int) bool {
		if out.Operations[i].Path != out.Operations[j].Path {
			return out.Operations[i].Path < out.Operations[j].Path
		}
		return out.Operations[i].Method < out.Operations[j].Method
	})
	for _, op := range out.Operations {
		if _, taken := out.byKey[op.Key()]; !taken {
			out.byKey[op.Key()] = op
		}
		if _, taken := out.byKey[op.Method+" "+op.Path]; !taken {
			out.byKey[op.Method+" "+op.Path] = op
		}
	}
	return out
}

// ParseSpec parses an OpenAPI 3 or Swagger 2 description. JSON documents
// decode with encoding/json, which is far quicker on large descriptions
// than YAML.
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
		u, err := url.Parse(raw)
		if err != nil {
			continue
		}
		if strings.Trim(u.Path, "/") != "" {
			s.Servers = append(s.Servers, "/"+strings.Trim(u.Path, "/"))
		}
		if host := strings.ToLower(u.Hostname()); host != "" && !strings.Contains(host, "{") {
			s.Hosts = append(s.Hosts, host)
		}
	}
	// A Swagger 2 description names its host and base path directly.
	if host, ok := doc["host"].(string); ok && host != "" && !strings.Contains(host, "{") {
		s.Hosts = append(s.Hosts, strings.ToLower(host))
	}
	if base, ok := doc["basePath"].(string); ok && strings.Trim(base, "/") != "" {
		s.Servers = append(s.Servers, "/"+strings.Trim(base, "/"))
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
			op := &Operation{Method: strings.ToUpper(method), Path: path, origin: s}
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
// when no template matches the request segment for segment: GitHub's {path}
// in a contents URL, and Azure's {scope}, {resourceUri} and {resourceId},
// which hold a whole resource path. Scope.SpanningParams adds to it.
var SpanningParams = []string{"path", "scope", "resourceUri", "resourceId"}

// Match finds the operation a recorded request exercised. A request on a
// host the description's servers do not name matches nothing, unless the
// description names no fixed host, and so does a request outside the
// description's base paths when it has any. A template segment such as
// {userId} matches one path segment. When no template matches that way, a
// spanning parameter anywhere in a template absorbs as many segments as it
// takes. Among the templates that match, the one with the most literal
// segments wins.
func (s *Spec) Match(method, rawURL string) (*Operation, bool) {
	return s.MatchSpanning(method, rawURL, nil)
}

// MatchSpanning is Match with more spanning parameter names.
func (s *Spec) MatchSpanning(method, rawURL string, spanning []string) (*Operation, bool) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, false
	}
	host := strings.ToLower(u.Hostname())
	method = strings.ToUpper(method)
	if method == "" {
		method = "GET"
	}
	// Each description the request could belong to sees the path with its
	// own base path removed.
	segsFor := map[*Spec][]string{}
	segments := func(origin *Spec) ([]string, bool) {
		if origin == nil {
			origin = s
		}
		if len(origin.Hosts) > 0 && !slices.Contains(origin.Hosts, host) {
			return nil, false
		}
		if segs, ok := segsFor[origin]; ok {
			return segs, true
		}
		path := u.Path
		if len(origin.Servers) > 0 {
			stripped := false
			for _, base := range origin.Servers {
				if strings.HasPrefix(path, base+"/") || path == base {
					path = strings.TrimPrefix(path, base)
					stripped = true
					break
				}
			}
			if !stripped {
				return nil, false
			}
		}
		segsFor[origin] = splitPath(path)
		return segsFor[origin], true
	}
	var best *Operation
	for _, greedy := range []bool{false, true} {
		for _, op := range s.Operations {
			if op.Method != method {
				continue
			}
			segs, ok := segments(op.origin)
			if !ok || !matchSegments(op.segments, segs, greedy, spanning) {
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

// matchSegments matches a template's segments against a request's. A
// parameter takes one segment, or, when spanning is allowed and the
// parameter is a spanning one, one or more.
func matchSegments(tmpl, got []string, spanning bool, extra []string) bool {
	if len(tmpl) == 0 {
		return len(got) == 0
	}
	if len(got) == 0 {
		return false
	}
	t := tmpl[0]
	switch {
	case !isParam(t):
		return t == got[0] && matchSegments(tmpl[1:], got[1:], spanning, extra)
	case spanning && spansSegments(t, extra):
		for n := 1; n <= len(got)-(len(tmpl)-1); n++ {
			if matchSegments(tmpl[1:], got[n:], spanning, extra) {
				return true
			}
		}
		return false
	default:
		return matchSegments(tmpl[1:], got[1:], spanning, extra)
	}
}

func spansSegments(param string, extra []string) bool {
	name := strings.Trim(param, "{}")
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
