package roster

import (
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"

	"github.com/locktivity/epack/componentsdk"
	"github.com/locktivity/epack/internal/outputcheck"
)

// The normalized schemas Derive gives values for.
const (
	IDPPosture      = "evidencepack/idp-posture@v1"
	CloudPosture    = "evidencepack/cloud-posture@v1"
	AccessPosture   = "evidencepack/access-posture@v1"
	EndpointPosture = "evidencepack/endpoint-posture@v1"
	VulnScanning    = "evidencepack/vuln-scanning@v1"
	VCSPosture      = "evidencepack/vcs-posture@v1"
	TLS             = "evidencepack/tls@v1"
	EmailDNS        = "evidencepack/email-dns@v1"
)

// schemaIDs maps each normalized schema's short name to its ID.
var schemaIDs = map[string]string{}

func init() {
	for _, id := range []string{IDPPosture, CloudPosture, AccessPosture, EndpointPosture, VulnScanning, VCSPosture, TLS, EmailDNS} {
		schemaIDs[shortName(id)] = id
	}
}

// shortName is a schema's name without its namespace and version, such as
// idp-posture.
func shortName(schemaID string) string {
	name := strings.TrimPrefix(schemaID, "evidencepack/")
	name, _, _ = strings.Cut(name, "@")
	return name
}

// identities names, for each list of objects in a normalized schema, the
// fields that tell one entry from another, by the list's pointer with * for
// any index above it.
var identities = map[string]map[string][]string{
	CloudPosture:  {"/accounts": {"account_id"}},
	AccessPosture: {"/scopes": {"id"}},
	VulnScanning:  {"/scanners": {"scanner", "category"}, "/scopes": {"id"}, "/scopes/*/scanners": {"scanner", "category"}},
	TLS:           {"/endpoints": {"host", "port"}},
	EmailDNS:      {"/domains": {"domain"}, "/domains/*/mx": {"host"}, "/domains/*/dkim": {"selector"}},
	EndpointPosture: {
		"/availability": {"path"}, "/devices": {"device_id"}, "/devices/*/local_admin_accounts": {"account_id"},
		"/devices/*/findings": {"finding_id"}, "/devices/*/protection_modules": {"kind"},
	},
}

// notDerived lists the fields of the identity and cloud schemas, and of every
// schema, that Derive gives no value for, by pointer with * for any index,
// each with the reason a tenant doesn't determine it. Each domain lists its
// own schema's.
var notDerived = map[string]map[string]string{
	"": {
		"/collected_at":   "the time of the run",
		"/schema_version": "the SDK version that wrote the artifact, where the schema doesn't fix it",
	},
}

// NotDerived lists the fields of schemaID that Derive gives no value for,
// whatever the roster, by pointer with * for any index or member of an
// object keyed by name, each with the reason.
func NotDerived(schemaID string) map[string]string {
	out := maps.Clone(notDerived[""])
	maps.Copy(out, notDerived[schemaID])
	for _, d := range domains {
		maps.Copy(out, d.notDerived[schemaID])
	}
	return out
}

// Uncovered lists the fields an artifact of schemaID writes that values,
// what Derive gives for that schema, has no value for, by pointer. It leaves
// out the fields NotDerived lists. A field is a value that holds no object
// with named properties, as outputcheck.Fields says, so an object keyed by
// name whose members are such objects, such as a device's controls, is
// compared member by member. A test that compares a collector's artifact
// with what a roster determines calls it to find what the comparison
// doesn't reach.
func Uncovered(schemaID string, artifact []byte, values map[string]any) ([]string, error) {
	s, err := compileSchema(schemaID)
	if err != nil {
		return nil, err
	}
	doc, err := outputcheck.Decode(artifact)
	if err != nil {
		return nil, fmt.Errorf("%s artifact: %w", schemaID, err)
	}
	aligned := Align(schemaID, doc, values)
	exempt := NotDerived(schemaID)
	var out []string
	for _, pointer := range outputcheck.Written(s, doc) {
		if _, ok := aligned[pointer]; ok {
			continue
		}
		if _, ok := exempt[outputcheck.FieldOf(s, pointer)]; ok {
			continue
		}
		out = append(out, pointer)
	}
	return out, nil
}

// Unanswered lists the fields of schemaID that no values in derived hold and
// NotDerived doesn't list, by pointer with * for any index. A test that
// derives values from rosters that between them have every part of a tenant
// calls it to find fields Derive has no rule for.
func Unanswered(schemaID string, derived []map[string]any) ([]string, error) {
	s, err := compileSchema(schemaID)
	if err != nil {
		return nil, err
	}
	answered := map[string]bool{}
	for _, values := range derived {
		for pointer := range values {
			answered[outputcheck.FieldOf(s, pointer)] = true
		}
	}
	exempt := NotDerived(schemaID)
	var out []string
	for _, field := range outputcheck.Fields(s) {
		if _, ok := exempt[field]; !ok && !answered[field] {
			out = append(out, field)
		}
	}
	return out, nil
}

// AboveLevel reports whether a collector run at level, such as trust, leaves
// out the value at pointer in an artifact of schemaID, because the schema
// places it, or a value that holds it, above that level with
// x-epack-level. A test that compares Derive's values with a run below the
// audit level calls it to drop the values the run doesn't write.
func AboveLevel(schemaID, pointer, level string) (bool, error) {
	s, err := compileSchema(schemaID)
	if err != nil {
		return false, err
	}
	return outputcheck.PointerAbove(s, pointer, level), nil
}

func compileSchema(schemaID string) (*outputcheck.Schema, error) {
	raw := componentsdk.NormalizedSchemaJSON(schemaID)
	if raw == nil {
		return nil, fmt.Errorf("the SDK has no normalized schema %s", schemaID)
	}
	return outputcheck.Compile(raw)
}

// pattern puts * in place of each index in pointer.
func pattern(pointer string) string {
	tokens := strings.Split(pointer, "/")
	for i, t := range tokens {
		if isIndex(t) {
			tokens[i] = "*"
		}
	}
	return strings.Join(tokens, "/")
}

// Align renumbers the list entries in values, what Derive gives for
// schemaID or Settle's Expect for each value, to match doc, an artifact of
// that schema decoded from JSON. An entry matches the artifact's entry
// whose identity fields hold the same values, or, when Derive gives no
// identity for it, the entry at its own index. An entry that matches none
// moves past the artifact's last entry, so a lookup in the artifact finds
// nothing there.
func Align(schemaID string, doc any, values map[string]any) map[string]any {
	out := maps.Clone(values)
	lists := slices.Collect(maps.Keys(identities[schemaID]))
	slices.SortFunc(lists, func(a, b string) int {
		if c := strings.Count(a, "/") - strings.Count(b, "/"); c != 0 {
			return c
		}
		return strings.Compare(a, b)
	})
	for _, list := range lists {
		fields := identities[schemaID][list]
		for _, at := range instances(list, out) {
			docList, _ := lookup(doc, at).([]any)
			used := make([]bool, len(docList))
			next := len(docList)
			mapping := map[string]string{}
			for _, i := range entries(at, out) {
				j := -1
				if id, ok := identityOf(out, at+"/"+i, fields); ok {
					j = slices.IndexFunc(docList, func(e any) bool {
						got, ok := identityOf(e, "", fields)
						return ok && got == id
					})
					if j >= 0 && used[j] {
						j = -1
					}
				} else if n, _ := strconv.Atoi(i); n < len(docList) && !used[n] {
					j = n
				}
				if j < 0 {
					j = next
					next++
				} else {
					used[j] = true
				}
				mapping[at+"/"+i] = at + "/" + strconv.Itoa(j)
			}
			renumbered := map[string]any{}
			for pointer, v := range out {
				renumbered[renumber(pointer, at, mapping)] = v
			}
			out = renumbered
		}
	}
	return out
}

// instances lists the lists values has entries in that match list, a
// pointer with * for any index above it.
func instances(list string, values map[string]any) []string {
	depth := strings.Count(list, "/")
	seen := map[string]bool{}
	for pointer := range values {
		tokens := strings.Split(pointer, "/")
		if len(tokens) <= depth+1 || !isIndex(tokens[depth+1]) {
			continue
		}
		at := strings.Join(tokens[:depth+1], "/")
		if pattern(at) == list {
			seen[at] = true
		}
	}
	return slices.Sorted(maps.Keys(seen))
}

// entries lists the indexes values gives entries at in the list at, in
// order.
func entries(at string, values map[string]any) []string {
	seen := map[int]bool{}
	for pointer := range values {
		rest, ok := strings.CutPrefix(pointer, at+"/")
		if !ok {
			continue
		}
		token, _, _ := strings.Cut(rest, "/")
		if n, err := strconv.Atoi(token); err == nil && isIndex(token) {
			seen[n] = true
		}
	}
	var out []string
	for _, n := range slices.Sorted(maps.Keys(seen)) {
		out = append(out, strconv.Itoa(n))
	}
	return out
}

// identityOf gives the identity fields' values of the entry at prefix in
// values, a map of pointers to values or a decoded JSON object, and reports
// whether it has all of them.
func identityOf(values any, prefix string, fields []string) (string, bool) {
	var parts []string
	for _, f := range fields {
		var v any
		var ok bool
		switch src := values.(type) {
		case map[string]any:
			if prefix == "" {
				v, ok = src[f]
			} else {
				v, ok = src[prefix+"/"+f]
			}
		}
		if e, isExpect := v.(Expect); isExpect {
			v, ok = e.Exact, ok && !e.Range && !e.Either
		}
		if !ok || v == nil {
			return "", false
		}
		raw, err := json.Marshal(v)
		if err != nil {
			return "", false
		}
		parts = append(parts, string(raw))
	}
	return strings.Join(parts, "\x00"), true
}

// renumber moves pointer to the entry mapping gives for the entry of the list
// at that holds it.
func renumber(pointer, at string, mapping map[string]string) string {
	rest, ok := strings.CutPrefix(pointer, at+"/")
	if !ok {
		return pointer
	}
	token, tail, _ := strings.Cut(rest, "/")
	to, ok := mapping[at+"/"+token]
	if !ok {
		return pointer
	}
	if tail == "" && !strings.Contains(rest, "/") {
		return to
	}
	return to + "/" + tail
}

// lookup returns the value at pointer in a decoded JSON document, or nil.
func lookup(doc any, pointer string) any {
	if pointer == "" {
		return doc
	}
	cur := doc
	for _, token := range strings.Split(strings.TrimPrefix(pointer, "/"), "/") {
		switch n := cur.(type) {
		case map[string]any:
			cur = n[token]
		case []any:
			i, err := strconv.Atoi(token)
			if err != nil || i < 0 || i >= len(n) {
				return nil
			}
			cur = n[i]
		default:
			return nil
		}
	}
	return cur
}
