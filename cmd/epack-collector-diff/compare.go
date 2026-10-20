package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"math/big"
	"strconv"
	"strings"

	"github.com/locktivity/epack/componentsdk"
)

const (
	kindArtifactAdded   = "artifact_added"
	kindArtifactRemoved = "artifact_removed"
	kindContentChanged  = "content_changed"
	kindValueChanged    = "value_changed"
	kindNewlyNull       = "newly_null"
	kindNewlyAbsent     = "newly_absent"
	kindFieldRemoved    = "field_removed"
	kindFieldAdded      = "field_added"
	kindItemRemoved     = "item_removed"
	kindItemAdded       = "item_added"
	kindStatusChanged   = "status_changed"
	kindSeverityChanged = "severity_changed"
)

// change is one difference between the base and head runs of a scenario.
// Base and Head hold the JSON value on each side and are left out where the
// value is absent. For a file they hold its size and digest, and for a
// control change each side's outcome. A scenario lists its evidence changes
// in artifact and pointer order, then its control changes.
type change struct {
	Kind        string          `json:"kind"`
	Artifact    string          `json:"artifact,omitempty"`
	Pointer     string          `json:"pointer,omitempty"`
	Requirement string          `json:"requirement,omitempty"`
	Name        string          `json:"name,omitempty"`
	Base        json.RawMessage `json:"base,omitempty"`
	Head        json.RawMessage `json:"head,omitempty"`
}

func (c change) control() bool {
	return c.Kind == kindStatusChanged || c.Kind == kindSeverityChanged
}

func compareTrees(base, head *tree) *report {
	keys := map[string]bool{}
	for k := range base.scenarios {
		keys[k] = true
	}
	for k := range head.scenarios {
		keys[k] = true
	}
	r := &report{Scenarios: []scenarioReport{}}
	for _, k := range sortedKeys(keys) {
		b, h := base.scenarios[k], head.scenarios[k]
		sr := scenarioReport{Changes: []change{}}
		switch {
		case h == nil:
			sr.Suite, sr.Scenario, sr.Status = b.suite, b.name, statusRemoved
		case b == nil:
			sr.Suite, sr.Scenario, sr.Status = h.suite, h.name, statusAdded
		default:
			sr.Suite, sr.Scenario, sr.Status = h.suite, h.name, statusCompared
			sr.Changes = compareFiles(evidence(base, b, head), evidence(head, h, base))
		}
		r.Scenarios = append(r.Scenarios, sr)
	}
	return r
}

// evidence returns a scenario's files without the collector build file. It
// describes the build rather than the evidence, and its trace map moves
// with every edit to the collector's code.
func evidence(t *tree, sc *scenario, other *tree) map[string][]byte {
	out := make(map[string][]byte, len(sc.files))
	for path, data := range sc.files {
		if t.schema(sc.key(), path, other) != componentsdk.BuildSchema {
			out[path] = data
		}
	}
	return out
}

func compareFiles(base, head map[string][]byte) []change {
	paths := map[string]bool{}
	for p := range base {
		paths[p] = true
	}
	for p := range head {
		paths[p] = true
	}
	changes := []change{}
	for _, p := range sortedKeys(paths) {
		b, inBase := base[p]
		h, inHead := head[p]
		switch {
		case !inHead:
			changes = append(changes, change{Kind: kindArtifactRemoved, Artifact: p, Base: fileInfo(b)})
		case !inBase:
			changes = append(changes, change{Kind: kindArtifactAdded, Artifact: p, Head: fileInfo(h)})
		case bytes.Equal(b, h):
		default:
			bv, bok := decodeJSON(b)
			hv, hok := decodeJSON(h)
			if bok && hok {
				compareJSON(p, "", bv, hv, &changes)
			} else {
				changes = append(changes, change{Kind: kindContentChanged, Artifact: p, Base: fileInfo(b), Head: fileInfo(h)})
			}
		}
	}
	return changes
}

func fileInfo(data []byte) json.RawMessage {
	sum := sha256.Sum256(data)
	return mustJSON(map[string]any{"bytes": len(data), "sha256": hex.EncodeToString(sum[:])})
}

// decodeJSON decodes a whole file as one JSON value, keeping numbers as
// written. A file with trailing data counts as not JSON, so it is compared
// by its bytes.
func decodeJSON(data []byte) (any, bool) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, false
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, false
	}
	return v, true
}

// compareJSON walks both values together and adds a change for each value
// that differs, addressed by JSON pointer. A member or item present on one
// side only is reported once, with its whole value.
func compareJSON(artifact, pointer string, base, head any, out *[]change) {
	switch b := base.(type) {
	case map[string]any:
		h, ok := head.(map[string]any)
		if !ok {
			*out = append(*out, valueChange(artifact, pointer, base, head))
			return
		}
		keys := map[string]bool{}
		for k := range b {
			keys[k] = true
		}
		for k := range h {
			keys[k] = true
		}
		for _, k := range sortedKeys(keys) {
			child := pointer + "/" + escapePointer(k)
			bv, inBase := b[k]
			hv, inHead := h[k]
			switch {
			case !inHead && bv == nil:
				*out = append(*out, change{Kind: kindFieldRemoved, Artifact: artifact, Pointer: child, Base: mustJSON(bv)})
			case !inHead:
				*out = append(*out, change{Kind: kindNewlyAbsent, Artifact: artifact, Pointer: child, Base: mustJSON(bv)})
			case !inBase:
				*out = append(*out, change{Kind: kindFieldAdded, Artifact: artifact, Pointer: child, Head: mustJSON(hv)})
			default:
				compareJSON(artifact, child, bv, hv, out)
			}
		}
	case []any:
		h, ok := head.([]any)
		if !ok {
			*out = append(*out, valueChange(artifact, pointer, base, head))
			return
		}
		for i := 0; i < max(len(b), len(h)); i++ {
			child := pointer + "/" + strconv.Itoa(i)
			switch {
			case i >= len(h):
				*out = append(*out, change{Kind: kindItemRemoved, Artifact: artifact, Pointer: child, Base: mustJSON(b[i])})
			case i >= len(b):
				*out = append(*out, change{Kind: kindItemAdded, Artifact: artifact, Pointer: child, Head: mustJSON(h[i])})
			default:
				compareJSON(artifact, child, b[i], h[i], out)
			}
		}
	default:
		if !scalarEqual(base, head) {
			*out = append(*out, valueChange(artifact, pointer, base, head))
		}
	}
}

func valueChange(artifact, pointer string, base, head any) change {
	kind := kindValueChanged
	if head == nil {
		kind = kindNewlyNull
	}
	return change{Kind: kind, Artifact: artifact, Pointer: pointer, Base: mustJSON(base), Head: mustJSON(head)}
}

// scalarEqual compares numbers by value, so 50 and 50.0 are equal and two
// large integers never round to the same float.
func scalarEqual(a, b any) bool {
	an, aok := a.(json.Number)
	bn, bok := b.(json.Number)
	if aok && bok {
		ar, aok := new(big.Rat).SetString(string(an))
		br, bok := new(big.Rat).SetString(string(bn))
		if aok && bok {
			return ar.Cmp(br) == 0
		}
		return an == bn
	}
	return a == b
}

func escapePointer(key string) string {
	return strings.NewReplacer("~", "~0", "/", "~1").Replace(key)
}

// mustJSON encodes a value decoded from JSON or built here, which always
// encodes.
func mustJSON(v any) json.RawMessage {
	data, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return data
}
