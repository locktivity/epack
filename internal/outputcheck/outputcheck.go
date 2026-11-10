// Package outputcheck checks collector artifacts against their JSON Schemas
// and the x-epack annotations in them. The SDK runs the checks when a
// collector emits, and the collectortest kit runs them on its runs.
package outputcheck

import (
	"bytes"
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/santhosh-tekuri/jsonschema/v6/kind"
	"golang.org/x/text/language"
	"golang.org/x/text/message"

	"github.com/locktivity/epack/internal/jsonpointer"
)

// Check names.
const (
	CheckSchema         = "schema"
	CheckSchemaUnusable = "schema_unusable"
	CheckPopulation     = "population"
	CheckNulls          = "nulls"
	CheckRollups        = "rollups"
	CheckRatios         = "ratios"
	CheckLevels         = "levels"
	CheckTargets        = "targets"
)

// Finding is one problem a check found in an artifact.
type Finding struct {
	Check   string
	Path    string
	Pointer string
	Message string
}

// Gap locates a value an artifact left out.
type Gap struct {
	Path    string
	Pointer string
}

// Schema is a compiled JSON Schema and the document its annotations are read
// from.
type Schema struct {
	validator *jsonschema.Schema
	root      any
	patterns  sync.Map
}

type compileResult struct {
	schema *Schema
	err    error
}

var compiled sync.Map

// Compile compiles a schema held in memory. It loads nothing from disk or the
// network, so a ref outside the schema fails to compile. Results are kept by
// content, so each schema compiles once per process.
func Compile(raw []byte) (*Schema, error) {
	sum := sha256.Sum256(raw)
	if v, ok := compiled.Load(sum); ok {
		r := v.(compileResult)
		return r.schema, r.err
	}
	s, err := compile(raw, hex.EncodeToString(sum[:]))
	compiled.Store(sum, compileResult{schema: s, err: err})
	return s, err
}

func compile(raw []byte, name string) (*Schema, error) {
	doc, err := Decode(raw)
	if err != nil {
		return nil, err
	}
	root, err := Decode(raw)
	if err != nil {
		return nil, err
	}
	url := "https://schemas.componentsdk.invalid/" + name + ".json"
	c := jsonschema.NewCompiler()
	c.UseLoader(noLoader{})
	if err := c.AddResource(url, doc); err != nil {
		return nil, err
	}
	validator, err := c.Compile(url)
	if err != nil {
		return nil, err
	}
	return &Schema{validator: validator, root: root}, nil
}

type noLoader struct{}

func (noLoader) Load(url string) (any, error) {
	return nil, fmt.Errorf("refs outside the schema are not loaded: %s", url)
}

// CompileFile compiles the schema file at path. Refs to other local files load
// from disk.
func CompileFile(path string) (*Schema, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	root, err := Decode(raw)
	if err != nil {
		return nil, err
	}
	validator, err := jsonschema.NewCompiler().Compile(path)
	if err != nil {
		return nil, err
	}
	return &Schema{validator: validator, root: root}, nil
}

// Decode parses JSON for the checks, keeping numbers exact.
func Decode(raw []byte) (any, error) {
	return jsonschema.UnmarshalJSON(bytes.NewReader(raw))
}

var printer = message.NewPrinter(language.English)

// Validate checks doc, the artifact at path, against the schema. Each failing
// keyword is one finding at the value it failed on.
func Validate(s *Schema, path string, doc any) []Finding {
	return validate(s, path, doc, nil)
}

// ValidateAt checks doc as Validate does, for an artifact emitted at level.
// A property the schema requires but places above level, with x-epack-level
// on the property or on a value that holds it, is not reported missing: the
// level leaves it out. A field can then stay required for the runs that
// write it.
func ValidateAt(s *Schema, path string, doc any, level string) []Finding {
	rank := rankOf(level)
	return validate(s, path, doc, func(e *jsonschema.ValidationError) (string, bool) {
		required, ok := e.ErrorKind.(*kind.Required)
		if !ok {
			return "", true
		}
		missing := s.requiredAt(doc, jsonpointer.Format(e.InstanceLocation), required.Missing, rank)
		if len(missing) == 0 {
			return "", false
		}
		return (&kind.Required{Missing: missing}).LocalizedString(printer), true
	})
}

// requiredAt returns the properties among missing, required of the object at
// ptr in doc, that the schema places at or below rank.
func (s *Schema) requiredAt(doc any, ptr string, missing []string, rank int) []string {
	v, at, ok := s.levelAt(doc, ptr)
	if !ok {
		return missing
	}
	var out []string
	for _, name := range missing {
		if max(at, levelOf(s.member(v, name))) <= rank {
			out = append(out, name)
		}
	}
	return out
}

// validate runs the schema's validator. keep, when set, decides for each
// failing keyword whether it is a finding, and may give its message.
func validate(s *Schema, path string, doc any, keep func(*jsonschema.ValidationError) (string, bool)) []Finding {
	err := s.validator.Validate(doc)
	if err == nil {
		return nil
	}
	var verr *jsonschema.ValidationError
	if !errors.As(err, &verr) {
		return []Finding{{Check: CheckSchema, Path: path, Message: err.Error()}}
	}
	seen := map[Finding]bool{}
	var out []Finding
	var walk func(e *jsonschema.ValidationError)
	walk = func(e *jsonschema.ValidationError) {
		if len(e.Causes) > 0 {
			for _, cause := range e.Causes {
				walk(cause)
			}
			return
		}
		message := e.ErrorKind.LocalizedString(printer)
		if keep != nil {
			text, ok := keep(e)
			if !ok {
				return
			}
			message = cmp.Or(text, message)
		}
		f := Finding{Check: CheckSchema, Path: path, Pointer: jsonpointer.Format(e.InstanceLocation), Message: message}
		if !seen[f] {
			seen[f] = true
			out = append(out, f)
		}
	}
	walk(verr)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Pointer != out[j].Pointer {
			return out[i].Pointer < out[j].Pointer
		}
		return out[i].Message < out[j].Message
	})
	return out
}

// Resolve returns the value at an RFC 6901 pointer in doc and whether it
// exists.
func Resolve(doc any, ptr string) (any, bool) {
	if ptr == "" {
		return doc, true
	}
	if !strings.HasPrefix(ptr, "/") {
		return nil, false
	}
	cur := doc
	for _, token := range jsonpointer.Tokens(ptr) {
		switch node := cur.(type) {
		case map[string]any:
			next, ok := node[token]
			if !ok {
				return nil, false
			}
			cur = next
		case []any:
			idx, ok := jsonpointer.Index(token)
			if !ok || idx >= len(node) {
				return nil, false
			}
			cur = node[idx]
		default:
			return nil, false
		}
	}
	return cur, true
}

// pattern compiles a patternProperties key once per schema. A pattern Go
// cannot compile matches nothing.
func (s *Schema) pattern(p string) *regexp.Regexp {
	if v, ok := s.patterns.Load(p); ok {
		re, _ := v.(*regexp.Regexp)
		return re
	}
	re, _ := regexp.Compile(p)
	s.patterns.Store(p, re)
	return re
}
