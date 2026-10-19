// Package outputcheck checks collector artifacts against their JSON Schemas
// and the x-epack annotations in them. The SDK runs the checks when a
// collector emits, and the collectortest kit runs them on its runs.
package outputcheck

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"golang.org/x/text/language"
	"golang.org/x/text/message"
)

// Check names.
const (
	CheckSchema         = "schema"
	CheckSchemaUnusable = "schema_unusable"
	CheckPopulation     = "population"
	CheckNulls          = "nulls"
	CheckRollups        = "rollups"
	CheckLevels         = "levels"
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
		f := Finding{Check: CheckSchema, Path: path, Pointer: pointer(e.InstanceLocation), Message: e.ErrorKind.LocalizedString(printer)}
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
	for _, token := range strings.Split(ptr[1:], "/") {
		token = unescape(token)
		switch node := cur.(type) {
		case map[string]any:
			next, ok := node[token]
			if !ok {
				return nil, false
			}
			cur = next
		case []any:
			idx, err := strconv.Atoi(token)
			if err != nil || idx < 0 || idx >= len(node) || (len(token) > 1 && token[0] == '0') {
				return nil, false
			}
			cur = node[idx]
		default:
			return nil, false
		}
	}
	return cur, true
}

func pointer(tokens []string) string {
	var sb strings.Builder
	for _, t := range tokens {
		sb.WriteByte('/')
		sb.WriteString(escape(t))
	}
	return sb.String()
}

func escape(token string) string {
	return strings.ReplaceAll(strings.ReplaceAll(token, "~", "~0"), "/", "~1")
}

func unescape(token string) string {
	return strings.ReplaceAll(strings.ReplaceAll(token, "~1", "/"), "~0", "~")
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
