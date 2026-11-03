package collectortest

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/locktivity/epack/internal/outputcheck"
)

// The responses check validates a suite's canned answers against the
// vendor's own API. Each successful answer to an operation in
// Suite.ResponseSchemas must match the schema the vendor publishes for it.
// The answer must also hold no field the schema does not define. Without the
// check, a hand-written answer can hold a field the author only assumed the
// vendor sends, such as a status on an API token. A collector that reads
// that field then passes its tests but is wrong on the vendor's real
// answers.

// compileResponseSchemas makes each of Suite.ResponseSchemas strict and
// compiles it. It returns the compiled schemas by operation.
func compileResponseSchemas(schemas map[string][]byte) (map[string]*outputcheck.Schema, error) {
	out := map[string]*outputcheck.Schema{}
	for op, raw := range schemas {
		var doc any
		if err := json.Unmarshal(raw, &doc); err != nil {
			return nil, fmt.Errorf("the response schema for %s is not JSON: %w", op, err)
		}
		strict, err := json.Marshal(strictSchema(doc, false))
		if err != nil {
			return nil, err
		}
		s, err := outputcheck.Compile(strict)
		if err != nil {
			return nil, fmt.Errorf("the response schema for %s does not compile: %w", op, err)
		}
		out[op] = s
	}
	return out, nil
}

// strictSchema adds unevaluatedProperties: false to each object schema that
// sets no rule for properties it does not list. A field the vendor's schema
// does not define then fails validation. A branch of allOf, anyOf, or oneOf
// is left as it is. The parent's unevaluatedProperties accounts for the
// properties every branch defines and covers the object as a whole. A
// definition in $defs or definitions is left as it is too, since it may be
// a branch through a $ref. The schema that holds the $ref gets the rule
// instead, and it accounts for the properties the definition defines.
func strictSchema(v any, branch bool) any {
	switch n := v.(type) {
	case map[string]any:
		for key, child := range n {
			switch key {
			case "allOf", "anyOf", "oneOf":
				if list, ok := child.([]any); ok {
					for i, item := range list {
						list[i] = strictSchema(item, true)
					}
				}
			case "properties", "patternProperties", "dependentSchemas":
				if m, ok := child.(map[string]any); ok {
					for k, item := range m {
						m[k] = strictSchema(item, false)
					}
				}
			case "$defs", "definitions":
				if m, ok := child.(map[string]any); ok {
					for k, item := range m {
						m[k] = strictSchema(item, true)
					}
				}
			case "items", "additionalProperties", "not", "if", "then", "else", "contains", "unevaluatedItems":
				n[key] = strictSchema(child, false)
			case "prefixItems":
				if list, ok := child.([]any); ok {
					for i, item := range list {
						list[i] = strictSchema(item, false)
					}
				}
			}
		}
		_, hasProps := n["properties"]
		_, composed := n["allOf"]
		_, anyOf := n["anyOf"]
		_, oneOf := n["oneOf"]
		_, ref := n["$ref"]
		_, additional := n["additionalProperties"]
		_, unevaluated := n["unevaluatedProperties"]
		if !branch && (hasProps || composed || anyOf || oneOf || ref) && !additional && !unevaluated {
			n["unevaluatedProperties"] = false
		}
		return n
	}
	return v
}

// checkResponses validates a scenario's successful canned answers against
// the response schema of each operation that consumed them in its run.
func (k *kit) checkResponses(label string, sc Scenario, n *network) {
	if len(k.responseSchemas) == 0 || n == nil {
		return
	}
	ops := n.replay.operationsFor()
	for i, r := range sc.Responses {
		if r.Status != 0 && (r.Status < 200 || r.Status > 299) {
			continue
		}
		for _, op := range ops[i] {
			s := k.responseSchemas[op]
			if s == nil {
				continue
			}
			doc, err := outputcheck.Decode([]byte(k.textOf(op, r)))
			if err != nil {
				k.violate("responses", label, "the canned answer to %s at %s is not JSON, so it cannot match the vendor's schema", op, describeResponse(r))
				continue
			}
			for _, f := range outputcheck.Validate(s, "", doc) {
				k.violate("responses", label, "the canned answer to %s at %s does not match the vendor's schema at %s: %s. A canned answer must hold what the vendor sends",
					op, describeResponse(r), pointerLabel(f.Pointer), readableSchemaMessage(f.Message))
			}
		}
	}
}

func describeResponse(r Response) string {
	if r.URL != "" {
		return r.URL
	}
	return "operation " + r.Operation
}

// readableSchemaMessage turns a failure of the unevaluatedProperties the
// check adds into a readable message. The validator reports that failure as
// a false schema.
func readableSchemaMessage(m string) string {
	if m == "false schema" || strings.Contains(m, "unevaluatedProperties") {
		return "a field the vendor's schema does not define"
	}
	return m
}
