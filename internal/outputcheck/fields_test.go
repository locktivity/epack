package outputcheck

import (
	"slices"
	"testing"
)

const fieldsSchema = `{
  "type": "object",
  "properties": {
    "version": {"type": "string"},
    "summary": {"$ref": "#/$defs/summary"},
    "by_os": {"type": "object", "additionalProperties": {"type": "integer"}},
    "controls": {"type": "object", "additionalProperties": {"type": "object", "properties": {"state": {"type": "string"}}}},
    "hosts": {"type": "array", "items": {"type": "object", "properties": {
      "name": {"type": "string"},
      "names": {"type": "array", "items": {"type": "string"}},
      "record": {"oneOf": [{"$ref": "#/$defs/record"}, {"type": "null"}]}
    }}}
  },
  "$defs": {
    "summary": {"type": "object", "properties": {"count": {"type": "integer"}, "pct": {"type": ["number", "null"]}}},
    "record": {"type": "object", "properties": {"valid": {"type": "boolean"}}}
  }
}`

func TestFieldsListsEveryValueThatHoldsNoNamedProperties(t *testing.T) {
	s, err := Compile([]byte(fieldsSchema))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"/by_os", "/controls/*/state", "/hosts/*/name", "/hosts/*/names", "/hosts/*/record/valid", "/summary/count", "/summary/pct", "/version"}
	if got := Fields(s); !slices.Equal(got, want) {
		t.Errorf("Fields = %v, want %v", got, want)
	}
}

func TestWrittenListsTheFieldsADocumentHolds(t *testing.T) {
	s, err := Compile([]byte(fieldsSchema))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := Decode([]byte(`{"version": "1", "summary": {"pct": null}, "by_os": {"linux": 2}, "controls": {"firewall": {"state": "pass"}},
	  "hosts": [{"name": "a", "names": ["a", "b"], "record": null}, {"record": {"valid": true}}]}`))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"/by_os", "/controls/firewall/state", "/hosts/0/name", "/hosts/0/names", "/hosts/0/record", "/hosts/1/record/valid", "/summary/pct", "/version"}
	if got := Written(s, doc); !slices.Equal(got, want) {
		t.Errorf("Written = %v, want %v", got, want)
	}
}

func TestFieldOfNamesTheFieldAPointerIsIn(t *testing.T) {
	s, err := Compile([]byte(fieldsSchema))
	if err != nil {
		t.Fatal(err)
	}
	for pointer, want := range map[string]string{
		"/hosts/3/record/valid":    "/hosts/*/record/valid",
		"/controls/firewall/state": "/controls/*/state",
		"/by_os/linux":             "/by_os/linux",
		"/summary/count":           "/summary/count",
	} {
		if got := FieldOf(s, pointer); got != want {
			t.Errorf("FieldOf(%s) = %s, want %s", pointer, got, want)
		}
	}
}

func TestListsNamesArraysOfObjectsOnly(t *testing.T) {
	s, err := Compile([]byte(fieldsSchema))
	if err != nil {
		t.Fatal(err)
	}
	if got := Lists(s); !slices.Equal(got, []string{"/hosts"}) {
		t.Errorf("Lists = %v, want [/hosts]", got)
	}
}
