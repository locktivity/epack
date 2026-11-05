package outputcheck

import (
	"strings"
	"testing"
)

const methodsBase = `{
	"type": "object",
	"properties": {
		"count": {"type": ["integer", "null"], "x-epack-label": "Count"},
		"rows": {"type": "array", "items": {"$ref": "#/$defs/row"}},
		"pair": {"type": "object", "properties": {"a": {"$ref": "#/$defs/flag"}, "b": {"$ref": "#/$defs/flag"}}},
		"first": {"$ref": "#/$defs/shared"},
		"second": {"$ref": "#/$defs/shared"}
	},
	"$defs": {
		"row": {"type": "object", "properties": {"ok": {"type": "boolean"}, "port": {"type": "integer", "minimum": 1.5e0}}},
		"flag": {"type": "boolean"},
		"shared": {"type": "object", "properties": {"n": {"type": "integer"}}}
	}
}`

func TestAddMethodsWritesEachSentenceOnItsField(t *testing.T) {
	out, problems, err := AddMethods([]byte(methodsBase), map[string]string{
		"/count":      "Counts the rows.",
		"/rows/*/ok":  "Reads each row's flag.",
		"/pair/a":     "Reads a.",
		"/pair/b":     "Reads b.",
		"/first/n":    "Counts n.",
		"/second/n":   "Counts n another way.",
		"/rows/*/nil": "Reads nothing.",
		"count":       "Not a pointer.",
	})
	if err != nil {
		t.Fatal(err)
	}
	s := mustCompile(t, string(out))
	for ptr, want := range map[string]string{
		"/count": "Counts the rows.", "/rows/0/ok": "Reads each row's flag.",
		"/pair/a": "Reads a.", "/pair/b": "Reads b.", "/first/n": "Counts n.",
	} {
		if got := MethodAt(s, ptr); got != want {
			t.Errorf("method at %s = %q, want %q", ptr, got, want)
		}
	}
	if !strings.Contains(string(out), `"minimum":1.5e0`) && !strings.Contains(string(out), `"minimum":1.5`) {
		t.Errorf("a number in the schema changed: %s", out)
	}
	want := "/rows/*/nil names no field of the schema; /first/n and /second/n are declared by one schema, so one sentence has to cover both; count names no field of the schema"
	if got := strings.Join(problems, "; "); got != want {
		t.Errorf("problems = %s\nwant       %s", got, want)
	}
}

func TestAddMethodsWritesAMapValuesSentenceOnItsAdditionalProperties(t *testing.T) {
	const base = `{
		"type": "object",
		"properties": {
			"by_os": {"type": "object", "additionalProperties": {"$ref": "#/$defs/count", "x-epack-label": "Devices"}},
			"by_kind": {"type": "object", "properties": {"other": {"type": "integer"}}, "additionalProperties": {"type": "integer"}}
		},
		"$defs": {"count": {"type": "integer"}}
	}`
	out, problems, err := AddMethods([]byte(base), map[string]string{
		"/by_os/*":       "Counts the devices with each OS.",
		"/by_kind/other": "Counts the rest.",
		"/by_kind/macos": "Counts each kind.",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(problems) != 0 {
		t.Errorf("problems = %v, want none", problems)
	}
	s := mustCompile(t, string(out))
	for ptr, want := range map[string]string{
		"/by_os/macos":   "Counts the devices with each OS.",
		"/by_os/windows": "Counts the devices with each OS.",
		"/by_kind/other": "Counts the rest.",
		"/by_kind/linux": "Counts each kind.",
	} {
		if got := MethodAt(s, ptr); got != want {
			t.Errorf("method at %s = %q, want %q", ptr, got, want)
		}
	}
}
