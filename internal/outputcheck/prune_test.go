package outputcheck

import (
	"strings"
	"testing"
)

func TestPrune(t *testing.T) {
	s := mustCompile(t, `{
		"type": "object",
		"properties": {
			"summary": {"type": "integer"},
			"users": {"type": "array", "x-epack-level": "audit", "items": {"properties": {"id": {}, "email": {"x-epack-level": "internal"}}}},
			"rows": {"type": "array", "prefixItems": [{}, {"x-epack-level": "audit"}], "items": {}},
			"a/b~c": {"x-epack-level": "audit"},
			"detail": {"$ref": "#/$defs/internal"}
		},
		"$defs": {"internal": {"x-epack-level": "internal"}}
	}`)
	raw := `{"users":[{"id":"u1","email":"a@example.test"},{"email":"b@example.test","id":"u2"}],"summary":1,"rows":[1,2,3],"a/b~c":true,"detail":null}`
	cases := map[string]string{
		"trust":    `{"summary":1,"rows":[1,3]}`,
		"audit":    `{"users":[{"id":"u1"},{"id":"u2"}],"summary":1,"rows":[1,2,3],"a/b~c":true}`,
		"internal": raw,
	}
	for level, want := range cases {
		got, err := Prune(s, []byte(raw), level)
		if err != nil {
			t.Fatalf("%s: %v", level, err)
		}
		if string(got) != want {
			t.Errorf("%s: %s\nwant %s", level, got, want)
		}
	}

	// A container with nothing dropped from it is copied as it is, including
	// spacing and escapes.
	spaced := `{"keep": {"x": "<b>",  "y": [1, 2]}, "a/b~c": 1}`
	if got, err := Prune(s, []byte(spaced), "trust"); err != nil || string(got) != `{"keep":{"x": "<b>",  "y": [1, 2]}}` {
		t.Errorf("trust: %s, %v", got, err)
	}

	whole := mustCompile(t, `{"x-epack-level": "audit"}`)
	if _, err := Prune(whole, []byte(`{}`), "trust"); err == nil || !strings.Contains(err.Error(), "whole document") {
		t.Errorf("a document marked audit at trust: %v, want an error", err)
	}
	if _, err := Prune(s, []byte(`{`), "trust"); err == nil {
		t.Error("a document that does not decode should fail")
	}
}
