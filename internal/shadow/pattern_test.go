package shadow

import "testing"

func TestPatternsKeepOnlyWhatTheSchemaNames(t *testing.T) {
	s := parseSchema([]byte(`{
	  "$defs": {"repo": {"type": "object", "properties": {"name": {"type": "string"}, "protected": {"type": "boolean", "x-epack-level": "audit"}}}},
	  "type": "object",
	  "properties": {
	    "repos": {"type": "array", "items": {"$ref": "#/$defs/repo"}},
	    "regions": {"type": "object", "additionalProperties": {"type": "object", "properties": {"enabled": {"type": "boolean"}}}}
	  }
	}`))
	w := newWalker(s, s)
	for pointer, want := range map[string]string{
		"/repos/3/name":              "/repos/*/name",
		"/regions/us-east-1/enabled": "/regions/{key}/enabled",
		"/undeclared/0":              "/{key}/{key}",
		"/a~1b":                      "/{key}",
	} {
		if got := w.pointerPattern(pointer); got != want {
			t.Errorf("pointerPattern(%q) = %q, want %q", pointer, got, want)
		}
	}
	if got := w.levelAt("/repos/*/protected"); got != "audit" {
		t.Errorf("levelAt = %q, want audit", got)
	}
	if got := newWalker(nil, nil).pointerPattern("/acme/0/name"); got != "/{key}/*/{key}" {
		t.Errorf("without a schema = %q, want every key hidden", got)
	}
}

func TestFilePatternHidesIdentifiers(t *testing.T) {
	for path, want := range map[string]string{
		"artifacts/github.json":                                      "artifacts/github.json",
		"artifacts/aws.cloud-posture.json":                           "artifacts/aws.cloud-posture.json",
		"artifacts/documents/3f2a9c1e-7b4d-4e8a-9c1f-2b3d4e5f6a7b/x": "artifacts/documents/{id}/x",
	} {
		if got := filePattern(path); got != want {
			t.Errorf("filePattern(%q) = %q, want %q", path, got, want)
		}
	}
}

func TestClassify(t *testing.T) {
	a := map[string]string{"/r/0": "1", "/r/1": "2"}
	for name, tc := range map[string]struct {
		locked, candidate map[string]string
		want              string
	}{
		"same":      {a, map[string]string{"/r/0": "1", "/r/1": "2"}, ""},
		"reordered": {a, map[string]string{"/r/0": "2", "/r/1": "1"}, "reordered"},
		"changed":   {a, map[string]string{"/r/0": "1", "/r/1": "3"}, "changed"},
		"added":     {nil, a, "added"},
		"removed":   {a, nil, "removed"},
	} {
		if got := classify(tc.locked, tc.candidate); got != tc.want {
			t.Errorf("%s: classify = %q, want %q", name, got, tc.want)
		}
	}
}
