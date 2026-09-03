package mapping

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

const validYAML = `
schema_version: "1.0.0"
captured_at: "2026-08-28T14:02:11Z"
profile:
  id: acme/security-baseline@v1
  digest: sha256:9f2c41d6e8a3b7c015d94f6a2e8b1c7d3a5f0e9b8c6d4a2f1e0d9c8b7a6f5e4d
mappings:
  - requirement: access-authorization
    evidence:
      artifact: artifacts/idp-posture.json
      pointer: /policy/phishing_resistant_required_for_privileged
    label: Phishing-resistant MFA required for privileged users
  - control: PL-01
    evidence:
      document_id: doc-8f2c1a9e
      quote:
        exact: reviewed at least annually
    label: Information Security Policy.pdf
`

func TestParseAndCheckValidDocument(t *testing.T) {
	doc, err := Parse([]byte(validYAML))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if doc.Profile.ID != "acme/security-baseline@v1" {
		t.Errorf("profile id = %q", doc.Profile.ID)
	}
	if len(doc.Mappings) != 2 {
		t.Fatalf("mappings = %d, want 2", len(doc.Mappings))
	}
	if warnings := doc.Check(); len(warnings) != 0 {
		t.Errorf("unexpected warnings: %v", warnings)
	}
}

func TestCheckFlagsMalformedEntries(t *testing.T) {
	cases := []struct {
		name string
		yaml string
		want string
	}{
		{
			name: "no join key",
			yaml: "schema_version: \"1.0.0\"\nprofile: {id: a/b@v1}\nmappings:\n  - evidence: {artifact: artifacts/x.json}\n",
			want: "exactly one of requirement, control, or type",
		},
		{
			name: "two join keys",
			yaml: "schema_version: \"1.0.0\"\nprofile: {id: a/b@v1}\nmappings:\n  - requirement: r1\n    control: CC1\n    evidence: {artifact: artifacts/x.json}\n",
			want: "exactly one of requirement, control, or type",
		},
		{
			name: "both evidence targets",
			yaml: "schema_version: \"1.0.0\"\nprofile: {id: a/b@v1}\nmappings:\n  - control: CC1\n    evidence: {artifact: artifacts/x.json, document_id: doc-1}\n",
			want: "exactly one of artifact or document_id",
		},
		{
			name: "pointer without artifact",
			yaml: "schema_version: \"1.0.0\"\nprofile: {id: a/b@v1}\nmappings:\n  - control: CC1\n    evidence: {document_id: doc-1, pointer: /a/b}\n",
			want: "pointer requires an artifact",
		},
		{
			name: "quote on artifact reference",
			yaml: "schema_version: \"1.0.0\"\nprofile: {id: a/b@v1}\nmappings:\n  - control: CC1\n    evidence:\n      artifact: artifacts/x.json\n      quote: {exact: hello}\n",
			want: "require a document_id",
		},
		{
			name: "quote and table together",
			yaml: "schema_version: \"1.0.0\"\nprofile: {id: a/b@v1}\nmappings:\n  - control: CC1\n    evidence:\n      document_id: doc-1\n      quote: {exact: hello}\n      table: {where: {Employee: a}}\n",
			want: "mutually exclusive",
		},
		{
			name: "wrong schema version",
			yaml: "schema_version: \"2.0.0\"\nprofile: {id: a/b@v1}\nmappings: []\n",
			want: "schema_version",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc, err := Parse([]byte(tc.yaml))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			warnings := doc.Check()
			found := false
			for _, w := range warnings {
				if strings.Contains(w, tc.want) {
					found = true
				}
			}
			if !found {
				t.Errorf("warnings %v missing %q", warnings, tc.want)
			}
		})
	}
}

func TestCheckArtifactRefs(t *testing.T) {
	doc, err := Parse([]byte(validYAML))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	warnings := doc.CheckArtifactRefs(map[string]bool{"artifacts/idp-posture.json": true})
	if len(warnings) != 0 {
		t.Errorf("resolved refs should not warn: %v", warnings)
	}

	warnings = doc.CheckArtifactRefs(map[string]bool{})
	if len(warnings) != 1 || !strings.Contains(warnings[0], "artifacts/idp-posture.json") {
		t.Errorf("missing artifact should warn once, got %v", warnings)
	}
}

func TestCheckProfileDigest(t *testing.T) {
	doc, err := Parse([]byte(validYAML))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	locked := "sha256:9f2c41d6e8a3b7c015d94f6a2e8b1c7d3a5f0e9b8c6d4a2f1e0d9c8b7a6f5e4d"
	if warnings := doc.CheckProfileDigest([]string{locked}); len(warnings) != 0 {
		t.Errorf("matching digest should not warn: %v", warnings)
	}
	if warnings := doc.CheckProfileDigest([]string{"sha256:other"}); len(warnings) != 1 {
		t.Errorf("mismatched digest should warn, got %v", warnings)
	}

	noDigest, err := Parse([]byte("schema_version: \"1.0.0\"\nprofile: {id: a/b@v1}\nmappings: []\n"))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if warnings := noDigest.CheckProfileDigest(nil); len(warnings) != 0 {
		t.Errorf("absent digest should not warn: %v", warnings)
	}
}

func TestEmitJSONPreservesJSONVerbatim(t *testing.T) {
	source := []byte(`{
  "schema_version": "1.0.0",
  "profile": { "id": "a/b@v1" },
  "publisher_extra": { "kept": true },
  "mappings": []
}
`)
	out, err := EmitJSON(source)
	if err != nil {
		t.Fatalf("EmitJSON: %v", err)
	}
	if !bytes.Equal(out, source) {
		t.Error("JSON input should be embedded verbatim")
	}
}

func TestEmitJSONConvertsYAMLDeterministically(t *testing.T) {
	out1, err := EmitJSON([]byte(validYAML))
	if err != nil {
		t.Fatalf("EmitJSON: %v", err)
	}
	out2, err := EmitJSON([]byte(validYAML))
	if err != nil {
		t.Fatalf("EmitJSON: %v", err)
	}
	if !bytes.Equal(out1, out2) {
		t.Error("YAML conversion should be deterministic")
	}

	var parsed map[string]any
	if err := json.Unmarshal(out1, &parsed); err != nil {
		t.Fatalf("emitted output is not valid JSON: %v", err)
	}
	if parsed["schema_version"] != "1.0.0" {
		t.Errorf("schema_version = %v", parsed["schema_version"])
	}
}

func TestEmitJSONRejectsInvalidJSON(t *testing.T) {
	if _, err := EmitJSON([]byte("{not json")); err == nil {
		t.Error("invalid JSON should error")
	}
}

func TestArtifactPath(t *testing.T) {
	cases := map[string]string{
		"mappings/control-mappings.yaml": "artifacts/control-mappings.json",
		"control-mappings.json":          "artifacts/control-mappings.json",
		"soc2.mapping.yml":               "artifacts/soc2.mapping.json",
	}
	for key, want := range cases {
		if got := ArtifactPath(key); got != want {
			t.Errorf("ArtifactPath(%q) = %q, want %q", key, got, want)
		}
	}
}
