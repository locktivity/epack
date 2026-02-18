package intoto

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestConstantsAreValidURLs ensures type constants are valid URLs.
func TestConstantsAreValidURLs(t *testing.T) {
	tests := []struct {
		name  string
		value string
	}{
		{"StatementType", StatementType},
		{"EvidencePackPredicateType", EvidencePackPredicateType},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !strings.HasPrefix(tt.value, "https://") {
				t.Errorf("%s = %q, want https:// prefix", tt.name, tt.value)
			}
		})
	}
}

// TestStatementTypeIsInToto ensures the statement type matches in-toto spec.
func TestStatementTypeIsInToto(t *testing.T) {
	if !strings.Contains(StatementType, "in-toto.io") {
		t.Errorf("StatementType = %q, should contain in-toto.io", StatementType)
	}
	if !strings.Contains(StatementType, "v1") {
		t.Errorf("StatementType = %q, should contain v1", StatementType)
	}
}

// TestStatementJSONSerialization ensures Statement serializes correctly.
func TestStatementJSONSerialization(t *testing.T) {
	stmt := Statement{
		Type: StatementType,
		Subject: []Subject{
			{
				Name:   "test.pack",
				Digest: map[string]string{"sha256": "abc123"},
			},
		},
		PredicateType: EvidencePackPredicateType,
		Predicate: EvidencePackPayload{
			PackDigest: "sha256:abc123",
			Stream:     "org/stream",
		},
	}

	data, err := json.Marshal(stmt)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	// Verify _type field is present (the JSON tag)
	if !strings.Contains(string(data), `"_type"`) {
		t.Error("JSON should contain _type field")
	}

	// Roundtrip
	var decoded Statement
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if decoded.Type != stmt.Type {
		t.Errorf("Type = %q, want %q", decoded.Type, stmt.Type)
	}
	if decoded.PredicateType != stmt.PredicateType {
		t.Errorf("PredicateType = %q, want %q", decoded.PredicateType, stmt.PredicateType)
	}
	if len(decoded.Subject) != 1 {
		t.Fatalf("len(Subject) = %d, want 1", len(decoded.Subject))
	}
	if decoded.Subject[0].Name != "test.pack" {
		t.Errorf("Subject[0].Name = %q, want %q", decoded.Subject[0].Name, "test.pack")
	}
	if decoded.Predicate.PackDigest != "sha256:abc123" {
		t.Errorf("Predicate.PackDigest = %q, want %q", decoded.Predicate.PackDigest, "sha256:abc123")
	}
}

// TestSubjectJSONSerialization ensures Subject serializes correctly.
func TestSubjectJSONSerialization(t *testing.T) {
	subj := Subject{
		Name: "artifact.json",
		Digest: map[string]string{
			"sha256": "abc123",
			"sha512": "def456",
		},
	}

	data, err := json.Marshal(subj)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var decoded Subject
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if decoded.Name != subj.Name {
		t.Errorf("Name = %q, want %q", decoded.Name, subj.Name)
	}
	if len(decoded.Digest) != 2 {
		t.Errorf("len(Digest) = %d, want 2", len(decoded.Digest))
	}
	if decoded.Digest["sha256"] != "abc123" {
		t.Errorf("Digest[sha256] = %q, want %q", decoded.Digest["sha256"], "abc123")
	}
}

// TestEvidencePackPayloadStreamOmitempty ensures stream is omitted when empty.
func TestEvidencePackPayloadStreamOmitempty(t *testing.T) {
	payload := EvidencePackPayload{
		PackDigest: "sha256:abc123",
		Stream:     "", // empty
	}

	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	if strings.Contains(string(data), `"stream"`) {
		t.Error("JSON should omit empty stream field")
	}
}

// TestEvidencePackPayloadWithStream ensures stream is included when set.
func TestEvidencePackPayloadWithStream(t *testing.T) {
	payload := EvidencePackPayload{
		PackDigest: "sha256:abc123",
		Stream:     "org/stream",
	}

	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	if !strings.Contains(string(data), `"stream"`) {
		t.Error("JSON should include stream field when set")
	}
}

// TestStatementWithEmptySubjects ensures empty subjects serialize as empty array.
func TestStatementWithEmptySubjects(t *testing.T) {
	stmt := Statement{
		Type:          StatementType,
		Subject:       []Subject{},
		PredicateType: EvidencePackPredicateType,
		Predicate:     EvidencePackPayload{PackDigest: "sha256:abc"},
	}

	data, err := json.Marshal(stmt)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	if !strings.Contains(string(data), `"subject":[]`) {
		t.Errorf("JSON = %s, want empty subject array", string(data))
	}
}
