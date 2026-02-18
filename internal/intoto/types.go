// Package intoto defines in-toto statement types for evidence pack attestations.
package intoto

const (
	// StatementType is the in-toto statement type for v1 statements.
	StatementType = "https://in-toto.io/Statement/v1"

	// EvidencePackPredicateType is the predicate type for evidence pack attestations.
	EvidencePackPredicateType = "https://evidencepack.org/attestation/v1"
)

// Statement represents an in-toto v1 statement.
// This is the payload that gets signed in the Sigstore bundle.
type Statement struct {
	Type          string              `json:"_type"`
	Subject       []Subject           `json:"subject"`
	PredicateType string              `json:"predicateType"`
	Predicate     EvidencePackPayload `json:"predicate"`
}

// Subject represents a subject in an in-toto statement.
type Subject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

// EvidencePackPayload is the predicate content for evidence pack attestations.
type EvidencePackPayload struct {
	PackDigest string `json:"pack_digest"`
	Stream     string `json:"stream,omitempty"`
}
