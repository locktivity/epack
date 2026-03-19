package packspec

import "encoding/json"

// Manifest represents the structure of the manifest.json file in an evidence pack.
type Manifest struct {
	SpecVersion string      `json:"spec_version"`
	Stream      string      `json:"stream"`
	GeneratedAt string      `json:"generated_at"`
	PackDigest  string      `json:"pack_digest"`
	Sources     []Source    `json:"sources"`
	Artifacts   []Artifact  `json:"artifacts"`
	Provenance  *Provenance `json:"provenance,omitempty"`

	// Profiles lists the profile configurations used to validate this pack.
	// These are traceability references recorded by the producer for audit purposes.
	// Note: For MVP, consumers provide profiles via tool config, not manifest.
	Profiles []ProfileRef `json:"profiles,omitempty"`

	// Overlays lists overlay configurations applied during validation.
	// Recorded for traceability; consumers provide overlays via tool config.
	Overlays []ProfileRef `json:"overlays,omitempty"`
}

// ProfileRef records a profile or overlay configuration for traceability.
// This captures which profile was used when the pack was created/validated.
type ProfileRef struct {
	// Source is the original config path or source reference.
	// For local paths: "profiles/hitrust.yaml"
	// For remote sources: "evidencepack/soc2-basic@v1"
	Source string `json:"source"`

	// Digest is the SHA256 digest of the profile/overlay file content.
	// Format: "sha256:<hex>" (64 hex characters after prefix).
	// May be empty for older packs or if digest was not computed.
	Digest string `json:"digest,omitempty"`
}

// Source represents a source collector that contributed artifacts.
type Source struct {
	Name         string   `json:"name"`
	Version      string   `json:"version"`
	Source       string   `json:"source,omitempty"`        // Repository path (e.g., "github.com/locktivity/epack-collector-aws")
	Commit       string   `json:"commit,omitempty"`        // Git commit SHA that built the collector binary
	BinaryDigest string   `json:"binary_digest,omitempty"` // SHA256 digest of the collector binary
	Artifacts    []string `json:"artifacts,omitempty"`
}

// Artifact represents an artifact in the manifest.
type Artifact struct {
	Type        string       `json:"type"`
	Path        string       `json:"path,omitempty"`
	Digest      string       `json:"digest,omitempty"`
	Size        *json.Number `json:"size,omitempty"`
	ContentType string       `json:"content_type,omitempty"`
	DisplayName string       `json:"display_name,omitempty"`
	Description string       `json:"description,omitempty"`
	CollectedAt string       `json:"collected_at,omitempty"`
	Schema      string       `json:"schema,omitempty"`
	Controls    []string     `json:"controls,omitempty"`
}

// Provenance describes the origin and attestation chain for merged packs.
type Provenance struct {
	Type        string       `json:"type"`
	MergedAt    string       `json:"merged_at,omitempty"`
	MergedBy    string       `json:"merged_by,omitempty"`
	SourcePacks []SourcePack `json:"source_packs,omitempty"`
}

// SourcePack represents a source pack in merged provenance.
//
// Embedded attestations contain complete Sigstore bundles that receivers should
// verify with their own identity constraints using VerifyEmbeddedAttestations().
// The merge operation validates cryptographic signatures but not signer identity,
// since the merge operator is untrusted from the receiver's perspective and
// identity policy is receiver-specific.
type SourcePack struct {
	Stream               string                `json:"stream"`
	PackDigest           string                `json:"pack_digest"`
	ManifestDigest       string                `json:"manifest_digest"`
	Artifacts            json.Number           `json:"artifacts"`
	EmbeddedAttestations []EmbeddedAttestation `json:"embedded_attestations,omitempty"`
}

// EmbeddedAttestation is a complete Sigstore bundle from a source pack.
// Per spec Section 3.7, this must contain mediaType, verificationMaterial, and dsseEnvelope.
type EmbeddedAttestation struct {
	MediaType            string          `json:"mediaType"`
	VerificationMaterial json.RawMessage `json:"verificationMaterial"`
	DSSEEnvelope         json.RawMessage `json:"dsseEnvelope"`
}

// Copy returns a deep copy of the manifest.
// Mutations to the copy do not affect the original.
func (m *Manifest) Copy() Manifest {
	cp := *m

	// Deep copy Sources slice
	if m.Sources != nil {
		cp.Sources = make([]Source, len(m.Sources))
		for i, s := range m.Sources {
			cp.Sources[i] = s.Copy()
		}
	}

	// Deep copy Artifacts slice
	if m.Artifacts != nil {
		cp.Artifacts = make([]Artifact, len(m.Artifacts))
		for i, a := range m.Artifacts {
			cp.Artifacts[i] = a.Copy()
		}
	}

	// Deep copy Provenance
	if m.Provenance != nil {
		prov := m.Provenance.Copy()
		cp.Provenance = &prov
	}

	// Deep copy Profiles slice
	if m.Profiles != nil {
		cp.Profiles = make([]ProfileRef, len(m.Profiles))
		copy(cp.Profiles, m.Profiles)
	}

	// Deep copy Overlays slice
	if m.Overlays != nil {
		cp.Overlays = make([]ProfileRef, len(m.Overlays))
		copy(cp.Overlays, m.Overlays)
	}

	return cp
}

// Copy returns a deep copy of the source.
func (s *Source) Copy() Source {
	cp := *s
	if s.Artifacts != nil {
		cp.Artifacts = make([]string, len(s.Artifacts))
		copy(cp.Artifacts, s.Artifacts)
	}
	return cp
}

// Copy returns a deep copy of the artifact.
func (a *Artifact) Copy() Artifact {
	cp := *a
	if a.Size != nil {
		size := *a.Size
		cp.Size = &size
	}
	if a.Controls != nil {
		cp.Controls = make([]string, len(a.Controls))
		copy(cp.Controls, a.Controls)
	}
	return cp
}

// Copy returns a deep copy of the provenance.
func (p *Provenance) Copy() Provenance {
	cp := *p
	if p.SourcePacks != nil {
		cp.SourcePacks = make([]SourcePack, len(p.SourcePacks))
		for i, sp := range p.SourcePacks {
			cp.SourcePacks[i] = sp.Copy()
		}
	}
	return cp
}

// Copy returns a deep copy of the source pack.
func (sp *SourcePack) Copy() SourcePack {
	cp := *sp
	if len(sp.EmbeddedAttestations) > 0 {
		cp.EmbeddedAttestations = make([]EmbeddedAttestation, len(sp.EmbeddedAttestations))
		for i, att := range sp.EmbeddedAttestations {
			cp.EmbeddedAttestations[i] = att.Copy()
		}
	}
	return cp
}

// Copy returns a deep copy of the embedded attestation.
func (ea *EmbeddedAttestation) Copy() EmbeddedAttestation {
	cp := EmbeddedAttestation{
		MediaType: ea.MediaType,
	}
	if ea.VerificationMaterial != nil {
		cp.VerificationMaterial = make(json.RawMessage, len(ea.VerificationMaterial))
		copy(cp.VerificationMaterial, ea.VerificationMaterial)
	}
	if ea.DSSEEnvelope != nil {
		cp.DSSEEnvelope = make(json.RawMessage, len(ea.DSSEEnvelope))
		copy(cp.DSSEEnvelope, ea.DSSEEnvelope)
	}
	return cp
}
