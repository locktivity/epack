package pack

import (
	"fmt"

	"github.com/locktivity/epack/errors"
	"github.com/locktivity/epack/internal/digest"
	"github.com/locktivity/epack/internal/jsonutil"
	"github.com/locktivity/epack/internal/limits"
	"github.com/locktivity/epack/internal/packpath"
	"github.com/locktivity/epack/internal/timestamp"
	"github.com/locktivity/epack/packspec"
)

// Re-export constants from packspec for backwards compatibility.
const (
	SpecVersion             = packspec.SpecVersion
	DSSEPayloadType         = packspec.DSSEPayloadType
	SigstoreBundleMediaType = packspec.SigstoreBundleMediaType
)

// validArtifactTypes contains the set of supported artifact types.
var validArtifactTypes = map[string]struct{}{
	"embedded": {},
}

// Type aliases for backwards compatibility.
// These allow existing code using pack.Manifest, pack.Artifact, etc. to continue working.
type (
	Manifest            = packspec.Manifest
	Source              = packspec.Source
	Artifact            = packspec.Artifact
	Provenance          = packspec.Provenance
	SourcePack          = packspec.SourcePack
	EmbeddedAttestation = packspec.EmbeddedAttestation
)

// ValidateManifestBytes validates raw manifest JSON without returning the parsed manifest.
// Use this to validate manifest bytes at trust boundaries (test fixtures, manual ZIP creation, etc.).
//
// SECURITY: All codepaths that create or ingest manifest.json (builder, merge, tests) should
// call either ValidateManifestBytes or ParseManifest to ensure structural validity, path safety,
// and spec compliance.
func ValidateManifestBytes(jsonBytes []byte) error {
	_, err := ParseManifest(jsonBytes)
	return err
}

// ParseManifest parses and validates manifest JSON with strict decoding.
//
// Validation includes:
//   - Required field checks (spec_version, stream, pack_digest, etc.)
//   - Spec version compatibility
//   - Timestamp format validation (YYYY-MM-DDTHH:MM:SSZ)
//   - Artifact path safety (no traversal, Windows collision detection)
//   - Digest format validation
//   - Size range checks (non-negative, within limits)
//
// SECURITY: This is the primary entrypoint for manifest parsing. All manifest bytes
// MUST pass through this function before being trusted.
func ParseManifest(jsonBytes []byte) (*Manifest, error) {
	manifest, err := jsonutil.DecodeStrict[Manifest](jsonBytes)
	if err != nil {
		return nil, err
	}

	if err := validateManifest(&manifest); err != nil {
		return nil, err
	}

	return &manifest, nil
}

func validateManifest(manifest *Manifest) error {
	if err := validateRequiredFields(manifest); err != nil {
		return err
	}

	if manifest.SpecVersion != SpecVersion {
		return errors.E(errors.UnsupportedSpecVersion, fmt.Sprintf("unsupported spec_version: %s", manifest.SpecVersion), nil)
	}

	if err := validateStrictTimestamp(manifest.GeneratedAt, "generated_at"); err != nil {
		return err
	}

	if err := validateDigest(manifest.PackDigest); err != nil {
		return errors.E(errors.InvalidManifest, "invalid pack_digest format", err)
	}

	if err := validateArtifacts(manifest.Artifacts); err != nil {
		return err
	}

	if err := validateSources(manifest.Sources); err != nil {
		return err
	}

	if manifest.Provenance != nil {
		if err := validateProvenance(*manifest.Provenance); err != nil {
			return err
		}
	}

	return nil
}

func validateRequiredFields(manifest *Manifest) error {
	if manifest.SpecVersion == "" {
		return errors.E(errors.MissingRequiredField, "spec_version is required", nil)
	}

	if manifest.Stream == "" {
		return errors.E(errors.MissingRequiredField, "stream is required", nil)
	}

	if manifest.GeneratedAt == "" {
		return errors.E(errors.MissingRequiredField, "generated_at is required", nil)
	}

	if manifest.PackDigest == "" {
		return errors.E(errors.MissingRequiredField, "pack_digest is required", nil)
	}

	if manifest.Sources == nil {
		return errors.E(errors.MissingRequiredField, "sources is required", nil)
	}

	if manifest.Artifacts == nil {
		return errors.E(errors.MissingRequiredField, "artifacts is required", nil)
	}

	return nil
}

func validateArtifacts(artifacts []Artifact) error {
	seenPaths := make(map[string]int) // Windows-canonical path -> first index seen

	for i, artifact := range artifacts {
		if _, ok := validArtifactTypes[artifact.Type]; !ok {
			return errors.E(errors.InvalidManifest, fmt.Sprintf("invalid artifact type at index %d: %s", i, artifact.Type), nil)
		}

		if err := digest.Validate(artifact.Digest); err != nil {
			return errors.E(errors.InvalidManifest, fmt.Sprintf("invalid digest format for artifact at index %d: %s", i, artifact.Digest), err)
		}

		if artifact.Path == "" {
			return errors.E(errors.MissingRequiredField, fmt.Sprintf("path is required for artifact at index %d", i), nil)
		}

		// SECURITY: For embedded artifacts, use packpath.ValidateArtifactPathAndCollisionKey
		// which validates path safety AND returns the Windows collision key.
		// This ensures consistent validation between builder and manifest parsing.
		if artifact.Type == "embedded" {
			collisionKey, err := packpath.ValidateArtifactPathAndCollisionKey(artifact.Path)
			if err != nil {
				return errors.E(errors.InvalidPath,
					fmt.Sprintf("invalid artifact path at index %d: %v", i, err), nil)
			}

			// SECURITY: Check for duplicate paths using Windows-canonical form.
			// This catches not just case differences, but also Windows path normalization:
			// - "report." and "report" map to same file (trailing dot stripped)
			// - "file " and "file" map to same file (trailing space stripped)
			// Without this check, two artifact paths could target the same filesystem path,
			// causing integrity ambiguity during extraction.
			if firstIdx, exists := seenPaths[collisionKey]; exists {
				return errors.E(errors.DuplicatePath,
					fmt.Sprintf("duplicate artifact path %q at index %d (collides with path at index %d on Windows)", artifact.Path, i, firstIdx), nil)
			}
			seenPaths[collisionKey] = i
		}

		if artifact.Size == nil {
			return errors.E(errors.MissingRequiredField, fmt.Sprintf("size is required for artifact at index %d", i), nil)
		}

		// SECURITY: Validate artifact size is within safe bounds.
		// - Must be non-negative (reject negative numbers that could wrap)
		// - Must be within JSON-safe integer range (2^53-1) to prevent precision loss
		// - Must be within MaxArtifactSizeBytes to prevent DoS
		sizeInt, err := artifact.Size.Int64()
		if err != nil {
			return errors.E(errors.InvalidManifest, fmt.Sprintf("invalid size for artifact at index %d: cannot parse as integer", i), err)
		}
		if sizeInt < 0 {
			return errors.E(errors.InvalidManifest, fmt.Sprintf("invalid size for artifact at index %d: size cannot be negative", i), nil)
		}
		// JSON numbers can represent up to 2^53-1 exactly; beyond that, precision loss can occur
		const maxSafeJSONInt int64 = (1 << 53) - 1
		if sizeInt > maxSafeJSONInt {
			return errors.E(errors.InvalidManifest, fmt.Sprintf("invalid size for artifact at index %d: exceeds JSON safe integer range", i), nil)
		}
		if sizeInt > limits.Artifact.Bytes() {
			return errors.E(errors.ArtifactTooLarge, fmt.Sprintf("artifact at index %d size %d exceeds maximum %d bytes", i, sizeInt, limits.Artifact.Bytes()), nil)
		}

		if artifact.CollectedAt != "" {
			if err := validateStrictTimestamp(artifact.CollectedAt, fmt.Sprintf("collected_at for artifact at index %d", i)); err != nil {
				return err
			}
		}
	}

	return nil
}

func validateSources(sources []Source) error {
	for i, source := range sources {
		if source.Name == "" {
			return errors.E(errors.MissingRequiredField, fmt.Sprintf("name is required for source at index %d", i), nil)
		}
	}

	return nil
}

func validateProvenance(provenance Provenance) error {
	if provenance.Type == "" {
		return errors.E(errors.MissingRequiredField, "type is required for provenance", nil)
	}

	switch provenance.Type {
	case "merged":
		// R-043: merged_at is required for merged type
		if provenance.MergedAt == "" {
			return errors.E(errors.MissingRequiredField, "merged_at is required for merged provenance type", nil)
		}
		if err := validateStrictTimestamp(provenance.MergedAt, "merged_at"); err != nil {
			return err
		}

		// R-043: source_packs is required and must be non-empty
		if len(provenance.SourcePacks) == 0 {
			return errors.E(errors.MissingRequiredField, "source_packs is required and must be non-empty for merged provenance type", nil)
		}

		for i, sp := range provenance.SourcePacks {
			// R-044: stream, pack_digest, artifacts all required
			if sp.Stream == "" {
				return errors.E(errors.MissingRequiredField, fmt.Sprintf("stream is required for source pack at index %d", i), nil)
			}

			if sp.PackDigest == "" {
				return errors.E(errors.MissingRequiredField, fmt.Sprintf("pack_digest is required for source pack at index %d", i), nil)
			}

			if err := validateDigest(sp.PackDigest); err != nil {
				return errors.E(errors.InvalidManifest, fmt.Sprintf("invalid pack_digest format for source pack at index %d", i), err)
			}

			// R-044: artifacts count is required
			if sp.Artifacts == "" {
				return errors.E(errors.MissingRequiredField, fmt.Sprintf("artifacts is required for source pack at index %d", i), nil)
			}

			// R-045: If attestations are embedded, each must be a complete Sigstore bundle
			for j, att := range sp.EmbeddedAttestations {
				if err := validateEmbeddedAttestation(att); err != nil {
					return errors.E(errors.InvalidManifest, fmt.Sprintf("invalid embedded attestation %d for source pack at index %d", j, i), err)
				}
			}
		}

		return nil
	case "single":
		return nil
	default:
		return errors.E(errors.InvalidManifest, fmt.Sprintf("unsupported provenance type: %s", provenance.Type), nil)
	}
}

func validateEmbeddedAttestation(att EmbeddedAttestation) error {
	// R-045: Embedded attestation must be a complete Sigstore bundle
	if att.MediaType == "" {
		return errors.E(errors.MissingRequiredField, "mediaType is required for embedded attestation", nil)
	}

	if att.MediaType != SigstoreBundleMediaType {
		return errors.E(errors.InvalidManifest, fmt.Sprintf("invalid mediaType for embedded attestation: %s (expected %s)", att.MediaType, SigstoreBundleMediaType), nil)
	}

	if len(att.VerificationMaterial) == 0 {
		return errors.E(errors.MissingRequiredField, "verificationMaterial is required for embedded attestation", nil)
	}

	if len(att.DSSEEnvelope) == 0 {
		return errors.E(errors.MissingRequiredField, "dsseEnvelope is required for embedded attestation", nil)
	}

	return nil
}

func validateDigest(d string) error {
	if err := digest.Validate(d); err != nil {
		return errors.E(errors.InvalidManifest, fmt.Sprintf("invalid digest format: %s", d), err)
	}
	return nil
}

// validateStrictTimestamp validates that a timestamp matches the exact format
// YYYY-MM-DDTHH:MM:SSZ per spec Section 3.4.3. No timezone offsets, fractional
// seconds, or other ISO 8601 variants are permitted.
// Uses internal/timestamp package for centralized format enforcement.
func validateStrictTimestamp(ts, fieldName string) error {
	if err := timestamp.Validate(ts); err != nil {
		return errors.E(errors.InvalidTimestamp,
			fmt.Sprintf("%s must be format YYYY-MM-DDTHH:MM:SSZ: %s", fieldName, ts), err)
	}
	return nil
}

// Note: Copy() methods are defined in packspec and are available via type aliases.
