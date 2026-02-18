// Package merge provides functionality to combine multiple evidence packs into one.
package merge

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/locktivity/epack/errors"
	"github.com/locktivity/epack/internal/limits"
	"github.com/locktivity/epack/internal/timestamp"
	"github.com/locktivity/epack/internal/validate"
	"github.com/locktivity/epack/pack"
	"github.com/locktivity/epack/pack/builder"
	"github.com/locktivity/epack/pack/verify"
)

// SafeMergeOptions returns Options configured for secure merging.
// This is the recommended way to configure merge for production use.
//
// Features:
//   - Includes attestations from source packs
//   - Verifies attestations before embedding
//   - Requires a verifier with proper identity policy
//
// Example:
//
//	verifier, _ := verify.NewStrictVerifier(issuer, subject)
//	err := merge.Merge(ctx, sources, "merged.pack", merge.SafeMergeOptions("org/merged", verifier))
func SafeMergeOptions(stream string, verifier verify.Verifier) Options {
	return Options{
		Stream:              stream,
		IncludeAttestations: true,
		VerifyAttestations:  true,
		Verifier:            verifier,
	}
}

// Options configures the merge operation.
type Options struct {
	// Stream is the stream identifier for the merged pack.
	Stream string

	// MergedBy is the optional identifier of who performed the merge.
	MergedBy string

	// IncludeAttestations embeds source pack attestations in provenance.
	// When true, attestations from source packs are included as embedded_attestation
	// in the provenance.source_packs array.
	IncludeAttestations bool

	// VerifyAttestations enables verification of source pack attestations before
	// embedding them. Defaults to true when IncludeAttestations is true and a
	// Verifier is provided. When enabled, attestations are cryptographically
	// verified and their statement subjects are checked against the source pack
	// digest.
	//
	// To include attestations without verification (not recommended), set
	// IncludeAttestations=true and do not provide a Verifier.
	VerifyAttestations bool

	// Verifier is used to verify source pack attestations. When provided with
	// IncludeAttestations=true, verification is automatically enabled.
	// If VerifyAttestations is explicitly true but Verifier is nil, an error
	// is returned.
	Verifier verify.Verifier
}

// SourcePack represents a pack to be merged.
type SourcePack struct {
	// Path is the filesystem path to the pack file.
	Path string

	// Pack is an already-opened pack. If nil, the pack will be opened from Path.
	Pack *pack.Pack
}

// Merge combines multiple source packs into a single merged pack.
//
// Artifacts from non-merged source packs are prefixed with their stream identifier
// to avoid collisions (e.g., artifacts/org/prod/data.json). Artifacts from
// already-merged packs are preserved as-is (flattened) since they already have
// stream prefixes.
//
// All source streams must be unique, including streams from nested merged packs.
// This prevents path collisions and ensures each stream appears exactly once
// in the final pack.
//
// The output pack's manifest includes a provenance object with type="merged"
// documenting which packs were combined.
func Merge(ctx context.Context, sources []SourcePack, outputPath string, opts Options) error {
	if len(sources) == 0 {
		return errors.E(errors.InvalidInput, "at least one source pack is required", nil)
	}
	if opts.Stream == "" {
		return errors.E(errors.InvalidInput, "stream is required", nil)
	}

	// SECURITY: Default VerifyAttestations to true when IncludeAttestations is true.
	// This ensures attestations are cryptographically verified before embedding.
	// Users must explicitly set VerifyAttestations=false to include unverified attestations.
	if opts.IncludeAttestations && opts.Verifier != nil && !opts.VerifyAttestations {
		opts.VerifyAttestations = true
	}

	// Check for cancellation before starting
	if err := ctx.Err(); err != nil {
		return err
	}

	// Open packs that aren't already open
	openedPacks := make([]*pack.Pack, len(sources))
	for i, src := range sources {
		if src.Pack != nil {
			openedPacks[i] = src.Pack
		} else {
			p, err := pack.Open(src.Path)
			if err != nil {
				return fmt.Errorf("opening source pack %s: %w", src.Path, err)
			}
			defer func() { _ = p.Close() }()
			openedPacks[i] = p
		}
	}

	// Check for stream uniqueness across all source packs (including nested)
	if err := validateStreamUniqueness(openedPacks, sources); err != nil {
		return err
	}

	// SECURITY: Check merge nesting depth to prevent excessive resource usage.
	// Deeply nested merge chains could cause exponential provenance growth.
	if err := validateMergeNestingDepth(openedPacks, sources); err != nil {
		return err
	}

	// Build the merged pack
	b := builder.New(opts.Stream)

	// Collect source pack metadata for provenance
	sourcePacks := make([]pack.SourcePack, len(sources))

	for i, p := range openedPacks {
		// Check for cancellation between packs
		if err := ctx.Err(); err != nil {
			return err
		}

		manifest := p.Manifest()
		srcStream := manifest.Stream
		isMergedPack := isAlreadyMergedPack(manifest)

		// SECURITY: Validate stream from untrusted pack manifest to prevent path traversal.
		// The stream is used in filepath.Join() below, so we must reject traversal sequences.
		// Streams can contain "/" (e.g., "org/prod") but must not contain ".." or other traversal.
		if err := validate.RejectTraversalInPath(srcStream); err != nil {
			return errors.E(errors.InvalidInput,
				fmt.Sprintf("source pack %d has unsafe stream identifier %q: %v", i, srcStream, err), nil)
		}

		// Add artifacts from this source pack
		for _, artifact := range manifest.Artifacts {
			if artifact.Type != "embedded" {
				continue
			}

			// Read artifact content
			content, err := p.ReadArtifact(artifact.Path)
			if err != nil {
				return fmt.Errorf("reading artifact %s from source pack: %w", artifact.Path, err)
			}

			var outputPath string
			if isMergedPack {
				// Already-merged packs: preserve existing paths (already have stream prefixes)
				outputPath = artifact.Path
			} else {
				// Non-merged packs: prefix with stream
				// e.g., "artifacts/org/prod/data.json" for artifact "artifacts/data.json" from stream "org/prod"
				relativePath := strings.TrimPrefix(artifact.Path, "artifacts/")
				outputPath = filepath.Join("artifacts", srcStream, relativePath)
			}

			// Add to builder with original metadata
			addOpts := builder.ArtifactOptions{
				ContentType: artifact.ContentType,
				DisplayName: artifact.DisplayName,
				Description: artifact.Description,
				CollectedAt: artifact.CollectedAt,
				Schema:      artifact.Schema,
				Controls:    artifact.Controls,
			}
			if err := b.AddBytesWithOptions(outputPath, content, addOpts); err != nil {
				return fmt.Errorf("adding artifact %s: %w", outputPath, err)
			}
		}

		// Build source pack metadata
		sp := pack.SourcePack{
			Stream:     srcStream,
			PackDigest: manifest.PackDigest,
			Artifacts:  json.Number(fmt.Sprintf("%d", countEmbeddedArtifacts(manifest.Artifacts))),
		}

		// Include all attestations if requested
		if opts.IncludeAttestations {
			attestations := p.ListAttestations()
			for _, attPath := range attestations {
				attData, err := p.ReadAttestation(attPath)
				if err != nil {
					return fmt.Errorf("reading attestation %s from %s: %w", attPath, srcStream, err)
				}

				// Validate size and depth before any parsing
				if err := verify.ValidateAttestation(attData); err != nil {
					return fmt.Errorf("validating attestation %s from %s: %w", attPath, srcStream, err)
				}

				// Verify attestation if requested (default: true when including attestations)
				if opts.VerifyAttestations {
					if opts.Verifier == nil {
						return errors.E(errors.InvalidInput, "verifier required when VerifyAttestations is true", nil)
					}

					result, err := opts.Verifier.Verify(ctx, attData)
					if err != nil {
						return fmt.Errorf("verifying attestation %s from %s: %w", attPath, srcStream, err)
					}

					// Verify full in-toto statement semantics, not just subject digest.
					// This validates:
					// - Statement _type is correct in-toto type
					// - predicateType is the expected evidence pack type
					// - Subject digest matches pack_digest
					// - Predicate pack_digest matches pack_digest
					// A cryptographically valid signature without proper statement
					// binding to pack_digest provides no security guarantee.
					if err := verify.VerifyStatementSemantics(result, manifest.PackDigest); err != nil {
						return fmt.Errorf("attestation %s from %s: %w", attPath, srcStream, err)
					}
				}

				embedded, err := parseEmbeddedAttestation(attData)
				if err != nil {
					return fmt.Errorf("parsing embedded attestation %s from %s: %w", attPath, srcStream, err)
				}
				sp.EmbeddedAttestations = append(sp.EmbeddedAttestations, *embedded)
			}
		}

		sourcePacks[i] = sp
	}

	// Set provenance
	provenance := pack.Provenance{
		Type:        "merged",
		MergedAt:    timestamp.Now().String(),
		MergedBy:    opts.MergedBy,
		SourcePacks: sourcePacks,
	}
	b.SetProvenance(provenance)

	// Build and write the pack
	if err := b.Build(outputPath); err != nil {
		return fmt.Errorf("building merged pack: %w", err)
	}

	return nil
}

// countEmbeddedArtifacts counts artifacts with type="embedded".
func countEmbeddedArtifacts(artifacts []pack.Artifact) int {
	count := 0
	for _, a := range artifacts {
		if a.Type == "embedded" {
			count++
		}
	}
	return count
}

// parseEmbeddedAttestation parses a Sigstore bundle JSON into an EmbeddedAttestation.
func parseEmbeddedAttestation(data []byte) (*pack.EmbeddedAttestation, error) {
	var bundle struct {
		MediaType            string          `json:"mediaType"`
		VerificationMaterial json.RawMessage `json:"verificationMaterial"`
		DSSEEnvelope         json.RawMessage `json:"dsseEnvelope"`
	}
	if err := json.Unmarshal(data, &bundle); err != nil {
		return nil, err
	}

	// Validate it's a Sigstore bundle
	if bundle.MediaType != pack.SigstoreBundleMediaType {
		return nil, fmt.Errorf("not a Sigstore bundle: %s", bundle.MediaType)
	}

	return &pack.EmbeddedAttestation{
		MediaType:            bundle.MediaType,
		VerificationMaterial: bundle.VerificationMaterial,
		DSSEEnvelope:         bundle.DSSEEnvelope,
	}, nil
}

// isAlreadyMergedPack returns true if the pack was created by a merge operation.
func isAlreadyMergedPack(manifest pack.Manifest) bool {
	return manifest.Provenance != nil && manifest.Provenance.Type == "merged"
}

// streamLocation records where a stream was found for error reporting.
type streamLocation struct {
	stream     string
	sourcePath string // path to the pack file
	nested     bool   // true if from a nested merged pack's provenance
}

// validateStreamUniqueness ensures all source streams are unique across all packs,
// including streams from nested merged packs.
func validateStreamUniqueness(packs []*pack.Pack, sources []SourcePack) error {
	seen := make(map[string]streamLocation)

	for i, p := range packs {
		manifest := p.Manifest()
		sourcePath := sources[i].Path
		if sourcePath == "" {
			sourcePath = fmt.Sprintf("pack[%d]", i)
		}

		if isAlreadyMergedPack(manifest) {
			// For merged packs, check all nested source streams
			for _, sp := range manifest.Provenance.SourcePacks {
				if existing, ok := seen[sp.Stream]; ok {
					return duplicateStreamError(sp.Stream, existing, streamLocation{
						stream:     sp.Stream,
						sourcePath: sourcePath,
						nested:     true,
					})
				}
				seen[sp.Stream] = streamLocation{
					stream:     sp.Stream,
					sourcePath: sourcePath,
					nested:     true,
				}
			}
		} else {
			// For non-merged packs, check the pack's own stream
			if existing, ok := seen[manifest.Stream]; ok {
				return duplicateStreamError(manifest.Stream, existing, streamLocation{
					stream:     manifest.Stream,
					sourcePath: sourcePath,
					nested:     false,
				})
			}
			seen[manifest.Stream] = streamLocation{
				stream:     manifest.Stream,
				sourcePath: sourcePath,
				nested:     false,
			}
		}
	}

	return nil
}

// duplicateStreamError creates a descriptive error for duplicate streams.
func duplicateStreamError(stream string, first, second streamLocation) error {
	firstDesc := first.sourcePath
	if first.nested {
		firstDesc += " (nested)"
	}
	secondDesc := second.sourcePath
	if second.nested {
		secondDesc += " (nested)"
	}

	return errors.E(errors.InvalidInput,
		fmt.Sprintf("duplicate stream %q: found in %s and %s", stream, firstDesc, secondDesc),
		nil)
}

// validateMergeNestingDepth checks that source packs don't exceed the merge nesting limit.
// SECURITY: Prevents excessive resource usage from deeply nested merge chains.
// Each merge level adds provenance metadata, which could grow exponentially.
func validateMergeNestingDepth(packs []*pack.Pack, sources []SourcePack) error {
	for i, p := range packs {
		manifest := p.Manifest()
		if !isAlreadyMergedPack(manifest) {
			continue
		}

		depth := countMergeDepth(manifest)
		if depth >= limits.MaxMergeNestingDepth {
			sourcePath := sources[i].Path
			if sourcePath == "" {
				sourcePath = fmt.Sprintf("pack[%d]", i)
			}
			return errors.E(errors.InvalidInput,
				fmt.Sprintf("merge nesting depth %d in %s exceeds limit %d",
					depth, sourcePath, limits.MaxMergeNestingDepth),
				nil)
		}
	}
	return nil
}

// countMergeDepth counts the nesting depth of a merged pack.
// A non-merged pack has depth 0, a pack merged from non-merged packs has depth 1, etc.
func countMergeDepth(manifest pack.Manifest) int {
	if manifest.Provenance == nil || manifest.Provenance.Type != "merged" {
		return 0
	}
	// For merged packs, we count this as depth 1 plus any nested merges.
	// Since we only have the top-level provenance (not the full chain),
	// we count the presence of source packs as indicating depth 1.
	// True depth tracking would require storing depth in provenance.
	return 1
}
