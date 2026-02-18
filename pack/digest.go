package pack

import (
	"bytes"
	"io"
	"sort"
	"strings"

	"github.com/locktivity/epack/errors"
	"github.com/locktivity/epack/internal/digest"
	"github.com/locktivity/epack/internal/jcsutil"
)

// computeSHA256 computes SHA256 of data and returns sha256:{hex} format.
// Uses the digest package for consistent formatting.
func computeSHA256(data []byte) string {
	return digest.FromBytes(data).String()
}

// computeSHA256Reader computes SHA256 from a reader and returns sha256:{hex} format.
// Uses the digest package for consistent formatting.
func computeSHA256Reader(r io.Reader) (string, error) {
	d, err := digest.FromReader(r)
	if err != nil {
		return "", err
	}
	return d.String(), nil
}

// verifyDigest compares two digest strings using constant-time comparison.
// Returns true if they match. Uses the digest package for type-safe comparison.
func verifyDigest(expected, computed string) bool {
	expectedDigest, err := digest.Parse(expected)
	if err != nil {
		return false
	}
	computedDigest, err := digest.Parse(computed)
	if err != nil {
		return false
	}
	return expectedDigest.Equal(computedDigest)
}

type artifactEntry struct {
	path   string
	digest string
}

// BuildCanonicalArtifactList builds the canonical artifact list per spec.
// Format: {path}\t{digest}\n for each embedded artifact, sorted by path.
// Returns the canonical bytes to be hashed.
func BuildCanonicalArtifactList(manifest *Manifest) []byte {
	entries := make([]artifactEntry, 0, len(manifest.Artifacts))
	for _, artifact := range manifest.Artifacts {
		if artifact.Type == "embedded" {
			entries = append(entries, artifactEntry{
				path:   artifact.Path,
				digest: artifact.Digest,
			})
		}
	}

	if len(entries) == 0 {
		return []byte{}
	}

	// Sort by path using byte-wise lexicographic ordering
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].path < entries[j].path
	})

	// Build canonical list: {path}\t{digest}\n
	var b strings.Builder
	for _, e := range entries {
		b.WriteString(e.path)
		b.WriteByte('\t')
		b.WriteString(e.digest)
		b.WriteByte('\n')
	}

	return []byte(b.String())
}

// HashCanonicalList computes SHA256 of the canonical list and formats as sha256:{hex}.
// Uses the digest package for consistent formatting.
func HashCanonicalList(canonical []byte) string {
	return digest.FromBytes(canonical).String()
}

// ComputeManifestDigest computes the manifest_digest per spec.
// It canonicalizes the raw manifest JSON using JCS (RFC 8785) and returns:
//   - canonical: the JCS canonical form of the manifest
//   - digest: the SHA256 hash in "sha256:{hex}" format
//   - err: any error during canonicalization (e.g., invalid_number)
func ComputeManifestDigest(rawManifest []byte) (canonical string, digest string, err error) {
	trimmed := bytes.TrimSpace(rawManifest)
	if len(trimmed) == 0 {
		return "", "", errors.E(errors.InvalidManifest, "empty JSON input", nil)
	}

	// Validate that the JSON is an object (manifest must be a JSON object)
	if !bytes.HasPrefix(trimmed, []byte("{")) || !bytes.HasSuffix(trimmed, []byte("}")) {
		return "", "", errors.E(errors.InvalidManifest, "manifest JSON must be an object", nil)
	}

	canonicalBytes, digest, err := jcsutil.CanonicalizeAndHashWithOptions(rawManifest, jcsutil.Options{
		NumberPolicy:        jcsutil.NumberPolicySafeIntNonNegative,
		RejectDuplicateKeys: true,
	})
	if err != nil {
		return "", "", err
	}
	return string(canonicalBytes), digest, nil
}
