package pack

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"testing"

	"github.com/locktivity/epack/internal/ziputil"
)

// FuzzTamperedZip tests that the pack library correctly rejects tampered ZIP archives.
// This fuzz test explores the space of:
// - Corrupted manifest JSON
// - Mismatched digests
// - Malformed artifact content
// - Partial/truncated data
//
// The security property is: tampered packs should NEVER return content from ReadArtifact
// without proper verification. They may fail to open, fail to read, or fail verification,
// but they must never silently return bad data.
func FuzzTamperedZip(f *testing.F) {
	// Seed corpus with known attack patterns
	seeds := []struct {
		manifestMod func(m *manifestForFuzz)
		contentMod  func(c []byte) []byte
	}{
		// Valid baseline
		{nil, nil},

		// Digest attacks
		{func(m *manifestForFuzz) {
			m.PackDigest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
		}, nil},
		{func(m *manifestForFuzz) { m.PackDigest = "" }, nil},
		{func(m *manifestForFuzz) { m.PackDigest = "sha256:short" }, nil},
		{func(m *manifestForFuzz) {
			if len(m.Artifacts) > 0 {
				m.Artifacts[0].Digest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
			}
		}, nil},

		// Size attacks
		{func(m *manifestForFuzz) {
			if len(m.Artifacts) > 0 {
				s := json.Number("999999")
				m.Artifacts[0].Size = &s
			}
		}, nil},
		{func(m *manifestForFuzz) {
			if len(m.Artifacts) > 0 {
				s := json.Number("0")
				m.Artifacts[0].Size = &s
			}
		}, nil},

		// Content attacks
		{nil, func(c []byte) []byte { return []byte("MALICIOUS") }},
		{nil, func(c []byte) []byte { return append(c, 0xFF) }},
		{nil, func(c []byte) []byte {
			if len(c) > 0 {
				return c[:len(c)/2]
			}
			return c
		}},
		{nil, func(c []byte) []byte { return []byte{} }},

		// Stream/version attacks
		{func(m *manifestForFuzz) { m.Stream = "" }, nil},
		{func(m *manifestForFuzz) { m.SpecVersion = "999.0" }, nil},
		{func(m *manifestForFuzz) { m.SpecVersion = "" }, nil},

		// Missing fields
		{func(m *manifestForFuzz) { m.GeneratedAt = "" }, nil},
		{func(m *manifestForFuzz) { m.Artifacts = nil }, nil},
	}

	// Add seeds with content variations
	contents := [][]byte{
		[]byte(`{"valid": "json"}`),
		[]byte(`{}`),
		[]byte(`[]`),
		[]byte(``),
		[]byte{0x00, 0xFF, 0xFE},
		bytes.Repeat([]byte("x"), 1024),
	}

	for _, seed := range seeds {
		for _, content := range contents {
			zipBytes := createFuzzZip(content, seed.manifestMod, seed.contentMod)
			f.Add(zipBytes)
		}
	}

	// The fuzz function
	f.Fuzz(func(t *testing.T, data []byte) {
		// Try to open the pack
		pack, err := OpenFromBytes(data)
		if err != nil {
			// Failed to open - this is fine, pack was malformed
			return
		}
		defer func() { _ = pack.Close() }()

		// If we got here, the pack opened successfully.
		// Now try to read artifacts - this is where security matters.
		manifest := pack.Manifest()
		for _, artifact := range manifest.Artifacts {
			if artifact.Type != "embedded" {
				continue
			}

			// Try to read the artifact
			content, readErr := pack.ReadArtifact(artifact.Path)

			if readErr == nil {
				// ReadArtifact succeeded - content MUST be verified
				// Verify that the content matches the claimed digest
				h := sha256.Sum256(content)
				actualDigest := "sha256:" + hex.EncodeToString(h[:])

				if actualDigest != artifact.Digest {
					// SECURITY VIOLATION: ReadArtifact returned content that doesn't match digest
					panic("SECURITY: ReadArtifact returned unverified content! " +
						"actual=" + actualDigest + " claimed=" + artifact.Digest)
				}

				// Verify size if present
				if artifact.Size != nil {
					claimedSize, err := artifact.Size.Int64()
					if err == nil && int64(len(content)) != claimedSize {
						panic("SECURITY: ReadArtifact returned content with wrong size! " +
							"actual=" + strconv.Itoa(len(content)) + " claimed=" + artifact.Size.String())
					}
				}
			}
		}

		// Also verify that VerifyIntegrity works correctly
		_ = pack.VerifyIntegrity()
		_ = pack.VerifyPackDigest()
	})
}

// manifestForFuzz is a simplified manifest for fuzz test manipulation.
type manifestForFuzz struct {
	SpecVersion string         `json:"spec_version"`
	Stream      string         `json:"stream"`
	GeneratedAt string         `json:"generated_at"`
	PackDigest  string         `json:"pack_digest"`
	Sources     []Source       `json:"sources"`
	Artifacts   []artifactFuzz `json:"artifacts"`
}

type artifactFuzz struct {
	Type   string       `json:"type"`
	Path   string       `json:"path"`
	Digest string       `json:"digest"`
	Size   *json.Number `json:"size,omitempty"`
}

// createFuzzZip creates a ZIP archive for fuzzing with optional modifications.
func createFuzzZip(content []byte, manifestMod func(*manifestForFuzz), contentMod func([]byte) []byte) []byte {
	// Compute correct values
	h := sha256.Sum256(content)
	artifactDigest := "sha256:" + hex.EncodeToString(h[:])
	size := json.Number(strconv.Itoa(len(content)))

	// Build manifest
	m := &manifestForFuzz{
		SpecVersion: "1.0",
		Stream:      "fuzz/test",
		GeneratedAt: "2024-01-15T10:30:00Z",
		Sources:     []Source{},
		Artifacts: []artifactFuzz{
			{
				Type:   "embedded",
				Path:   "artifacts/test.json",
				Digest: artifactDigest,
				Size:   &size,
			},
		},
	}

	// Compute pack_digest before modifications (for valid baseline)
	tmpManifest := &Manifest{
		Artifacts: []Artifact{
			{
				Type:   "embedded",
				Path:   "artifacts/test.json",
				Digest: artifactDigest,
				Size:   &size,
			},
		},
	}
	canonical := BuildCanonicalArtifactList(tmpManifest)
	m.PackDigest = HashCanonicalList(canonical)

	// Apply manifest modifications
	if manifestMod != nil {
		manifestMod(m)
	}

	// Apply content modifications
	zipContent := content
	if contentMod != nil {
		zipContent = contentMod(content)
	}

	// Build ZIP
	manifestData, _ := json.Marshal(m)

	var buf bytes.Buffer
	w := zip.NewWriter(&buf)

	fw, _ := w.Create("manifest.json")
	_, _ = fw.Write(manifestData)

	fw, _ = w.Create("artifacts/test.json")
	_, _ = fw.Write(zipContent)

	_ = w.Close()

	return buf.Bytes()
}

// OpenFromBytes opens a pack from in-memory bytes (for fuzzing).
func OpenFromBytes(data []byte) (*Pack, error) {
	reader := bytes.NewReader(data)
	safeReader, err := ziputil.NewSafeReader(reader, int64(len(data)))
	if err != nil {
		return nil, err
	}

	return loadFromSafeReader(safeReader)
}
