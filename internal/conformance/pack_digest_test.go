package conformance

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/locktivity/epack/pack"
)

func TestPackDigestVectors(t *testing.T) {
	SkipIfNoVectors(t)

	files, err := ListVectorFiles("pack-digest")
	if err != nil {
		t.Fatalf("failed to list pack-digest vectors: %v", err)
	}

	for _, file := range files {
		t.Run(file, func(t *testing.T) {
			v, err := LoadVector[PackDigestVector]("pack-digest", file)
			if err != nil {
				t.Fatalf("failed to load vector %s: %v", file, err)
			}

			// Skip vectors without input (informational vectors)
			if len(v.Input.Artifacts) == 0 && v.Expected.PackDigest == "" {
				t.Skipf("skipping informational vector: %s", v.Name)
			}

			// Build manifest from input artifacts
			manifest := &pack.Manifest{
				Artifacts: make([]pack.Artifact, len(v.Input.Artifacts)),
			}
			for i, a := range v.Input.Artifacts {
				size := json.Number(fmt.Sprintf("%d", a.Size))
				manifest.Artifacts[i] = pack.Artifact{
					Type:   a.Type,
					Path:   a.Path,
					Digest: a.Digest,
					Size:   &size,
				}
			}

			// Compute pack_digest using the library functions
			canonical := pack.BuildCanonicalArtifactList(manifest)
			computed := pack.HashCanonicalList(canonical)

			// Check canonical_input if expected
			if v.Expected.CanonicalInput != "" {
				if string(canonical) != v.Expected.CanonicalInput {
					t.Errorf("canonical_input mismatch for %s:\n  expected: %q\n  computed: %q",
						v.Name, v.Expected.CanonicalInput, string(canonical))
				}
			}

			// Check pack_digest if expected
			if v.Expected.PackDigest != "" {
				if computed != v.Expected.PackDigest {
					t.Errorf("pack_digest mismatch for %s:\n  expected: %s\n  computed: %s",
						v.Name, v.Expected.PackDigest, computed)
				}
			}

			// Check sorted_paths if expected (verify sorting order)
			// SortedPaths test is implicitly covered by canonical_input matching
			// The canonical function sorts paths in a deterministic order
			_ = v.Expected.SortedPaths // Acknowledge field for documentation
		})
	}
}
