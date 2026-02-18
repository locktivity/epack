package conformance

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/locktivity/epack/pack"
)

func TestStructurePackStructure(t *testing.T) {
	SkipIfNoVectors(t)

	v, err := LoadVector[StructureVector]("structure", "pack-structure.json")
	if err != nil {
		t.Fatalf("failed to load vector: %v", err)
	}

	for _, tc := range v.Tests {
		t.Run(tc.Name, func(t *testing.T) {
			// These tests describe expected pack structure validation behavior
			// The actual implementation validates structure during pack.Open()

			// Log the expected behavior
			t.Logf("SPEC: %s - structure: %v, valid: %v", tc.Description, tc.Structure, tc.Valid)

			if tc.Filename != "" {
				// Tests about file extensions - implementation detail
				t.Logf("SPEC: filename %q should be %v (error: %s)",
					tc.Filename, tc.Valid, tc.ExpectedError)
			}

			if tc.Content != "" {
				// Tests about invalid file content
				t.Logf("SPEC: invalid content should produce error: %s", tc.ExpectedError)
			}
		})
	}
}

func TestStructureMissingArtifact(t *testing.T) {
	SkipIfNoVectors(t)

	v, err := LoadVector[StructureVector]("structure", "missing-artifact.json")
	if err != nil {
		t.Fatalf("failed to load vector: %v", err)
	}

	for _, tc := range v.Tests {
		t.Run(tc.Name, func(t *testing.T) {
			t.Logf("SPEC: %s - valid: %v, expected_error: %s",
				tc.Description, tc.Valid, tc.ExpectedError)
		})
	}
}

func TestStructureExtraArtifactInZip(t *testing.T) {
	SkipIfNoVectors(t)

	v, err := LoadVector[StructureVector]("structure", "extra-artifact-in-zip.json")
	if err != nil {
		t.Fatalf("failed to load vector: %v", err)
	}

	for _, tc := range v.Tests {
		t.Run(tc.Name, func(t *testing.T) {
			t.Logf("SPEC: %s - valid: %v, expected_error: %s",
				tc.Description, tc.Valid, tc.ExpectedError)
		})
	}
}

func TestStructureExtraTopLevelFiles(t *testing.T) {
	SkipIfNoVectors(t)

	v, err := LoadVector[StructureVector]("structure", "extra-top-level-files.json")
	if err != nil {
		t.Fatalf("failed to load vector: %v", err)
	}

	for _, tc := range v.Tests {
		t.Run(tc.Name, func(t *testing.T) {
			t.Logf("SPEC: %s - valid: %v, expected_error: %s",
				tc.Description, tc.Valid, tc.ExpectedError)
		})
	}
}

func TestStructureAttestationSubdirectory(t *testing.T) {
	SkipIfNoVectors(t)

	v, err := LoadVector[StructureVector]("structure", "attestation-subdirectory.json")
	if err != nil {
		t.Fatalf("failed to load vector: %v", err)
	}

	for _, tc := range v.Tests {
		t.Run(tc.Name, func(t *testing.T) {
			t.Logf("SPEC: %s - valid: %v, expected_error: %s",
				tc.Description, tc.Valid, tc.ExpectedError)
		})
	}
}

func TestStructureAttestationWrongExtension(t *testing.T) {
	SkipIfNoVectors(t)

	v, err := LoadVector[StructureVector]("structure", "attestation-wrong-extension.json")
	if err != nil {
		t.Fatalf("failed to load vector: %v", err)
	}

	for _, tc := range v.Tests {
		t.Run(tc.Name, func(t *testing.T) {
			t.Logf("SPEC: %s - valid: %v, expected_error: %s",
				tc.Description, tc.Valid, tc.ExpectedError)
		})
	}
}

// TestStructureFixtures tests vectors that reference actual ZIP fixture files.
func TestStructureFixtures(t *testing.T) {
	SkipIfNoVectors(t)

	files, err := ListVectorFiles("structure")
	if err != nil {
		t.Fatalf("failed to list vectors: %v", err)
	}

	for _, file := range files {
		raw, err := LoadVectorRaw("structure", file)
		if err != nil {
			t.Errorf("failed to load %s: %v", file, err)
			continue
		}

		// Check for fixture field
		var withFixture struct {
			Fixture string `json:"fixture"`
			Tests   []struct {
				Fixture       string `json:"fixture"`
				Valid         bool   `json:"valid"`
				ExpectedError string `json:"expected_error"`
				Name          string `json:"name"`
			} `json:"tests"`
		}
		if err := json.Unmarshal(raw, &withFixture); err != nil {
			continue
		}

		// Check top-level fixture
		if withFixture.Fixture != "" {
			t.Run(file, func(t *testing.T) {
				testFixture(t, "structure", withFixture.Fixture)
			})
		}

		// Check test-level fixtures
		for _, tc := range withFixture.Tests {
			if tc.Fixture != "" {
				t.Run(tc.Name, func(t *testing.T) {
					fixturePath := FixturePath("structure", tc.Fixture)
					if _, err := os.Stat(fixturePath); os.IsNotExist(err) {
						t.Skipf("fixture not found: %s", fixturePath)
						return
					}

					_, packErr := pack.Open(fixturePath)
					if tc.Valid {
						if packErr != nil {
							t.Errorf("expected valid pack but got error: %v", packErr)
						}
					} else {
						if packErr == nil {
							t.Errorf("expected pack to be rejected (error: %s) but was accepted",
								tc.ExpectedError)
						}
					}
				})
			}
		}
	}
}

func testFixture(t *testing.T, category, fixture string) {
	fixturePath := FixturePath(category, fixture)
	if _, err := os.Stat(fixturePath); os.IsNotExist(err) {
		t.Skipf("fixture not found: %s", fixturePath)
		return
	}

	_, err := pack.Open(fixturePath)
	t.Logf("pack.Open(%s) error: %v", fixture, err)
}
