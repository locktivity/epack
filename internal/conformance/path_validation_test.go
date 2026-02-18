package conformance

import (
	"testing"

	"github.com/locktivity/epack/internal/ziputil"
)

func TestPathValidationVectors(t *testing.T) {
	SkipIfNoVectors(t)

	files, err := ListVectorFiles("path-validation")
	if err != nil {
		t.Fatalf("failed to list path-validation vectors: %v", err)
	}

	for _, file := range files {
		t.Run(file, func(t *testing.T) {
			v, err := LoadVector[PathValidationVector]("path-validation", file)
			if err != nil {
				t.Fatalf("failed to load vector %s: %v", file, err)
			}

			for _, tc := range v.Tests {
				testName := tc.Description
				if testName == "" {
					testName = tc.Path
				}

				// Use Paths if set, otherwise use Path
				paths := tc.Paths
				if len(paths) == 0 && tc.Path != "" {
					paths = []string{tc.Path}
				}

				t.Run(testName, func(t *testing.T) {
					for _, p := range paths {
						err := ziputil.ValidatePath(p)
						gotValid := err == nil

						if gotValid != tc.Valid {
							if tc.Valid {
								t.Errorf("path %q should be valid but got error: %v", p, err)
							} else {
								t.Errorf("path %q should be invalid (reason: %s) but was accepted",
									p, tc.Reason)
							}
						}
					}
				})
			}
		})
	}
}
