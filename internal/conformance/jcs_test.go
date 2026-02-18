package conformance

import (
	"encoding/json"
	"testing"

	"github.com/locktivity/epack/internal/jcsutil"
)

func TestJCSKeySorting(t *testing.T) {
	SkipIfNoVectors(t)

	raw, err := LoadVectorRaw("jcs", "key-sorting.json")
	if err != nil {
		t.Fatalf("failed to load key-sorting.json: %v", err)
	}

	var v struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		Tests       []struct {
			Name              string          `json:"name"`
			Input             json.RawMessage `json:"input"`
			ExpectedCanonical string          `json:"expected_canonical"`
			Description       string          `json:"description"`
		} `json:"tests"`
		Notes string `json:"notes"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("failed to parse vector: %v", err)
	}

	for _, tc := range v.Tests {
		t.Run(tc.Name, func(t *testing.T) {
			canonical, err := jcsutil.Canonicalize(tc.Input)
			if err != nil {
				t.Fatalf("canonicalization failed: %v", err)
			}

			if string(canonical) != tc.ExpectedCanonical {
				t.Errorf("canonical output mismatch:\n  expected: %s\n  computed: %s",
					tc.ExpectedCanonical, string(canonical))
			}
		})
	}
}

func TestJCSKeySortingSurrogate(t *testing.T) {
	SkipIfNoVectors(t)

	raw, err := LoadVectorRaw("jcs", "key-sorting-surrogate.json")
	if err != nil {
		t.Skipf("key-sorting-surrogate.json not found: %v", err)
	}

	var v struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		Tests       []struct {
			Name              string          `json:"name"`
			Input             json.RawMessage `json:"input"`
			ExpectedCanonical string          `json:"expected_canonical"`
			Description       string          `json:"description"`
		} `json:"tests"`
		Notes string `json:"notes"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("failed to parse vector: %v", err)
	}

	for _, tc := range v.Tests {
		t.Run(tc.Name, func(t *testing.T) {
			canonical, err := jcsutil.Canonicalize(tc.Input)
			if err != nil {
				t.Fatalf("canonicalization failed: %v", err)
			}

			if string(canonical) != tc.ExpectedCanonical {
				t.Errorf("canonical output mismatch:\n  expected: %s\n  computed: %s",
					tc.ExpectedCanonical, string(canonical))
			}
		})
	}
}

func TestJCSNumberNormalization(t *testing.T) {
	SkipIfNoVectors(t)

	raw, err := LoadVectorRaw("jcs", "number-normalization.json")
	if err != nil {
		t.Fatalf("failed to load number-normalization.json: %v", err)
	}

	var v struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		Tests       []struct {
			Name              string          `json:"name"`
			Input             json.RawMessage `json:"input"`
			ExpectedCanonical string          `json:"expected_canonical"`
			Description       string          `json:"description"`
		} `json:"tests"`
		Notes string `json:"notes"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("failed to parse vector: %v", err)
	}

	for _, tc := range v.Tests {
		t.Run(tc.Name, func(t *testing.T) {
			canonical, err := jcsutil.Canonicalize(tc.Input)
			if err != nil {
				t.Fatalf("canonicalization failed: %v", err)
			}

			if string(canonical) != tc.ExpectedCanonical {
				t.Errorf("canonical output mismatch:\n  expected: %s\n  computed: %s",
					tc.ExpectedCanonical, string(canonical))
			}
		})
	}
}

func TestJCSNonFiniteRejection(t *testing.T) {
	SkipIfNoVectors(t)

	raw, err := LoadVectorRaw("jcs", "non-finite-rejection.json")
	if err != nil {
		t.Fatalf("failed to load non-finite-rejection.json: %v", err)
	}

	var v struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		Tests       []struct {
			Name          string `json:"name"`
			Input         string `json:"input"` // Raw string to allow invalid JSON
			Valid         bool   `json:"valid"`
			ExpectedError string `json:"expected_error"`
			Description   string `json:"description"`
		} `json:"tests"`
		Notes string `json:"notes"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("failed to parse vector: %v", err)
	}

	for _, tc := range v.Tests {
		t.Run(tc.Name, func(t *testing.T) {
			_, err := jcsutil.Canonicalize([]byte(tc.Input))
			if tc.Valid {
				if err != nil {
					t.Errorf("expected valid but got error: %v", err)
				}
			} else {
				if err == nil {
					t.Errorf("expected invalid (error: %s) but canonicalization succeeded", tc.ExpectedError)
				}
			}
		})
	}
}

func TestJCSStringEscaping(t *testing.T) {
	SkipIfNoVectors(t)

	raw, err := LoadVectorRaw("jcs", "string-escaping.json")
	if err != nil {
		t.Fatalf("failed to load string-escaping.json: %v", err)
	}

	var v struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		Tests       []struct {
			Name              string          `json:"name"`
			Input             json.RawMessage `json:"input"`
			InputJSON         string          `json:"input_json"` // Alternative: raw JSON string
			ExpectedCanonical string          `json:"expected_canonical"`
			Description       string          `json:"description"`
		} `json:"tests"`
		Notes string `json:"notes"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("failed to parse vector: %v", err)
	}

	for _, tc := range v.Tests {
		t.Run(tc.Name, func(t *testing.T) {
			// Use input_json if provided (for testing unicode escape normalization),
			// otherwise use the input field
			var inputBytes []byte
			if tc.InputJSON != "" {
				inputBytes = []byte(tc.InputJSON)
			} else {
				inputBytes = tc.Input
			}

			canonical, err := jcsutil.Canonicalize(inputBytes)
			if err != nil {
				t.Fatalf("canonicalization failed: %v", err)
			}

			if string(canonical) != tc.ExpectedCanonical {
				t.Errorf("canonical output mismatch:\n  expected: %s\n  computed: %s",
					tc.ExpectedCanonical, string(canonical))
			}
		})
	}
}
