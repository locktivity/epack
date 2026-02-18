// Package conformance implements test vector runners for Evidence Pack spec conformance testing.
// This package is intended for this repository's test harness and does not provide
// a stable public API contract for external consumers.
package conformance

import "encoding/json"

// VectorResult represents the output of running a single test vector, per runner-spec.md.
type VectorResult struct {
	Vector string       `json:"vector"`
	Valid  bool         `json:"valid"`
	Result ResultDetail `json:"result"`
}

// ResultDetail contains the actual test execution results.
type ResultDetail struct {
	OK       bool          `json:"ok"`
	Errors   []VectorError `json:"errors,omitempty"`
	Computed *Computed     `json:"computed,omitempty"`
}

// VectorError describes an error encountered during vector execution.
type VectorError struct {
	Code     string `json:"code"`
	Message  string `json:"message,omitempty"`
	Location string `json:"location,omitempty"`
}

// Computed contains computed values for comparison with expected values.
type Computed struct {
	PackDigest     string `json:"pack_digest,omitempty"`
	CanonicalInput string `json:"canonical_input,omitempty"`
}

// PackDigestVector represents a test vector for pack_digest computation.
type PackDigestVector struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Input       struct {
		Artifacts []ArtifactInput `json:"artifacts"`
	} `json:"input"`
	Expected struct {
		PackDigest     string   `json:"pack_digest"`
		CanonicalInput string   `json:"canonical_input,omitempty"`
		SortedPaths    []string `json:"sorted_paths,omitempty"`
	} `json:"expected"`
	Valid bool   `json:"valid"`
	Notes string `json:"notes,omitempty"`
}

// ArtifactInput represents an artifact in test vector input.
type ArtifactInput struct {
	Type   string `json:"type"`
	Path   string `json:"path"`
	Digest string `json:"digest"`
	Size   int64  `json:"size"`
}

// PathValidationVector represents a test vector file for path validation.
type PathValidationVector struct {
	Name        string               `json:"name"`
	Description string               `json:"description"`
	Tests       []PathValidationTest `json:"tests"`
}

// PathValidationTest is a single path validation test case.
type PathValidationTest struct {
	Path        string   `json:"path,omitempty"`
	Paths       []string `json:"paths,omitempty"`
	Valid       bool     `json:"valid"`
	Reason      string   `json:"reason,omitempty"`
	Description string   `json:"description,omitempty"`
}

// ZipSafetyVector represents a test vector file for ZIP safety checks.
// Some vectors have a single test (with fixture), others have multiple tests.
type ZipSafetyVector struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	// For single-test vectors with ZIP fixtures
	Fixture string `json:"fixture,omitempty"`
	Valid   bool   `json:"valid"`
	Reason  string `json:"reason,omitempty"`
	Notes   string `json:"notes,omitempty"`
	// For multi-test vectors
	Tests []ZipSafetyTest `json:"tests,omitempty"`
}

// ZipSafetyTest is a single ZIP safety test case.
type ZipSafetyTest struct {
	EntryPath   string `json:"entry_path,omitempty"`
	Path        string `json:"path,omitempty"`
	Expected    string `json:"expected"` // "reject" or "accept"
	Reason      string `json:"reason"`
	Description string `json:"description,omitempty"`
}

// StructureVector represents a test vector file for pack structure validation.
type StructureVector struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Tests       []StructureTest `json:"tests,omitempty"`
	// Additional metadata sections
	ZIP64Requirements json.RawMessage `json:"zip64_requirements,omitempty"`
	MetadataHandling  json.RawMessage `json:"metadata_handling,omitempty"`
	Notes             string          `json:"notes,omitempty"`
}

// StructureTest is a single structure validation test case.
type StructureTest struct {
	Name          string   `json:"name"`
	Structure     []string `json:"structure,omitempty"`
	Filename      string   `json:"filename,omitempty"`
	Content       string   `json:"content,omitempty"`
	Valid         bool     `json:"valid"`
	ExpectedError string   `json:"expected_error,omitempty"`
	Requirements  []string `json:"requirements,omitempty"`
	Description   string   `json:"description"`
}

// LimitsVector represents a test vector file for limit enforcement.
type LimitsVector struct {
	Name                  string `json:"name"`
	Description           string `json:"description"`
	MinimumRequiredLimits struct {
		MaxArtifactSize struct {
			Minimum      int64  `json:"minimum"`
			MinimumHuman string `json:"minimum_human"`
			Description  string `json:"description"`
		} `json:"max_artifact_size"`
		MaxPackSize struct {
			Minimum      int64  `json:"minimum"`
			MinimumHuman string `json:"minimum_human"`
			Description  string `json:"description"`
		} `json:"max_pack_size"`
		MaxArtifactCount struct {
			Minimum     int    `json:"minimum"`
			Description string `json:"description"`
		} `json:"max_artifact_count"`
	} `json:"minimum_required_limits"`
	Tests []LimitsTest `json:"tests"`
	Notes string       `json:"notes,omitempty"`
}

// LimitsTest is a single limit enforcement test case.
type LimitsTest struct {
	Config      map[string]int64 `json:"config"`
	Expected    string           `json:"expected"` // "reject_config" or "accept_config"
	Reason      string           `json:"reason,omitempty"`
	Description string           `json:"description"`
}

// ManifestVector represents a test vector file for manifest validation.
type ManifestVector struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Tests       []ManifestTest `json:"tests,omitempty"`
	Notes       string         `json:"notes,omitempty"`
}

// ManifestTest is a single manifest validation test case.
type ManifestTest struct {
	Name          string          `json:"name"`
	Input         json.RawMessage `json:"input"`
	Valid         bool            `json:"valid"`
	ExpectedError string          `json:"expected_error,omitempty"`
	Requirements  []string        `json:"requirements,omitempty"`
	Description   string          `json:"description"`
}

// TimestampVector represents a test vector file for timestamp validation.
type TimestampVector struct {
	Name              string          `json:"name"`
	Description       string          `json:"description"`
	ValidTimestamps   []TimestampCase `json:"valid_timestamps"`
	InvalidTimestamps []TimestampCase `json:"invalid_timestamps"`
	Notes             string          `json:"notes,omitempty"`
}

// TimestampCase is a single timestamp validation test case.
type TimestampCase struct {
	Value       string `json:"value"`
	Valid       bool   `json:"valid"`
	Reason      string `json:"reason,omitempty"`
	Description string `json:"description"`
}

// IntegerVector represents a test vector file for JSON integer validation.
type IntegerVector struct {
	Name            string        `json:"name"`
	Description     string        `json:"description"`
	ValidIntegers   []IntegerCase `json:"valid_integers"`
	InvalidIntegers []IntegerCase `json:"invalid_integers"`
	Notes           string        `json:"notes,omitempty"`
}

// IntegerCase is a single integer validation test case.
type IntegerCase struct {
	Value       int64  `json:"value,omitempty"`
	JSON        string `json:"json"`
	Reason      string `json:"reason,omitempty"`
	Description string `json:"description"`
}

// ManifestDigestVector represents a test vector for manifest_digest computation.
type ManifestDigestVector struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Input       struct {
		Manifest json.RawMessage `json:"manifest"`
	} `json:"input"`
	Expected struct {
		JCSCanonical string `json:"jcs_canonical"`
		SHA256       string `json:"sha256"`
	} `json:"expected"`
	Valid bool   `json:"valid"`
	Notes string `json:"notes,omitempty"`
}

// JCSVector represents a test vector for JCS canonicalization.
type JCSVector struct {
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Tests       []JCSTest `json:"tests"`
	Notes       string    `json:"notes,omitempty"`
}

// JCSTest is a single JCS test case.
type JCSTest struct {
	Name              string          `json:"name"`
	Input             json.RawMessage `json:"input"`
	ExpectedCanonical string          `json:"expected_canonical"`
	Valid             bool            `json:"valid"`
	ExpectedError     string          `json:"expected_error,omitempty"`
	Description       string          `json:"description"`
}

// AttestationVector represents a test vector for attestation validation.
type AttestationVector struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Input       struct {
		Bundle json.RawMessage `json:"bundle"`
	} `json:"input"`
	Valid         bool   `json:"valid"`
	ExpectedError string `json:"expected_error,omitempty"`
	Notes         string `json:"notes,omitempty"`
}

// ManifestRequiredFieldsVector represents test vectors for manifest required fields.
type ManifestRequiredFieldsVector struct {
	Name        string                       `json:"name"`
	Description string                       `json:"description"`
	Tests       []ManifestRequiredFieldsTest `json:"tests"`
	Notes       string                       `json:"notes,omitempty"`
}

// ManifestRequiredFieldsTest is a single required fields test case.
type ManifestRequiredFieldsTest struct {
	Name          string          `json:"name"`
	Input         json.RawMessage `json:"input"`
	Valid         bool            `json:"valid"`
	ExpectedError string          `json:"expected_error,omitempty"`
	Description   string          `json:"description"`
}

// DigestFormatVector represents test vectors for digest format validation.
type DigestFormatVector struct {
	Name        string             `json:"name"`
	Description string             `json:"description"`
	Tests       []DigestFormatTest `json:"tests"`
	Notes       string             `json:"notes,omitempty"`
}

// DigestFormatTest is a single digest format test case.
type DigestFormatTest struct {
	Digest        string `json:"digest"`
	Valid         bool   `json:"valid"`
	ExpectedError string `json:"expected_error,omitempty"`
	Description   string `json:"description"`
}

// DigestFormatVectorActual matches the actual test vector format with separate arrays.
type DigestFormatVectorActual struct {
	Name           string                    `json:"name"`
	Description    string                    `json:"description"`
	ValidDigests   []DigestFormatValidCase   `json:"valid_digests"`
	InvalidDigests []DigestFormatInvalidCase `json:"invalid_digests"`
	Notes          string                    `json:"notes,omitempty"`
}

// DigestFormatValidCase is a valid digest test case.
type DigestFormatValidCase struct {
	Value       string `json:"value"`
	Description string `json:"description"`
}

// DigestFormatInvalidCase is an invalid digest test case.
type DigestFormatInvalidCase struct {
	Value       string `json:"value"`
	Valid       bool   `json:"valid"`
	Reason      string `json:"reason"`
	Description string `json:"description"`
}

// ArtifactFieldsVector represents test vectors for artifact field validation.
type ArtifactFieldsVector struct {
	Name                    string              `json:"name"`
	Description             string              `json:"description"`
	EmbeddedArtifactTests   []ArtifactFieldTest `json:"embedded_artifact_tests"`
	ReferencedArtifactTests []ArtifactFieldTest `json:"referenced_artifact_tests"`
	Notes                   string              `json:"notes,omitempty"`
}

// ArtifactFieldTest is a single artifact field validation test case.
type ArtifactFieldTest struct {
	Name          string          `json:"name"`
	Input         json.RawMessage `json:"input"`
	Valid         bool            `json:"valid"`
	ExpectedError string          `json:"expected_error,omitempty"`
	Requirements  []string        `json:"requirements,omitempty"`
	Description   string          `json:"description"`
}

// ProvenanceVector represents test vectors for provenance validation.
type ProvenanceVector struct {
	Name              string                  `json:"name"`
	Description       string                  `json:"description"`
	ValidProvenance   []ProvenanceValidCase   `json:"valid_provenance"`
	InvalidProvenance []ProvenanceInvalidCase `json:"invalid_provenance"`
	Notes             string                  `json:"notes,omitempty"`
}

// ProvenanceValidCase is a valid provenance test case.
type ProvenanceValidCase struct {
	Description string          `json:"description"`
	Provenance  json.RawMessage `json:"provenance"`
	Valid       bool            `json:"valid"`
}

// ProvenanceInvalidCase is an invalid provenance test case.
type ProvenanceInvalidCase struct {
	Description string          `json:"description"`
	Provenance  json.RawMessage `json:"provenance"`
	Valid       bool            `json:"valid"`
	Reason      string          `json:"reason"`
}

// AccessPolicyVector represents test vectors for access policy validation.
type AccessPolicyVector struct {
	Name            string                    `json:"name"`
	Description     string                    `json:"description"`
	ValidPolicies   []AccessPolicyCase        `json:"valid_policies"`
	InvalidPolicies []AccessPolicyInvalidCase `json:"invalid_policies"`
	Notes           string                    `json:"notes,omitempty"`
}

// AccessPolicyCase is a valid policy test case.
type AccessPolicyCase struct {
	Policy      string `json:"policy"`
	Description string `json:"description"`
}

// AccessPolicyInvalidCase is an invalid policy test case.
type AccessPolicyInvalidCase struct {
	Policy      string `json:"policy"`
	Valid       bool   `json:"valid"`
	Reason      string `json:"reason"`
	Description string `json:"description"`
}
