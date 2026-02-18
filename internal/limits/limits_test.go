package limits

import "testing"

// TestLimitsArePositive ensures all typed limits are positive values.
// This catches accidental zero or negative values that would disable safety checks.
func TestLimitsArePositive(t *testing.T) {
	tests := []struct {
		name  string
		value SizeLimit
	}{
		{"Artifact", Artifact},
		{"Manifest", Manifest},
		{"Attestation", Attestation},
		{"ConfigFile", ConfigFile},
		{"LockFile", LockFile},
		{"JSONResponse", JSONResponse},
		{"Catalog", Catalog},
		{"CatalogMeta", CatalogMeta},
		{"ToolResult", ToolResult},
		{"CollectorOutput", CollectorOutput},
		{"AssetDownload", AssetDownload},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.value <= 0 {
				t.Errorf("%s = %d, want > 0", tt.name, tt.value)
			}
		})
	}
}

func TestIntLimitsArePositive(t *testing.T) {
	tests := []struct {
		name  string
		value int
	}{
		{"MaxArtifactCount", MaxArtifactCount},
		{"MaxCompressionRatio", MaxCompressionRatio},
		{"MaxZipEntries", MaxZipEntries},
		{"MaxAttestationJSONDepth", MaxAttestationJSONDepth},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.value <= 0 {
				t.Errorf("%s = %d, want > 0", tt.name, tt.value)
			}
		})
	}
}

// TestLimitsAreConsistent ensures related limits are logically consistent.
func TestLimitsAreConsistent(t *testing.T) {
	// Artifact size must be less than pack size
	if Artifact.Bytes() >= MaxPackSizeBytes {
		t.Errorf("Artifact (%d) >= MaxPackSizeBytes (%d)",
			Artifact.Bytes(), MaxPackSizeBytes)
	}

	// Manifest size must be less than pack size
	if Manifest.Bytes() >= MaxPackSizeBytes {
		t.Errorf("Manifest (%d) >= MaxPackSizeBytes (%d)",
			Manifest.Bytes(), MaxPackSizeBytes)
	}

	// Attestation size should be much smaller than artifact size
	if Attestation >= Artifact {
		t.Errorf("Attestation (%d) >= Artifact (%d)",
			Attestation.Bytes(), Artifact.Bytes())
	}

	// Max artifacts should fit within zip entry limit (with room for manifest/attestations)
	if MaxArtifactCount >= MaxZipEntries {
		t.Errorf("MaxArtifactCount (%d) >= MaxZipEntries (%d)",
			MaxArtifactCount, MaxZipEntries)
	}
}

// TestLimitsMatchSpec verifies limits match spec Section 7.2 values.
func TestLimitsMatchSpec(t *testing.T) {
	// These are the documented spec values - tests will fail if changed accidentally
	const (
		specMaxArtifactSize = 100 * 1024 * 1024      // 100 MB
		specMaxPackSize     = 2 * 1024 * 1024 * 1024 // 2 GB
		specMaxArtifacts    = 10000
		specMaxManifest     = 10 * 1024 * 1024 // 10 MB
	)

	if Artifact.Bytes() != specMaxArtifactSize {
		t.Errorf("Artifact = %d, spec says %d", Artifact.Bytes(), specMaxArtifactSize)
	}
	if MaxPackSizeBytes != specMaxPackSize {
		t.Errorf("MaxPackSizeBytes = %d, spec says %d", MaxPackSizeBytes, specMaxPackSize)
	}
	if MaxArtifactCount != specMaxArtifacts {
		t.Errorf("MaxArtifactCount = %d, spec says %d", MaxArtifactCount, specMaxArtifacts)
	}
	if Manifest.Bytes() != specMaxManifest {
		t.Errorf("Manifest = %d, spec says %d", Manifest.Bytes(), specMaxManifest)
	}
}

// TestSizeLimitBytes verifies the Bytes() method works correctly.
func TestSizeLimitBytes(t *testing.T) {
	if ConfigFile.Bytes() != 1*1024*1024 {
		t.Errorf("ConfigFile.Bytes() = %d, want %d", ConfigFile.Bytes(), 1*1024*1024)
	}
	if LockFile.Bytes() != 10*1024*1024 {
		t.Errorf("LockFile.Bytes() = %d, want %d", LockFile.Bytes(), 10*1024*1024)
	}
}
