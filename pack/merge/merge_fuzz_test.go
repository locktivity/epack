package merge

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/locktivity/epack/pack"
)

// FuzzParseEmbeddedAttestation tests parsing of Sigstore bundle JSON.
// This is called when merging packs with IncludeAttestations enabled.
func FuzzParseEmbeddedAttestation(f *testing.F) {
	// Valid Sigstore bundle
	f.Add([]byte(`{
		"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
		"verificationMaterial": {"key": "value"},
		"dsseEnvelope": {"payload": "base64data"}
	}`))

	// Valid but minimal
	f.Add([]byte(`{"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json", "verificationMaterial": {}, "dsseEnvelope": {}}`))

	// Wrong media type
	f.Add([]byte(`{"mediaType": "application/json", "verificationMaterial": {}, "dsseEnvelope": {}}`))
	f.Add([]byte(`{"mediaType": "", "verificationMaterial": {}, "dsseEnvelope": {}}`))

	// Missing mediaType
	f.Add([]byte(`{"verificationMaterial": {}, "dsseEnvelope": {}}`))

	// Not JSON
	f.Add([]byte(`not json at all`))
	f.Add([]byte(``))
	f.Add([]byte(`{`))

	// Large nested structures (depth bomb)
	deep := `{"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json", "verificationMaterial": `
	for i := 0; i < 50; i++ {
		deep += `{"nested": `
	}
	deep += `"value"`
	for i := 0; i < 50; i++ {
		deep += `}`
	}
	deep += `, "dsseEnvelope": {}}`
	f.Add([]byte(deep))

	// Large arrays
	f.Add([]byte(`{"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json", "verificationMaterial": {"certs": [` +
		strings.Repeat(`"cert",`, 1000) + `"last"]}, "dsseEnvelope": {}}`))

	// Unicode in fields
	f.Add([]byte(`{"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json", "verificationMaterial": {"key": "日本語"}, "dsseEnvelope": {}}`))

	// Extra fields (should be preserved in RawMessage)
	f.Add([]byte(`{"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json", "verificationMaterial": {}, "dsseEnvelope": {}, "extraField": "ignored"}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		att, err := parseEmbeddedAttestation(data)

		if err == nil && att != nil {
			// Property: MediaType must be the expected Sigstore type
			if att.MediaType != pack.SigstoreBundleMediaType {
				t.Errorf("accepted wrong mediaType: %q", att.MediaType)
			}

			// Property: VerificationMaterial and DSSEEnvelope should be valid JSON
			if len(att.VerificationMaterial) > 0 {
				var vm interface{}
				if json.Unmarshal(att.VerificationMaterial, &vm) != nil {
					t.Errorf("VerificationMaterial is not valid JSON")
				}
			}
			if len(att.DSSEEnvelope) > 0 {
				var env interface{}
				if json.Unmarshal(att.DSSEEnvelope, &env) != nil {
					t.Errorf("DSSEEnvelope is not valid JSON")
				}
			}
		}
	})
}

// FuzzCountEmbeddedArtifacts tests artifact counting.
func FuzzCountEmbeddedArtifacts(f *testing.F) {
	// Various artifact lists encoded as comma-separated types
	f.Add("embedded,embedded,embedded")
	f.Add("embedded,reference,embedded")
	f.Add("reference,reference")
	f.Add("")
	f.Add("embedded")
	f.Add(strings.Repeat("embedded,", 100) + "embedded")

	f.Fuzz(func(t *testing.T, typesStr string) {
		// Build artifacts list from fuzz input
		var artifacts []pack.Artifact
		if typesStr != "" {
			types := strings.Split(typesStr, ",")
			for i, typ := range types {
				artifacts = append(artifacts, pack.Artifact{
					Type: typ,
					Path: "artifacts/file" + string(rune('0'+i%10)) + ".json",
				})
			}
		}

		count := countEmbeddedArtifacts(artifacts)

		// Property: Count must be non-negative
		if count < 0 {
			t.Errorf("negative count: %d", count)
		}

		// Property: Count must not exceed total artifacts
		if count > len(artifacts) {
			t.Errorf("count %d exceeds artifact count %d", count, len(artifacts))
		}

		// Property: Count must match manual count
		expected := 0
		for _, a := range artifacts {
			if a.Type == "embedded" {
				expected++
			}
		}
		if count != expected {
			t.Errorf("count mismatch: got %d, want %d", count, expected)
		}
	})
}

// FuzzIsAlreadyMergedPack tests detection of merged packs.
func FuzzIsAlreadyMergedPack(f *testing.F) {
	f.Add("merged", true)
	f.Add("collected", true)
	f.Add("", true)
	f.Add("merged", false)
	f.Add("other", true)

	f.Fuzz(func(t *testing.T, provType string, hasProvenance bool) {
		var manifest pack.Manifest
		if hasProvenance {
			manifest.Provenance = &pack.Provenance{
				Type: provType,
			}
		}

		result := isAlreadyMergedPack(manifest)

		// Property: Only "merged" type with non-nil provenance returns true
		expected := hasProvenance && provType == "merged"
		if result != expected {
			t.Errorf("isAlreadyMergedPack(%q, hasProvenance=%v) = %v, want %v",
				provType, hasProvenance, result, expected)
		}
	})
}

// FuzzDuplicateStreamError tests error message generation.
func FuzzDuplicateStreamError(f *testing.F) {
	f.Add("org/prod", "pack1.zip", false, "pack2.zip", true)
	f.Add("stream", "", true, "", false)
	f.Add("a/b/c", "file.zip", false, "file.zip", false)

	f.Fuzz(func(t *testing.T, stream, path1 string, nested1 bool, path2 string, nested2 bool) {
		first := streamLocation{
			stream:     stream,
			sourcePath: path1,
			nested:     nested1,
		}
		second := streamLocation{
			stream:     stream,
			sourcePath: path2,
			nested:     nested2,
		}

		err := duplicateStreamError(stream, first, second)

		// Property: Error should not be nil
		if err == nil {
			t.Errorf("duplicateStreamError returned nil")
			return
		}

		// Property: Error message should contain stream name (quoted with %q)
		errStr := err.Error()
		quotedStream := fmt.Sprintf("%q", stream)
		if !strings.Contains(errStr, quotedStream) {
			t.Errorf("error message missing stream: %s", errStr)
		}

		// Property: Error message should mention "duplicate"
		if !strings.Contains(strings.ToLower(errStr), "duplicate") {
			t.Errorf("error message missing 'duplicate': %s", errStr)
		}

		// Property: Nested locations should have "(nested)" in message
		if nested1 && !strings.Contains(errStr, "(nested)") {
			t.Errorf("error message missing '(nested)' for nested first: %s", errStr)
		}
		if nested2 && !strings.Contains(errStr, "(nested)") {
			t.Errorf("error message missing '(nested)' for nested second: %s", errStr)
		}
	})
}

// FuzzCountMergeDepth tests merge depth counting.
func FuzzCountMergeDepth(f *testing.F) {
	f.Add("merged", 0)
	f.Add("collected", 0)
	f.Add("", 0)
	f.Add("merged", 5)

	f.Fuzz(func(t *testing.T, provType string, sourceCount int) {
		if sourceCount < 0 {
			sourceCount = 0
		}
		if sourceCount > 100 {
			sourceCount = 100
		}

		var manifest pack.Manifest
		if provType != "" {
			sourcePacks := make([]pack.SourcePack, sourceCount)
			for i := 0; i < sourceCount; i++ {
				sourcePacks[i] = pack.SourcePack{
					Stream: "stream" + string(rune('0'+i%10)),
				}
			}
			manifest.Provenance = &pack.Provenance{
				Type:        provType,
				SourcePacks: sourcePacks,
			}
		}

		depth := countMergeDepth(manifest)

		// Property: Depth is non-negative
		if depth < 0 {
			t.Errorf("negative depth: %d", depth)
		}

		// Property: Non-merged packs have depth 0
		if provType != "merged" && depth != 0 {
			t.Errorf("non-merged pack has depth %d, want 0", depth)
		}

		// Property: Merged packs have depth >= 1
		if provType == "merged" && manifest.Provenance != nil && depth < 1 {
			t.Errorf("merged pack has depth %d, want >= 1", depth)
		}
	})
}
