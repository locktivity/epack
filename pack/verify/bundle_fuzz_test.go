package verify

import (
	"context"
	"testing"
)

// FuzzParseSigstoreBundle tests Sigstore bundle parsing with fuzzed inputs.
// This helps find edge cases in the bundle parsing and verification code path.
//
// SECURITY: The Sigstore bundle format is complex (protobuf + JSON + X.509 certs).
// Malformed bundles should fail gracefully without panics or excessive resource usage.
func FuzzParseSigstoreBundle(f *testing.F) {
	// Seed with minimal valid-looking JSON structures
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"mediaType":"application/vnd.dev.sigstore.bundle+json;version=0.1"}`))

	// Seed with DSSE envelope structure
	f.Add([]byte(`{
		"mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.1",
		"dsseEnvelope": {
			"payload": "eyJ0ZXN0IjoidmFsdWUifQ==",
			"payloadType": "application/vnd.in-toto+json",
			"signatures": []
		}
	}`))

	// Seed with verification material
	f.Add([]byte(`{
		"mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.1",
		"verificationMaterial": {
			"publicKey": {"hint": "test"},
			"tlogEntries": []
		}
	}`))

	// Seed with certificate chain
	f.Add([]byte(`{
		"mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.1",
		"verificationMaterial": {
			"x509CertificateChain": {
				"certificates": [{"rawBytes": "dGVzdA=="}]
			}
		}
	}`))

	// Seed with deeply nested structure
	f.Add([]byte(`{
		"mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.1",
		"dsseEnvelope": {
			"payload": "e30=",
			"payloadType": "application/vnd.in-toto+json",
			"signatures": [{
				"sig": "dGVzdA==",
				"keyid": "test"
			}]
		},
		"verificationMaterial": {
			"publicKey": {"hint": "test"},
			"tlogEntries": [{
				"logIndex": "1",
				"logId": {"keyId": "dGVzdA=="},
				"kindVersion": {"kind": "hashedrekord", "version": "0.0.1"},
				"integratedTime": "1234567890",
				"inclusionPromise": {"signedEntryTimestamp": "dGVzdA=="},
				"inclusionProof": {
					"logIndex": "1",
					"rootHash": "dGVzdA==",
					"treeSize": "10",
					"hashes": ["dGVzdA=="]
				},
				"canonicalizedBody": "dGVzdA=="
			}],
			"timestampVerificationData": {
				"rfc3161Timestamps": [{"signedTimestamp": "dGVzdA=="}]
			}
		}
	}`))

	// Seed with message signature structure
	f.Add([]byte(`{
		"mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.1",
		"messageSignature": {
			"messageDigest": {
				"algorithm": "SHA2_256",
				"digest": "dGVzdA=="
			},
			"signature": "dGVzdA=="
		}
	}`))

	// Seed with potential attack patterns
	// Very long strings
	f.Add([]byte(`{"mediaType":"` + string(make([]byte, 1000)) + `"}`))

	// Unicode edge cases
	f.Add([]byte(`{"mediaType":"application/vnd.dev.sigstore.bundle\u0000+json"}`))

	// Duplicate keys (security issue for some parsers)
	f.Add([]byte(`{"mediaType":"type1","mediaType":"type2"}`))

	// Invalid base64 in fields expecting base64
	f.Add([]byte(`{
		"verificationMaterial": {
			"x509CertificateChain": {
				"certificates": [{"rawBytes": "not-valid-base64!!!"}]
			}
		}
	}`))

	// Integer overflow attempts
	f.Add([]byte(`{
		"verificationMaterial": {
			"tlogEntries": [{
				"logIndex": "99999999999999999999999999999999"
			}]
		}
	}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		// ValidateAttestation should not panic
		_ = ValidateAttestation(data)

		// Create a verifier with insecure settings for fuzzing
		// (we're testing parsing, not actual crypto verification)
		verifier, err := NewSigstoreVerifier(WithInsecureSkipIdentityCheck())
		if err != nil {
			// Verifier creation can fail (e.g., network issues getting TUF root)
			// This is not a bug in the bundle parsing code
			return
		}

		// Verify should not panic, even on malformed input
		// Errors are expected and acceptable
		_, _ = verifier.Verify(context.Background(), data)
	})
}

// FuzzValidateAttestation tests attestation validation with fuzzed inputs.
// This specifically tests the size and depth limits that protect against DoS.
func FuzzValidateAttestation(f *testing.F) {
	// Seed with various JSON structures
	f.Add([]byte(`{}`))
	f.Add([]byte(`[]`))
	f.Add([]byte(`null`))
	f.Add([]byte(`"string"`))
	f.Add([]byte(`123`))
	f.Add([]byte(`true`))

	// Deeply nested objects
	f.Add([]byte(`{"a":{"b":{"c":{"d":{"e":{"f":{"g":{"h":{"i":{"j":{}}}}}}}}}}}`))

	// Deeply nested arrays
	f.Add([]byte(`[[[[[[[[[[]]]]]]]]]]`))

	// Mixed deep nesting
	f.Add([]byte(`{"a":[{"b":[{"c":[{"d":[]}]}]}]}`))

	// Very wide objects
	f.Add([]byte(`{"a":1,"b":2,"c":3,"d":4,"e":5,"f":6,"g":7,"h":8,"i":9,"j":10}`))

	// Large arrays
	f.Add([]byte(`[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20]`))

	// Invalid JSON
	f.Add([]byte(`{invalid}`))
	f.Add([]byte(`{"key": undefined}`))
	f.Add([]byte(`{'single': 'quotes'}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		// ValidateAttestation should not panic on any input
		// It should return an error for invalid/oversized input
		_ = ValidateAttestation(data)
	})
}

// FuzzExtractStatementFromBundleJSON tests statement extraction from bundle payloads.
// This tests the JSON parsing path for in-toto statements.
func FuzzExtractStatementFromBundleJSON(f *testing.F) {
	// Valid in-toto statement
	f.Add([]byte(`{
		"_type": "https://in-toto.io/Statement/v1",
		"predicateType": "https://example.com/predicate/v1",
		"subject": [{"name": "artifact", "digest": {"sha256": "abc123"}}],
		"predicate": {"key": "value"}
	}`))

	// Statement with multiple subjects
	f.Add([]byte(`{
		"_type": "https://in-toto.io/Statement/v1",
		"predicateType": "https://slsa.dev/provenance/v1",
		"subject": [
			{"name": "artifact1", "digest": {"sha256": "abc"}},
			{"name": "artifact2", "digest": {"sha256": "def"}}
		],
		"predicate": {}
	}`))

	// Empty predicate
	f.Add([]byte(`{
		"_type": "https://in-toto.io/Statement/v1",
		"predicateType": "https://example.com/empty",
		"subject": [],
		"predicate": null
	}`))

	// Duplicate keys (security: should be detected)
	f.Add([]byte(`{
		"_type": "https://in-toto.io/Statement/v1",
		"predicate": {"safe": true},
		"predicate": {"malicious": true}
	}`))

	// Deep nesting in predicate
	f.Add([]byte(`{
		"_type": "https://in-toto.io/Statement/v1",
		"predicateType": "test",
		"subject": [],
		"predicate": {"a":{"b":{"c":{"d":{"e":{"f":{}}}}}}}
	}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		// Wrap the data in a minimal bundle structure and test statement extraction
		// This tests the jsonutil.ValidateNoDuplicateKeys path
		bundleJSON := []byte(`{
			"mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.1",
			"dsseEnvelope": {
				"payload": "` + string(data) + `",
				"payloadType": "application/vnd.in-toto+json",
				"signatures": []
			}
		}`)

		// ValidateAttestation should not panic
		_ = ValidateAttestation(bundleJSON)
	})
}
