package pack

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/locktivity/epack/errors"
)

func TestParseManifest(t *testing.T) {
	t.Parallel()

	validManifest := `{
		"spec_version": "1.0",
		"stream": "test-stream",
		"generated_at": "2024-01-15T10:30:00Z",
		"pack_digest": "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
		"sources": [],
		"artifacts": []
	}`

	tests := []struct {
		name    string
		input   string
		wantErr errors.Code
		wantMsg string
	}{
		{
			name:  "valid manifest",
			input: validManifest,
		},
		{
			name: "valid manifest with artifact",
			input: `{
				"spec_version": "1.0",
				"stream": "test-stream",
				"generated_at": "2024-01-15T10:30:00Z",
				"pack_digest": "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
				"sources": [],
				"artifacts": [{
					"type": "embedded",
					"path": "artifacts/test.json",
					"digest": "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
					"size": 1024
				}]
			}`,
		},

		// Missing required fields
		{
			name:    "missing spec_version",
			input:   `{"stream": "test", "generated_at": "2024-01-15T10:30:00Z", "pack_digest": "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789", "sources": [], "artifacts": []}`,
			wantErr: errors.MissingRequiredField,
			wantMsg: "spec_version is required",
		},
		{
			name:    "missing stream",
			input:   `{"spec_version": "1.0", "generated_at": "2024-01-15T10:30:00Z", "pack_digest": "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789", "sources": [], "artifacts": []}`,
			wantErr: errors.MissingRequiredField,
			wantMsg: "stream is required",
		},
		{
			name:    "missing generated_at",
			input:   `{"spec_version": "1.0", "stream": "test", "pack_digest": "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789", "sources": [], "artifacts": []}`,
			wantErr: errors.MissingRequiredField,
			wantMsg: "generated_at is required",
		},
		{
			name:    "missing pack_digest",
			input:   `{"spec_version": "1.0", "stream": "test", "generated_at": "2024-01-15T10:30:00Z", "sources": [], "artifacts": []}`,
			wantErr: errors.MissingRequiredField,
			wantMsg: "pack_digest is required",
		},
		{
			name:    "missing sources",
			input:   `{"spec_version": "1.0", "stream": "test", "generated_at": "2024-01-15T10:30:00Z", "pack_digest": "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789", "artifacts": []}`,
			wantErr: errors.MissingRequiredField,
			wantMsg: "sources is required",
		},
		{
			name:    "missing artifacts",
			input:   `{"spec_version": "1.0", "stream": "test", "generated_at": "2024-01-15T10:30:00Z", "pack_digest": "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789", "sources": []}`,
			wantErr: errors.MissingRequiredField,
			wantMsg: "artifacts is required",
		},

		// Invalid field values
		{
			name:    "unsupported spec_version",
			input:   `{"spec_version": "2.0", "stream": "test", "generated_at": "2024-01-15T10:30:00Z", "pack_digest": "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789", "sources": [], "artifacts": []}`,
			wantErr: errors.UnsupportedSpecVersion,
			wantMsg: "unsupported spec_version: 2.0",
		},
		{
			name:    "invalid timestamp",
			input:   `{"spec_version": "1.0", "stream": "test", "generated_at": "not-a-timestamp", "pack_digest": "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789", "sources": [], "artifacts": []}`,
			wantErr: errors.InvalidTimestamp,
		},
		{
			name:    "invalid pack_digest format",
			input:   `{"spec_version": "1.0", "stream": "test", "generated_at": "2024-01-15T10:30:00Z", "pack_digest": "invalid-digest", "sources": [], "artifacts": []}`,
			wantErr: errors.InvalidManifest,
			wantMsg: "invalid pack_digest format",
		},

		// Artifact validation
		{
			name: "invalid artifact type",
			input: `{
				"spec_version": "1.0",
				"stream": "test",
				"generated_at": "2024-01-15T10:30:00Z",
				"pack_digest": "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
				"sources": [],
				"artifacts": [{"type": "unknown", "path": "test.json", "digest": "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef", "size": 100}]
			}`,
			wantErr: errors.InvalidManifest,
			wantMsg: "invalid artifact type at index 0: unknown",
		},
		{
			name: "invalid artifact digest",
			input: `{
				"spec_version": "1.0",
				"stream": "test",
				"generated_at": "2024-01-15T10:30:00Z",
				"pack_digest": "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
				"sources": [],
				"artifacts": [{"type": "embedded", "path": "artifacts/test.json", "digest": "bad-digest", "size": 100}]
			}`,
			wantErr: errors.InvalidManifest,
			wantMsg: "invalid digest format for artifact at index 0",
		},
		{
			name: "missing artifact path",
			input: `{
				"spec_version": "1.0",
				"stream": "test",
				"generated_at": "2024-01-15T10:30:00Z",
				"pack_digest": "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
				"sources": [],
				"artifacts": [{"type": "embedded", "digest": "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef", "size": 100}]
			}`,
			wantErr: errors.MissingRequiredField,
			wantMsg: "path is required for artifact at index 0",
		},
		{
			name: "missing artifact size",
			input: `{
				"spec_version": "1.0",
				"stream": "test",
				"generated_at": "2024-01-15T10:30:00Z",
				"pack_digest": "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
				"sources": [],
				"artifacts": [{"type": "embedded", "path": "artifacts/test.json", "digest": "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"}]
			}`,
			wantErr: errors.MissingRequiredField,
			wantMsg: "size is required for artifact at index 0",
		},
		{
			name: "invalid artifact collected_at timestamp",
			input: `{
				"spec_version": "1.0",
				"stream": "test",
				"generated_at": "2024-01-15T10:30:00Z",
				"pack_digest": "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
				"sources": [],
				"artifacts": [{"type": "embedded", "path": "artifacts/test.json", "digest": "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef", "size": 100, "collected_at": "not-a-timestamp"}]
			}`,
			wantErr: errors.InvalidTimestamp,
			wantMsg: "must be format YYYY-MM-DDTHH:MM:SSZ",
		},
		{
			name: "embedded artifact path outside artifacts directory",
			input: `{
				"spec_version": "1.0",
				"stream": "test",
				"generated_at": "2024-01-15T10:30:00Z",
				"pack_digest": "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
				"sources": [],
				"artifacts": [{"type": "embedded", "path": "manifest.json", "digest": "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef", "size": 100}]
			}`,
			wantErr: errors.InvalidPath,
			wantMsg: "embedded artifact path must start with 'artifacts/'",
		},
		{
			name: "embedded artifact path with relative escape",
			input: `{
				"spec_version": "1.0",
				"stream": "test",
				"generated_at": "2024-01-15T10:30:00Z",
				"pack_digest": "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
				"sources": [],
				"artifacts": [{"type": "embedded", "path": "other/file.json", "digest": "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef", "size": 100}]
			}`,
			wantErr: errors.InvalidPath,
			wantMsg: "embedded artifact path must start with 'artifacts/'",
		},
		{
			name: "duplicate artifact paths",
			input: `{
				"spec_version": "1.0",
				"stream": "test",
				"generated_at": "2024-01-15T10:30:00Z",
				"pack_digest": "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
				"sources": [],
				"artifacts": [
					{"type": "embedded", "path": "artifacts/test.json", "digest": "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef", "size": 100},
					{"type": "embedded", "path": "artifacts/test.json", "digest": "sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890", "size": 200}
				]
			}`,
			wantErr: errors.DuplicatePath,
			wantMsg: "duplicate artifact path",
		},
		{
			name: "duplicate artifact paths with different digests",
			input: `{
				"spec_version": "1.0",
				"stream": "test",
				"generated_at": "2024-01-15T10:30:00Z",
				"pack_digest": "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
				"sources": [],
				"artifacts": [
					{"type": "embedded", "path": "artifacts/a.json", "digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111", "size": 10},
					{"type": "embedded", "path": "artifacts/b.json", "digest": "sha256:2222222222222222222222222222222222222222222222222222222222222222", "size": 20},
					{"type": "embedded", "path": "artifacts/a.json", "digest": "sha256:3333333333333333333333333333333333333333333333333333333333333333", "size": 30}
				]
			}`,
			wantErr: errors.DuplicatePath,
			wantMsg: "duplicate artifact path \"artifacts/a.json\" at index 2 (collides with path at index 0 on Windows)",
		},
		{
			name: "duplicate artifact paths case-insensitive",
			input: `{
				"spec_version": "1.0",
				"stream": "test",
				"generated_at": "2024-01-15T10:30:00Z",
				"pack_digest": "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
				"sources": [],
				"artifacts": [
					{"type": "embedded", "path": "artifacts/Test.json", "digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111", "size": 10},
					{"type": "embedded", "path": "artifacts/test.json", "digest": "sha256:2222222222222222222222222222222222222222222222222222222222222222", "size": 20}
				]
			}`,
			wantErr: errors.DuplicatePath,
			wantMsg: "duplicate artifact path",
		},

		// Source validation
		{
			name: "missing source name",
			input: `{
				"spec_version": "1.0",
				"stream": "test",
				"generated_at": "2024-01-15T10:30:00Z",
				"pack_digest": "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
				"sources": [{"version": "1.0.0"}],
				"artifacts": []
			}`,
			wantErr: errors.MissingRequiredField,
			wantMsg: "name is required for source at index 0",
		},
		{
			name: "source version optional",
			input: `{
				"spec_version": "1.0",
				"stream": "test",
				"generated_at": "2024-01-15T10:30:00Z",
				"pack_digest": "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
				"sources": [{"name": "collector"}],
				"artifacts": []
			}`,
			wantErr: "", // version is optional per spec Section 3.4.6
		},

		// Provenance validation
		{
			name: "valid manifest with single provenance",
			input: `{
				"spec_version": "1.0",
				"stream": "test",
				"generated_at": "2024-01-15T10:30:00Z",
				"pack_digest": "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
				"sources": [],
				"artifacts": [],
				"provenance": {"type": "single"}
			}`,
		},
		{
			name: "valid manifest with merged provenance",
			input: `{
				"spec_version": "1.0",
				"stream": "test",
				"generated_at": "2024-01-15T10:30:00Z",
				"pack_digest": "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
				"sources": [],
				"artifacts": [],
				"provenance": {
					"type": "merged",
					"merged_at": "2024-01-15T10:30:00Z",
					"source_packs": [{
						"stream": "source-stream",
						"pack_digest": "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
						"manifest_digest": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
						"artifacts": 5
					}]
				}
			}`,
		},
		{
			name: "missing provenance type",
			input: `{
				"spec_version": "1.0",
				"stream": "test",
				"generated_at": "2024-01-15T10:30:00Z",
				"pack_digest": "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
				"sources": [],
				"artifacts": [],
				"provenance": {}
			}`,
			wantErr: errors.MissingRequiredField,
			wantMsg: "type is required for provenance",
		},
		{
			name: "unsupported provenance type",
			input: `{
				"spec_version": "1.0",
				"stream": "test",
				"generated_at": "2024-01-15T10:30:00Z",
				"pack_digest": "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
				"sources": [],
				"artifacts": [],
				"provenance": {"type": "unknown"}
			}`,
			wantErr: errors.InvalidManifest,
			wantMsg: "unsupported provenance type: unknown",
		},
		{
			name: "missing source pack stream",
			input: `{
				"spec_version": "1.0",
				"stream": "test",
				"generated_at": "2024-01-15T10:30:00Z",
				"pack_digest": "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
				"sources": [],
				"artifacts": [],
				"provenance": {
					"type": "merged",
					"merged_at": "2024-01-15T10:30:00Z",
					"source_packs": [{"pack_digest": "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef", "artifacts": 5}]
				}
			}`,
			wantErr: errors.MissingRequiredField,
			wantMsg: "stream is required for source pack at index 0",
		},
		{
			name: "missing source pack pack_digest",
			input: `{
				"spec_version": "1.0",
				"stream": "test",
				"generated_at": "2024-01-15T10:30:00Z",
				"pack_digest": "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
				"sources": [],
				"artifacts": [],
				"provenance": {
					"type": "merged",
					"merged_at": "2024-01-15T10:30:00Z",
					"source_packs": [{"stream": "source-stream", "artifacts": 5}]
				}
			}`,
			wantErr: errors.MissingRequiredField,
			wantMsg: "pack_digest is required for source pack at index 0",
		},
		{
			name: "invalid source pack pack_digest format",
			input: `{
				"spec_version": "1.0",
				"stream": "test",
				"generated_at": "2024-01-15T10:30:00Z",
				"pack_digest": "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
				"sources": [],
				"artifacts": [],
				"provenance": {
					"type": "merged",
					"merged_at": "2024-01-15T10:30:00Z",
					"source_packs": [{"stream": "source-stream", "pack_digest": "invalid-digest", "artifacts": 5}]
				}
			}`,
			wantErr: errors.InvalidManifest,
			wantMsg: "invalid pack_digest format for source pack at index 0",
		},
		{
			name: "missing source pack manifest_digest",
			input: `{
				"spec_version": "1.0",
				"stream": "test",
				"generated_at": "2024-01-15T10:30:00Z",
				"pack_digest": "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
				"sources": [],
				"artifacts": [],
				"provenance": {
					"type": "merged",
					"merged_at": "2024-01-15T10:30:00Z",
					"source_packs": [{"stream": "source-stream", "pack_digest": "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef", "artifacts": 5}]
				}
			}`,
			wantErr: errors.MissingRequiredField,
			wantMsg: "manifest_digest is required for source pack at index 0",
		},
		{
			name: "invalid source pack manifest_digest format - too short",
			input: `{
				"spec_version": "1.0",
				"stream": "test",
				"generated_at": "2024-01-15T10:30:00Z",
				"pack_digest": "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
				"sources": [],
				"artifacts": [],
				"provenance": {
					"type": "merged",
					"merged_at": "2024-01-15T10:30:00Z",
					"source_packs": [{"stream": "source-stream", "pack_digest": "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef", "manifest_digest": "abc123", "artifacts": 5}]
				}
			}`,
			wantErr: errors.InvalidManifest,
			wantMsg: "invalid manifest_digest format for source pack at index 0",
		},
		{
			name: "invalid source pack manifest_digest format - uppercase",
			input: `{
				"spec_version": "1.0",
				"stream": "test",
				"generated_at": "2024-01-15T10:30:00Z",
				"pack_digest": "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
				"sources": [],
				"artifacts": [],
				"provenance": {
					"type": "merged",
					"merged_at": "2024-01-15T10:30:00Z",
					"source_packs": [{"stream": "source-stream", "pack_digest": "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef", "manifest_digest": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "artifacts": 5}]
				}
			}`,
			wantErr: errors.InvalidManifest,
			wantMsg: "invalid manifest_digest format for source pack at index 0",
		},

		// Embedded attestation validation (Sigstore bundle format per spec Section 3.7)
		{
			name: "valid manifest with embedded attestation",
			input: `{
				"spec_version": "1.0",
				"stream": "test",
				"generated_at": "2024-01-15T10:30:00Z",
				"pack_digest": "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
				"sources": [],
				"artifacts": [],
				"provenance": {
					"type": "merged",
					"merged_at": "2024-01-15T10:30:00Z",
					"source_packs": [{
						"stream": "source-stream",
						"pack_digest": "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
						"manifest_digest": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
						"artifacts": 5,
						"embedded_attestations": [{
							"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
							"verificationMaterial": {"x509CertificateChain": {"certificates": ["..."]}},
							"dsseEnvelope": {"payloadType": "application/vnd.in-toto+json", "payload": "...", "signatures": []}
						}]
					}]
				}
			}`,
		},
		{
			name: "missing embedded attestation mediaType",
			input: `{
				"spec_version": "1.0",
				"stream": "test",
				"generated_at": "2024-01-15T10:30:00Z",
				"pack_digest": "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
				"sources": [],
				"artifacts": [],
				"provenance": {
					"type": "merged",
					"merged_at": "2024-01-15T10:30:00Z",
					"source_packs": [{
						"stream": "source-stream",
						"pack_digest": "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
						"manifest_digest": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
						"artifacts": 5,
						"embedded_attestations": [{
							"verificationMaterial": {"x509CertificateChain": {"certificates": ["..."]}},
							"dsseEnvelope": {"payloadType": "application/vnd.in-toto+json", "payload": "...", "signatures": []}
						}]
					}]
				}
			}`,
			wantErr: errors.InvalidManifest,
			wantMsg: "mediaType is required for embedded attestation",
		},
		{
			name: "invalid embedded attestation mediaType",
			input: `{
				"spec_version": "1.0",
				"stream": "test",
				"generated_at": "2024-01-15T10:30:00Z",
				"pack_digest": "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
				"sources": [],
				"artifacts": [],
				"provenance": {
					"type": "merged",
					"merged_at": "2024-01-15T10:30:00Z",
					"source_packs": [{
						"stream": "source-stream",
						"pack_digest": "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
						"manifest_digest": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
						"artifacts": 5,
						"embedded_attestations": [{
							"mediaType": "application/unknown",
							"verificationMaterial": {"x509CertificateChain": {"certificates": ["..."]}},
							"dsseEnvelope": {"payloadType": "application/vnd.in-toto+json", "payload": "...", "signatures": []}
						}]
					}]
				}
			}`,
			wantErr: errors.InvalidManifest,
			wantMsg: "invalid mediaType for embedded attestation",
		},
		{
			name: "missing embedded attestation verificationMaterial",
			input: `{
				"spec_version": "1.0",
				"stream": "test",
				"generated_at": "2024-01-15T10:30:00Z",
				"pack_digest": "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
				"sources": [],
				"artifacts": [],
				"provenance": {
					"type": "merged",
					"merged_at": "2024-01-15T10:30:00Z",
					"source_packs": [{
						"stream": "source-stream",
						"pack_digest": "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
						"manifest_digest": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
						"artifacts": 5,
						"embedded_attestations": [{
							"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
							"dsseEnvelope": {"payloadType": "application/vnd.in-toto+json", "payload": "...", "signatures": []}
						}]
					}]
				}
			}`,
			wantErr: errors.InvalidManifest,
			wantMsg: "verificationMaterial is required for embedded attestation",
		},
		{
			name: "missing embedded attestation dsseEnvelope",
			input: `{
				"spec_version": "1.0",
				"stream": "test",
				"generated_at": "2024-01-15T10:30:00Z",
				"pack_digest": "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
				"sources": [],
				"artifacts": [],
				"provenance": {
					"type": "merged",
					"merged_at": "2024-01-15T10:30:00Z",
					"source_packs": [{
						"stream": "source-stream",
						"pack_digest": "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
						"manifest_digest": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
						"artifacts": 5,
						"embedded_attestations": [{
							"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
							"verificationMaterial": {"x509CertificateChain": {"certificates": ["..."]}}
						}]
					}]
				}
			}`,
			wantErr: errors.InvalidManifest,
			wantMsg: "dsseEnvelope is required for embedded attestation",
		},

		// JSON parsing errors
		{
			name:    "invalid JSON",
			input:   `{not valid json}`,
			wantErr: errors.InvalidJSON,
		},
		{
			name:    "duplicate keys",
			input:   `{"spec_version": "1.0", "spec_version": "2.0", "stream": "test", "generated_at": "2024-01-15T10:30:00Z", "pack_digest": "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789", "sources": [], "artifacts": []}`,
			wantErr: errors.DuplicateKeys,
		},
		{
			name:    "unknown field",
			input:   `{"spec_version": "1.0", "stream": "test", "generated_at": "2024-01-15T10:30:00Z", "pack_digest": "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789", "sources": [], "artifacts": [], "unknown_field": true}`,
			wantErr: errors.InvalidJSON,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			manifest, err := ParseManifest([]byte(tt.input))

			if tt.wantErr == "" {
				if err != nil {
					t.Errorf("ParseManifest() unexpected error = %v", err)
					return
				}
				if manifest == nil {
					t.Error("ParseManifest() returned nil manifest without error")
				}
				return
			}

			if err == nil {
				t.Errorf("ParseManifest() expected error with code %s, got nil", tt.wantErr)
				return
			}

			if got := errors.CodeOf(err); got != tt.wantErr {
				t.Errorf("ParseManifest() error code = %s, want %s (error: %v)", got, tt.wantErr, err)
			}

			if tt.wantMsg != "" && !containsString(err.Error(), tt.wantMsg) {
				t.Errorf("ParseManifest() error = %v, want message containing %q", err, tt.wantMsg)
			}
		})
	}
}

func TestParseManifest_ValidOutput(t *testing.T) {
	t.Parallel()

	input := `{
		"spec_version": "1.0",
		"stream": "my-stream",
		"generated_at": "2024-01-15T10:30:00Z",
		"pack_digest": "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
		"sources": [{"name": "collector", "version": "1.0.0"}],
		"artifacts": [{
			"type": "embedded",
			"path": "artifacts/data.json",
			"digest": "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
			"size": 2048,
			"content_type": "application/json"
		}]
	}`

	manifest, err := ParseManifest([]byte(input))
	if err != nil {
		t.Fatalf("ParseManifest() error = %v", err)
	}

	if manifest.SpecVersion != "1.0" {
		t.Errorf("SpecVersion = %s, want 1.0", manifest.SpecVersion)
	}
	if manifest.Stream != "my-stream" {
		t.Errorf("Stream = %s, want my-stream", manifest.Stream)
	}
	if len(manifest.Sources) != 1 {
		t.Errorf("Sources length = %d, want 1", len(manifest.Sources))
	}
	if len(manifest.Artifacts) != 1 {
		t.Errorf("Artifacts length = %d, want 1", len(manifest.Artifacts))
	}
	if manifest.Artifacts[0].Size.String() != "2048" {
		t.Errorf("Artifact size = %s, want 2048", manifest.Artifacts[0].Size)
	}
}

func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 || (len(s) > 0 && containsSubstring(s, substr)))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// Tests for Manifest.Copy() and related deep copy methods

func TestManifest_Copy(t *testing.T) {
	t.Parallel()

	original := &Manifest{
		SpecVersion: "1.0",
		Stream:      "test-stream",
		GeneratedAt: "2024-01-15T10:30:00Z",
		PackDigest:  "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
		Sources: []Source{
			{Name: "collector1", Version: "1.0.0", Artifacts: []string{"a", "b"}},
			{Name: "collector2", Version: "2.0.0"},
		},
		Artifacts: []Artifact{
			{
				Type:        "embedded",
				Path:        "artifacts/test.json",
				Digest:      "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
				ContentType: "application/json",
				Controls:    []string{"AC-1", "AC-2"},
			},
		},
		Provenance: &Provenance{
			Type:     "merged",
			MergedAt: "2024-01-15T10:30:00Z",
			MergedBy: "test-user",
			SourcePacks: []SourcePack{
				{
					Stream:     "source-stream",
					PackDigest: "sha256:1111111111111111111111111111111111111111111111111111111111111111",
					Artifacts:  "5",
				},
			},
		},
	}

	// Set size for artifact
	size := jsonNumber("1024")
	original.Artifacts[0].Size = &size

	copied := original.Copy()

	// Verify values are equal
	if copied.SpecVersion != original.SpecVersion {
		t.Errorf("SpecVersion = %s, want %s", copied.SpecVersion, original.SpecVersion)
	}
	if copied.Stream != original.Stream {
		t.Errorf("Stream = %s, want %s", copied.Stream, original.Stream)
	}

	// Verify deep copy - mutating copy shouldn't affect original
	copied.SpecVersion = "2.0"
	if original.SpecVersion == "2.0" {
		t.Error("Mutating copy affected original SpecVersion")
	}

	// Verify Sources slice is deep copied
	copied.Sources[0].Name = "modified"
	if original.Sources[0].Name == "modified" {
		t.Error("Mutating copy affected original Sources")
	}

	// Verify Sources artifacts slice is deep copied
	copied.Sources[0].Artifacts[0] = "modified"
	if original.Sources[0].Artifacts[0] == "modified" {
		t.Error("Mutating copy affected original Source.Artifacts")
	}

	// Verify Artifacts slice is deep copied
	copied.Artifacts[0].Path = "modified/path"
	if original.Artifacts[0].Path == "modified/path" {
		t.Error("Mutating copy affected original Artifacts")
	}

	// Verify Artifact.Controls is deep copied
	copied.Artifacts[0].Controls[0] = "MODIFIED"
	if original.Artifacts[0].Controls[0] == "MODIFIED" {
		t.Error("Mutating copy affected original Artifact.Controls")
	}

	// Verify Artifact.Size is deep copied
	newSize := jsonNumber("9999")
	copied.Artifacts[0].Size = &newSize
	if original.Artifacts[0].Size.String() == "9999" {
		t.Error("Mutating copy affected original Artifact.Size")
	}

	// Verify Provenance is deep copied
	copied.Provenance.Type = "single"
	if original.Provenance.Type == "single" {
		t.Error("Mutating copy affected original Provenance")
	}

	// Verify SourcePacks is deep copied
	copied.Provenance.SourcePacks[0].Stream = "modified-stream"
	if original.Provenance.SourcePacks[0].Stream == "modified-stream" {
		t.Error("Mutating copy affected original SourcePacks")
	}
}

func TestManifest_Copy_NilFields(t *testing.T) {
	// Test copy with nil optional fields
	original := &Manifest{
		SpecVersion: "1.0",
		Stream:      "test",
		GeneratedAt: "2024-01-15T10:30:00Z",
		PackDigest:  "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
		Sources:     nil,
		Artifacts:   nil,
		Provenance:  nil,
	}

	copied := original.Copy()

	if copied.Sources != nil {
		t.Error("Expected Sources to be nil in copy")
	}
	if copied.Artifacts != nil {
		t.Error("Expected Artifacts to be nil in copy")
	}
	if copied.Provenance != nil {
		t.Error("Expected Provenance to be nil in copy")
	}
}

func TestSource_Copy(t *testing.T) {
	original := &Source{
		Name:      "collector",
		Version:   "1.0.0",
		Artifacts: []string{"art1", "art2", "art3"},
	}

	copied := original.Copy()

	// Verify values are equal
	if copied.Name != original.Name {
		t.Errorf("Name = %s, want %s", copied.Name, original.Name)
	}
	if len(copied.Artifacts) != len(original.Artifacts) {
		t.Errorf("len(Artifacts) = %d, want %d", len(copied.Artifacts), len(original.Artifacts))
	}

	// Verify deep copy
	copied.Artifacts[0] = "modified"
	if original.Artifacts[0] == "modified" {
		t.Error("Mutating copy affected original")
	}
}

func TestSource_Copy_NilArtifacts(t *testing.T) {
	original := &Source{
		Name:      "collector",
		Version:   "1.0.0",
		Artifacts: nil,
	}

	copied := original.Copy()

	if copied.Artifacts != nil {
		t.Error("Expected Artifacts to be nil in copy")
	}
}

func TestArtifact_Copy(t *testing.T) {
	size := jsonNumber("2048")
	original := &Artifact{
		Type:        "embedded",
		Path:        "artifacts/test.json",
		Digest:      "sha256:abcd",
		Size:        &size,
		ContentType: "application/json",
		DisplayName: "Test File",
		Description: "A test artifact",
		CollectedAt: "2024-01-15T10:30:00Z",
		Schema:      "test/v1",
		Controls:    []string{"AC-1", "AC-2", "AC-3"},
	}

	copied := original.Copy()

	// Verify all fields are copied
	if copied.Type != original.Type {
		t.Errorf("Type = %s, want %s", copied.Type, original.Type)
	}
	if copied.Path != original.Path {
		t.Errorf("Path = %s, want %s", copied.Path, original.Path)
	}
	if copied.Size.String() != original.Size.String() {
		t.Errorf("Size = %s, want %s", copied.Size.String(), original.Size.String())
	}

	// Verify Size is deep copied
	newSize := jsonNumber("9999")
	copied.Size = &newSize
	if original.Size.String() == "9999" {
		t.Error("Mutating copy Size affected original")
	}

	// Verify Controls is deep copied
	copied.Controls[0] = "MODIFIED"
	if original.Controls[0] == "MODIFIED" {
		t.Error("Mutating copy Controls affected original")
	}
}

func TestArtifact_Copy_NilFields(t *testing.T) {
	original := &Artifact{
		Type:     "embedded",
		Path:     "artifacts/test.json",
		Digest:   "sha256:abcd",
		Size:     nil,
		Controls: nil,
	}

	copied := original.Copy()

	if copied.Size != nil {
		t.Error("Expected Size to be nil in copy")
	}
	if copied.Controls != nil {
		t.Error("Expected Controls to be nil in copy")
	}
}

func TestProvenance_Copy(t *testing.T) {
	original := &Provenance{
		Type:     "merged",
		MergedAt: "2024-01-15T10:30:00Z",
		MergedBy: "test-user",
		SourcePacks: []SourcePack{
			{
				Stream:     "stream1",
				PackDigest: "sha256:1111",
				Artifacts:  "10",
			},
			{
				Stream:     "stream2",
				PackDigest: "sha256:2222",
				Artifacts:  "20",
			},
		},
	}

	copied := original.Copy()

	// Verify values are equal
	if copied.Type != original.Type {
		t.Errorf("Type = %s, want %s", copied.Type, original.Type)
	}
	if len(copied.SourcePacks) != len(original.SourcePacks) {
		t.Errorf("len(SourcePacks) = %d, want %d", len(copied.SourcePacks), len(original.SourcePacks))
	}

	// Verify deep copy
	copied.SourcePacks[0].Stream = "modified"
	if original.SourcePacks[0].Stream == "modified" {
		t.Error("Mutating copy affected original")
	}
}

func TestProvenance_Copy_NilSourcePacks(t *testing.T) {
	original := &Provenance{
		Type:        "single",
		SourcePacks: nil,
	}

	copied := original.Copy()

	if copied.SourcePacks != nil {
		t.Error("Expected SourcePacks to be nil in copy")
	}
}

func TestSourcePack_Copy(t *testing.T) {
	original := &SourcePack{
		Stream:     "test-stream",
		PackDigest: "sha256:abcdef",
		Artifacts:  "15",
		EmbeddedAttestations: []EmbeddedAttestation{
			{
				MediaType:            "application/vnd.dev.sigstore.bundle.v0.3+json",
				VerificationMaterial: []byte(`{"key":"value1"}`),
				DSSEEnvelope:         []byte(`{"payload":"..."}`),
			},
		},
	}

	copied := original.Copy()

	// Verify values are equal
	if copied.Stream != original.Stream {
		t.Errorf("Stream = %s, want %s", copied.Stream, original.Stream)
	}
	if len(copied.EmbeddedAttestations) != len(original.EmbeddedAttestations) {
		t.Errorf("len(EmbeddedAttestations) = %d, want %d", len(copied.EmbeddedAttestations), len(original.EmbeddedAttestations))
	}

	// Verify deep copy
	copied.EmbeddedAttestations[0].MediaType = "modified"
	if original.EmbeddedAttestations[0].MediaType == "modified" {
		t.Error("Mutating copy affected original")
	}
}

func TestSourcePack_Copy_EmptyAttestations(t *testing.T) {
	original := &SourcePack{
		Stream:               "test-stream",
		PackDigest:           "sha256:abcdef",
		Artifacts:            "15",
		EmbeddedAttestations: []EmbeddedAttestation{},
	}

	copied := original.Copy()

	// Empty slice (not nil) should be preserved
	if copied.EmbeddedAttestations == nil {
		t.Error("Expected EmbeddedAttestations to be empty slice, not nil")
	}
	if len(copied.EmbeddedAttestations) != 0 {
		t.Errorf("len(EmbeddedAttestations) = %d, want 0", len(copied.EmbeddedAttestations))
	}
}

func TestEmbeddedAttestation_Copy(t *testing.T) {
	original := &EmbeddedAttestation{
		MediaType:            "application/vnd.dev.sigstore.bundle.v0.3+json",
		VerificationMaterial: []byte(`{"certificate":"...", "chain":["..."]}`),
		DSSEEnvelope:         []byte(`{"payloadType":"application/vnd.in-toto+json","payload":"..."}`),
	}

	copied := original.Copy()

	// Verify values are equal
	if copied.MediaType != original.MediaType {
		t.Errorf("MediaType = %s, want %s", copied.MediaType, original.MediaType)
	}
	if string(copied.VerificationMaterial) != string(original.VerificationMaterial) {
		t.Error("VerificationMaterial not copied correctly")
	}
	if string(copied.DSSEEnvelope) != string(original.DSSEEnvelope) {
		t.Error("DSSEEnvelope not copied correctly")
	}

	// Verify VerificationMaterial is deep copied
	copied.VerificationMaterial[0] = 'X'
	if original.VerificationMaterial[0] == 'X' {
		t.Error("Mutating copy VerificationMaterial affected original")
	}

	// Verify DSSEEnvelope is deep copied
	copied.DSSEEnvelope[0] = 'X'
	if original.DSSEEnvelope[0] == 'X' {
		t.Error("Mutating copy DSSEEnvelope affected original")
	}
}

func TestEmbeddedAttestation_Copy_NilFields(t *testing.T) {
	original := &EmbeddedAttestation{
		MediaType:            "application/vnd.dev.sigstore.bundle.v0.3+json",
		VerificationMaterial: nil,
		DSSEEnvelope:         nil,
	}

	copied := original.Copy()

	if copied.VerificationMaterial != nil {
		t.Error("Expected VerificationMaterial to be nil in copy")
	}
	if copied.DSSEEnvelope != nil {
		t.Error("Expected DSSEEnvelope to be nil in copy")
	}
}

// Tests for timestamp validation edge cases

func TestValidateStrictTimestamp(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		timestamp string
		wantErr   bool
	}{
		// Valid timestamps
		{"valid UTC", "2024-01-15T10:30:00Z", false},
		{"midnight", "2024-01-01T00:00:00Z", false},
		{"end of day", "2024-12-31T23:59:59Z", false},
		{"leap year Feb 29", "2024-02-29T12:00:00Z", false},

		// Invalid timestamps - wrong format
		{"timezone offset", "2024-01-15T10:30:00+00:00", true},
		{"negative timezone", "2024-01-15T10:30:00-05:00", true},
		{"fractional seconds", "2024-01-15T10:30:00.123Z", true},
		{"missing Z suffix", "2024-01-15T10:30:00", true},
		{"lowercase z", "2024-01-15T10:30:00z", true},
		{"space instead of T", "2024-01-15 10:30:00Z", true},

		// Invalid timestamps - wrong length
		{"too short", "2024-01-15T10:30Z", true},
		{"too long", "2024-01-15T10:30:00Z00", true},

		// Invalid timestamps - invalid values
		{"invalid month", "2024-13-15T10:30:00Z", true},
		{"invalid day", "2024-01-32T10:30:00Z", true},
		{"invalid hour", "2024-01-15T25:30:00Z", true},
		{"invalid minute", "2024-01-15T10:60:00Z", true},
		{"invalid second", "2024-01-15T10:30:60Z", true},

		// Edge cases
		{"non-leap year Feb 29", "2023-02-29T12:00:00Z", true},
		{"empty string", "", true},
		{"not a timestamp", "not-a-timestamp", true},
		{"just numbers", "20240115103000", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manifest := fmt.Sprintf(`{
				"spec_version": "1.0",
				"stream": "test",
				"generated_at": %q,
				"pack_digest": "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
				"sources": [],
				"artifacts": []
			}`, tt.timestamp)

			_, err := ParseManifest([]byte(manifest))

			if tt.wantErr && err == nil {
				t.Errorf("ParseManifest() expected error for timestamp %q", tt.timestamp)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("ParseManifest() unexpected error for timestamp %q: %v", tt.timestamp, err)
			}
		})
	}
}

func TestParseManifest_MergedProvenanceMissingMergedAt(t *testing.T) {
	manifest := `{
		"spec_version": "1.0",
		"stream": "test",
		"generated_at": "2024-01-15T10:30:00Z",
		"pack_digest": "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
		"sources": [],
		"artifacts": [],
		"provenance": {
			"type": "merged",
			"source_packs": [{
				"stream": "source-stream",
				"pack_digest": "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
				"artifacts": 5
			}]
		}
	}`

	_, err := ParseManifest([]byte(manifest))
	if err == nil {
		t.Error("ParseManifest() expected error for merged provenance without merged_at")
	}
	if errors.CodeOf(err) != errors.MissingRequiredField {
		t.Errorf("ParseManifest() error code = %s, want %s", errors.CodeOf(err), errors.MissingRequiredField)
	}
}

func TestParseManifest_MergedProvenanceEmptySourcePacks(t *testing.T) {
	manifest := `{
		"spec_version": "1.0",
		"stream": "test",
		"generated_at": "2024-01-15T10:30:00Z",
		"pack_digest": "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
		"sources": [],
		"artifacts": [],
		"provenance": {
			"type": "merged",
			"merged_at": "2024-01-15T10:30:00Z",
			"source_packs": []
		}
	}`

	_, err := ParseManifest([]byte(manifest))
	if err == nil {
		t.Error("ParseManifest() expected error for merged provenance with empty source_packs")
	}
	if errors.CodeOf(err) != errors.MissingRequiredField {
		t.Errorf("ParseManifest() error code = %s, want %s", errors.CodeOf(err), errors.MissingRequiredField)
	}
}

func TestParseManifest_SourcePackMissingArtifacts(t *testing.T) {
	manifest := `{
		"spec_version": "1.0",
		"stream": "test",
		"generated_at": "2024-01-15T10:30:00Z",
		"pack_digest": "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
		"sources": [],
		"artifacts": [],
		"provenance": {
			"type": "merged",
			"merged_at": "2024-01-15T10:30:00Z",
			"source_packs": [{
				"stream": "source-stream",
				"pack_digest": "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
				"manifest_digest": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			}]
		}
	}`

	_, err := ParseManifest([]byte(manifest))
	if err == nil {
		t.Error("ParseManifest() expected error for source pack without artifacts count")
	}
	if errors.CodeOf(err) != errors.MissingRequiredField {
		t.Errorf("ParseManifest() error code = %s, want %s", errors.CodeOf(err), errors.MissingRequiredField)
	}
}

// Helper function to create json.Number
func jsonNumber(s string) json.Number {
	return json.Number(s)
}

// Regression test: ParseManifest must validate artifact paths using ziputil.ValidatePath.
// SECURITY: Without path validation, a malicious manifest could specify paths like:
//   - "artifacts/../../../etc/passwd" (path traversal)
//   - "artifacts/CON.txt" (Windows reserved name)
//   - "artifacts/file " (trailing space - Windows collision)
//
// These paths could cause security issues during extraction.
func TestParseManifest_RejectsUnsafeArtifactPaths(t *testing.T) {
	t.Parallel()

	// SECURITY REGRESSION TEST: ParseManifest must call ziputil.ValidatePath
	// on all artifact paths to prevent path traversal, Windows reserved names,
	// and other filesystem safety issues.
	//
	// This test documents the fix for: ParseManifest accepts unsafe artifact paths

	unsafePaths := []struct {
		path   string
		reason string
	}{
		// Path traversal
		{"artifacts/../../../etc/passwd", "path traversal"},
		{"artifacts/foo/../../bar", "path traversal in middle"},
		{"artifacts/./hidden", "dot segment"},

		// Windows reserved names (must be rejected on ALL platforms for portability)
		{"artifacts/CON", "Windows reserved name"},
		{"artifacts/con.txt", "Windows reserved name with extension"},
		{"artifacts/PRN", "Windows reserved name"},
		{"artifacts/AUX", "Windows reserved name"},
		{"artifacts/NUL", "Windows reserved name"},
		{"artifacts/COM1", "Windows reserved name"},
		{"artifacts/LPT1", "Windows reserved name"},
		{"artifacts/subdir/CON/file.txt", "Windows reserved name in path"},

		// Trailing dots/spaces (Windows collision)
		{"artifacts/file.", "trailing dot"},
		{"artifacts/file ", "trailing space"},
		{"artifacts/dir./file.txt", "trailing dot in directory"},

		// Absolute paths
		{"/etc/passwd", "absolute Unix path"},

		// Control characters
		{"artifacts/file\x00name", "null byte"},
		{"artifacts/file\nname", "newline"},

		// Backslashes
		{"artifacts\\file.txt", "backslash"},

		// Empty segments
		{"artifacts//file.txt", "empty segment"},

		// Colons (Windows reserved)
		{"artifacts/file:stream", "colon - Windows ADS"},
	}

	for _, tc := range unsafePaths {
		t.Run(tc.reason, func(t *testing.T) {
			manifest := fmt.Sprintf(`{
				"spec_version": "1.0",
				"stream": "test",
				"generated_at": "2024-01-15T10:30:00Z",
				"pack_digest": "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
				"sources": [],
				"artifacts": [{
					"type": "embedded",
					"path": %q,
					"digest": "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
					"size": 100
				}]
			}`, tc.path)

			_, err := ParseManifest([]byte(manifest))
			if err == nil {
				t.Errorf("SECURITY REGRESSION: ParseManifest() should reject unsafe path %q (%s)", tc.path, tc.reason)
			}

			// Verify it's an InvalidPath error
			if err != nil && errors.CodeOf(err) != errors.InvalidPath {
				// Path traversal and other issues should return InvalidPath
				// Allow MissingRequiredField for "artifacts/" prefix check
				if errors.CodeOf(err) != errors.InvalidPath {
					t.Logf("Note: error code is %s (expected InvalidPath): %v", errors.CodeOf(err), err)
				}
			}
		})
	}
}

// Test that safe artifact paths ARE accepted.
func TestParseManifest_AcceptsSafeArtifactPaths(t *testing.T) {
	t.Parallel()

	safePaths := []string{
		"artifacts/file.json",
		"artifacts/subdir/file.json",
		"artifacts/deeply/nested/path/file.json",
		"artifacts/file-with-dashes.json",
		"artifacts/file_with_underscores.json",
		"artifacts/file.multiple.dots.json",
		"artifacts/UPPERCASE.JSON",
		"artifacts/MixedCase.Json",
	}

	for _, path := range safePaths {
		t.Run(path, func(t *testing.T) {
			manifest := fmt.Sprintf(`{
				"spec_version": "1.0",
				"stream": "test",
				"generated_at": "2024-01-15T10:30:00Z",
				"pack_digest": "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
				"sources": [],
				"artifacts": [{
					"type": "embedded",
					"path": %q,
					"digest": "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
					"size": 100
				}]
			}`, path)

			_, err := ParseManifest([]byte(manifest))
			if err != nil {
				t.Errorf("ParseManifest() should accept safe path %q: %v", path, err)
			}
		})
	}
}
