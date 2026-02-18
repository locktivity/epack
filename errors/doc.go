// Package errors provides typed error handling for evidence pack operations.
//
// # Error Code Stability
//
// Error codes are stable strings that form part of the public API. They are
// suitable for programmatic handling, test assertions, and machine parsing.
// Breaking changes to error codes follow semantic versioning:
//   - New codes may be added in minor releases
//   - Existing codes will not be removed or renamed without a major version bump
//   - Error messages may change; code on the Code field, not message text
//
// # Creating Errors
//
// Use the E function to create errors with a code, message, and optional cause:
//
//	return errors.E(errors.InvalidManifest, "missing required field: stream", nil)
//
// Errors can wrap underlying causes for context:
//
//	return errors.E(errors.DigestMismatch, "artifact digest mismatch", originalErr)
//
// # Handling Errors
//
// Use CodeOf to extract the error code, or errors.As for full access:
//
//	code := errors.CodeOf(err)
//	if code == errors.DigestMismatch {
//	    // Handle integrity failure
//	}
//
//	var e *errors.Error
//	if errors.As(err, &e) {
//	    switch e.Code {
//	    case errors.DigestMismatch:
//	        // Handle integrity failure
//	    case errors.InvalidManifest:
//	        // Handle malformed pack
//	    }
//	}
//
// # Error Categories
//
// Codes are grouped by category:
//   - JSON/Parsing: duplicate_keys, invalid_json, missing_required_field
//   - Manifest: invalid_manifest, invalid_timestamp, unsupported_spec_version
//   - Pack Structure: zip_bomb, too_many_artifacts, duplicate_path, artifact_too_large, invalid_path, missing_entry
//   - Attestation: invalid_attestation, attestation_too_large
//   - Signature: signature_invalid, identity_mismatch
//   - Integrity: digest_mismatch, size_mismatch, pack_digest_mismatch
//   - Filesystem: symlink_not_allowed, path_traversal, permission_denied
//   - Operations: timeout, network_error
//   - Collector: lockfile_invalid, binary_not_found, insecure_install
//   - Input: invalid_input
package errors
