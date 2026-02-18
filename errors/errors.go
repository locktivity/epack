// Package errors defines typed errors for the evidence-pack library.
//
// Error codes are stable strings suitable for test-vector matching.
// Use E() to create errors and CodeOf() to extract codes through wrapped errors.
package errors

import (
	"errors"

	"github.com/locktivity/epack/internal/exitcode"
)

// Code identifies the category of error. These are stable strings
// suitable for test-vector matching.
type Code string

const (
	// JSON parsing/shape errors.
	DuplicateKeys        Code = "duplicate_keys"
	InvalidJSON          Code = "invalid_json"
	MissingRequiredField Code = "missing_required_field"

	// Manifest validation errors
	InvalidManifest        Code = "invalid_manifest"
	InvalidTimestamp       Code = "invalid_timestamp"
	UnsupportedSpecVersion Code = "unsupported_spec_version"

	// Zip/pack validation errors
	ZipBomb          Code = "zip_bomb"
	TooManyArtifacts Code = "too_many_artifacts"
	DuplicatePath    Code = "duplicate_path"
	ArtifactTooLarge Code = "artifact_too_large"
	InvalidPath      Code = "invalid_path"
	MissingEntry     Code = "missing_entry"

	// Attestation validation errors
	InvalidAttestation  Code = "invalid_attestation"
	AttestationTooLarge Code = "attestation_too_large"

	// Signature verification errors
	SignatureInvalid Code = "signature_invalid"
	IdentityMismatch Code = "identity_mismatch"

	// Integrity verification errors
	DigestMismatch     Code = "digest_mismatch"
	SizeMismatch       Code = "size_mismatch"
	PackDigestMismatch Code = "pack_digest_mismatch"

	// Input validation errors
	InvalidInput Code = "invalid_input"

	// Filesystem errors
	SymlinkNotAllowed Code = "symlink_not_allowed"
	PathTraversal     Code = "path_traversal"
	PermissionDenied  Code = "permission_denied"

	// Operation errors
	Timeout      Code = "timeout"
	NetworkError Code = "network_error"

	// Collector errors
	LockfileInvalid Code = "lockfile_invalid"
	BinaryNotFound  Code = "binary_not_found"
	InsecureInstall Code = "insecure_install"

	// Remote adapter errors
	RemoteNotFound    Code = "remote_not_found"
	AdapterNotFound   Code = "adapter_not_found"
	AdapterExecFailed Code = "adapter_exec_failed"
	ProtocolMismatch  Code = "protocol_mismatch"
	UploadFailed      Code = "upload_failed"
	AuthRequired      Code = "auth_required"
	RemoteForbidden   Code = "remote_forbidden"
	RemoteConflict    Code = "remote_conflict"

	// Catalog errors
	CatalogNotFound     Code = "catalog_not_found"
	CatalogMetaNotFound Code = "catalog_meta_not_found"
	CircularDependency  Code = "circular_dependency"
	DependencyNotFound  Code = "dependency_not_found"
	ComponentNotFound   Code = "component_not_found"

	// Component errors
	AlreadyExists Code = "already_exists"
	InvalidName   Code = "invalid_name"
)

// DocsBaseURL is the base URL for error documentation.
// Set this at init time to enable doc links in error messages.
var DocsBaseURL = "https://docs.epack.dev/errors"

// Error is a typed error carrying a stable Code, message, and optional cause.
// It unifies the previous errors.Error, exitcode.ExitError, and sync.*Error types.
type Error struct {
	Code    Code   // Stable string code for programmatic handling
	Exit    int    // CLI exit code override (0 = derive from Code)
	Message string // Human-readable error message
	Hint    string // Actionable hint for CLI users (optional)
	DocURL  string // URL to documentation for this error (optional)
	Cause   error  // Wrapped error for error chains
}

// Error implements the error interface.
// If Hint is set, it's appended on a new line for CLI display.
// If DocURL is set, it's appended after the hint.
func (e *Error) Error() string {
	msg := e.Message
	if e.Cause != nil {
		msg += ": " + e.Cause.Error()
	}
	if e.Hint != "" {
		msg += "\n  Hint: " + e.Hint
	}
	if e.DocURL != "" {
		msg += "\n  Docs: " + e.DocURL
	}
	return msg
}

// Unwrap returns the underlying cause, enabling errors.Is and errors.As.
func (e *Error) Unwrap() error {
	return e.Cause
}

// ExitCode returns the CLI exit code for this error.
// If Exit is explicitly set (> 0), returns that value.
// Otherwise, maps the Code to an appropriate exit code.
func (e *Error) ExitCode() int {
	if e.Exit > 0 {
		return e.Exit
	}
	return codeToExit(e.Code)
}

// codeToExit maps error codes to CLI exit codes.
func codeToExit(code Code) int {
	switch code {
	case LockfileInvalid:
		return exitcode.LockInvalid
	case DigestMismatch, PackDigestMismatch, SizeMismatch:
		return exitcode.DigestMismatch
	case SignatureInvalid, IdentityMismatch:
		return exitcode.SignatureMismatch
	case Timeout:
		return exitcode.Timeout
	case BinaryNotFound:
		return exitcode.MissingBinary
	case NetworkError:
		return exitcode.Network
	default:
		return exitcode.General
	}
}

// E creates a new Error with the given code, message, and optional cause.
// Pass nil for cause if there is no underlying error.
// For errors that need hints or explicit exit codes, use WithHint instead.
func E(code Code, msg string, cause error) error {
	return &Error{Code: code, Message: msg, Cause: cause}
}

// WithHint creates an Error with an explicit exit code and user-facing hint.
// This replaces the previous sync.LockError, sync.DigestError, etc. types.
// The exit code should come from internal/exitcode constants.
func WithHint(code Code, exit int, msg, hint string, cause error) error {
	return &Error{Code: code, Exit: exit, Message: msg, Hint: hint, Cause: cause}
}

// WithDocs creates an Error with a hint and documentation URL.
// The doc URL is automatically generated from DocsBaseURL and the error code.
func WithDocs(code Code, exit int, msg, hint string, cause error) error {
	return &Error{
		Code:    code,
		Exit:    exit,
		Message: msg,
		Hint:    hint,
		DocURL:  DocsBaseURL + "/" + string(code),
		Cause:   cause,
	}
}

// codeHasDocs returns true if the error code has documentation.
// This is used to determine whether to include a doc link.
var codeHasDocs = map[Code]bool{
	// Complex errors that benefit from documentation
	SignatureInvalid:       true,
	IdentityMismatch:       true,
	DigestMismatch:         true,
	PackDigestMismatch:     true,
	LockfileInvalid:        true,
	InsecureInstall:        true,
	ProtocolMismatch:       true,
	AuthRequired:           true,
	UnsupportedSpecVersion: true,
	ZipBomb:                true,
}

// HasDocs returns true if the error code has documentation available.
func HasDocs(code Code) bool {
	return codeHasDocs[code]
}

// DocURLFor returns the documentation URL for an error code,
// or empty string if no documentation is available.
func DocURLFor(code Code) string {
	if HasDocs(code) {
		return DocsBaseURL + "/" + string(code)
	}
	return ""
}

// CodeOf extracts the Code from an error. It unwraps through error chains
// to find the first *Error. Returns empty string if no *Error is found.
func CodeOf(err error) Code {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}
