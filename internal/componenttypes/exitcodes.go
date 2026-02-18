// Package componenttypes defines shared types for component management.
// This file defines exit codes and error codes shared across all component types.
package componenttypes

// Protocol versions for each component type.
const (
	// CollectorProtocolVersion is the current collector protocol version.
	CollectorProtocolVersion = 1

	// ToolProtocolVersion is the current tool protocol version.
	ToolProtocolVersion = 1

	// RemoteProtocolVersion is the current remote adapter protocol version.
	RemoteProtocolVersion = 1
)

// Component-specific exit codes (2-9).
// These are used by components to indicate specific error conditions.
// See C-022 in component-rules.md.
const (
	// ExitConfigError indicates a configuration error (invalid config, missing required fields).
	ExitConfigError = 2

	// ExitAuthError indicates an authentication error (invalid credentials, expired token).
	ExitAuthError = 3

	// ExitNetworkError indicates a network/API error (connection failed, timeout, HTTP error).
	ExitNetworkError = 4
)

// Component wrapper exit codes (10-19).
// These are used consistently across all component types (tools, collectors, remotes, utilities).
const (
	// ExitComponentNotFound indicates the component binary was not found.
	// For tools: not in lockfile or PATH
	// For utilities: not installed
	// For collectors/remotes: not configured or binary missing
	ExitComponentNotFound = 10

	// ExitVerifyFailed indicates digest verification failed.
	// The binary exists but its digest doesn't match the lockfile.
	ExitVerifyFailed = 11

	// ExitPackVerifyFailed indicates pack integrity verification failed.
	// Used by tools that require a pack.
	ExitPackVerifyFailed = 12

	// ExitLockfileMissing indicates the lockfile is missing or invalid.
	ExitLockfileMissing = 13

	// ExitRunDirFailed indicates run directory creation failed.
	// Used by tool protocol when the wrapper can't create the run directory.
	ExitRunDirFailed = 14

	// ExitConfigFailed indicates configuration file write/read failed.
	ExitConfigFailed = 15

	// ExitPackRequired indicates a pack is required but not provided.
	ExitPackRequired = 16

	// ExitDependencyMissing indicates a required dependency is missing.
	ExitDependencyMissing = 17
)

// Component error codes for structured errors.
// These are used in result.json and error responses across all component types.
const (
	// ErrCodeComponentNotFound indicates the component was not found.
	ErrCodeComponentNotFound = "COMPONENT_NOT_FOUND"

	// ErrCodeVerifyFailed indicates digest verification failed.
	ErrCodeVerifyFailed = "VERIFICATION_FAILED"

	// ErrCodePackVerifyFailed indicates pack verification failed.
	ErrCodePackVerifyFailed = "PACK_VERIFICATION_FAILED"

	// ErrCodePackRequired indicates a pack is required but not provided.
	ErrCodePackRequired = "PACK_REQUIRED"

	// ErrCodeComponentFailed indicates the component execution failed.
	ErrCodeComponentFailed = "COMPONENT_FAILED"

	// ErrCodeComponentKilled indicates the component was killed (timeout, signal).
	ErrCodeComponentKilled = "COMPONENT_KILLED"

	// ErrCodeResultMissing indicates result.json was not written.
	ErrCodeResultMissing = "RESULT_MISSING"

	// ErrCodeResultInvalid indicates result.json is invalid.
	ErrCodeResultInvalid = "RESULT_INVALID"

	// ErrCodeInvalidOutput indicates an output path is invalid.
	ErrCodeInvalidOutput = "INVALID_OUTPUT_PATH"

	// ErrCodeRunDirFailed indicates run directory creation failed.
	ErrCodeRunDirFailed = "RUN_DIR_FAILED"

	// ErrCodeLockfileError indicates a lockfile error (missing, parse error, etc).
	ErrCodeLockfileError = "LOCKFILE_ERROR"

	// ErrCodeConfigFailed indicates config file write/read failed.
	ErrCodeConfigFailed = "CONFIG_WRITE_FAILED"

	// ErrCodeNotInLockfile indicates the component is not in the lockfile.
	ErrCodeNotInLockfile = "NOT_IN_LOCKFILE"

	// ErrCodePlatformNotInLockfile indicates the platform is not in lockfile.
	ErrCodePlatformNotInLockfile = "PLATFORM_NOT_IN_LOCKFILE"

	// ErrCodeDigestMissing indicates digest is missing from lockfile.
	ErrCodeDigestMissing = "DIGEST_MISSING"

	// ErrCodeDependencyMissing indicates a required dependency is missing.
	ErrCodeDependencyMissing = "DEPENDENCY_MISSING"
)
