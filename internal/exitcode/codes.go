// Package exitcode defines unified exit codes for epack CLI operations.
// These codes are stable and used by both collectors and tools.
//
// Note: The ExitError type has been unified into the errors package.
// Use errors.E() or errors.WithHint() to create errors with exit codes.
package exitcode

// General exit codes (0-9)
const (
	Success = 0 // Operation completed successfully
	General = 1 // General/unspecified error
)

// Component exit codes (10-19) - used by collector and tool operations
const (
	LockInvalid       = 10 // Lockfile missing, invalid, or mismatched
	DigestMismatch    = 11 // Binary digest doesn't match lockfile
	SignatureMismatch = 12 // Sigstore signature verification failed
	Timeout           = 13 // Operation timed out
	MissingBinary     = 14 // Binary not found/installed
	Network           = 15 // Network error during fetch
)

// Tool wrapper exit codes (10-19) - used by tool dispatch wrapper
// These overlap with component codes but have tool-specific meanings
const (
	ToolNotFound      = 10 // Tool binary not found
	ToolVerifyFailed  = 11 // Tool digest verification failed
	PackVerifyFailed  = 12 // Pack integrity verification failed
	LockfileMissing   = 13 // Lockfile missing for configured tool
	RunDirFailed      = 14 // Failed to create run directory
	ConfigFileFailed  = 15 // Failed to write tool config file
	PackRequired      = 16 // Tool requires pack but none provided
	DependencyMissing = 17 // Required tool dependency not satisfied
)

// General operational exit codes (20-29)
const (
	FileNotFound   = 20 // Required file not found
	NotImplemented = 21 // Feature not yet implemented
)

// IsToolExitCode returns true if the exit code is in the tool wrapper range (10-19).
func IsToolExitCode(code int) bool {
	return code >= 10 && code <= 19
}
