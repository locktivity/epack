package platformpath

// IsLocalWindowsPath checks if a path is a local Windows path (not UNC or otherwise unsafe).
// Returns true for paths like "C:\Users\..." and false for UNC paths like "\\server\share".
//
// SECURITY: UNC paths could redirect file operations to remote servers controlled by
// an attacker. Helps prevent SSRF-like attacks via environment variables like
// LOCALAPPDATA or user-provided paths.
//
// Safe to call on any platform - checks path string format without filesystem access.
func IsLocalWindowsPath(path string) bool {
	return hasMinWindowsPathLength(path) && !IsUNCPath(path) && hasDrivePrefixWithSeparator(path)
}

func hasMinWindowsPathLength(path string) bool {
	return len(path) >= 2
}

func hasDrivePrefixWithSeparator(path string) bool {
	return len(path) >= 3 && HasDriveLetter(path) && (path[2] == '\\' || path[2] == '/')
}

// IsUNCPath returns true if the path is a UNC path (\\server\share or //server/share).
//
// SECURITY: UNC paths can be used to:
//   - Redirect operations to attacker-controlled SMB servers
//   - Leak credentials via NTLM authentication
//   - Cause operations to hang waiting for network timeouts
func IsUNCPath(path string) bool {
	if len(path) < 2 {
		return false
	}
	return (path[0] == '\\' && path[1] == '\\') || (path[0] == '/' && path[1] == '/')
}

// HasDriveLetter returns true if the path starts with a Windows drive letter (C:, D:, etc.).
func HasDriveLetter(path string) bool {
	if len(path) < 2 {
		return false
	}
	if path[1] != ':' {
		return false
	}
	drive := path[0]
	return (drive >= 'A' && drive <= 'Z') || (drive >= 'a' && drive <= 'z')
}
