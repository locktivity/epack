// Package platformpath provides OS-specific path safety helpers.
//
// This package centralizes platform-specific path validation that was
// previously duplicated across multiple packages. It provides:
//
//   - UNC path detection for Windows
//   - Local path validation
//   - Platform-specific path safety checks
//
// # Security Properties
//
// These helpers prevent attacks that exploit platform-specific path semantics:
//   - UNC paths (\\server\share) could redirect operations to remote servers
//   - Path separators vary by platform
//   - Drive letters are Windows-specific
package platformpath
