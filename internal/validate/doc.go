// Package validate provides centralized security validation functions.
//
// This package consolidates validation logic that was previously duplicated
// across multiple packages, ensuring consistent security checks for:
//   - Version strings (semver format, path traversal prevention)
//   - Path components (filename/directory validation)
//   - Relative paths (traversal prevention)
//   - Path containment (ensuring paths stay within base directories)
//
// SECURITY: All validation functions are designed to prevent path traversal
// attacks, including edge cases like embedded separators, double-dot sequences,
// and platform-specific quirks (Windows reserved names, UNC paths, etc.).
package validate
