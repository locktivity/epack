// Package safejson provides secure JSON parsing with mandatory size validation.
//
// SECURITY: This package wraps encoding/json to ensure all JSON parsing
// goes through size validation BEFORE parsing. This prevents DoS attacks via:
//   - Large payload parsing (memory exhaustion)
//   - Unbounded network reads
//
// All packages needing to parse untrusted JSON should import this package
// instead of encoding/json directly for parsing operations. An import guard
// test can enforce this boundary.
//
// This mirrors the safeyaml package for consistency.
package safejson
