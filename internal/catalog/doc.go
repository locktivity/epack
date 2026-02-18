// Package catalog provides tool catalog schema, caching, and search operations.
//
// This package implements Layer 3 (Discovery) operations:
//   - Fetch: Download catalog from registry servers
//   - Cache: Store catalog locally with expiration
//   - Search: Find tools by name, description, or capabilities
//
// # Security Boundary (CRITICAL)
//
// This package is for DISCOVERY and DISPLAY ONLY.
//
// Catalog data must NEVER influence:
//   - Which binary gets executed
//   - Whether a binary is considered verified
//   - What digest is expected
//   - What signer identity is trusted
//
// The lockfile and Sigstore verification are the ONLY security sources of truth.
// Catalog provides publisher names and descriptions for display purposes only.
//
// This package MUST NOT be imported by:
//   - internal/dispatch (tool execution)
//   - internal/collector (collector execution)
//   - internal/tool (tool resolution)
//   - internal/component (component management)
//
// Only CLI-layer code (cmd/epack/toolcmd/catalog.go) should import this package.
package catalog
