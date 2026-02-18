// Package verify provides verification workflows for evidence packs.
//
// This package orchestrates the full pack verification process, combining:
//   - Artifact integrity verification (from pack package)
//   - Pack digest verification (from pack package)
//   - Attestation signature verification (from pack/verify package)
//   - Embedded attestation verification (from pack package)
//
// The package exists separately from pack/verify to avoid import cycles,
// as it needs to use both pack.Pack methods and pack/verify types.
//
// # Security Boundary
//
// This package is part of Layer 2 (Verification) and MUST NOT import:
//   - internal/component (execution configuration)
//   - internal/collector (collector execution)
//   - internal/tool (tool execution)
//   - internal/dispatch (tool dispatch)
//   - internal/catalog (discovery layer)
//   - internal/cli (presentation layer)
//
// Pack verification must remain independent of the execution layer.
// A pack can be verified with only the pack file and verification options.
// This boundary is enforced by import_guard_test.go.
package verify
