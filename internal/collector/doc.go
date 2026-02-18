// Package collector provides collector execution and workflow orchestration.
//
// This package implements Layer 2 (Execution) operations:
//   - Runner: Execute collector binaries with proper environment
//   - Workflow: Orchestrate lock → sync → run → build pipeline
//
// # Security Boundary
//
// This package is part of Layer 2 (Execution) and MUST NOT import:
//   - internal/catalog (discovery layer - for display only)
//   - internal/cli (presentation layer)
//
// Collector execution decisions (which binary to run, what digest to verify)
// come exclusively from the lockfile. This boundary is enforced by
// import_guard_test.go.
package collector
