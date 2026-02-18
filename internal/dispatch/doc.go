// Package dispatch implements TOCTOU-safe tool execution with verification.
//
// This package implements Layer 2 (Execution) operations for tools:
//   - Parse wrapper flags (--pack, --output-dir, --json, --quiet)
//   - Resolve tool binary from lockfile
//   - Verify tool digest before execution
//   - Execute tool with proper protocol environment
//   - Capture and structure tool output
//
// # Package Structure
//
// The package is organized into focused files:
//   - dispatch.go: Main entry points (Tool, dispatchVerifiedTool, dispatchToolFromPATH)
//   - flags.go: WrapperFlags parsing (domain logic)
//   - executor.go: Binary execution and environment setup (infrastructure)
//   - result.go: Result.json processing and backfill (domain logic)
//   - config.go: Config/lockfile loading and project root discovery
//
// # Security Boundary
//
// This package MUST NOT import:
//   - internal/catalog (discovery layer - for display only)
//   - internal/cli (presentation layer)
//
// Tool execution decisions (which binary to run, what digest to verify,
// what signer to trust) come exclusively from the lockfile. Catalog data
// is for discovery/display only and is handled at the CLI layer.
//
// This boundary is enforced by the import guard test in dispatch_test.go.
package dispatch
