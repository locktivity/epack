//go:build components

// Package tool provides tool discovery, resolution, and verification services.
//
// This package implements Layer 2 (Workflow/Application Services) operations for tools:
//   - Discovery: Finding tools in PATH and lockfile
//   - Resolution: Resolving tool paths and capabilities
//   - Verification: Verifying tool digests against lockfile
//
// SECURITY: This package MUST NOT import internal/catalog. Tool execution decisions
// (which binary to run, what digest to verify) come exclusively from the lockfile.
// Catalog data is for discovery/display only and is handled at the CLI layer.
package tool
