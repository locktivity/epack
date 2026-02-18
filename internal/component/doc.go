// Package component provides unified types and utilities for both collectors and tools.
//
// This package re-exports commonly used types from subpackages for convenience.
// For less common types, import the subpackages directly:
//
//   - config: Configuration types (JobConfig, CollectorConfig, ToolConfig) and parsing
//   - lockfile: Lockfile types (LockFile, LockedCollector, LockedTool) and I/O
//   - sync: Component synchronization (Syncer, Locker) and registry abstraction
//   - github: GitHub API client (Client, Release, Asset, ParseSource)
//   - semver: Semantic versioning (ParseConstraint, SelectVersion)
//   - sigstore: Sigstore verification
//
// # Security Model
//
// Both collectors and tools use the same supply chain security model:
//   - Version locking with cryptographic digests
//   - Sigstore signature verification
//   - Config/lockfile alignment validation
//
// # Security Boundary
//
// This package is part of Layer 2 (Component System) and MUST NOT import:
//   - internal/catalog (discovery layer - for display only)
//   - internal/cli (presentation layer)
//
// Component resolution and verification must come exclusively from the lockfile.
// This boundary is enforced by import_guard_test.go.
package component
