// Package sync provides component synchronization and locking operations.
//
// This package coordinates the download, verification, and installation of
// source-based components (collectors and tools) from registries.
//
// Key operations:
//   - Sync: download and verify components from lockfile
//   - Lock: resolve versions and create/update lockfile entries
//
// Security features:
//   - Sigstore signature verification
//   - Digest verification against lockfile
//   - Config/lockfile alignment validation (anti-retargeting)
//   - Insecure install markers for audit trail
package sync
