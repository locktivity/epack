// Package lockfile provides lockfile parsing, serialization, and management.
//
// The lockfile (epack.lock.yaml) pins component versions and digests for
// reproducible builds and supply chain security. It stores:
//   - Resolved component versions
//   - Per-platform digests for binary verification
//   - Signer identity (Sigstore certificate claims)
//   - Resolution metadata (which registry resolved the component)
//
// Security features:
//   - YAML alias bomb detection (pre-parse)
//   - Size limits (DoS prevention)
//   - Name and version validation (path traversal prevention)
//   - Atomic writes with symlink protection (TOCTOU-safe)
//   - Deterministic serialization (consistent diffs)
package lockfile
