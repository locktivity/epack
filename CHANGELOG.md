# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### NEW FEATURES

- **Unified Catalog Search** - `epack catalog search` command searches all component types (collectors, tools, remotes, utilities) with optional `--kind` filter
- **Catalog Refresh** - `epack catalog refresh` fetches latest catalog from registry with ETag/Last-Modified caching
- **Global Utility Management** - New `epack utility` command for managing user-installed utilities:
  - `epack utility install <name> <source>` - Install from GitHub releases with Sigstore verification
  - `epack utility list` - List installed utilities with version and signer info
  - `epack utility remove <name>` - Remove installed utilities
- **Utilities Lock** - Global utilities tracked in `~/.epack/utilities.lock` separate from project config
- **Windows support (core build)** - `epack-core-windows-amd64.exe` and `epack-core-windows-arm64.exe` release binaries with the same SLSA Level 3 provenance as other platforms. Windows covers pack operations (build, sign, verify, inspect, list, extract, merge, diff); collector and tool execution remains macOS/Linux and fails closed on Windows

### ENHANCEMENTS

- Catalog schema extended to support all component kinds with backwards-compatible `tools` array
- `CatalogComponent` type replaces `CatalogTool` (alias maintained for compatibility)
- `SearchWithOptions()` method allows filtering search by component kind
- `AllComponents()` and `ComponentsByKind()` methods for flexible catalog queries
- Dependency updates for published advisories: sigstore-go v1.2.1 (multi-log threshold bypass GHSA-9vcr-p3rj-q5q6, signing key validity period GHSA-wqqc-jjcq-vfxm) and grpc-go v1.82.1 (GHSA-hrxh-6v49-42gf)
- Path validation rejects rooted paths (`/foo`, `\foo`, `C:foo`) on every platform, closing a Windows-only gap where such paths passed relative-path checks

### BUG FIXES

- Merge, `list --filter`, and `extract --filter` operate on canonical slash paths, fixing broken merges and glob matching on Windows
- Recursive `**` result globbing during push handles Windows drive-letter paths

### UPGRADE NOTES

- The `epack tool catalog` subcommand is deprecated in favor of the top-level `epack catalog` command
- Catalog JSON format now supports `collectors`, `remotes`, and `utilities` arrays alongside `tools`
- Config paths that begin with `/` or `\` or carry a drive prefix are rejected on every platform; use paths relative to the project root

## [0.1.0] - 2025-02-18

Initial release.

### NEW FEATURES
- `epack build` command for creating evidence packs
- `epack sign` command with keyless (OIDC) and key-based signing
- `epack verify` command for integrity and attestation verification
- `epack inspect` command for viewing pack contents
- `epack list` command for listing artifacts, attestations, and sources
- `epack extract` command for extracting artifacts
- `epack merge` command for combining multiple packs
- `epack diff` command for comparing pack contents
- JSON output mode for all inspection commands
- Golden file testing infrastructure
- CLI acceptance tests
