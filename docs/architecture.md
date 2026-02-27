# Architecture

This document describes the security-relevant architecture of `epack`.

## Components

### Core Libraries

- `pack/`: Evidence pack reading, building, and verification.
- `sign/`: Sigstore signing and verification.
- `errors/`: Typed error codes for programmatic handling.

### Internal Libraries

- `internal/component/`: **Shared component abstractions** for collectors and tools.
  - `config/`: `JobConfig`, `CollectorConfig`, `ToolConfig` parsing with YAML bomb detection, validation, and safe modification.
  - `lockfile/`: `LockFile`, `LockedCollector`, `LockedTool` types with unified accessors.
  - `sync/`: Component synchronization (`Syncer`, `Locker`), binary resolution, platform helpers, insecure markers.
  - `github/`: GitHub API client with trusted host allowlists.
  - `semver/`: Semantic versioning with constraint matching.
  - `sigstore/`: Sigstore verification with identity binding.
- `internal/collector/`: **Collector-specific runtime**.
  - `runner.go`: Collector execution with protocol support, environment setup, output limits.
  - `workflow.go`: Orchestrates lock → sync → run → build pipeline (`Collect`, `RunAndBuild`).
  - **MUST NOT import `internal/catalog`** (enforced by import guard test).
- `internal/tool/`: **Tool discovery and resolution**.
  - `discovery.go`: Tool detection from PATH and lockfile.
  - `resolver.go`: Tool binary path resolution.
  - `probe.go`: Tool capabilities probing (`--capabilities`).
- `internal/dispatch/`: **Tool execution with security isolation**.
  - TOCTOU-safe binary verification and execution.
  - Protocol environment setup.
  - Result.json processing and validation.
  - **MUST NOT import `internal/catalog`** (enforced by import guard test).
- `internal/remote/`: **Remote adapter protocol for push/pull operations**.
  - `protocol.go`: Remote Adapter Protocol v1 types (requests, responses, error codes).
  - `discover.go`: Adapter discovery from lockfile, external binary, and PATH.
  - `capabilities.go`: Adapter capability declaration and feature detection.
  - `executor.go`: Adapter command execution with JSON protocol.
- `internal/push/`: **Push workflow orchestration**.
  - `workflow.go`: Orchestrates prepare → upload → finalize → sync pipeline.
  - `receipt.go`: Audit trail receipt file generation.
- `internal/pull/`: **Pull workflow orchestration**.
  - `workflow.go`: Orchestrates prepare → download → verify → finalize pipeline.
  - `receipt.go`: Audit trail receipt file generation.
- `internal/catalog/`: **Component discovery and display** (isolated from execution).
  - Schema types for catalog and metadata (includes `Dependencies` field for install-time resolution).
  - Supports all component kinds: collectors, tools, remotes, and utilities.
  - Lookup functions for resolving components from catalog to source strings.
  - Unified search across all component kinds with optional kind filtering.
  - XDG-compliant cache management with size limits.
  - Search with relevance ranking (exact > prefix > substring).
  - HTTP fetch with conditional requests (ETag/Last-Modified).
  - `resolve/`: Component argument parsing (`name@version`), dependency resolution with cycle detection.
- `internal/userconfig/`: **Global user configuration** for utilities.
  - Manages `~/.epack/` directory structure.
  - Handles `utilities.lock` for tracking installed utilities.
  - Utility installation with Sigstore verification.
- `internal/componentsdk/`: **Component SDK for authors**.
  - Project scaffolding with templates for all component kinds.
  - Development runtime (run, watch mode).
  - Conformance testing integration.
  - Mock input generation for testing.
- `internal/verify/`: Verification workflow orchestration.
- `internal/project/`: Project root detection and initialization.
- `internal/validate/`: Path validation, version validation, Windows reserved names.
- `internal/exitcode/`: Unified exit codes for components and tools.
- `internal/toolprotocol/`: Tool Protocol v1 types (result.json schema, run directories).
- `internal/execsafe/`: Copy-while-hash execution for TOCTOU-safe binary verification.
- `internal/safefile/`: Symlink-safe file operations with atomic writes and baked-in permissions.
- `internal/safeyaml/`: Safe YAML parsing with alias bomb detection and typed size limits.
- `internal/safejson/`: Safe JSON parsing with duplicate key rejection and typed size limits.
- `internal/boundedio/`: Bounded I/O readers/writers for DoS protection.
- `internal/limits/`: Resource limits for DoS protection (timeouts, sizes, catalog limits).
- `internal/redact/`: Output redaction for error messages.
- `internal/digest/`: Digest calculation and constant-time comparison.
- `internal/timestamp/`: Timestamp formatting and validation.
- `internal/netpolicy/`: Network policy helpers.
- `internal/yamlpolicy/`: YAML policy validation.
- `internal/ziputil/`: Safe ZIP operations with path validation.

### CLI Commands

- `cmd/epack/cmd/`: Core CLI command group (`build`, `sign`, `verify`, `inspect`, `diff`, `extract`, `merge`, `list`, `version`, `completion`).
- `cmd/epack/componentcmd/`: Shared component lifecycle commands, compiled only with `-tags components`:
  - `epack new`, `epack init` - Project scaffolding
  - `epack lock`, `epack sync`, `epack install`, `epack update` - Dependency management
  - `epack install tool <name>`, `epack install collector <name>` - Catalog-based installation with dependency resolution
- `cmd/epack/collectorcmd/`: Collector-specific commands, compiled only with `-tags components`:
  - `epack collect` - Auto-lock, sync, run, build (one-command workflow)
  - `epack collector run` - Run collectors and build pack
- `cmd/epack/toolcmd/`: Tool dispatch commands, compiled only with `-tags components`:
  - `epack tool <name>` - Explicit tool dispatch
  - `epack tool list` - List available tools (with optional `--probe` flag)
  - `epack tool info <name>` - Show tool details including signing identity
  - `epack tool source`, `epack tool verify` - Tool verification
- `cmd/epack/utilitycmd/`: Utility management and dispatch commands, compiled only with `-tags components`:
  - `epack utility install <name>[@version]` - Install utilities from the catalog with Sigstore verification
  - `epack utility list` - List installed utilities
  - `epack utility remove` - Remove installed utilities
  - `epack utility <name> [args...]` - Run installed utility with TOCTOU-safe verification
- `cmd/epack/sdkcmd/`: Component SDK commands for authors, compiled only with `-tags components`:
  - `epack sdk new <type> <name>` - Scaffold new component project
  - `epack sdk run [--watch] <path>` - Run component locally for development
  - `epack sdk test <path>` - Run conformance tests
  - `epack sdk mock <type>` - Generate sample test inputs
- `cmd/epack/cmd/`: Unified catalog commands, compiled only with `-tags components`:
  - `epack catalog search` - Search all component kinds (collectors, tools, remotes, utilities)
  - `epack catalog refresh` - Fetch latest catalog from registry
- `cmd/epack/remotecmd/`: Remote commands, compiled only with `-tags components`:
  - `epack push` - Push pack to remote registry
  - `epack pull` - Pull pack from remote registry
  - `epack remote list` - List configured remotes
  - `epack remote whoami` - Show remote authentication status

## Build Variants

- `epack-core` (default build, no `components` tag):
  - Includes core pack/sign/verify features.
  - Includes stub commands for `collector`, `lock`, `sync`, and `tool` that refuse execution.
  - Component-only commands (`collect`, `install`, `update`, `catalog`, `utility`, `push`, `pull`, `remote`, `sdk`) are not included.
  - No collector/tool runtime code is linked.
- `epack` full build (`-tags components`):
  - Includes core features plus full component orchestration.
  - `epack collect`, `epack lock`, `epack sync`, `epack install`, `epack update`
  - `epack collector run`, `epack tool <name>`, `epack tool list/info`
  - `epack catalog search`, `epack catalog refresh` - Unified catalog for all component types
  - `epack utility install/list/remove/<name>` - Global utility management and TOCTOU-safe dispatch
  - `epack sdk new/run/test/mock` - Component SDK for building custom components
  - `epack push`, `epack pull`, `epack remote list/whoami`
  - Downloads and executes collector, tool, and remote adapter binaries.

## Unified Component Model

Collectors and tools share the same supply chain security infrastructure. This is implemented in `internal/component/`:

### Component Kinds

- **Collectors** (`KindCollector`): Gather evidence and produce artifacts for packs.
- **Tools** (`KindTool`): Process existing packs and produce derived outputs.
- **Remotes** (`KindRemote`): Handle communication with registry backends for push/pull.
- **Utilities** (`KindUtility`): Standalone helper applications installed globally.

### Shared Security Model

Both component types use:

1. **Source Declaration**: Components declare their source repository in `epack.yaml`.
2. **Version Resolution**: Semantic versioning with constraint matching (exact, caret, tilde, latest).
3. **Dependency Resolution**: Install-time dependencies from catalog are resolved transitively with cycle detection.
4. **Sigstore Verification**: Signatures verified against expected repository identity at lock time.
5. **Digest Pinning**: Binary digests recorded in `epack.lock.yaml`.
6. **TOCTOU-Safe Execution**: Copy-while-hash verification prevents swap attacks.
7. **Restricted Environment**: Executables receive minimal, audited environment variables.
8. **Runtime Dependency Checking**: Tools declare `requires_tools` in capabilities; wrapper verifies dependencies ran successfully before execution.

### Configuration File (`epack.yaml`)

```yaml
stream: myorg/evidence              # Stream identifier (required for collect)

platforms:                          # Target platforms for lockfile
  - linux/amd64
  - darwin/arm64

collectors:
  my-collector:
    source: owner/repo@^1.0.0       # Source with version constraint
    config:
      key: value
    secrets:
      - API_KEY

tools:
  my-tool:
    source: owner/tool@^2.0.0       # Source with version constraint
    config:
      model: gpt-4
    secrets:                        # Env vars passed through to tool
      - API_KEY
```

### Lockfile (`epack.lock.yaml`)

```yaml
schema_version: 1
collectors:
  my-collector:
    source: github.com/owner/repo
    version: v1.2.3
    signer:
      issuer: https://token.actions.githubusercontent.com
      source_repository_uri: https://github.com/owner/repo
      source_repository_ref: refs/tags/v1.2.3
    platforms:
      linux/amd64:
        digest: sha256:abc123...
      darwin/arm64:
        digest: sha256:def456...
tools:
  my-tool:
    source: github.com/owner/tool
    version: v2.0.0
    # ... same structure as collectors
```

## Trust Boundaries

1. User inputs boundary:
   - Artifact paths, output paths, stream metadata, CLI flags, and environment variables are untrusted.
2. Component supply chain boundary:
   - Collector, tool, and remote adapter binaries and their metadata are untrusted until verified against lockfile/signature policy.
3. Runtime execution boundary:
   - Executed components, tools, and remote adapters are untrusted code and must be treated as potentially hostile.
4. Pack consumer boundary:
   - Pack contents from external parties are untrusted until integrity/signature verification succeeds.
5. Catalog/Dispatch boundary:
   - Catalog data is for display only; execution decisions come from the lockfile.
   - `internal/dispatch` cannot import `internal/catalog` (enforced by import guard test).
6. Remote adapter boundary:
   - Remote adapters handle sensitive operations (authentication, uploads).
   - Adapters from PATH are unverified; source-based adapters are Sigstore-verified.
   - Authentication credentials are managed by adapters, not epack.

## Data Flow (Collector Mode)

### Project Setup

1. `epack new <name>` creates a new project directory with:
   - `epack.yaml` configuration with commented examples
   - `sample.epack` for exploration
   - `packs/` output directory
   - `.gitignore` with managed block
   - `README.md` quick reference
2. `epack init` initializes the current directory (idempotent).

### Quick Path (`epack collect`)

1. `epack collect` automatically:
   - Locks components if lockfile is missing/stale (for platforms defined in `epack.yaml`)
   - Syncs (downloads) missing binaries for current platform
   - Verifies binary digests against lockfile
   - Executes components and builds a draft pack
2. `epack sign` signs the resulting pack.
3. `epack verify` validates integrity and signature constraints.

### CI Path (`epack collect --frozen`)

1. `epack collect --frozen` strictly:
   - Requires lockfile to exist and match config exactly
   - Verifies all binaries are installed with correct digests (no downloads)
   - Executes components and builds a draft pack
2. `epack sign` signs the resulting pack.
3. `epack verify` validates integrity and signature constraints.

### Explicit Path (individual commands)

1. `epack lock` resolves collector and tool versions and writes `epack.lock.yaml`.
2. `epack sync` installs or verifies binaries from lockfile.
3. `epack collector run` verifies installed binary digests, executes collectors, and builds a draft pack.
4. `epack sign` signs the resulting pack.
5. `epack verify` validates integrity and signature constraints.

## Collector Protocol

Collectors are standalone binaries that receive configuration via environment and write evidence JSON to stdout.

### Output (stdout)

```json
{
  "protocol_version": 1,
  "data": {
    // collector-specific evidence data
  }
}
```

- `protocol_version`: Integer version of the protocol.
- `data`: The collector's evidence data.

### Exit Codes

- `0`: Success. Stdout is parsed as JSON and stored as an artifact.
- Non-zero: Failure. Stderr is captured (sanitized) for error reporting.

### Environment

Collectors receive a restricted environment plus protocol variables:

**Protocol variables:**
- `EPACK_COLLECTOR_NAME`: Collector name from config (e.g., "github")
- `EPACK_PROTOCOL_VERSION`: Protocol version (1)
- `EPACK_COLLECTOR_CONFIG`: Path to JSON config file (if config exists)

**Base environment:**
- `HOME`, `USER`, `LANG`, `LC_ALL`, `TZ`, `TMPDIR`, `TEMP`, `TMP`
- `PATH` is set to a safe, deterministic value (`/usr/bin:/bin:/usr/sbin:/sbin`)
- Secrets from the `secrets:` allowlist in `epack.yaml` (passed by original name)

Only explicitly configured secrets are passed. Other environment variables are filtered.

**Reserved prefixes:** Secret names starting with `EPACK_`, `LD_`, `DYLD_`, or `_` are blocked to prevent protocol namespace hijacking and dynamic linker attacks.

**Config access:** Collectors read config from the file path in `EPACK_COLLECTOR_CONFIG`. The config file contains the collector's configuration block from `epack.yaml` as JSON.

## Tool Protocol

Tools are standalone binaries that operate on signed evidence packs. Unlike components (which gather evidence), tools process existing pack contents and produce derived outputs.

### Tool Invocation

**Top-level commands (recommended):** Configured tools are promoted to top-level commands:

```bash
epack ai --pack vendor.epack "What controls exist?"
epack policy --pack vendor.epack
EPACK_PACK=vendor.epack epack ai "What is the audit scope?"
```

**Explicit dispatch:** For tools not in `epack.yaml`:

```bash
epack tool <name> --pack <path> [tool-flags]
```

### Wrapper Flags

| CLI Flag | Environment Variable | Description |
|----------|---------------------|-------------|
| `--pack, -p` | `EPACK_PACK` | Path to evidence pack |
| `--output-dir, -o` | `EPACK_OUTPUT_DIR` | Override output location |
| `--json` | `EPACK_JSON=true` | JSON output mode |
| `--quiet, -q` | `EPACK_QUIET=true` | Suppress progress |
| `--insecure-allow-unpinned` | `EPACK_INSECURE_ALLOW_UNPINNED=true` | Allow execution without lockfile verification |

CLI flags take precedence over environment variables.

When a tool is invoked from PATH without lockfile verification, a warning is displayed by default. Use `--insecure-allow-unpinned` to suppress this warning (not recommended for production).

### Tool Execution Flow

1. **Verification**: Binary digest verified against lockfile (TOCTOU-safe).
2. **Pack Integrity**: Pack manifest and artifact digests verified.
3. **Run Directory**: Unique run directory created at `<basename>.runs/tools/<name>/<run-id>/` (e.g., `sample.epack` → `sample.runs/`).
4. **Execution**: Tool executed with protocol environment variables.
5. **Result Capture**: `result.json` written to run directory.

### Protocol Environment

Tools receive environment variables:

- `EPACK_RUN_ID`: Unique identifier for this execution.
- `EPACK_RUN_DIR`: Run directory for outputs.
- `EPACK_PACK_PATH`: Absolute path to the pack.
- `EPACK_PACK_DIGEST`: Verified pack digest.
- `EPACK_TOOL_NAME`: Tool name.
- `EPACK_TOOL_CONFIG`: Path to JSON config file (if configured).
- `EPACK_STARTED_AT`: ISO 8601 timestamp.
- `EPACK_PROTOCOL_VERSION`: Protocol version ("1").
- `EPACK_TOOL_CONFIG`: Path to JSON config file (if configured).
- `EPACK_JSON`: "true" if JSON mode enabled.
- `EPACK_QUIET`: "true" if quiet mode enabled.

### Exit Code Handling

| Tool Exit Code | Wrapper Exit Code | Meaning |
|----------------|-------------------|---------|
| 0              | 0                 | Success |
| 1-9            | 0                 | Tool-defined codes (recorded in result.json as `tool_exit_code`) |
| 10+            | 1                 | Normalized to avoid collision with wrapper codes |

Tool exit codes 1-9 are considered "soft" failures - the tool ran successfully but reported an application-level issue. These are passed through in `result.json.tool_exit_code` while the wrapper exit code remains 0.

Wrapper exit codes 10-19 are reserved for wrapper pre-execution failures:
- 10: Component not found
- 11: Verification failed
- 12: Pack verification failed
- 13: Lockfile missing/invalid
- 14: Run directory creation failed
- 15: Config file write failed
- 16: Pack required but not provided
- 17: Dependency missing

### Result Schema (`result.json`)

```json
{
  "schema_version": 1,
  "wrapper": { "version": "1.0.0" },
  "tool": { "name": "policy", "version": "1.2.3", "protocol_version": 1 },
  "run_id": "20240115T123456Z-abc123",
  "pack_path": "/path/to/vendor.epack",
  "started_at": "2024-01-15T12:34:56.789Z",
  "completed_at": "2024-01-15T12:34:57.123Z",
  "duration_ms": 334,
  "exit_code": 0,
  "tool_exit_code": 2,
  "status": "partial",
  "inputs": { "question": "What is the vendor's policy?" },
  "outputs": [{ "path": "answer.md", "media_type": "text/markdown" }],
  "errors": [],
  "warnings": [{ "code": "policy_unclear", "message": "..." }]
}
```

## Remote Adapter Protocol

Remote adapters are external binaries that handle communication with remote registries for pack push/pull operations. They follow a JSON-over-stdin/stdout protocol.

### Adapter Naming

```
epack-remote-<name>
```

Examples: `epack-remote-locktivity`, `epack-remote-s3`

### Discovery Priority

1. **Lockfile**: Source-based adapters installed to `.epack/remotes/<name>/<version>/`
2. **External binary**: Configured via `binary:` field in `epack.yaml`
3. **System PATH**: For adapter-only remotes (unverified)

### Commands

| Command | Purpose |
|---------|---------|
| `--capabilities` | Returns adapter capabilities (required) |
| `push.prepare` | Get presigned upload URL |
| `push.finalize` | Finalize upload and create release |
| `pull.prepare` | Get download URL and pack metadata |
| `pull.finalize` | Confirm pack receipt |
| `runs.sync` | Sync run ledgers to remote |
| `auth.login` | Interactive authentication |
| `auth.whoami` | Query current identity |

### Configuration (`epack.yaml`)

```yaml
remotes:
  locktivity:
    adapter: locktivity                    # Adapter name
    source: locktivity/remote-locktivity@v1  # Optional: source with version
    endpoint: https://api.locktivity.com
    target:
      workspace: acme
      environment: prod
    release:
      labels: ["monthly", "soc2"]
    runs:
      sync: true
```

### Push Workflow

1. Load and verify pack locally
2. Load remote configuration from `epack.yaml`
3. Discover and validate adapter binary (prompt to install if missing)
4. Call `push.prepare` to get presigned upload URL
5. Perform HTTP upload to provided URL (with progress)
6. Call `push.finalize` to create release
7. Sync run ledgers (optional)
8. Write receipt file for audit trail

### Pull Workflow

1. Load remote configuration from `epack.yaml`
2. Discover and validate adapter binary (prompt to install if missing)
3. Call `pull.prepare` with pack reference (digest, release ID, version, or latest)
4. Download pack from provided URL (with progress)
5. Verify pack integrity (SHA-256 digest match)
6. Call `pull.finalize` to confirm receipt
7. Write receipt file for audit trail

### Verification Status

| Status | Meaning |
|--------|---------|
| `verified` | Adapter in lockfile with valid digest |
| `unverified` | Adapter from PATH, not in lockfile |
| `managed` | In lockfile but not installed |
| `not_found` | Configured but not found |

See [Remote Adapter Protocol Specification](remote-protocol.md) for complete protocol details.

## Security Invariants

- Core commands must not import collector/tool runtime packages.
- Collector and tool commands must be build-tag gated (`components`).
- Verification must fail closed on malformed packs, digest mismatches, or invalid signatures.
- Unsafe modes must be explicit and off by default.
- TOCTOU-safe execution: Binary verification and execution are atomic (copy-while-hash).
- Identity-bound signatures: Sigstore signatures must come from the declared source repository.
- Lockfile retargeting protection: Config source must match lockfile source.
- **Catalog isolation**: `internal/dispatch` must never import `internal/catalog` (import guard enforced).

## Intended Deployment Patterns

- High-trust CI verification and consumer workflows: use `epack-core`.
- Evidence collection automation in controlled environments: use full `epack` with hardened runner settings.
