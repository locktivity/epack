# epack Tool Protocol v1 Specification

## Overview

Tools are standalone binaries that operate on signed evidence packs and produce derived outputs. Unlike collectors (which are orchestrated by epack with verification), tools are user-invoked utilities trusted by the operator.

## Design Principles

- Pack in, derived outputs out (sidecar)
- Never mutate signed content
- Always produce machine-readable run metadata
- Work offline unless explicitly networked

## Plugin Discovery

### Naming Convention

```
epack-tool-<name>
```

Examples: `epack-tool-ai`, `epack-tool-deploy`, `epack-tool-policy`

### Dispatch

Tools can be invoked in two ways:

**Top-level commands (recommended):** Configured tools are automatically promoted to top-level commands for ergonomic access:

```bash
# Direct invocation - most ergonomic
epack ai --pack vendor.epack "What controls exist?"
epack policy --pack vendor.epack

# With environment variables
EPACK_PACK=vendor.epack epack ai "What controls exist?"
```

This follows the pattern used by kubectl (plugins), git (aliases), and gh (extensions).

**Explicit dispatch:** For tools not in `epack.yaml`, or when you need the full namespace:

```bash
epack tool <name> --pack <pack> [tool-flags]
```

The `tool` namespace avoids collision with core commands. Pack paths must be specified via `--pack` or `EPACK_PACK`; positional pack arguments are not supported.

### Wrapper Flags

Wrapper flags control the wrapper behavior and can be set via CLI or environment variables:

| CLI Flag | Short | Environment Variable | Description |
|----------|-------|---------------------|-------------|
| `--pack <path>` | `-p` | `EPACK_PACK` | Path to evidence pack |
| `--output-dir <path>` | `-o` | `EPACK_OUTPUT_DIR` | Override output location |
| `--json` | | `EPACK_JSON=true` | Enable JSON output mode |
| `--quiet` | `-q` | `EPACK_QUIET=true` | Suppress progress output |
| `--insecure-allow-unpinned` | | `EPACK_INSECURE_ALLOW_UNPINNED=true` | Allow execution without lockfile verification |

CLI flags take precedence over environment variables. All remaining arguments after wrapper flags are passed to the tool.

## Tool Interface

### Required Commands

#### `--capabilities`

Returns tool metadata as JSON. Called with `EPACK_MODE=capabilities` environment variable set.

```json
{
  "name": "ai",
  "version": "0.1.0",
  "protocol_version": 1,
  "description": "AI-powered Q&A over pack contents",
  "requires_pack": true,
  "network": true,
  "requires_tools": ["index"],
  "requires_outputs": ["index/outputs/embeddings.json"],
  "publisher": "locktivity",
  "repo": "github.com/locktivity/epack-tool-ai"
}
```

Fields:
- `name`: Tool name (matches binary suffix)
- `version`: Semver tool version
- `protocol_version`: Protocol version (1)
- `description`: Human-readable description
- `requires_pack`: Whether tool requires a pack to operate (default: true if omitted or capabilities fails)
- `network`: Whether tool requires network access
- `requires_tools`: (optional) Tools that must run first (e.g., `["index"]`)
- `requires_outputs`: (optional) Output files that must exist relative to `<basename>.runs/tools/` (e.g., `["index/outputs/embeddings.json"]`)
- `publisher`: (optional) Tool publisher
- `repo`: (optional) Source repository URL

### Execution

Tools receive a protocol environment when invoked via `epack tool`:

| Variable | Description |
|----------|-------------|
| `EPACK_RUN_ID` | Unique run identifier (format: `YYYY-MM-DDTHH-MM-SS-uuuuuuZ-NNNNNN`) |
| `EPACK_RUN_DIR` | Absolute path to run directory (also CWD) |
| `EPACK_STARTED_AT` | ISO 8601 timestamp when run started |
| `EPACK_TOOL_NAME` | Tool name (e.g., "ai") |
| `EPACK_PROTOCOL_VERSION` | Protocol version ("1") |
| `EPACK_PACK_PATH` | Absolute pack path (only if pack provided) |
| `EPACK_PACK_DIGEST` | Pack digest from manifest (only if pack provided) |
| `EPACK_TOOL_CONFIG` | Path to JSON config file (if tool has config in epack.yaml) |
| `EPACK_IDENTITY` | Identity token or identifier (if set in environment, passed through) |

Standard flags all tools should support:
- `--json`: Machine-readable output to stdout (convenience mirror, not authoritative)
- `--quiet`: Suppress progress output

Note: `result.json` in the run directory is the source of truth; stdout JSON is for scripting convenience.

### Progress Messages

Tools can emit progress messages to stdout during execution. Progress messages use the same format as collectors:

```json
{"type":"epack_progress","protocol_version":1,"kind":"status","message":"Processing pack..."}
{"type":"epack_progress","protocol_version":1,"kind":"progress","current":5,"total":100,"message":"Analyzing files"}
```

Progress message fields:
- `type`: Always `"epack_progress"`
- `protocol_version`: Progress protocol version (currently 1)
- `kind`: Either `"status"` (indeterminate) or `"progress"` (determinate with current/total)
- `message`: Human-readable status message
- `current`, `total`: Progress counters (only for `kind: "progress"`)

Unlike collectors, tools write their final result to `result.json` in the run directory (not stdout), so stdout is available purely for progress messages.

**Using the SDK:**

```go
package main

import "github.com/locktivity/epack/componentsdk"

func main() {
    componentsdk.RunTool(componentsdk.ToolSpec{
        Name:         "example",
        Version:      "1.0.0",
        Description:  "Example tool with progress",
        RequiresPack: true,
    }, func(ctx componentsdk.ToolContext) error {
        ctx.Status("Loading pack...")

        // Process with progress
        for i := 1; i <= 10; i++ {
            ctx.Progress(int64(i), 10, "Processing")
        }

        ctx.Status("Writing output...")

        return ctx.WriteOutput("result.json", map[string]any{
            "message": "Done",
        })
    })
}
```

SDK methods for progress:
- `ctx.Status(message)` - Report indeterminate status
- `ctx.Progress(current, total, message)` - Report determinate progress

## Output Convention

### Sidecar Directory

Tools write to:

```
<basename>.runs/           # e.g., sample.epack -> sample.runs/
  tools/
    <tool>/
      <run-id>/
        result.json      # Required: run metadata
        outputs/         # Tool-specific outputs
```

For packless runs, outputs go to platform-appropriate state directory:
- Linux: `$XDG_STATE_HOME/epack/runs/<tool>/<run-id>/` (default: `~/.local/state/epack/...`)
- macOS: `$XDG_STATE_HOME/epack/runs/<tool>/<run-id>/` if set, else `~/Library/Application Support/epack/...`
- Windows: `%LOCALAPPDATA%\epack\runs\<tool>\<run-id>\`

Run ID format: `YYYY-MM-DDTHH-MM-SS-uuuuuuZ-NNNNNN` (e.g., `2026-02-19T14-30-00-123456Z-000000`)

Run IDs MUST sort chronologically when sorted lexicographically.

### result.json Schema

Every tool run produces this file:

```json
{
  "schema_version": 1,
  "wrapper": {
    "name": "epack",
    "version": "0.1.0"
  },
  "tool": {
    "name": "ai",
    "version": "0.1.0",
    "protocol_version": 1
  },
  "run_id": "2026-02-19T14-30-00-123456Z-000000",
  "pack_path": "vendor.epack",
  "pack_digest": "sha256:abc123...",
  "started_at": "2026-02-19T14:30:00Z",
  "completed_at": "2026-02-19T14:30:05Z",
  "duration_ms": 5000,
  "exit_code": 0,
  "tool_exit_code": 0,
  "status": "success",
  "inputs": {
    "question": "Do they enforce MFA?"
  },
  "outputs": [
    {
      "path": "outputs/answer.md",
      "media_type": "text/markdown"
    }
  ],
  "warnings": [],
  "errors": [],
  "identity": null,
  "run_context": null,
  "sync": null,
  "run_digest": null
}
```

**Optional fields** (may be null or omitted):
- `identity`: Actor identity for audit trails (workspace, actor, actor_type, auth_mode)
- `run_context`: CI/environment context (ci, ci_provider, repo, commit, branch, runner_os, runner_arch)
- `sync`: Sync state (ledger_id, synced_at, workspace)
- `run_digest`: Cryptographic hash of run for deduplication

### Status Values

- `success`: Completed without errors (exit code 0)
- `failure`: Tool encountered an error (exit code non-zero)
- `partial`: Completed with warnings but no errors

### Timestamps

- All timestamps must be `YYYY-MM-DDTHH:MM:SSZ` format (exactly 20 characters, UTC, no milliseconds)
- This matches the existing epack manifest timestamp format
- Clock source is system clock

### Failure Behavior

- `result.json` is always written, even on failure (wrapper backfills if tool doesn't write it)
- If tool writes invalid JSON, it's preserved as `result.json.tool` and wrapper creates backfill
- Invalid output paths generate warnings (not errors) and are removed from outputs list
- Incomplete outputs must still be referenced in `outputs` if produced

### Output Paths

- Output paths MUST be relative to the tool's run directory
- Output paths MUST NOT contain `..` or traverse outside the run directory
- Absolute paths are not permitted
- Invalid paths generate warnings and are removed from the outputs list

### Output Immutability

- Tool outputs are immutable after a run completes
- Re-running a tool creates a new run directory (new run ID)
- Tools must never overwrite previous run outputs
- This preserves provenance chains for audit trails

## Exit Codes

### Tool Exit Codes

Tools should use these exit codes:
- `0`: Success
- `1`: General error
- `2`: Pack not found or invalid
- `3`: Missing dependencies
- `4-9`: Tool-specific errors (reserved for tool use)

Tool exit codes 1-9 are "soft" failures - the wrapper exit code is 0 but `result.json` records the tool's exit code in `tool_exit_code`. This allows tools to signal application-level issues while indicating the tool itself ran successfully.

Tool exit codes ≥10 are normalized to wrapper exit code 1 to avoid collision with wrapper codes.

### Wrapper Exit Codes (10-19)

These codes indicate wrapper pre-execution failures (tool never ran):
- `10`: Tool not found
- `11`: Tool verification failed (digest mismatch)
- `12`: Pack verification failed
- `13`: Lockfile missing or invalid
- `14`: Run directory creation failed
- `15`: Config file write failed
- `16`: Pack required but not provided
- `17`: Required tool dependency not satisfied

## Listing Installed Tools

```bash
epack tool list           # List tools without probing (safe)
epack tool list --probe   # Query --capabilities from PATH tools (executes binaries)
epack tool list --json    # Machine-readable output
```

By default, `epack tool list` shows tools from the lockfile and PATH without executing them.
Use `--probe` to query `--capabilities` from PATH tools.

Output columns:
- **NAME**: Tool name (without `epack-` prefix)
- **VERSION**: From capabilities or lockfile
- **PUBLISHER**: From catalog (display only, if available)
- **STATUS**: `verified`, `unverified`, or `managed`
- **SOURCE**: `path`, `lockfile`, or `both`
- **DESCRIPTION**: From capabilities or status message

## Tool Information

```bash
epack tool info <name>         # Show detailed tool information
epack tool info <name> --json  # Machine-readable output
```

Displays:
- Binary path (if found in PATH)
- Capabilities (from `--capabilities` probe)
- Lockfile entry (version, source, platforms, digests)
- **Signing identity** (issuer/subject from Sigstore verification)

The signing identity establishes supply chain trust - it shows which OIDC identity signed the tool binary at sync time.

## Tool Catalog

The tool catalog provides discovery and display functionality. It is a cached index of tools from registries used for searching and enriching tool list output.

### Catalog Commands

```bash
epack tool catalog search [query]    # Search cached catalog (offline)
epack tool catalog search            # List all tools in catalog
epack tool catalog search policy     # Find tools matching 'policy'
epack tool catalog search --json     # JSON output

epack tool catalog refresh           # Fetch latest catalog from registry
epack tool catalog update            # Alias for 'refresh'
epack tool catalog refresh --json    # JSON output
```

### Search Ranking

Results are ranked by relevance:
1. **Exact match**: Tool name equals query
2. **Prefix match**: Tool name starts with query
3. **Substring match**: Name, description, or publisher contains query

Within each bucket, results are sorted by name for stability.

### Catalog Cache

The catalog is cached locally for offline searching:

```
$XDG_CACHE_HOME/epack/catalog.json       # Catalog data
$XDG_CACHE_HOME/epack/catalog.json.meta  # Fetch metadata
```

Cache location defaults:
- Linux: `~/.cache/epack/`
- macOS: `~/Library/Caches/epack/`
- Windows: `%LOCALAPPDATA%\epack\`

### Conditional Requests

The `catalog refresh` command uses HTTP conditional requests:
- `If-None-Match` (ETag): Avoids re-downloading unchanged catalogs
- `If-Modified-Since`: Falls back when ETag not available

This minimizes bandwidth when the catalog hasn't changed.

### Security Note

Catalog data is used for display only. Execution decisions (binary selection, digest verification, signer trust) come from the lockfile. The `internal/dispatch` package cannot import `internal/catalog` (enforced by import guard test).

## Installing Tools from Catalog

Tools can be installed directly from the catalog with automatic dependency resolution:

```bash
# Install a tool (looks up in catalog, resolves dependencies, adds to config, locks, syncs)
epack install tool ai
epack install tool ai@^1.0      # With version constraint
epack install tool ai@v1.2.3    # Exact version

# Install a collector
epack install collector github
epack install collector github@~2.0  # Tilde constraint

# Preview what would be installed (no changes made)
epack install tool ai --dry-run

# Install without automatic dependency resolution
epack install tool ai --no-deps

# Force refresh catalog before lookup
epack install tool ai --refresh
```

### Version Constraints

| Format | Meaning |
|--------|---------|
| `name` | Latest version |
| `name@latest` | Latest version (explicit) |
| `name@^1.0` | Caret: >=1.0.0 <2.0.0 |
| `name@~1.2` | Tilde: >=1.2.0 <1.3.0 |
| `name@v1.2.3` | Exact version |

### Dependency Resolution

Tools may declare dependencies in the catalog. When you install a tool, its dependencies are automatically resolved and installed:

```
$ epack install tool ai

Resolving dependencies...
  ai → index

Installing 2 tools:
  + index (dependency of ai)
  + ai

Added to epack.yaml:
  tools.index: locktivity/epack-index@latest
  tools.ai: locktivity/epack-tool-ai@^1.0

✓ Installed 2 tools
Remember to commit epack.lock.yaml
```

Dependencies are resolved using depth-first search with cycle detection. The catalog's `dependencies` field contains tool names (not version constraints); dependencies are installed with `@latest`.

### Runtime Dependency Checking

In addition to install-time dependencies, tools can declare runtime dependencies via `--capabilities`:

```json
{
  "requires_tools": ["index"],
  "requires_outputs": ["index/outputs/embeddings.json"]
}
```

The wrapper checks these before execution:
- `requires_tools`: Verifies each tool has at least one successful run on this pack
- `requires_outputs`: Verifies specific output files exist

If dependencies are not satisfied, the wrapper exits with code 17 (`DEPENDENCY_MISSING`):

```
Error: required tool 'index' has not been run

The tool "ai" requires "index" to run first.

Run:
  epack index --pack vendor.epack

Then retry:
  epack ai --pack vendor.epack
```

## Configuration

Tools share config and lockfile with collectors:

```yaml
# epack.yaml
stream: vendor/prod

collectors:
  github:
    source: locktivity/epack-collector-github@^1
    config:
      organization: myorg

tools:
  ai:
    source: locktivity/epack-tool-ai@^1
    config:
      model: gpt-4
    secrets:
      - OPENAI_API_KEY
  policy:
    source: locktivity/epack-tool-policy@^1
```

### Config Injection

Tool config is passed via:
- `EPACK_TOOL_CONFIG`: Path to temporary JSON file with config map contents

Secrets listed in `epack.yaml` are passed by their original names (e.g., `OPENAI_API_KEY`). Reserved prefixes (`EPACK_`, `LD_`, `DYLD_`, `_`) are blocked.

```yaml
# epack.lock.yaml
schema_version: 1

collectors:
  github:
    source: github.com/locktivity/epack-collector-github
    version: v1.2.3
    signer: ...
    platforms:
      linux/amd64:
        digest: sha256:...

tools:
  ai:
    source: github.com/locktivity/epack-tool-ai
    version: v0.5.0
    signer: ...
    platforms:
      linux/amd64:
        digest: sha256:...
```

## Unified Commands

- `epack lock` - Lock both collectors and tools
- `epack sync` - Sync both collectors and tools
- `epack install` - Lock (if needed) and sync dependencies
- `epack install tool <name>[@version]` - Install a tool from the catalog with dependencies
- `epack install collector <name>[@version]` - Install a collector from the catalog
- `epack update` - Update to latest versions
- `epack collect` - Auto-lock, sync, run collectors, build pack
- `epack collector run` - Run collectors and build pack
- `epack <tool-name> [flags]` - Run a configured tool (top-level)
- `epack tool <name> [flags]` - Run any tool (explicit dispatch)
- `epack tool list` - List available tools
- `epack tool info <name>` - Show tool details
- `epack tool catalog search` - Search tool catalog
- `epack tool catalog refresh` - Update cached catalog

## Security Model

Tools get the same supply chain security as collectors:

- **Sigstore signature verification**: Tool binaries verified against expected identity
- **Digest pinning in lockfile**: SHA256 digest per platform
- **TOCTOU-safe execution**: Binary copied to sealed temp dir, hashed during copy
- **Frozen mode for CI**: `--frozen` requires all tools installed with correct digests
- **Insecure markers**: Track tools installed without verification

### Tool Execution Security

When running `epack tool <name> --pack <pack>`:
1. Search upward for `epack.yaml` to find project root
2. Load lockfile, get expected digest for tool
3. Verify binary digest (TOCTOU-safe copy + hash)
4. Create run directory
5. Execute verified binary with protocol environment

If no lockfile/config found, the command fails with exit code 13 (lockfile missing). Tools must be configured in `epack.yaml` and locked via `epack lock` before execution.

### Working Directory Contract

- `epack` creates the run directory before invocation
- `epack` sets CWD to the run directory
- Tools write only inside CWD (unless `--output-dir` overrides)
- Tools must not write outside their run directory

### Environment Contract

Tools receive a restricted environment:

**Always passed:**
- `HOME`, `USER`
- `LANG`, `LC_ALL`, `LC_CTYPE`
- `TZ`
- `TMPDIR`, `TEMP`, `TMP`
- `TERM`, `NO_COLOR`, `CLICOLOR`, `CLICOLOR_FORCE`
- `SSL_CERT_FILE`, `SSL_CERT_DIR`
- `HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY` (and lowercase variants)
- `XDG_CONFIG_HOME`, `XDG_CACHE_HOME`, `XDG_DATA_HOME`, `XDG_STATE_HOME`, `XDG_RUNTIME_DIR`
- `PATH`: `/usr/bin:/bin:/usr/sbin:/sbin` (hardcoded safe PATH)

**Protocol variables (see Execution section above)**

**Secrets from `epack.yaml`** (passed by original name). Only explicitly listed secrets are passed. Reserved prefixes (`EPACK_`, `LD_`, `DYLD_`, `_`) are blocked.

All other environment variables are filtered.

### Pack Verification

- `epack` verifies pack integrity before invoking any tool
- Tools receive only valid, verified packs
- Tools do not need to call `epack verify` themselves
- **Tools must treat the pack path as read-only**

### Derived Outputs

- Tools may emit new evidence packs as outputs (e.g., redacted packs, normalized packs)
- Tools must not modify the input pack
- Derived packs are written to the tool's output directory like any other output

### Hardening Recommendations

Same as collectors:
- Run on dedicated hosts or ephemeral runners
- Use least-privilege credentials
- Filter network egress with domain-allowlisting proxy
- Run under AppArmor with allowlisted filesystem paths

## Trust Model

### Trust Levels

Tools have different trust levels based on their verification state:

| Level | Badge | Meaning |
|-------|-------|---------|
| `locktivity_verified` | ✓✓ | Verified by Locktivity registry with audit trail |
| `sigstore_signed` | ✓ | Sigstore signature verified against expected identity |
| `digest_pinned` | ○ | SHA256 digest matches lockfile (no signature verification) |
| `unverified` | × | Not verified (PATH-based or insecure install) |

Trust level is determined at lock time and persisted in the lockfile:

```yaml
# epack.lock.yaml
tools:
  ai:
    source: locktivity/epack-tool-ai
    version: v1.2.3
    resolved_from:
      registry: locktivity      # Where it was resolved from
      descriptor: "^1.0.0"      # Original constraint
    signer:
      issuer: "https://token.actions.githubusercontent.com"
      subject: ".github/workflows/release.yml"
      source_repository_uri: "https://github.com/locktivity/epack-tool-ai"
      source_repository_ref: "refs/tags/v1.2.3"
    verification:
      status: verified          # verified, unverified, skipped
      verified_at: "2026-02-19T14:30:00Z"
    platforms:
      linux/amd64:
        digest: sha256:abc123...
        url: "https://github.com/.../releases/download/v1.2.3/epack-tool-ai-linux-amd64"
```

### Trust Badge Display

The `epack tool list` command displays trust badges:

```
NAME     VERSION   TRUST
ai      v1.2.3    ✓ sigstore_signed
policy   v0.1.22   ○ digest_pinned
custom   external  × unverified
```

### Multi-Registry Ranking (Future)

When multiple registries are configured, resolution follows this ranking:

1. **First match wins**: Registries are checked in order; first to resolve succeeds
2. **Policy enforcement**:
   - `permissive` mode: Warn on unverified, allow execution
   - `strict` mode: Fail on unverified tools

Configuration (reserved, not implemented):

```yaml
# epack.yaml
registries:
  - name: epack
    url: https://registry.epack.dev
    priority: 1
  - name: github
    priority: 2

tool_policy:
  mode: strict  # or "permissive"
  allow:
    - "epack/*"
  deny:
    - "*-snapshot"
```

### Revocation Hooks (Future)

Registry metadata may include revocation information:

```json
{
  "tool": "epack-tool-example",
  "version": "v1.0.0",
  "revoked": true,
  "revoked_at": "2026-03-01T00:00:00Z",
  "reason": "CVE-2026-XXXXX: Remote code execution vulnerability",
  "replacement": "v1.0.1"
}
```

CLI behavior:
- `permissive` mode: Warn but continue execution
- `strict` mode: Fail with revocation error

The `epack tool verify` command checks revocation status when connected to a registry.

## Provenance in result.json

When running a locked tool, the wrapper populates supply chain provenance:

```json
{
  "schema_version": 1,
  "tool": {
    "name": "ai",
    "version": "1.2.3"
  },
  "signing": {
    "issuer": "https://token.actions.githubusercontent.com",
    "subject": ".github/workflows/release.yml",
    "source_repository_uri": "https://github.com/locktivity/epack-tool-ai",
    "source_repository_ref": "refs/tags/v1.2.3"
  },
  "resolved_from": {
    "registry": "github",
    "descriptor": "locktivity/epack-tool-ai@^1.0.0"
  },
  ...
}
```

These fields enable downstream consumers to verify provenance chains.

## Not Yet Implemented

The following features have reserved fields/hooks but are not yet implemented:

- **Embedded mode**: Outputs inside pack (currently sidecar only)
- **Formal capability enforcement**: Tools declare capabilities but enforcement is advisory
- **Tool dependency version constraints**: `requires_tools` supports tool names but not version constraints; tools can check `result.json` from dependencies for version validation
- **Run digest computation**: `run_digest` field exists but is not auto-populated
- **Sync integration**: `sync` field for ledger state tracking
- **Multi-registry support**: `registries` array and priority-based resolution
- **Tool policy enforcement**: `tool_policy` config with allow/deny patterns
- **Revocation checking**: Registry-based revocation feed integration
- **Catalog signature verification**: Catalog integrity is not cryptographically verified (mitigated by catalog/execution isolation)
