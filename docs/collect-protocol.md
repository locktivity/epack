# epack Collector Protocol v1 Specification

## Overview

Collectors are standalone binaries that gather evidence from external systems and produce structured output for inclusion in evidence packs. They are orchestrated by epack with full verification and security controls.

## Design Principles

- Evidence in, structured JSON out
- Stateless execution (all config via environment)
- Never require network unless explicitly documented
- Produce machine-readable output on stdout
- Support reproducible, auditable collection in CI/CD

## Plugin Discovery

### Naming Convention

Collector names must match:

```
^[a-z0-9][a-z0-9._-]{0,63}$
```

- Lowercase alphanumeric, dash, underscore, or dot
- 1-64 characters
- No path separators or traversal sequences

Examples: `github`, `aws`, `azure-devops`, `jira.cloud`

### Binary Location

**Source-based collectors** (from lockfile):

```
.epack/collectors/{name}/{version}/{os}-{arch}/{name}
```

Example: `.epack/collectors/github/v1.0.0/linux-amd64/github`

**External collectors** (explicit path):

Must be absolute paths specified in `epack.yaml`:

```yaml
collectors:
  custom:
    binary: /usr/local/bin/custom-collector
```

## Configuration

Collectors are configured in `epack.yaml`:

```yaml
# epack.yaml
stream: vendor/prod

collectors:
  github:
    source: locktivity/epack-collector-github@^1
    config:
      organization: myorg
      include_repos: ["app", "infra"]
    secrets:
      - GITHUB_TOKEN

  jira:
    source: locktivity/epack-collector-jira@^2
    config:
      project: SEC
      jql: "type = Control"
    secrets:
      - JIRA_API_TOKEN
      - JIRA_EMAIL
```

### Configuration Fields

| Field | Required | Description |
|-------|----------|-------------|
| `source` | One of source/binary | Source repository with version constraint |
| `binary` | One of source/binary | Absolute path to external binary |
| `config` | No | Collector-specific configuration (passed as JSON) |
| `secrets` | No | Environment variable names to pass through |

### Version Constraints

| Format | Meaning |
|--------|---------|
| `owner/repo` | Latest version |
| `owner/repo@latest` | Latest version (explicit) |
| `owner/repo@^1.0` | Caret: >=1.0.0 <2.0.0 |
| `owner/repo@~1.2` | Tilde: >=1.2.0 <1.3.0 |
| `owner/repo@v1.2.3` | Exact version |

## Collector Interface

### Execution

Collectors receive a protocol environment when invoked via `epack collect` or `epack collector run`:

| Variable | Description |
|----------|-------------|
| `EPACK_COLLECTOR_NAME` | Collector name (e.g., "github") |
| `EPACK_PROTOCOL_VERSION` | Protocol version ("1") |
| `EPACK_COLLECTOR_CONFIG` | Path to JSON config file (if config exists in epack.yaml) |
| `EPACK_IDENTITY` | Identity token or identifier (if set, passed through for CI contexts) |

### Allowed Environment Variables

Collectors receive a restricted environment. The following are passed through:

**User identity:**
- `HOME`, `USER`

**Locale:**
- `LANG`, `LC_ALL`, `LC_CTYPE`

**Timezone:**
- `TZ`

**Temp directories:**
- `TMPDIR`, `TEMP`, `TMP`

**Terminal:**
- `TERM`, `NO_COLOR`, `CLICOLOR`, `CLICOLOR_FORCE`

**SSL/TLS:**
- `SSL_CERT_FILE`, `SSL_CERT_DIR`

**Proxy settings:**
- `HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY` (and lowercase variants)
- Note: Credentials in proxy URLs are stripped for security

**XDG directories:**
- `XDG_CONFIG_HOME`, `XDG_CACHE_HOME`, `XDG_DATA_HOME`, `XDG_STATE_HOME`, `XDG_RUNTIME_DIR`

**Safe PATH:**
- Unix: `/usr/bin:/bin:/usr/sbin:/sbin`
- Windows: `C:\Windows\System32;C:\Windows`

All other environment variables are filtered out.

### Secrets

Secrets listed in `epack.yaml` are passed through by their original names:

```yaml
collectors:
  github:
    secrets:
      - GITHUB_TOKEN
      - GITHUB_APP_ID
```

**Validation rules:**
- Only explicitly listed secrets are passed
- Values are read from the environment (not from config)
- Reserved prefixes are blocked: `EPACK_`, `LD_`, `DYLD_`, `_`
- Empty-valued secrets are not passed

### Config File

If the collector has a `config` section in `epack.yaml`, a temporary JSON file is created and its path is passed via `EPACK_COLLECTOR_CONFIG`:

```json
{
  "organization": "myorg",
  "include_repos": ["app", "infra"]
}
```

## Output Convention

### Output Format

Collectors write JSON lines to stdout. The protocol supports two message types:

**Progress messages** (optional, 0 or more during execution):

```json
{"type":"epack_progress","protocol_version":1,"kind":"status","message":"Connecting to API..."}
{"type":"epack_progress","protocol_version":1,"kind":"progress","current":5,"total":100,"message":"Fetching repos"}
```

Progress message fields:
- `type`: Always `"epack_progress"`
- `protocol_version`: Progress protocol version (currently 1)
- `kind`: Either `"status"` (indeterminate) or `"progress"` (determinate with current/total)
- `message`: Human-readable status message
- `current`, `total`: Progress counters (only for `kind: "progress"`)

**Result message** (exactly 1, at end of execution):

```json
{"type":"epack_result","protocol_version":1,"data":{"collected_at":"2026-02-19T14:30:00Z","items":[...]}}
```

Result message fields:
- `type`: Always `"epack_result"`
- `protocol_version`: Protocol version (currently 1)
- `data`: The collected evidence data

**Legacy format (backwards compatible):**

Collectors that omit the `type` field are still supported:

```json
{
  "protocol_version": 1,
  "data": {
    "collected_at": "2026-02-19T14:30:00Z",
    "items": [...]
  }
}
```

The parser detects legacy format (no `type` + has `protocol_version` + has `data`) and treats it as `"epack_result"`.

**Plain JSON:**

Any valid JSON object or array without the envelope. The protocol version is inferred as 0.

**Non-JSON text:**

Plain text output is preserved as a JSON string.

### Output Parsing

The parser handles output as follows:

1. **Protocol envelope**: Extracts `protocol_version` and preserves exact bytes of `data` field (prevents float64 precision loss for large integers)
2. **Plain JSON**: Preserves as-is with `protocol_version = 0`
3. **Non-JSON text**: Quoted as JSON string with `protocol_version = 0`

### Artifact Storage

Collector output is stored in the evidence pack:

```
artifacts/{collector_name}.json
```

Example: `artifacts/github.json`, `artifacts/jira.json`

### Output Limits

| Limit | Value |
|-------|-------|
| Per-collector output | 64 MB |
| Aggregate output (all collectors) | 256 MB |

Exceeding these limits results in collection failure.

### Timeout

Default timeout: 60 seconds per collector.

Override via `--timeout` flag:

```bash
epack collect --timeout 5m
```

## Lockfile Schema

Collectors are pinned in `epack.lock.yaml`:

```yaml
schema_version: 1

collectors:
  github:
    source: github.com/locktivity/epack-collector-github
    version: v1.2.3
    signer:
      issuer: "https://token.actions.githubusercontent.com"
      subject: "https://github.com/locktivity/epack-collector-github/.github/workflows/release.yml@refs/heads/main"
      source_repository_uri: "https://github.com/locktivity/epack-collector-github"
      source_repository_ref: "v1.2.3"
    resolved_from:
      registry: "github"
      descriptor: "locktivity/epack-collector-github@^1"
    verification:
      status: "verified"
      verified_at: "2026-02-19T14:30:00Z"
    locked_at: "2026-02-19T14:30:00Z"
    platforms:
      linux/amd64:
        digest: sha256:abc123...
        asset: "collector-linux-amd64"
        url: "https://github.com/.../releases/download/v1.2.3/collector-linux-amd64"
      darwin/arm64:
        digest: sha256:def456...
        asset: "collector-darwin-arm64"
        url: "https://github.com/.../releases/download/v1.2.3/collector-darwin-arm64"
```

### Lockfile Limits

| Limit | Value |
|-------|-------|
| Maximum collectors | 1000 |
| Maximum platforms per collector | 100 |

## Exit Codes

### Collector Exit Codes

Collectors should use these exit codes:

- `0`: Success
- `1`: General error
- `2`: Configuration error
- `3`: Authentication error
- `4`: Network/API error
- `5-9`: Collector-specific errors

### Workflow Exit Codes

The `epack collect` workflow uses these exit codes:

| Code | Meaning |
|------|---------|
| `0` | Success |
| `1` | General failure |
| `10` | Collector not found |
| `11` | Digest verification failed |
| `12` | Pack verification failed |
| `13` | Lockfile missing or invalid |
| `14` | Run directory creation failed |
| `15` | Config file write failed |
| `16` | Pack required but not provided |
| `17` | Dependency missing |

## CLI Commands

### Primary Commands

```bash
# One-command workflow: lock, sync, run, build
epack collect

# Run collectors only (no auto-lock/sync)
epack collector run

# Run specific collectors
epack collect --only github,jira
epack collector run --only github
```

### Component Management

```bash
# Lock collector versions
epack lock

# Download/install collectors
epack sync

# Install a specific collector
epack install collector github
epack install collector github@^1.0

# Update to latest versions
epack update
```

### Command Flags

| Flag | Description |
|------|-------------|
| `--config, -c` | Path to epack.yaml (default: epack.yaml) |
| `--frozen` | CI mode: fail on any mismatch, no auto-lock/sync |
| `--timeout` | Timeout per collector (e.g., 30s, 2m) |
| `--output, -o` | Output pack file path |
| `--only` | Run only specific collectors (comma-separated) |
| `--parallel` | Max parallel collector executions (0=auto, 1=sequential) |

### Security Flags

| Flag | Description |
|------|-------------|
| `--frozen` | Strict CI mode (requires all collectors verified) |
| `--insecure-allow-unverified` | Allow collectors installed without verification |
| `--insecure-skip-verify` | Skip verification during sync (creates marker) |

## Security Model

### TOCTOU-Safe Binary Verification

Collectors undergo Time-of-Check-Time-of-Use safe verification:

1. Open binary with `O_RDONLY | O_NOFOLLOW` (prevents symlink attacks)
2. Create temp directory with 0700 permissions
3. Copy bytes through `TeeReader` that simultaneously:
   - Computes SHA256 hash
   - Writes to sealed temp file
4. Verify hash matches expected digest from lockfile
5. Execute the sealed copy

**Invariant:** The bytes executed are exactly the bytes that were hashed.

### Verification Levels

| Level | Badge | Meaning |
|-------|-------|---------|
| `verified` | ✓ | Sigstore signature verified against expected identity |
| `digest_pinned` | ○ | SHA256 digest matches lockfile |
| `unverified` | × | Not verified (external binary without digest) |

### Frozen Mode

The `--frozen` flag enforces strict security for CI/CD:

- ALL collectors must exist in lockfile
- ALL collectors must have platform-specific digests
- Config and lockfile must match exactly
- No auto-lock or auto-sync
- Collectors with insecure markers are rejected

```bash
# CI workflow
epack collect --frozen
```

### Insecure Install Markers

When collectors are synced with `--insecure-skip-verify`:

- A `.insecure-install` marker file is created in the install directory
- Marker contains timestamp and reason
- At runtime:
  - **Frozen mode**: Always rejected
  - **Non-frozen mode**: Requires `--insecure-allow-unverified` flag

### Process Isolation

Collectors run with:

- Restricted environment (only allowed variables)
- Safe PATH (no PATH injection)
- Timeout enforcement
- Output size limits
- stderr sanitization (truncated, control chars escaped)

### Supply Chain Security

- **Sigstore signature verification**: Collector binaries verified against expected OIDC identity
- **Digest pinning**: SHA256 per platform in lockfile
- **Source repository attestation**: Signer fields link to exact source commit
- **Reproducible builds**: Same lockfile produces same collector binaries

## Hardening Recommendations

For production deployments:

1. **Run on dedicated hosts or ephemeral runners**
2. **Use least-privilege credentials** (scoped tokens, read-only where possible)
3. **Filter network egress** with domain-allowlisting proxy
4. **Run under AppArmor/SELinux** with allowlisted filesystem paths
5. **Use `--frozen` mode in CI** for reproducible, auditable builds
6. **Commit `epack.lock.yaml`** to version control
7. **Review collector updates** before updating lockfile

## Example Collector Implementation

### Using the SDK (Recommended)

The `componentsdk` package provides a simple API with built-in progress support:

```go
package main

import (
    "time"
    "github.com/locktivity/epack/componentsdk"
)

func main() {
    componentsdk.RunCollector(componentsdk.CollectorSpec{
        Name:        "example",
        Version:     "1.0.0",
        Description: "Example collector with progress",
    }, func(ctx componentsdk.CollectorContext) error {
        // Report indeterminate status
        ctx.Status("Connecting to API...")

        // Simulate collecting items with progress
        items := []any{}
        for i := 1; i <= 10; i++ {
            ctx.Progress(int64(i), 10, "Fetching items")
            items = append(items, map[string]any{"id": i})
        }

        ctx.Status("Finalizing...")

        // Emit evidence (automatically wrapped with type and protocol_version)
        return ctx.Emit(map[string]any{
            "collected_at": time.Now().UTC().Format(time.RFC3339),
            "source":       ctx.Name(),
            "items":        items,
        })
    })
}
```

SDK methods:
- `ctx.Status(message)` - Report indeterminate status (e.g., "Connecting...")
- `ctx.Progress(current, total, message)` - Report determinate progress (e.g., 5/100)
- `ctx.Emit(data)` - Emit the final result (handles envelope automatically)
- `ctx.Config()` - Access collector configuration from epack.yaml
- `ctx.Name()` - Get collector name

### Manual Implementation

For collectors not using the SDK:

```go
package main

import (
    "encoding/json"
    "os"
)

type Output struct {
    Type            string      `json:"type"`
    ProtocolVersion int         `json:"protocol_version"`
    Data            interface{} `json:"data"`
}

type Evidence struct {
    CollectedAt string `json:"collected_at"`
    Source      string `json:"source"`
    Items       []Item `json:"items"`
}

type Item struct {
    ID          string `json:"id"`
    Title       string `json:"title"`
    Description string `json:"description"`
}

func main() {
    // Read config if provided
    configPath := os.Getenv("EPACK_COLLECTOR_CONFIG")
    if configPath != "" {
        // Parse config file...
    }

    // Collect evidence
    evidence := Evidence{
        CollectedAt: "2026-02-19T14:30:00Z",
        Source:      os.Getenv("EPACK_COLLECTOR_NAME"),
        Items: []Item{
            {ID: "1", Title: "Control A", Description: "..."},
        },
    }

    // Output with protocol envelope (include type field)
    output := Output{
        Type:            "epack_result",
        ProtocolVersion: 1,
        Data:            evidence,
    }

    json.NewEncoder(os.Stdout).Encode(output)
}
```

## Differences from Tools

| Aspect | Collectors | Tools |
|--------|------------|-------|
| Purpose | Gather evidence | Process packs |
| Orchestration | Managed by epack workflow | User-invoked |
| Output | JSON to stdout | Files in sidecar directory |
| Capabilities | No `--capabilities` command | Supports `--capabilities` |
| Working directory | Managed by epack | Set to run directory |
| Pack access | N/A (creates pack content) | Read-only access to pack |

## Not Yet Implemented

The following features are reserved but not yet implemented:

- **Collector capabilities**: `--capabilities` command for self-description
- **Incremental collection**: Delta collection based on previous runs
- **Collector dependencies**: Declaring dependencies on other collectors
