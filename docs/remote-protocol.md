# epack Remote Adapter Protocol v1 Specification

## Overview

Remote adapters are external binaries that handle communication with remote registries for pack push/pull operations. They follow a JSON-over-stdin/stdout protocol, similar to how Git credential helpers work.

This extensible architecture allows epack to integrate with multiple registry backends (Locktivity, S3, filesystem, etc.) without building registry-specific logic into the core tool.

## Design Principles

- External binary protocol (like Git credential helpers)
- JSON request/response over stdin/stdout
- Adapters handle authentication, not epack
- Two-phase upload: prepare → upload → finalize
- Pluggable: add new registries without modifying epack

## Adapter Naming

```
epack-remote-<name>
```

Examples: `epack-remote-locktivity`, `epack-remote-s3`, `epack-remote-filesystem`

## Discovery

Adapters are discovered from multiple locations (in priority order):

1. **Project lockfile**: Source-based remotes are installed to `.epack/remotes/<name>/<version>/`
2. **External binary**: Configured via `binary:` field in `epack.yaml`
3. **System PATH**: For adapter-only remotes (`adapter:` field without `source`/`binary`)

### Verification Status

| Status | Meaning |
|--------|---------|
| `verified` | Adapter is in `epack.lock.yaml` with valid digest |
| `unverified` | Adapter is in PATH but not in lockfile |
| `managed` | Adapter is in lockfile but not yet installed |
| `not_found` | Adapter was configured but not found anywhere |

### Platform-Specific Locations

Managed adapters are installed to platform-specific directories:

- **macOS**: `~/Library/Application Support/epack/bin/`
- **Linux**: `~/.local/share/epack/bin/` (XDG default)
- **Windows**: `%LOCALAPPDATA%\epack\bin\`

If `XDG_DATA_HOME` is set on Unix-like systems, it takes precedence.

## Configuration

Remotes are configured in `epack.yaml`:

```yaml
# epack.yaml
stream: myorg/evidence

remotes:
  locktivity:
    adapter: locktivity                              # Adapter name (binary: epack-remote-locktivity)
    source: locktivity/epack-remote-locktivity@v1   # Optional: source with version constraint
    binary: /path/to/binary                          # Optional: external binary path
    endpoint: https://api.locktivity.com
    target:
      workspace: acme
      environment: prod
    release:
      labels: ["monthly", "soc2"]
      notes: "Monthly SOC2 evidence"
    runs:
      sync: true
      paths: [".epack/runs/**/result.json"]
```

### Configuration Fields

| Field | Required | Description |
|-------|----------|-------------|
| `adapter` | Yes | Adapter name (used to find `epack-remote-<adapter>` binary) |
| `source` | No | Source repository with version constraint (enables lockfile verification) |
| `binary` | No | Explicit path to adapter binary (overrides discovery) |
| `endpoint` | No | Remote endpoint URL (passed to adapter) |
| `target` | No | Target configuration (workspace, environment) |
| `release` | No | Release metadata (labels, notes) |
| `runs.sync` | No | Whether to sync run ledgers after push |
| `runs.paths` | No | Glob patterns for run results to sync |
| `transport` | No | Transport-level security settings (see below) |

### Transport Configuration

The `transport` section configures security settings for adapter URLs:

```yaml
remotes:
  local-storage:
    adapter: filesystem
    transport:
      file_root: /storage/packs        # Required for file:// URLs
      allow_loopback_http: false       # Default: false
```

| Field | Default | Description |
|-------|---------|-------------|
| `file_root` | (none) | **Required for file:// URLs.** Constrains file:// paths to this directory. Prevents path traversal attacks. |
| `allow_loopback_http` | `false` | Permits http:// URLs to localhost/127.0.0.1/::1. Only enable for local development. |

**Security notes:**

- `file_root` is mandatory when the adapter returns `file://` URLs. Without it, push/pull operations will fail with an error.
- Even with `allow_loopback_http: true`, authentication headers (Bearer tokens, etc.) are never sent over HTTP.
- HTTPS URLs are always allowed regardless of these settings.

## Protocol

The protocol uses newline-delimited JSON. Requests are sent on stdin, responses on stdout. Stderr is used for human-readable log messages.

### Protocol Version

Current version: `1`

Adapters declare their supported protocol version via `--capabilities`. Requests include `protocol_version` for forward compatibility.

### Commands

| Command | Purpose |
|---------|---------|
| `--capabilities` | Returns adapter capabilities (synchronous, no stdin) |
| `push.prepare` | Get presigned upload URL |
| `push.finalize` | Finalize upload and create release |
| `pull.prepare` | Get download URL and pack metadata |
| `pull.finalize` | Confirm pack receipt |
| `runs.sync` | Sync run ledgers to remote |
| `auth.login` | Authenticate with remote (interactive) |
| `auth.whoami` | Query current identity |

### Invocation

```bash
# Capability probe (no stdin)
epack-remote-locktivity --capabilities

# Protocol commands (JSON on stdin)
echo '{"type":"push.prepare",...}' | epack-remote-locktivity push.prepare
```

## Capabilities

The `--capabilities` command returns adapter metadata:

```json
{
  "name": "locktivity",
  "kind": "remote_adapter",
  "deploy_protocol_version": 1,
  "features": {
    "prepare_finalize": true,
    "direct_upload": false,
    "pull": true,
    "runs_sync": true,
    "auth_login": true,
    "whoami": true
  },
  "auth": {
    "modes": ["device_code", "oidc_token", "api_key"],
    "token_storage": "os_keychain"
  },
  "limits": {
    "max_pack_bytes": 104857600,
    "max_runs_per_sync": 100
  }
}
```

### Feature Flags

| Feature | Description |
|---------|-------------|
| `prepare_finalize` | Supports two-phase upload (prepare + finalize) |
| `direct_upload` | Adapter handles upload itself (mutually exclusive with prepare_finalize) |
| `pull` | Supports two-phase download (pull.prepare + pull.finalize) |
| `runs_sync` | Supports run ledger syncing |
| `auth_login` | Supports interactive authentication |
| `whoami` | Supports identity query |

### Authentication Modes

| Mode | Description |
|------|-------------|
| `device_code` | Device code flow (opens browser) |
| `oidc_token` | OIDC token injection (CI/CD) |
| `api_key` | API key authentication |

## Push Workflow

The push workflow consists of:

1. Load and verify the pack locally
2. Load remote configuration from `epack.yaml`
3. Discover and validate the adapter binary
4. Call `push.prepare` to get a presigned upload URL
5. Perform HTTP upload to the provided URL
6. Call `push.finalize` to create the release
7. Sync run ledgers (unless disabled)
8. Write a receipt file for audit trail

### push.prepare Request

```json
{
  "type": "push.prepare",
  "protocol_version": 1,
  "request_id": "req_abc123",
  "remote": "locktivity",
  "target": {
    "workspace": "acme",
    "environment": "prod"
  },
  "pack": {
    "path": "packs/evidence.pack",
    "digest": "sha256:abc123...",
    "size_bytes": 1048576
  },
  "release": {
    "labels": ["monthly", "soc2"],
    "notes": "Monthly evidence collection",
    "source": {
      "git_sha": "abc123def456",
      "ci_run_url": "https://github.com/..."
    }
  },
  "identity": {
    "mode": "oidc_token",
    "token": "eyJhbGc...",
    "claims": {"sub": "repo:org/repo:ref:refs/heads/main"}
  }
}
```

### push.prepare Response

```json
{
  "ok": true,
  "type": "push.prepare.result",
  "request_id": "req_abc123",
  "upload": {
    "method": "PUT",
    "url": "https://storage.example.com/presigned-url",
    "headers": {
      "Content-Type": "application/zip",
      "x-amz-acl": "private"
    },
    "expires_at": "2024-01-15T13:00:00Z"
  },
  "finalize_token": "tok_xyz789"
}
```

### push.finalize Request

```json
{
  "type": "push.finalize",
  "protocol_version": 1,
  "request_id": "req_def456",
  "remote": "locktivity",
  "target": {
    "workspace": "acme",
    "environment": "prod"
  },
  "pack": {
    "path": "packs/evidence.pack",
    "digest": "sha256:abc123...",
    "size_bytes": 1048576
  },
  "finalize_token": "tok_xyz789"
}
```

### push.finalize Response

```json
{
  "ok": true,
  "type": "push.finalize.result",
  "request_id": "req_def456",
  "release": {
    "release_id": "rel_123",
    "pack_digest": "sha256:abc123...",
    "created_at": "2024-01-15T12:34:56Z",
    "canonical_ref": "locktivity.com/acme/prod@sha256:abc123"
  },
  "links": {
    "release": "https://app.locktivity.com/releases/rel_123",
    "pack": "https://app.locktivity.com/packs/sha256:abc123"
  }
}
```

## Pull Workflow

The pull workflow downloads packs from a remote registry:

1. Load remote configuration from `epack.yaml`
2. Discover and validate the adapter binary
3. Call `pull.prepare` with pack reference (digest, release ID, version, or latest)
4. Download pack from the provided URL
5. Verify pack integrity (SHA-256 digest match)
6. Call `pull.finalize` to confirm receipt
7. Write a receipt file for audit trail

### pull.prepare Request

```json
{
  "type": "pull.prepare",
  "protocol_version": 1,
  "request_id": "req_abc123",
  "remote": "locktivity",
  "target": {
    "workspace": "acme",
    "environment": "prod"
  },
  "ref": {
    "digest": "",
    "release_id": "",
    "version": "",
    "latest": true
  }
}
```

Pack references are mutually exclusive. Use one of:
- `digest`: Pull by exact SHA-256 digest (immutable, for reproducibility)
- `release_id`: Pull by release ID (e.g., `rel_abc123`)
- `version`: Pull by version string (e.g., `v1.2.3`)
- `latest`: Pull the most recent release (default)

### pull.prepare Response

```json
{
  "ok": true,
  "type": "pull.prepare.result",
  "request_id": "req_abc123",
  "download": {
    "url": "https://storage.example.com/presigned-download-url",
    "headers": {
      "Accept": "application/zip"
    },
    "expires_at": "2024-01-15T13:00:00Z"
  },
  "pack": {
    "digest": "sha256:abc123...",
    "size_bytes": 1048576,
    "stream": "acme/evidence",
    "release_id": "rel_123",
    "version": "v1.2.3",
    "created_at": "2024-01-15T12:00:00Z"
  },
  "finalize_token": "tok_xyz789"
}
```

### pull.finalize Request

```json
{
  "type": "pull.finalize",
  "protocol_version": 1,
  "request_id": "req_def456",
  "remote": "locktivity",
  "target": {
    "workspace": "acme",
    "environment": "prod"
  },
  "finalize_token": "tok_xyz789",
  "pack_digest": "sha256:abc123..."
}
```

### pull.finalize Response

```json
{
  "ok": true,
  "type": "pull.finalize.result",
  "request_id": "req_def456",
  "confirmed": true
}
```

## Run Syncing

### runs.sync Request

```json
{
  "type": "runs.sync",
  "protocol_version": 1,
  "request_id": "req_ghi789",
  "target": {
    "workspace": "acme",
    "environment": "prod"
  },
  "pack_digest": "sha256:abc123...",
  "runs": [
    {
      "run_id": "2024-01-15T12-00-00-000000Z-000001",
      "result_path": ".epack/tools/ai/2024-01-15T12-00-00-000000Z-000001/result.json",
      "result_digest": "sha256:def456..."
    }
  ]
}
```

### runs.sync Response

```json
{
  "ok": true,
  "type": "runs.sync.result",
  "request_id": "req_ghi789",
  "accepted": 1,
  "rejected": 0,
  "items": [
    {
      "run_id": "2024-01-15T12-00-00-000000Z-000001",
      "status": "accepted"
    }
  ]
}
```

Run sync statuses: `accepted`, `rejected`, `duplicate`

## Authentication

### auth.login Request

```json
{
  "type": "auth.login",
  "protocol_version": 1,
  "request_id": "req_jkl012"
}
```

### auth.login Response

```json
{
  "ok": true,
  "type": "auth.login.result",
  "request_id": "req_jkl012",
  "instructions": {
    "user_code": "ABCD-1234",
    "verification_uri": "https://auth.locktivity.com/device",
    "expires_in_seconds": 600
  }
}
```

### auth.whoami Request

```json
{
  "type": "auth.whoami",
  "protocol_version": 1,
  "request_id": "req_mno345"
}
```

### auth.whoami Response

```json
{
  "ok": true,
  "type": "auth.whoami.result",
  "request_id": "req_mno345",
  "identity": {
    "authenticated": true,
    "subject": "user@example.com",
    "issuer": "https://accounts.google.com",
    "expires_at": "2024-01-16T12:00:00Z"
  }
}
```

## Error Handling

### Error Response

```json
{
  "ok": false,
  "type": "error",
  "request_id": "req_abc123",
  "error": {
    "code": "auth_required",
    "message": "Authentication required. Run: epack remote login locktivity",
    "retryable": false,
    "action": {
      "type": "run_command",
      "command": "epack remote login locktivity"
    }
  }
}
```

### Error Codes

| Code | Meaning |
|------|---------|
| `unsupported_protocol` | Protocol version not supported |
| `invalid_request` | Malformed or invalid request |
| `auth_required` | Authentication required |
| `forbidden` | Permission denied |
| `not_found` | Resource not found |
| `conflict` | Resource conflict (e.g., duplicate release) |
| `rate_limited` | Rate limit exceeded |
| `server_error` | Remote server error |
| `network_error` | Network connectivity issue |

### Action Hints

Action hints provide guidance on resolving errors:

| Type | Fields | Description |
|------|--------|-------------|
| `run_command` | `command` | CLI command to run |
| `open_url` | `url` | URL to open in browser |

## Receipt Files

Push operations write receipt files for audit trail:

```
.epack/receipts/push/<remote>/<timestamp>_<digest>.json
```

Receipt files include:
- Release information
- Synced runs
- Client metadata
- Timestamps

## Security Model

### Adapter Verification

| Source | Verification |
|--------|--------------|
| Source-based (`source:` in config) | Sigstore signature + lockfile digest |
| External binary (`binary:` in config) | Digest pinned in lockfile |
| PATH-only (`adapter:` without `source`/`binary`) | **Unverified** - use with caution |

### Best Practices

- **Use source-based adapters** for production workflows
- **Pin adapter versions** in `epack.yaml` with version constraints
- **Commit `epack.lock.yaml`** to version control
- **Use `--frozen` mode in CI** to prevent downloads during push

### Authentication Security

- Authentication is managed by the adapter, not epack
- Credentials are stored per adapter (keychain, encrypted file, or env var)
- OIDC tokens are passed through for CI/CD environments
- API keys should be passed via environment variables

### Transport Security

Adapters may return URLs using different schemes. epack enforces security policies on these URLs:

| URL Scheme | Requirements |
|------------|--------------|
| `https://` | Always allowed |
| `http://` (non-loopback) | Always rejected (SSRF risk) |
| `http://` (localhost/127.0.0.1/::1) | Requires `transport.allow_loopback_http: true` |
| `file://` | Requires `transport.file_root` to be configured |

**File operations are hardened against symlink attacks:**
- All file:// reads/writes use O_NOFOLLOW to reject symlinks
- Path traversal is blocked (e.g., `../` cannot escape `file_root`)

See [Hardening Guide](hardening.md) for additional recommendations.

## CLI Commands

```bash
# Push a pack to a remote
epack push locktivity packs/evidence.pack

# Push with labels
epack push locktivity packs/evidence.pack --label monthly --label soc2

# Preview what would be pushed (dry-run)
epack push locktivity packs/evidence.pack --dry-run

# Push in background (returns immediately)
epack push locktivity packs/evidence.pack --detach

# Pull the latest pack from a remote
epack pull locktivity

# Pull a specific version
epack pull locktivity --version v1.2.3

# Pull by release ID
epack pull locktivity --release rel_abc123

# Pull by digest (immutable)
epack pull locktivity --digest sha256:abc123...

# Pull to specific output path
epack pull locktivity -o ./packs/evidence.pack

# Preview what would be pulled (dry-run)
epack pull locktivity --dry-run

# Pull in background (returns immediately)
epack pull locktivity --detach
```

## Example Adapter Implementation

A minimal adapter supporting push:

```go
func main() {
    if len(os.Args) > 1 && os.Args[1] == "--capabilities" {
        json.NewEncoder(os.Stdout).Encode(Capabilities{
            Name:                  "example",
            Kind:                  "remote_adapter",
            DeployProtocolVersion: 1,
            Features: Features{
                PrepareFinalize: true,
            },
        })
        return
    }

    cmd := os.Args[1]
    var req json.RawMessage
    json.NewDecoder(os.Stdin).Decode(&req)

    switch cmd {
    case "push.prepare":
        handlePrepare(req)
    case "push.finalize":
        handleFinalize(req)
    default:
        writeError("invalid_request", "unknown command")
    }
}
```

## Not Yet Implemented

The following features are reserved but not yet implemented:

- **Remote management CLI**: `epack remote login`, `epack remote whoami`, `epack remote list`, `epack remote info` (protocol types exist in `internal/remote/protocol.go`)
- **List operations**: List releases on a remote
- **Delete operations**: Remove releases from a remote
- **Resume uploads/downloads**: Resume interrupted transfers
