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

Source-based remotes are installed per project:

```
.epack/remotes/{remote-name}/{version}/{os}-{arch}/epack-remote-{adapter}
```

Examples:
- `.epack/remotes/locktivity/v1.2.3/linux-amd64/epack-remote-locktivity`
- `.epack/remotes/s3/v0.9.0/darwin-arm64/epack-remote-s3`

This differs from utilities, which are user-global under `~/.epack/bin/`.

## Configuration

Remotes are configured in `epack.yaml`:

```yaml
# epack.yaml
stream: myorg/evidence

remotes:
  locktivity:
    adapter: locktivity                              # Adapter name (binary: epack-remote-locktivity)
    source: locktivity/epack-remote-locktivity@^0.1.0   # Optional: source with version constraint
    binary: /path/to/binary                          # Optional: external binary path
    insecure_endpoint: https://registry.example.com  # Optional custom API endpoint (SECURITY: use with caution)
    auth:
      insecure_endpoint: https://auth.example.com    # Optional custom auth endpoint (SECURITY: use with caution)
    target:
      workspace: acme
      environment: prod
    release:
      labels: ["monthly", "soc2"]
      notes: "Monthly SOC2 evidence"
    runs:
      sync: true
      paths: ["tools/**/result.json", "runs/**/result.json"]
```

### Configuration Fields

| Field | Required | Description |
|-------|----------|-------------|
| `adapter` | Yes | Adapter name (used to find `epack-remote-<adapter>` binary) |
| `source` | No | Source repository with version constraint (enables lockfile verification) |
| `binary` | No | Explicit path to adapter binary (overrides discovery) |
| `insecure_endpoint` | No | Custom API endpoint override (SECURITY: use with caution) |
| `auth.insecure_endpoint` | No | Custom auth endpoint override (SECURITY: use with caution) |
| `target` | No | Target configuration (workspace, environment) |
| `release` | No | Release metadata (labels, notes) |
| `runs.sync` | No | Whether to sync run ledgers after push |
| `runs.paths` | No | Glob patterns for run results to sync |
| `transport` | No | Transport-level security settings (see below) |

### Custom Endpoint Overrides

Custom remote endpoints are declared in `epack.yaml` using the `insecure_` prefix as acknowledgement:

```yaml
remotes:
  locktivity:
    source: locktivity/epack-remote-locktivity@^0.1.0
    insecure_endpoint: https://dev-tunnel.ngrok-free.app
    auth:
      insecure_endpoint: https://dev-tunnel.ngrok-free.app
```

`epack` validates these fields, blocks them when `EPACK_STRICT_PRODUCTION=true`, emits an insecure-bypass
audit event, and passes the resolved values to the adapter as trusted explicit env:

- `EPACK_REMOTE_ENDPOINT`
- `EPACK_REMOTE_AUTH_ENDPOINT`

Adapters should treat these env vars as explicit base-URL overrides provided by `epack`.
If set, use them for API and auth requests instead of built-in defaults or ambient config.

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
| `lock.report` | Report lockfile provenance without pushing a pack |
| `auth.login` | Start a browser sign-in that returns to a loopback redirect |
| `auth.complete` | Finish a browser sign-in with the code the browser returned |
| `auth.whoami` | Query current identity |

### Invocation

```bash
# Capability probe (no stdin)
epack-remote-locktivity --capabilities

# Protocol commands (JSON on stdin)
echo '{"type":"push.prepare",...}' | epack-remote-locktivity push.prepare
```

Every command runs with `EPACK_REMOTE_PROTOCOL_VERSION` set, and with
`EPACK_PROJECT_ROOT` set to the project folder when there is one, so an
adapter can read files it put there without being told where they are.

## Capabilities

The `--capabilities` command returns adapter metadata:

```json
{
  "name": "locktivity",
  "kind": "remote_adapter",
  "deploy_protocol_version": 1,
  "version": "v0.1.6",
  "features": {
    "prepare_finalize": true,
    "direct_upload": false,
    "pull": true,
    "runs_sync": true,
    "lock_report": true,
    "auth_login": true,
    "auth_browser": true,
    "whoami": true
  },
  "auth": {
    "modes": ["browser", "oidc_token", "api_key"],
    "token_storage": "os_keychain"
  },
  "files_dir": ".locktivity",
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
| `lock_report` | Supports lockfile provenance reports through `lock.report` |
| `auth_login` | Supports interactive authentication |
| `auth_browser` | Signs in through the browser: `auth.login` takes a loopback `redirect_uri` and `auth.complete` finishes the sign-in. `epack remote login` requires it |
| `whoami` | Supports identity query |
| `config_pull` | Supports handing over a named configuration through `config.pull` |
| `keys` | Manages the signing keys a pipeline accepts through `key.register`, `key.list`, `key.retire`, and `key.revoke` |

`files_dir`, outside the feature flags, names the one hidden folder a fetched
configuration from this adapter may carry for its own bookkeeping, such as
`.locktivity`. It must be a single hidden folder name and may not be `.epack`
or `.git`; an adapter that declares none may not put hidden files in a pull.
Adapters released before `files_dir` declare none, so a pull through one is
refused with a pointer to `epack remote update <remote>`.

### Authentication Modes

| Mode | Description |
|------|-------------|
| `browser` | Browser sign-in with a loopback redirect, through `auth.login` and `auth.complete` |
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
    "environment": "prod",
    "stream": "acme/evidence"
  },
  "pack": {
    "path": "packs/evidence.epack",
    "digest": "sha256:abc123...",
    "manifest_digest": "sha256:def456...",
    "file_digest": "sha256:789abc...",
    "size_bytes": 1048576
  },
  "release": {
    "labels": ["monthly", "soc2"],
    "notes": "Monthly evidence collection",
    "build_context": {
      "git_sha": "abc123def456",
      "ci_run_url": "https://github.com/..."
    },
    "lock_provenance": {
      "lockfile": "schema_version: 1\ncollectors:\n  github:\n    ...",
      "lockfile_sha256": "5b3a...",
      "lockfile_path": "epack.lock.yaml",
      "trigger_kind": "frozen_check",
      "outcome": "success",
      "reported_at": "2026-05-25T12:00:00Z",
      "summary": {
        "schema_version": 1,
        "collectors": [
          {
            "name": "github",
            "source": "github.com/acme/epack-collector-github",
            "version": "v1.2.3",
            "commit": "abc123",
            "platforms": [
              {
                "name": "linux/amd64",
                "digest": "sha256:..."
              }
            ]
          }
        ]
      },
      "runtime_context": {
        "runner_type": "github_actions",
        "pipeline_id": "01234567-89ab-cdef-0123-456789abcdef",
        "github": {
          "repository": "acme/evidence",
          "ref": "refs/heads/main",
          "run_id": "12345"
        }
      }
    }
  },
  "identity": {
    "mode": "oidc_token",
    "token": "eyJhbGc..."
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
    "environment": "prod",
    "stream": "acme/evidence"
  },
  "pack": {
    "path": "packs/evidence.epack",
    "digest": "sha256:abc123...",
    "manifest_digest": "sha256:def456...",
    "file_digest": "sha256:789abc...",
    "size_bytes": 1048576
  },
  "release": {
    "lock_provenance": {
      "lockfile_sha256": "5b3a...",
      "lockfile_path": "epack.lock.yaml",
      "trigger_kind": "frozen_check",
      "outcome": "success"
    }
  },
  "finalize_token": "tok_xyz789"
}
```

Clients should send the same lock provenance envelope in `push.prepare` and `push.finalize`. That keeps adapters stateless and avoids forcing them to embed large raw lockfiles inside finalize tokens.

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
    "method": "GET",
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
  "digest": "sha256:abc123..."
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
  "file_digest": "sha256:file456...",
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
  ],
  "failed_outputs": [
    {
      "run_id": "2024-01-15T12-00-00-000000Z-000001",
      "path": "outputs/large-report.pdf",
      "reason": "file size 52428800 exceeds maximum 50000000 bytes"
    }
  ]
}
```

Run sync statuses: `accepted`, `rejected`, `duplicate`

The `failed_outputs` field (optional) lists output files that could not be uploaded. Reasons include:
- File exceeds maximum size (50MB)
- File path outside result directory
- Upload or confirmation failure

## Lock Reporting

Adapters that advertise `features.lock_report: true` accept `lock.report`. This command lets CI report the current `epack.lock.yaml` before a pack exists, for example during setup bootstrap or a lock refresh pull request.

The lock provenance envelope is the same shape used by `release.lock_provenance` in `push.prepare`.

### lock.report Request

```json
{
  "type": "lock.report",
  "protocol_version": 1,
  "request_id": "req_lock_123",
  "remote": "locktivity",
  "target": {
    "workspace": "acme",
    "environment": "prod"
  },
  "lock_provenance": {
    "lockfile": "schema_version: 1\ncollectors:\n  github:\n    ...",
    "lockfile_sha256": "5b3a...",
    "lockfile_path": "epack.lock.yaml",
    "trigger_kind": "bootstrap",
    "outcome": "success",
    "reported_at": "2026-05-25T12:00:00Z",
    "summary": {
      "schema_version": 1,
      "collectors": []
    },
    "runtime_context": {
      "pipeline_id": "01234567-89ab-cdef-0123-456789abcdef",
      "head_sha": "def456abc789",
      "github": {
        "repository": "acme/evidence",
        "ref": "refs/heads/locktivity/setup"
      }
    }
  }
}
```

`runtime_context.head_sha` names the branch head commit the lock was resolved at. On `pull_request` events `GITHUB_SHA` is the ephemeral merge commit, so the workflow passes the real head explicitly via the `EPACK_HEAD_SHA` environment variable. Remotes use it to order reports and discard stale ones.

Failure reports omit the raw lockfile and include a stable failure code:

```json
{
  "type": "lock.report",
  "protocol_version": 1,
  "request_id": "req_lock_124",
  "remote": "locktivity",
  "target": {
    "workspace": "acme",
    "environment": "prod"
  },
  "lock_provenance": {
    "trigger_kind": "frozen_check",
    "outcome": "failure",
    "failure_code": "lock_config_mismatch",
    "failure_message": "epack.yaml changed without a matching lock refresh",
    "reported_at": "2026-05-25T12:00:00Z",
    "runtime_context": {
      "pipeline_id": "01234567-89ab-cdef-0123-456789abcdef"
    }
  }
}
```

Allowed `trigger_kind` values are `bootstrap`, `refresh`, `frozen_check`, and `check`. A `check` report comes from `epack run --check` (or a run with `EPACK_CHECK=1`): the run signed in, verified the lock, the variables, the credentials, and the publishers, collected nothing, and put what it found under `metadata.check` (`signed_in_as`, `lock_present`, `lock_current`, `env_present`, `env_total`, `env_missing`, `env_covered`, `credentials`, `publishers_trusted`, `findings`); its outcome is `success` with the lockfile when the run would have everything it needs, otherwise `failure` with the code `check_failed`. A variable that only the remote reads, such as the remote's own fallback credential, is listed under `env_covered` rather than counted when the run is signed in: the session is the credential and the run will not read the variable.
Allowed `outcome` values are `success` and `failure`.

Stable frozen failure codes include:

| Code | Meaning |
|------|---------|
| `lock_config_mismatch` | `epack.yaml` and `epack.lock.yaml` no longer describe the same components, or a locked version no longer satisfies its configured range |
| `lock_stale` | The lockfile contains source-based entries no longer present in config |
| `lock_missing_pinned_artifact` | The lockfile is missing the current platform, a pinned binary, or a required digest |

CI extracts these codes without scraping logs: when the `EPACK_ERROR_FILE` environment variable names a file, every failed epack command appends `code=`, `exit=`, and `summary=` lines to it. A workflow reads that file to pass `--failure-code` and `--failure-message` to `epack remote report-lock` and to render a job summary.

### lock.report Response

```json
{
  "ok": true,
  "type": "lock.report.result",
  "request_id": "req_lock_123",
  "status": "accepted",
  "outcome": "success",
  "lockfile_sha256": "5b3a...",
  "revision_id": "rev_123"
}
```

The `pipeline_url` field (optional) is the address of the pipeline's page on the remote; `epack run --check` shows it after the report when it is an http or https URL.

## Authentication

`epack remote login <remote>` signs in through the browser with a loopback
redirect. epack listens on `127.0.0.1`, on a free port or the one `--port`
names, asks the adapter for a sign-in that returns there, and opens the link.
When the browser comes back, epack hands what it brought to the adapter to
finish. The adapter talks to its remote; epack only carries the redirect.

### auth.login Request

```json
{
  "type": "auth.login",
  "protocol_version": 1,
  "request_id": "req_jkl012",
  "redirect_uri": "http://127.0.0.1:51234/callback"
}
```

`redirect_uri` is always `http://127.0.0.1:{port}/callback`, on the port epack
is listening on.

### auth.login Response

```json
{
  "ok": true,
  "type": "auth.login.result",
  "request_id": "req_jkl012",
  "instructions": {
    "authorization_url": "https://app.example.com/oauth/authorize?client_id=epack&redirect_uri=http%3A%2F%2F127.0.0.1%3A51234%2Fcallback&state=af0ifjsldkj",
    "state": "af0ifjsldkj",
    "session": "opaque-session",
    "expires_in_seconds": 600
  }
}
```

`authorization_url` is the page where the person allows epack. epack opens it
in the browser only when it is an http or https URL, and prints it either way.
`state` is also carried in that URL. `session` is the adapter's handle for the
sign-in in flight and carries what it needs for the code exchange. epack keeps
it in memory, never shows or logs it, and passes it back unchanged to
`auth.complete`. epack waits for the browser for at most `expires_in_seconds`,
10 minutes when it is 0, and never longer than 15 minutes.

The remote sends the browser back to `redirect_uri` with `code` and `state`
once the person allows epack, or with `error`, `error_description`, and
`state` when they do not (`access_denied` when they cancel). epack serves only
`GET /callback`, turns away a callback whose `state` does not match, and lets
the first one that matches decide the sign-in. A callback with an `error` ends
the sign-in without calling the adapter again.

### auth.complete Request

```json
{
  "type": "auth.complete",
  "protocol_version": 1,
  "request_id": "req_jkl013",
  "session": "opaque-session",
  "code": "SplxlOBeZQQYbYS6WxSbIA",
  "state": "af0ifjsldkj"
}
```

### auth.complete Response

```json
{
  "ok": true,
  "type": "auth.complete.result",
  "request_id": "req_jkl013",
  "identity": {
    "authenticated": true,
    "subject": "dana@northwind.com"
  }
}
```

The adapter exchanges the code with its remote and stores the credentials it
gets wherever it keeps them before it answers. A failed exchange answers with
an [error response](#error-response), and epack shows its message.

### config.pull Request

A remote that generates project configuration (Locktivity generates one per
pipeline) can hand it to a terminal with `config.pull`. The name is whatever the
remote shows the person, such as `epack run northwind-production`.

```json
{
  "type": "config.pull",
  "protocol_version": 1,
  "request_id": "req_mno014",
  "remote": "locktivity",
  "target": {},
  "config": {"name": "northwind-production"}
}
```

### config.pull Response

```json
{
  "ok": true,
  "type": "config.pull.result",
  "request_id": "req_mno014",
  "config": {
    "id": "0b1c6f2e-5b1a-4f4e-9c3a-7d2e8a1b4c5d",
    "name": "northwind-production",
    "title": "Northwind production",
    "stream": "northwind/production",
    "runs_in": "My laptop",
    "revision": 3,
    "folder": "northwind/production",
    "files": {"epack.yaml": "stream: northwind/production\n..."},
    "shas": {"epack.yaml": "sha256 hex of the managed file"},
    "lockfile": "schema_version: 1\n..."
  }
}
```

Files are keyed by path relative to the project folder and use LF line endings.
`shas` covers managed files only; a file the person is expected to edit has no
sha. `lockfile` is present once the remote has a pinned lock for the revision.
`folder` is where the same files sit in a repository the remote generates for,
for anyone laying out a repository by hand. A fetched configuration may name
only published components: `epack run` refuses a `binary:` entry in it, and
runs its collectors, tools, and remote only when their publishers (the GitHub
owners of their sources) are trusted, by the person once in a terminal, by
`EPACK_TRUSTED_PUBLISHERS` or `--trust-publisher` for one process, or by the
`epack remote login` that recorded the adapter's own publisher. `id` is the remote's identifier
for the configuration; `epack run` exports it as `EPACK_PIPELINE_ID` unless
the environment already names one, so a push or a failure report from a
cloned folder reaches the pipeline it came from. A folder laid out from a
downloaded bundle has no pull record; the adapter that made the bundle can
recognise the folder itself, since every command runs with
`EPACK_PROJECT_ROOT` set to the project folder. A name the caller cannot see
answers with the `not_found` error code.

epack writes only what a project is made of. A path must stay inside the
folder, contain no control characters, and carry no hidden segment, with two
exceptions: anything under the folder the adapter declared as `files_dir`
(`.locktivity/` for Locktivity) and hook scripts at `.epack/hooks/<name>.sh`. Everything else, including `.epack/collectors/`,
`.epack/remotes/`, and `.git/`, is refused, so a remote cannot place a binary
where sync would treat it as already verified. The folder is named by the
person, not by the response.

Files without a sha are the person's. epack writes them when absent, keeps
them up to date with the remote's template until the person edits them, and
then leaves them alone. A hook script that still matches the delivered
template is never run, so a configuration cannot bring shell with it; hooks
run once the person has made them their own. After a fetch that changed the
configuration, epack prints what it will run and read, from the written files.

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

## Signing Keys

A remote that keeps the list of keys a pipeline accepts signatures from
advertises `keys`. `epack key create` makes a key on the person's machine,
keeps the private half there, and registers the public half with these
operations; `epack run` then signs with it, and `epack run --check` reports
whether the pipeline accepts it. Only a signed-in person may use them: an
adapter answers a job with `forbidden`, even one signed in with a key the
pipeline approved, since a job must not mint its own trust. `config` is the
configuration's name or the remote's identifier for it; left out, the
adapter may recognise the folder itself, as the Locktivity adapter does for
a bundle laid out by hand from its own manifest.

### key.register Request

```json
{
  "type": "key.register",
  "protocol_version": 1,
  "request_id": "req_mno345",
  "config": "northwind-production",
  "public_key_pem": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n",
  "name": "Michaels-MacBook-Pro-2",
  "expires_in_days": 365
}
```

`name` is how the key is listed, by default the machine's name. `expires_in_days`
of 0 or absent means the remote's default, which may be no expiry.

### key.register Response

```json
{
  "ok": true,
  "type": "key.register.result",
  "request_id": "req_mno345",
  "created": true,
  "key": {
    "id": "key_123",
    "name": "Michaels-MacBook-Pro-2",
    "fingerprint": "9f14322ec5bab3f56c2d773a9ad06cc30cef404fc2bdeb5e5105a8e3daf68c6d",
    "algorithm": "ecdsa",
    "status": "usable",
    "registered_by": "dana@northwind.example",
    "created_at": "2026-10-01T18:00:00Z",
    "expires_at": "2027-10-01T18:00:00Z"
  }
}
```

`fingerprint` is the hex SHA-256 of the key's PKIX DER encoding, the identity
a signature made with the key carries. Registering a key the pipeline already
holds answers with that key and `created` false, so the command is safe to
repeat.

A remote may hold a new key as `pending` until a person approves it, and then
also returns `approval`: the `code` to type at `url` before `expires_at`, and
the `interval` in seconds between checks. `epack key create` shows the code,
opens the link, and checks `key.list` until the key is `usable`, the only
status a run signs with.

The `pipeline_url` field (optional) is the address of the pipeline's page on
the remote; `epack key create` and `epack key rotate` show it once the key is
`usable`, when it is an http or https URL.

### key.list Request

```json
{
  "type": "key.list",
  "protocol_version": 1,
  "request_id": "req_pqr678",
  "config": "northwind-production"
}
```

### key.list Response

```json
{
  "ok": true,
  "type": "key.list.result",
  "request_id": "req_pqr678",
  "keys": [
    {"id": "key_123", "name": "Michaels-MacBook-Pro-2", "fingerprint": "9f14...", "status": "usable", "expires_at": "2027-10-01T18:00:00Z"},
    {"id": "key_122", "name": "old laptop", "fingerprint": "0a0a...", "status": "revoked", "revoked_at": "2026-09-01T00:00:00Z"}
  ]
}
```

`status` is `pending`, `lapsed`, `usable`, `denied`, `expired`, `retired`, or
`revoked`, newest first. `machine` names the machine that registered the key, when the
remote records it.

### key.retire Request

```json
{
  "type": "key.retire",
  "protocol_version": 1,
  "request_id": "req_vwx234",
  "config": "northwind-production",
  "id": "key_122"
}
```

### key.retire Response

```json
{
  "ok": true,
  "type": "key.retire.result",
  "request_id": "req_vwx234",
  "key": {"id": "key_122", "fingerprint": "0a0a...", "status": "retired", "retired_at": "2026-10-01T18:05:00Z"}
}
```

A retired key signs nothing new, and the packs it signed before then stay
trusted. `epack key rotate` retires the old key once the new one is usable.
Retiring a key that is already retired or revoked leaves it as it is.

### key.revoke Request

```json
{
  "type": "key.revoke",
  "protocol_version": 1,
  "request_id": "req_stu901",
  "config": "northwind-production",
  "id": "key_122"
}
```

### key.revoke Response

```json
{
  "ok": true,
  "type": "key.revoke.result",
  "request_id": "req_stu901",
  "key": {"id": "key_122", "fingerprint": "0a0a...", "status": "revoked", "revoked_at": "2026-10-01T18:05:00Z"}
}
```

Revoking a key withdraws trust from every pack it signed, so it is for a key
that can no longer be trusted. To replace a key and keep what it signed
trusted, retire it instead.

## Error Handling

### Error Response

```json
{
  "ok": false,
  "type": "error",
  "request_id": "req_abc123",
  "error": {
    "code": "auth_required",
    "message": "Authentication required. Authenticate using the remote's supported flow (for example, epack push locktivity <pack.epack>).",
    "retryable": false,
    "action": {
      "type": "run_command",
      "command": "epack remote whoami locktivity"
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

Push and pull operations write receipt files for audit trail in the project-local state directory:

```
.epack/receipts/push/<remote>/<timestamp>_<digest>.json
.epack/receipts/pull/<remote>/<timestamp>_<digest>.json
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
- Browser sign-in returns to a listener on `127.0.0.1` only; epack hands the code to the adapter and never stores or logs it
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
epack push locktivity packs/evidence.epack

# Push with labels
epack push locktivity packs/evidence.epack --label monthly --label soc2

# Preview what would be pushed (dry-run)
epack push locktivity packs/evidence.epack --dry-run

# Push in background (returns immediately)
epack push locktivity packs/evidence.epack --detach

# Move the adapter you signed in with to its newest release; the pin in
# ~/.epack/remotes.lock never moves on its own
epack remote update locktivity

# Make a signing key for this machine and register it with the remote;
# once the remote accepts it, runs from this machine sign with it instead of
# the browser
epack key create
epack key list
epack key rotate

# Pull the latest pack from a remote
epack pull locktivity

# Pull a specific version
epack pull locktivity --version v1.2.3

# Pull by release ID
epack pull locktivity --release rel_abc123

# Pull by digest (immutable)
epack pull locktivity --digest sha256:abc123...

# Pull to specific output path
epack pull locktivity -o ./packs/evidence.epack

# Preview what would be pulled (dry-run)
epack pull locktivity --dry-run

# Pull in background (returns immediately)
epack pull locktivity --detach

# Report a resolved lockfile during setup bootstrap
epack remote report-lock locktivity --reason bootstrap

# Sign in to a remote from this machine (adapter installed from the catalog if needed)
epack remote login locktivity

# Fetch a configuration the remote generated into ./northwind-production
epack remote clone northwind-production

# Fetch, install, collect, run tools, sign, and push in one command
epack run northwind-production

# The same inside an existing project, for a CI job
epack run --yes
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

- **Remote management CLI**: `epack remote info`
  - Currently implemented: `epack remote list`, `epack remote login`, `epack remote clone`, `epack remote whoami`
- **List operations**: List releases on a remote
- **Delete operations**: Remove releases from a remote
- **Resume uploads/downloads**: Resume interrupted transfers
