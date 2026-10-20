# epack Component Normative Requirements

This document specifies normative requirements for implementing epack components using RFC 2119 terminology. These requirements apply to:

- **Collectors** - Evidence gathering plugins
- **Tools** - Pack processing plugins
- **Remote Adapters** - Registry communication plugins
- **Utilities** - Standalone helper applications

## Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119](https://datatracker.ietf.org/doc/html/rfc2119).

---

## 1. Common Requirements

These requirements apply to all component types.

### 1.1 Binary Naming

| ID | Level | Requirement |
|----|-------|-------------|
| C-001 | MUST | Binary name follow pattern `epack-{type}-{name}` where type is `collector`, `tool`, `remote`, or `util` |
| C-002 | MUST | Name segment match `^[a-z0-9][a-z0-9._-]{0,63}$` (lowercase alphanumeric, dash, underscore, dot; 1-64 chars) |
| C-003 | MUST NOT | Name contain path separators (`/` or `\`) or traversal sequences (`..`) |

### 1.2 Environment Contract

| ID | Level | Requirement |
|----|-------|-------------|
| C-010 | MUST | Component accept protocol variables via environment (see type-specific sections) |
| C-011 | MUST NOT | Component depend on environment variables other than explicitly allowed ones |
| C-012 | MUST NOT | Component use reserved prefixes (`EPACK_`, `LD_`, `DYLD_`, `_`) except those provided by epack |
| C-013 | SHOULD | Component honor `NO_COLOR` for terminal output |
| C-014 | SHOULD | Component respect proxy settings (`HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY`) |

### 1.3 Exit Codes

| ID | Level | Requirement |
|----|-------|-------------|
| C-020 | MUST | Exit code 0 indicate success |
| C-021 | MUST | Exit code 1 indicate general error |
| C-022 | SHOULD | Exit codes 2-9 be used for component-specific errors |
| C-023 | MUST NOT | Exit codes 10-19 be used (reserved for epack wrapper) |

### 1.4 Security

| ID | Level | Requirement |
|----|-------|-------------|
| C-030 | MUST NOT | Component write to locations outside designated output area |
| C-031 | MUST NOT | Component log credentials, tokens, or secrets |
| C-032 | SHOULD | Component redact sensitive values from error messages |
| C-033 | MUST | Component validate all input before use |

---

## 2. Collector Requirements

Collectors gather evidence from external systems and output structured JSON.

### 2.1 Capabilities

| ID | Level | Requirement |
|----|-------|-------------|
| COL-060 | MUST | Implement `--capabilities` flag returning JSON metadata |
| COL-061 | MUST | Implement `--version` flag returning version string |
| COL-062 | MUST | Capabilities include `kind`, `name`, `version`, `protocol_version` fields |
| COL-063 | SHOULD | Capabilities include `description` field |

**Capabilities format:**
```json
{
  "kind": "collector",
  "name": "example",
  "version": "1.0.0",
  "protocol_version": 1,
  "description": "Example collector"
}
```

### 2.2 Output Format

| ID | Level | Requirement |
|----|-------|-------------|
| COL-001 | MUST | Output valid JSON to stdout |
| COL-002 | SHOULD | Output use protocol envelope format with `protocol_version` and `data` fields |
| COL-003 | MAY | Output plain JSON without envelope (treated as protocol version 0) |
| COL-004 | MAY | Output plain text (quoted as JSON string, protocol version 0) |
| COL-005 | MUST NOT | Output size exceed 64 MB per collector |
| COL-006 | MUST | JSON be UTF-8 encoded |
| COL-070 | MAY | Emit file artifacts by staging files under `EPACK_COLLECTOR_OUTPUT_DIR` and referencing them with the per-artifact `file` field |
| COL-071 | MUST | File artifact paths be relative and stay within the staging directory (no traversal, no symlinks) |
| COL-072 | MUST | File artifacts carry an explicit `path` and no `data` field |
| COL-073 | MUST | Collectors requiring file artifacts exit with config error (exit 2) when `EPACK_COLLECTOR_OUTPUT_DIR` is not set |
| COL-074 | MAY | Emit a collector result artifact (`evidencepack/collector-result@v1`) recording each value left out and the API calls made |
| COL-075 | MUST | A collector result artifact match `evidencepack/collector-result@v1` |
| COL-076 | SHOULD | Request rows that carry call numbers agree: one call's attempts share its operation and step and number up in order, and only a retry waits |
| COL-077 | SHOULD | Run steps be named once each, listed in start order, end no earlier than they start, and count their calls consistently |
| COL-078 | SHOULD | A gap's operation be one the result counts, its call have rows when no failed row was dropped, and a missing permission sit only on a `permission_denied` gap |
| COL-079 | MUST | A build file (`evidencepack/collector-build@v1`) match its schema and name the collector result's version and commit |
| COL-080 | MUST | At the trust level, the collector result hold no request rows, gap warnings or error text, or principal ID |

**Protocol envelope format:**
```json
{
  "protocol_version": 1,
  "data": { /* collector-specific content */ }
}
```

### 2.3 Environment Variables

| ID | Level | Requirement |
|----|-------|-------------|
| COL-010 | MUST | Read collector name from `EPACK_COLLECTOR_NAME` |
| COL-011 | MUST | Read protocol version from `EPACK_PROTOCOL_VERSION` |
| COL-012 | SHOULD | Read config file path from `EPACK_COLLECTOR_CONFIG` if present |
| COL-013 | MAY | Read identity token from `EPACK_IDENTITY` if present |
| COL-014 | MAY | Read the file artifact staging directory from `EPACK_COLLECTOR_OUTPUT_DIR` if present |
| COL-015 | MAY | Read the run's ID from `EPACK_RUN_ID` if present |
| COL-016 | MAY | Read the time the runner will stop it from `EPACK_DEADLINE` if present, and stop collecting early enough to emit |

### 2.4 Configuration

| ID | Level | Requirement |
|----|-------|-------------|
| COL-020 | MUST | Parse config file as JSON when `EPACK_COLLECTOR_CONFIG` is set |
| COL-021 | MUST | Not crash or hang when config file is missing |
| COL-022 | SHOULD | Validate config schema and report clear errors for invalid config |
| COL-023 | MUST NOT | Read config from hardcoded paths or user home directory |
| COL-024 | SHOULD | Exit with config error (exit 2) if required configuration is missing |

### 2.5 Execution

| ID | Level | Requirement |
|----|-------|-------------|
| COL-030 | MUST | Complete within timeout (default: 60 seconds) |
| COL-031 | MUST | Handle SIGTERM gracefully (cleanup and exit) |
| COL-032 | SHOULD | Output progress to stderr for long-running operations |
| COL-033 | MUST NOT | Modify filesystem outside temp directories |
| COL-034 | MUST | Exit with code 0 only when collection succeeds. A collection that leaves out values it could not read, and records each one, succeeds |
| COL-035 | MUST NOT | Write a default, such as `0`, `false`, or an empty list, in place of a value it could not read |

### 2.6 Exit Codes

| ID | Level | Requirement |
|----|-------|-------------|
| COL-040 | MUST | Exit 0 on success |
| COL-041 | SHOULD | Exit 1 on general error |
| COL-042 | SHOULD | Exit 2 on configuration error |
| COL-043 | SHOULD | Exit 3 on authentication error |
| COL-044 | SHOULD | Exit 4 on network/API error |
| COL-045 | MAY | Print an `epack_progress` line of kind `failure`, with one of the collection codes, before exiting non-zero |

### 2.7 Network

| ID | Level | Requirement |
|----|-------|-------------|
| COL-050 | SHOULD | Document network requirements (domains, protocols) |
| COL-051 | SHOULD | Support proxy configuration via environment |
| COL-052 | MUST | Use HTTPS for external API calls |
| COL-053 | SHOULD | Implement timeout and retry logic for API calls |

---

## 3. Tool Requirements

Tools operate on signed evidence packs and produce derived outputs.

### 3.1 Capabilities

| ID | Level | Requirement |
|----|-------|-------------|
| TOOL-001 | MUST | Implement `--capabilities` flag returning JSON metadata |
| TOOL-002 | MUST | Implement `--version` flag returning version string |
| TOOL-003 | MUST | Capabilities include `kind`, `name`, `version`, `protocol_version` fields |
| TOOL-004 | SHOULD | Capabilities include `description` field |
| TOOL-005 | MAY | Capabilities include `network`, `requires_tools`, `requires_outputs` fields |

**Capabilities format:**
```json
{
  "kind": "tool",
  "name": "example",
  "version": "1.0.0",
  "protocol_version": 1,
  "description": "Example tool",
  "requires_pack": true,
  "network": false
}
```

### 3.2 Environment Variables

| ID | Level | Requirement |
|----|-------|-------------|
| TOOL-010 | MUST | Read run ID from `EPACK_RUN_ID` |
| TOOL-011 | MUST | Read run directory from `EPACK_RUN_DIR` |
| TOOL-012 | MUST | Read tool name from `EPACK_TOOL_NAME` |
| TOOL-013 | MUST | Read protocol version from `EPACK_PROTOCOL_VERSION` |
| TOOL-014 | SHOULD | Read pack path from `EPACK_PACK_PATH` when pack is provided |
| TOOL-015 | SHOULD | Read pack digest from `EPACK_PACK_DIGEST` when pack is provided |
| TOOL-016 | MAY | Read config file path from `EPACK_TOOL_CONFIG` if present |

### 3.3 Working Directory

| ID | Level | Requirement |
|----|-------|-------------|
| TOOL-020 | MUST | Write all outputs inside current working directory (run directory) |
| TOOL-021 | MUST NOT | Write outside the run directory |
| TOOL-022 | MUST NOT | Use `..` to traverse outside run directory |
| TOOL-023 | MUST NOT | Create symlinks pointing outside run directory |

### 3.4 result.json

| ID | Level | Requirement |
|----|-------|-------------|
| TOOL-030 | MUST | Write `result.json` to run directory root |
| TOOL-031 | MUST | Include `schema_version`, `tool.name`, `tool.version`, `run_id`, `status` in result.json |
| TOOL-032 | MUST | Set `status` to `success`, `failure`, or `partial` |
| TOOL-033 | SHOULD | Include `started_at`, `completed_at`, `duration_ms` timestamps |
| TOOL-034 | SHOULD | Include `outputs` array listing produced files |
| TOOL-035 | MAY | Include `inputs`, `warnings`, `errors` fields |
| TOOL-036 | MUST | Write result.json even on failure (may be incomplete) |

**result.json format:**
```json
{
  "schema_version": 1,
  "tool": {
    "name": "example",
    "version": "1.0.0",
    "protocol_version": 1
  },
  "run_id": "2026-02-19T14-30-00-123456Z-000000",
  "status": "success",
  "started_at": "2026-02-19T14:30:00Z",
  "completed_at": "2026-02-19T14:30:05Z",
  "duration_ms": 5000,
  "outputs": [
    {"path": "outputs/result.txt", "media_type": "text/plain"}
  ]
}
```

### 3.5 Output Paths

| ID | Level | Requirement |
|----|-------|-------------|
| TOOL-040 | MUST | Output paths in `outputs` array be relative to run directory |
| TOOL-041 | MUST NOT | Output paths contain `..` segments |
| TOOL-042 | MUST NOT | Output paths be absolute |
| TOOL-043 | SHOULD | Place output files in `outputs/` subdirectory |

### 3.6 Timestamps

| ID | Level | Requirement |
|----|-------|-------------|
| TOOL-050 | MUST | Format timestamps as `YYYY-MM-DDTHH:MM:SSZ` (exactly 20 characters, UTC) |
| TOOL-051 | MUST NOT | Include milliseconds or timezone offsets in timestamps |
| TOOL-052 | MUST | Run IDs sort chronologically when sorted lexicographically |

### 3.7 Pack Access

| ID | Level | Requirement |
|----|-------|-------------|
| TOOL-060 | MUST | Treat pack path as read-only |
| TOOL-061 | MUST NOT | Modify the input pack |
| TOOL-062 | MAY | Produce new packs as outputs (written to run directory) |

### 3.8 Flags

| ID | Level | Requirement |
|----|-------|-------------|
| TOOL-070 | SHOULD | Support `--json` flag for machine-readable output |
| TOOL-071 | SHOULD | Support `--quiet` flag to suppress progress output |

---

## 4. Remote Adapter Requirements

Remote adapters handle communication with registry backends.

### 4.1 Capabilities

| ID | Level | Requirement |
|----|-------|-------------|
| REM-001 | MUST | Implement `--capabilities` flag returning JSON metadata |
| REM-002 | MUST | Implement `--version` flag returning version string |
| REM-003 | MUST | Capabilities include `name`, `kind: "remote_adapter"`, `version`, `deploy_protocol_version` |
| REM-004 | MUST | Capabilities include `features` object |
| REM-005 | SHOULD | Capabilities include `auth` and `limits` objects |

**Capabilities format:**
```json
{
  "name": "example",
  "kind": "remote_adapter",
  "version": "1.0.0",
  "deploy_protocol_version": 1,
  "features": {
    "prepare_finalize": true,
    "pull": true
  }
}
```

### 4.2 Protocol

| ID | Level | Requirement |
|----|-------|-------------|
| REM-010 | MUST | Accept JSON requests on stdin |
| REM-011 | MUST | Write JSON responses to stdout |
| REM-012 | MAY | Write human-readable logs to stderr |
| REM-013 | MUST | Include `type` field in all responses |
| REM-014 | MUST | Include `ok` boolean in all responses |
| REM-015 | MUST | Echo `request_id` from request in response |

### 4.3 Commands

| ID | Level | Requirement |
|----|-------|-------------|
| REM-020 | MUST | Support `push.prepare` if `features.prepare_finalize` is true |
| REM-021 | MUST | Support `push.finalize` if `features.prepare_finalize` is true |
| REM-022 | SHOULD | Support `pull.prepare` if `features.pull` is true |
| REM-023 | SHOULD | Support `pull.finalize` if `features.pull` is true |
| REM-024 | MAY | Support `runs.sync` if `features.runs_sync` is true |
| REM-025 | MAY | Support `auth.login` if `features.auth_login` is true |
| REM-026 | MAY | Support `auth.whoami` if `features.whoami` is true |

### 4.4 push.prepare

| ID | Level | Requirement |
|----|-------|-------------|
| REM-030 | MUST | Accept `target`, `pack`, `release` in request |
| REM-031 | MUST | Return `upload` object with `method`, `url` on success |
| REM-032 | SHOULD | Return `upload.headers` for required upload headers |
| REM-033 | SHOULD | Return `upload.expires_at` timestamp |
| REM-034 | MUST | Return `finalize_token` for subsequent finalize call |

### 4.5 push.finalize

| ID | Level | Requirement |
|----|-------|-------------|
| REM-040 | MUST | Accept `finalize_token` from prepare response |
| REM-041 | MUST | Return `release` object with `release_id`, `pack_digest` on success |
| REM-042 | SHOULD | Return `links` object with URLs to created resources |

### 4.6 pull.prepare

| ID | Level | Requirement |
|----|-------|-------------|
| REM-050 | MUST | Accept `target` and `ref` (one of: `digest`, `release_id`, `version`, `latest`) |
| REM-051 | MUST | Return `download.url` on success |
| REM-052 | MUST | Return `pack.digest` for integrity verification |
| REM-053 | SHOULD | Return `pack.size_bytes` |
| REM-054 | MUST | Return `finalize_token` for subsequent finalize call |

### 4.7 pull.finalize

| ID | Level | Requirement |
|----|-------|-------------|
| REM-060 | MUST | Accept `finalize_token` and `digest` |
| REM-061 | MUST | Return `confirmed: true` on success |

### 4.8 Error Responses

| ID | Level | Requirement |
|----|-------|-------------|
| REM-070 | MUST | Set `ok: false` for error responses |
| REM-071 | MUST | Set `type: "error"` for error responses |
| REM-072 | MUST | Include `error.code` with machine-readable error code |
| REM-073 | MUST | Include `error.message` with human-readable description |
| REM-074 | SHOULD | Include `error.retryable` boolean |
| REM-075 | MAY | Include `error.action` with remediation hint |

**Standard error codes:**
- `unsupported_protocol` - Protocol version not supported
- `invalid_request` - Malformed request
- `auth_required` - Authentication needed
- `forbidden` - Permission denied
- `not_found` - Resource not found
- `conflict` - Resource conflict
- `rate_limited` - Rate limit exceeded
- `server_error` - Remote server error
- `network_error` - Network issue

### 4.9 Authentication

| ID | Level | Requirement |
|----|-------|-------------|
| REM-080 | MUST | Handle authentication internally (epack does not manage credentials) |
| REM-081 | SHOULD | Support at least one of: `browser` (the browser sign-in with a loopback redirect), `oidc_token`, `api_key` auth modes |
| REM-082 | MUST | Accept identity token via `identity` field in requests |
| REM-083 | SHOULD | Use OS keychain or secure storage for persistent credentials |
| REM-084 | MUST NOT | Log or expose credentials |

### 4.10 Lock Reporting

| ID | Level | Requirement |
|----|-------|-------------|
| REM-090 | MUST | Support `lock.report` if `features.lock_report` is true |

Adapters that advertise `lock_report` accept a lockfile provenance envelope without a pack push. See [remote-protocol.md](remote-protocol.md#lock-reporting) for the request and response shapes.

---

## 5. Utility Requirements

Utilities are standalone helper applications that complement the epack ecosystem. Utilities can be invoked via `epack utility <name>`, which provides TOCTOU-safe verification before execution. They are user-facing applications with lighter protocol requirements than collectors or tools.

### 5.1 Capabilities

| ID | Level | Requirement |
|----|-------|-------------|
| UTIL-001 | MUST | Implement `--version` flag returning version string |
| UTIL-002 | MUST | Implement `--capabilities` flag returning JSON metadata |
| UTIL-003 | MUST | Capabilities include `name`, `kind: "utility"`, `version`, `protocol_version` fields |
| UTIL-004 | SHOULD | Capabilities include `description` field |

**Capabilities format:**
```json
{
  "name": "viewer",
  "kind": "utility",
  "version": "1.0.0",
  "protocol_version": 1,
  "description": "Interactive pack viewer"
}
```

### 5.2 Help

| ID | Level | Requirement |
|----|-------|-------------|
| UTIL-010 | SHOULD | Implement `--help` flag with usage information |
| UTIL-011 | SHOULD | Help output includes synopsis, description, and examples |

### 5.3 Exit Codes

Utilities follow the common exit code requirements (C-020, C-021, C-022).

### 5.4 Environment

Utilities are not required to read protocol environment variables (C-010 does not apply). They operate as standalone applications.

---

## 6. Lockfile Integration

These requirements apply to components distributed via epack lockfile.

### 6.1 Binary Distribution

| ID | Level | Requirement |
|----|-------|-------------|
| LOCK-001 | MUST | Provide platform-specific binaries (at minimum: linux/amd64, darwin/arm64) |
| LOCK-002 | SHOULD | Provide binaries for linux/arm64, darwin/amd64, windows/amd64 |
| LOCK-003 | MUST | Binary names follow `{name}-{os}-{arch}` pattern for releases |
| LOCK-004 | MUST | Use consistent naming across versions |

### 6.2 Versioning

| ID | Level | Requirement |
|----|-------|-------------|
| LOCK-010 | MUST | Use semantic versioning (semver) |
| LOCK-011 | MUST | Tag releases with `v` prefix (e.g., `v1.0.0`) |
| LOCK-012 | MUST NOT | Remove or modify published releases |
| LOCK-013 | SHOULD | Maintain backwards compatibility within major version |

### 6.3 Sigstore Signing

| ID | Level | Requirement |
|----|-------|-------------|
| LOCK-020 | SHOULD | Sign releases with Sigstore |
| LOCK-021 | MUST | Use consistent signer identity across releases |
| LOCK-022 | SHOULD | Use GitHub Actions or other OIDC provider for keyless signing |
| LOCK-023 | MUST | Include Sigstore bundle with release if signed |

---

## 7. Conformance Levels

### 7.1 Minimal Conformance

A component is minimally conformant if it satisfies all MUST requirements for its type.

### 7.2 Standard Conformance

A component is standard conformant if it satisfies all MUST and SHOULD requirements for its type.

### 7.3 Full Conformance

A component is fully conformant if it satisfies all MUST, SHOULD, and MAY requirements for its type.

---

## 8. Conformance Testing

The `epack-conformance` tool validates component binaries against the requirements in this document. For component authors, the `epack sdk test` command provides a convenient wrapper.

### 8.1 Using epack sdk test (Recommended for Development)

If you have the full epack build with SDK commands:

```bash
# Test a component binary or directory (auto-detects type)
epack sdk test ./my-component
epack sdk test .                    # Test current directory
epack sdk test --verbose ./my-tool  # Verbose output
epack sdk test --config cfg.json .  # Collector config to collect with
epack sdk test --secret API_TOKEN . # Check how a collector handles its credential
```

When given a directory, `epack sdk test` builds the Go project first, then runs conformance tests on the resulting binary. It builds `cmd/<directory name>`, or the only package under `cmd/`, else the project root. For a collector project with `testdata/conformance.json`, that config is passed to the harness unless `--config` names another.

### 8.2 Building the Harness

For direct use of the conformance tool:

```bash
make build-conformance
```

This produces the `epack-conformance` binary in the project root.

### 8.3 Running Tests Directly

```bash
# Test a collector
./epack-conformance collector ./path/to/epack-collector-myname

# Test a tool
./epack-conformance tool ./path/to/epack-tool-myname

# Test a remote adapter
./epack-conformance remote ./path/to/epack-remote-myname

# Test a utility
./epack-conformance utility ./path/to/epack-util-myname
```

### 8.4 Output Formats

**Human-readable (default):**
```
Conformance Report: epack-collector-example (collector)
Level: full

Summary:
  MUST:   17 pass, 0 fail, 4 skip
  SHOULD: 3 pass, 0 fail, 7 skip
  MAY:    0 pass, 0 fail, 0 skip

Skipped (MUST/SHOULD):
  COL-043 [SHOULD] requires authentication failure scenario
  ...
```

**JSON output:**
```bash
./epack-conformance collector ./my-collector --json
```

### 8.5 Options

| Flag | Description |
|------|-------------|
| `--json` | Output results as JSON |
| `--level <level>` | Minimum required conformance level: `minimal`, `standard`, or `full` |
| `--timeout <duration>` | Test timeout (default: 30s) |
| `--config <file>` | Collector config the collector can collect with, passed as `EPACK_COLLECTOR_CONFIG` to the runs that check its output, signal handling, filesystem boundary, and `NO_COLOR` |
| `--secret <name>` | Variable the collector reads a credential from (repeatable). Every run sets it to a random canary value, overriding any real value in the environment |
| `-v, --verbose` | List every result, including passes |

### 8.6 Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Component meets required conformance level |
| 1 | Component does not meet required conformance level |
| 2 | Usage error or invalid arguments |

### 8.7 Test Fixtures

Minimal test fixtures for each component type are provided in `internal/componentconf/testdata/`:

```bash
# Build fixtures
cd internal/componentconf/testdata
go build -o epack-collector-minimal ./minimal-collector.go
go build -o epack-tool-minimal ./minimal-tool.go
go build -o epack-remote-minimal ./minimal-remote.go

# Run conformance tests
./epack-conformance collector ./internal/componentconf/testdata/epack-collector-minimal
./epack-conformance tool ./internal/componentconf/testdata/epack-tool-minimal
./epack-conformance remote ./internal/componentconf/testdata/epack-remote-minimal
```

### 8.8 CI Integration

A collector on GitHub Actions can call epack's shared collector workflow, which runs its tests with `-race`, golangci-lint, a build of each release target, conformance at the epack version in `go.mod`, and govulncheck:

```yaml
jobs:
  collector:
    uses: locktivity/epack/.github/workflows/collector-ci.yaml@<commit-sha>
    with:
      name: myname
      conformance-secrets: MYNAME_API_TOKEN
      checks: |
        ./scripts/check-forbidden-data.sh
```

Pin it to the commit of the epack release in `go.mod`. `checks` runs the repository's own checks after lint, one command per line. `main-package`, `targets`, `conformance-level`, and `golangci-lint-version` override the defaults.

The `trace-map` job runs `epack sdk map --check` at the epack version in `go.mod`, which rebuilds the trace map from the collectortest suites and the source and fails when the committed one differs, naming the command that rewrites it (see [Trace map](collect-protocol.md#trace-map)). The release workflow runs CI before the SLSA build, so a tag cannot ship a stale map. `trace-map` names the committed map, `docs/schema/trace-map.json` by default. A collector without one passes the job.

To add conformance to another pipeline, run the same steps yourself:

```yaml
# GitHub Actions example
jobs:
  conformance:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-go@v5
        with:
          go-version-file: go.mod

      - name: Build component
        run: go build -o epack-collector-myname ./cmd/epack-collector-myname

      - name: Install epack-conformance
        run: |
          # The harness at the epack version go.mod pins, so CI and local runs agree
          EPACK_VERSION="$(go list -m -f '{{.Version}}' github.com/locktivity/epack)"
          go install -tags conformance github.com/locktivity/epack/cmd/epack-conformance@"${EPACK_VERSION}"

      - name: Run conformance tests
        run: |
          set -- --level standard --secret MYNAME_API_TOKEN
          if [ -f testdata/conformance.json ]; then set -- "$@" --config testdata/conformance.json; fi
          epack-conformance collector ./epack-collector-myname "$@"
```

A collector made with `epack sdk new collector` runs the same thing with `make conformance`, which takes the secret names from `CONFORMANCE_SECRETS` in its Makefile. `testdata/conformance.json` is a config with no secrets in it. A collector that can collect without credentials collects with it, so the output, signal, and timeout checks run against a real collection. One that needs credentials reaches its API with the `--secret` canaries instead, which checks how it handles a rejected credential.

**Note**: In CI, `actions/setup-go` adds `~/go/bin` to PATH automatically. For local development, either add `$(go env GOPATH)/bin` to your PATH or use the full path:

```bash
# Option 1: Add to PATH (add to ~/.zshrc or ~/.bashrc for persistence)
export PATH="$PATH:$(go env GOPATH)/bin"

# Option 2: Use full path
$(go env GOPATH)/bin/epack-conformance collector ./my-collector --level standard
```

#### Evidence diff

On pull requests, the `evidence-diff` job runs the repository's tests with `COLLECTORTEST_OUT` set (see [Testing](collect-protocol.md#testing)) at the pull request and at the newest release tag on the base branch. It then compares the two trees with `epack-collector-diff` at the epack version in `go.mod` and writes the result to the job summary: for each scenario, the artifacts added or removed and each JSON value that changed, such as a metric that became null. The job skips with a summary line saying why when the base branch has no release tag or the release has no collectortest suite.

- `profile-url` names a profile to validate both sides against with `epack-tool-validate` at `validate-version`. The summary then also lists each requirement whose status or severity changed. Without it, the job compares evidence only.
- `require-changelog: true` fails the job when the diff lists changes and the pull request changes neither `CHANGELOG.md` nor the file named by `changelog-file`.
- `comment: true` posts the summary as a pull request comment and updates that comment on later runs. The calling job must grant `pull-requests: write`. Pull requests from forks get no comment.

```yaml
jobs:
  collector:
    uses: locktivity/epack/.github/workflows/collector-ci.yaml@<commit-sha>
    permissions:
      contents: read
      pull-requests: write
    with:
      name: myname
      profile-url: https://example.com/profiles/baseline.yaml
      require-changelog: true
      comment: true
```

To run the same comparison locally against release `v1.2.3`:

```bash
COLLECTORTEST_OUT=/tmp/evidence/head go test -count=1 ./...
git worktree add /tmp/release v1.2.3
(cd /tmp/release && COLLECTORTEST_OUT=/tmp/evidence/base go test -count=1 ./...)
go run github.com/locktivity/epack/cmd/epack-collector-diff@<epack-version> \
  --base /tmp/evidence/base --head /tmp/evidence/head
```

`-count=1` keeps Go from reusing cached test results, which would write no scenarios. `epack-collector-diff` prints Markdown unless `--markdown` names a file, writes every change as JSON with `--json`, caps the table at `--max-rows` rows (default 50), and takes `--profile` with `--validate` for control outcomes. It exits 0 whether or not anything changed and 2 for bad input.

### 8.9 Skipped Tests

Some tests are skipped by default because they require specific conditions:

| Condition | Affected Tests |
|-----------|----------------|
| No network mock available | COL-052, COL-044 |
| No pack fixture provided | TOOL-060, TOOL-061 |
| Collector: no `--secret` given | C-031, C-032, COL-043 |
| Collector: `--secret` without `--config`, so it never uses the credential | C-032, COL-043 |
| Requires malformed input injection | C-033 |
| Feature not supported | REM-020 to REM-061 (based on capabilities) |
| Collector exits 2 (needs config), 3 (needs credentials), or 4 (cannot reach its API) on the run that should collect | C-010, C-020, COL-001, COL-002, COL-005, COL-006, COL-010, COL-011, COL-034, COL-040, COL-075 to COL-080 |
| Collector writes no collector result, as one built without the SDK does | COL-075 to COL-080 |
| Collector result without call numbers on its rows, steps, gap calls, or a build file, as from an older SDK | COL-076, COL-077, COL-078, COL-079 |
| The run that should collect asks for the audit or internal level | COL-080 |
| Collector exits before SIGTERM is sent | COL-031 |
| No general-error scenario | COL-041 |

Every collector run gets its own `EPACK_COLLECTOR_OUTPUT_DIR`, as under `epack collect`. With `--secret`, C-031 fails when a canary value appears in anything a run wrote: its stdout, with the data artifacts and progress lines, its stderr, its staged file artifacts, and any other file it left in its working directory. C-032 fails when one appears in an error message: a failed run's stderr, or the warnings of a run that exited 0. The run that should collect (with `--config`, when the collector needs config) holds canary credentials, which a real API rejects. COL-043 passes when the collector exits 3, and fails when it exits with another code and its error or output says the credentials were rejected (status 401 or 403, "unauthorized", "invalid token", and similar). A collector that exits 0 and emits evidence after the rejection also fails COL-034: every metric the credential gates would read as zero. An error that says nothing about the credentials, such as a DNS failure, skips COL-043.

The canaries go to every run, so a collector that needs no config reaches its API in COL-020's run with a test config and COL-021's run without one; both accept exit 3 or 4 there, as well as 0 to 2.

Name variables that hold a credential, not a path to one: a canary path printed in a "file not found" error would fail C-031. A credential that must parse before it is used, such as a JSON key, fails parsing with a canary value; the collector exits 2 and COL-043 skips.

COL-031 sends SIGTERM at the collector's first `epack_progress` line, when it is mid-collection, or 5 seconds after start for a collector that reports no progress. It fails when SIGTERM kills the collector, which means it installed no handler, and when the collector is still running 5 seconds after the signal. COL-030 fails when any run is stopped at `--timeout`.

To achieve full conformance, components must pass all testable requirements. Skipped tests do not count as failures.

---

## Appendix A: Requirement Summary by Component Type

### Collectors

| Level | Count | IDs |
|-------|-------|-----|
| MUST | 33 | C-001, C-002, C-003, C-010, C-020, C-021, C-030, C-031, C-033, COL-001, COL-005, COL-006, COL-010, COL-011, COL-020, COL-021, COL-023, COL-030, COL-031, COL-033, COL-034, COL-035, COL-040, COL-052, COL-060, COL-061, COL-062, COL-071, COL-072, COL-073, COL-075, COL-079, COL-080 |
| SHOULD | 20 | C-013, C-014, C-022, C-032, COL-002, COL-012, COL-022, COL-024, COL-032, COL-041, COL-042, COL-043, COL-044, COL-050, COL-051, COL-053, COL-063, COL-076, COL-077, COL-078 |
| MAY | 9 | COL-003, COL-004, COL-013, COL-014, COL-015, COL-016, COL-045, COL-070, COL-074 |

### Tools

| Level | Count | IDs |
|-------|-------|-----|
| MUST | 27 | C-001, C-002, C-003, C-010, C-020, C-021, C-030, C-031, C-033, TOOL-001, TOOL-002, TOOL-003, TOOL-010, TOOL-011, TOOL-012, TOOL-013, TOOL-020, TOOL-021, TOOL-022, TOOL-023, TOOL-030, TOOL-031, TOOL-032, TOOL-036, TOOL-040, TOOL-041, TOOL-042, TOOL-050, TOOL-051, TOOL-052, TOOL-060, TOOL-061 |
| SHOULD | 10 | C-013, C-014, C-022, C-032, TOOL-004, TOOL-014, TOOL-015, TOOL-033, TOOL-034, TOOL-043, TOOL-070, TOOL-071 |
| MAY | 4 | TOOL-005, TOOL-016, TOOL-035, TOOL-062 |

### Remote Adapters

| Level | Count | IDs |
|-------|-------|-----|
| MUST | 32 | C-001, C-002, C-003, C-010, C-020, C-021, C-030, C-031, C-033, REM-001, REM-002, REM-003, REM-004, REM-010, REM-011, REM-013, REM-014, REM-015, REM-020, REM-021, REM-030, REM-031, REM-034, REM-040, REM-041, REM-050, REM-051, REM-052, REM-054, REM-060, REM-061, REM-070, REM-071, REM-072, REM-073, REM-080, REM-082, REM-084, REM-090 |
| SHOULD | 11 | C-013, C-014, C-022, C-032, REM-005, REM-022, REM-023, REM-032, REM-033, REM-042, REM-053, REM-074, REM-081, REM-083 |
| MAY | 5 | REM-012, REM-024, REM-025, REM-026, REM-075 |

### Utilities

| Level | Count | IDs |
|-------|-------|-----|
| MUST | 8 | C-001, C-002, C-003, C-020, C-021, UTIL-001, UTIL-002, UTIL-003 |
| SHOULD | 4 | C-013, C-022, UTIL-004, UTIL-010, UTIL-011 |
| MAY | 0 | - |

---

## Appendix B: Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2026-02-22 | Initial release |
