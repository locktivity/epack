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

### 2.1 Output Format

| ID | Level | Requirement |
|----|-------|-------------|
| COL-001 | MUST | Output valid JSON to stdout |
| COL-002 | SHOULD | Output use protocol envelope format with `protocol_version` and `data` fields |
| COL-003 | MAY | Output plain JSON without envelope (treated as protocol version 0) |
| COL-004 | MAY | Output plain text (quoted as JSON string, protocol version 0) |
| COL-005 | MUST NOT | Output size exceed 64 MB per collector |
| COL-006 | MUST | JSON be UTF-8 encoded |

**Protocol envelope format:**
```json
{
  "protocol_version": 1,
  "data": { /* collector-specific content */ }
}
```

### 2.2 Environment Variables

| ID | Level | Requirement |
|----|-------|-------------|
| COL-010 | MUST | Read collector name from `EPACK_COLLECTOR_NAME` |
| COL-011 | MUST | Read protocol version from `EPACK_PROTOCOL_VERSION` |
| COL-012 | SHOULD | Read config file path from `EPACK_COLLECTOR_CONFIG` if present |
| COL-013 | MAY | Read identity token from `EPACK_IDENTITY` if present |

### 2.3 Configuration

| ID | Level | Requirement |
|----|-------|-------------|
| COL-020 | MUST | Parse config file as JSON when `EPACK_COLLECTOR_CONFIG` is set |
| COL-021 | MUST | Handle missing config file gracefully (use defaults) |
| COL-022 | SHOULD | Validate config schema and report clear errors for invalid config |
| COL-023 | MUST NOT | Read config from hardcoded paths or user home directory |

### 2.4 Execution

| ID | Level | Requirement |
|----|-------|-------------|
| COL-030 | MUST | Complete within timeout (default: 60 seconds) |
| COL-031 | MUST | Handle SIGTERM gracefully (cleanup and exit) |
| COL-032 | SHOULD | Output progress to stderr for long-running operations |
| COL-033 | MUST NOT | Modify filesystem outside temp directories |
| COL-034 | MUST | Exit with code 0 only when collection succeeds |

### 2.5 Exit Codes

| ID | Level | Requirement |
|----|-------|-------------|
| COL-040 | MUST | Exit 0 on success |
| COL-041 | SHOULD | Exit 1 on general error |
| COL-042 | SHOULD | Exit 2 on configuration error |
| COL-043 | SHOULD | Exit 3 on authentication error |
| COL-044 | SHOULD | Exit 4 on network/API error |

### 2.6 Network

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
| TOOL-002 | MUST | Set `EPACK_MODE=capabilities` environment when invoked with `--capabilities` |
| TOOL-003 | MUST | Capabilities include `name`, `version`, `protocol_version` fields |
| TOOL-004 | SHOULD | Capabilities include `description` field |
| TOOL-005 | MAY | Capabilities include `network`, `requires_tools`, `requires_outputs` fields |

**Capabilities format:**
```json
{
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
| REM-002 | MUST | Capabilities include `name`, `kind: "remote_adapter"`, `deploy_protocol_version` |
| REM-003 | MUST | Capabilities include `features` object |
| REM-004 | SHOULD | Capabilities include `auth` and `limits` objects |

**Capabilities format:**
```json
{
  "name": "example",
  "kind": "remote_adapter",
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
| REM-060 | MUST | Accept `finalize_token` and `pack_digest` |
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
| REM-081 | SHOULD | Support at least one of: `device_code`, `oidc_token`, `api_key` auth modes |
| REM-082 | MUST | Accept identity token via `identity` field in requests |
| REM-083 | SHOULD | Use OS keychain or secure storage for persistent credentials |
| REM-084 | MUST NOT | Log or expose credentials |

---

## 5. Utility Requirements

Utilities are standalone helper applications that complement the epack ecosystem. Utilities can be invoked via `epack utility <name>`, which provides TOCTOU-safe verification before execution. They are user-facing applications with lighter protocol requirements than collectors or tools.

### 5.1 Capabilities

| ID | Level | Requirement |
|----|-------|-------------|
| UTIL-001 | MUST | Implement `--version` flag returning version string |
| UTIL-002 | MUST | Implement `--capabilities` flag returning JSON metadata |
| UTIL-003 | MUST | Capabilities include `name`, `kind: "utility"`, `version` fields |
| UTIL-004 | SHOULD | Capabilities include `description` field |

**Capabilities format:**
```json
{
  "name": "viewer",
  "kind": "utility",
  "version": "1.0.0",
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
```

When given a directory, `epack sdk test` builds the Go project first, then runs conformance tests on the resulting binary.

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
| `-v, --verbose` | Enable verbose output |

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

Add conformance testing to your CI pipeline:

```yaml
# GitHub Actions example
jobs:
  conformance:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Build component
        run: go build -o epack-collector-myname ./cmd/collector

      - name: Download epack-conformance
        run: |
          # Download from releases or build from source
          go install -tags conformance github.com/locktivity/epack/cmd/epack-conformance@latest

      - name: Run conformance tests
        run: epack-conformance collector ./epack-collector-myname --level standard
```

**Note**: In CI, `actions/setup-go` adds `~/go/bin` to PATH automatically. For local development, either add `$(go env GOPATH)/bin` to your PATH or use the full path:

```bash
# Option 1: Add to PATH (add to ~/.zshrc or ~/.bashrc for persistence)
export PATH="$PATH:$(go env GOPATH)/bin"

# Option 2: Use full path
$(go env GOPATH)/bin/epack-conformance collector ./my-collector --level standard
```

### 8.9 Skipped Tests

Some tests are skipped by default because they require specific conditions:

| Condition | Affected Tests |
|-----------|----------------|
| No network mock available | COL-052, COL-043, COL-044 |
| No pack fixture provided | TOOL-060, TOOL-061 |
| Requires log inspection | C-031, C-032, C-033 |
| Feature not supported | REM-020 to REM-061 (based on capabilities) |

To achieve full conformance, components must pass all testable requirements. Skipped tests do not count as failures.

---

## Appendix A: Requirement Summary by Component Type

### Collectors

| Level | Count | IDs |
|-------|-------|-----|
| MUST | 17 | C-001 to C-003, C-010, C-020, C-021, C-030 to C-034, COL-001, COL-005, COL-006, COL-010, COL-011, COL-020, COL-021, COL-030, COL-034, COL-052 |
| SHOULD | 13 | C-013, C-014, C-022, C-032, COL-002, COL-022, COL-032, COL-041 to COL-044, COL-050, COL-051, COL-053 |
| MAY | 4 | COL-003, COL-004, COL-013 |

### Tools

| Level | Count | IDs |
|-------|-------|-----|
| MUST | 26 | C-001 to C-003, C-010, C-020, C-021, C-030 to C-034, TOOL-001 to TOOL-003, TOOL-010 to TOOL-013, TOOL-020 to TOOL-023, TOOL-030 to TOOL-032, TOOL-036, TOOL-040 to TOOL-042, TOOL-050 to TOOL-052, TOOL-060, TOOL-061 |
| SHOULD | 12 | C-013, C-014, C-022, C-032, TOOL-004, TOOL-014, TOOL-015, TOOL-033, TOOL-034, TOOL-043, TOOL-070, TOOL-071 |
| MAY | 4 | TOOL-005, TOOL-016, TOOL-035, TOOL-062 |

### Remote Adapters

| Level | Count | IDs |
|-------|-------|-----|
| MUST | 30 | C-001 to C-003, C-010, C-020, C-021, C-030 to C-034, REM-001 to REM-003, REM-010 to REM-015, REM-020, REM-021, REM-030, REM-031, REM-034, REM-040, REM-041, REM-050 to REM-052, REM-054, REM-060, REM-061, REM-070 to REM-073, REM-080, REM-082, REM-084 |
| SHOULD | 12 | C-013, C-014, C-022, C-032, REM-004, REM-022, REM-023, REM-032, REM-033, REM-042, REM-053, REM-074, REM-081, REM-083 |
| MAY | 5 | REM-012, REM-024 to REM-026, REM-075 |

### Utilities

| Level | Count | IDs |
|-------|-------|-----|
| MUST | 5 | C-001 to C-003, C-020, C-021, UTIL-001 to UTIL-003 |
| SHOULD | 4 | C-013, C-022, UTIL-004, UTIL-010, UTIL-011 |
| MAY | 0 | - |

---

## Appendix B: Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2026-02-22 | Initial release |
