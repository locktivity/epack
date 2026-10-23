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

  aws:
    source: locktivity/epack-collector-aws@^0.4
    secrets:
      - name: AWS_PROFILE
        optional: true
```

### Configuration Fields

| Field | Required | Description |
|-------|----------|-------------|
| `source` | One of source/binary | Source repository with version constraint |
| `binary` | One of source/binary | Absolute path to external binary |
| `config` | No | Collector-specific configuration (passed as JSON) |
| `secrets` | No | Environment variables to pass through. A bare name is required; `{name: AWS_PROFILE, optional: true}` is passed through only when set |

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
| `EPACK_COLLECTOR_OUTPUT_DIR` | Staging directory for file artifacts (see File Artifacts) |
| `EPACK_IDENTITY` | Identity token or identifier (if set, passed through for CI contexts) |
| `EPACK_RUN_ID` | ID of the run, the same for every collector in it. SDK collectors send it in the `User-Agent` of their API calls and record it in the collector result, so a vendor's request logs can be matched to a run |
| `EPACK_DEADLINE` | When the runner will stop the collector, in RFC 3339 format and UTC. SDK collectors stop collecting a tenth of the remaining time before it, at most 10 seconds, so they can still emit what they have |

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

## Collection Levels

Collectors that support graduated collection (gathering more or less detail depending on the caller's intent) read a reserved top-level config key named `level`.

```yaml
collectors:
  aws:
    source: locktivity/epack-collector-aws@^1
    config:
      level: audit
      auth_mode: oidc
      role_arn: arn:aws:iam::123:role/epack
```

### Vocabulary

The `level` value is one of three strings:

| Level | Meaning |
|-------|---------|
| `trust` | Pass/fail posture only. The minimum a collector needs to answer "do they pass?" |
| `audit` | Adds per-resource breakdowns, policy details, and alert counts. Enough for an auditor to answer "where is the gap?" |
| `internal` | Adds raw inventory (user lists, group rosters, audit-log slices). Enough for an investigator to answer "who or what specifically?" |

Levels are **cumulative**: `audit` is a strict superset of `trust`, and `internal` is a strict superset of `audit`. No level removes a field that a lower level included.

### Defaults and safety

- `level` is **optional**. When absent, empty, or not a string, the collector treats the value as `trust`.
- **Unknown values downgrade to `trust`** and emit a one-line warning to stderr. A typo or future-level value must never silently promote collection to data the caller didn't ask to gather. Collectors must never fail open.

### Artifact convention

Collectors that honor `level` should record the level they ran at on their top-level output as `collected_at_level: "<level>"`. Downstream tools rely on this to interpret missing fields: a profile evaluator needs to know whether the absence of `iam_users` means "no IAM users exist" or "this pack was collected at trust level."

### SDK helpers

Collectors built on `componentsdk` read the level with the typed helper:

```go
level := ctx.Level()
if level.AtLeast(componentsdk.LevelAudit) {
    // gate audit-only field collection
}
if level.AtLeast(componentsdk.LevelInternal) {
    // gate internal-only field collection
}
```

`componentsdk.Level` is a string type with constants `LevelTrust`, `LevelAudit`, and `LevelInternal`. `Level.AtLeast(other)` implements the ordinal `trust < audit < internal` comparison. The SDK's `ctx.Level()` reader applies the default-and-downgrade rules above so individual collectors do not reimplement them.

## Output Convention

### Output Format

Collectors write JSON lines to stdout. The protocol supports two message types:

**Progress messages** (optional, 0 or more during execution):

```json
{"type":"epack_progress","protocol_version":1,"kind":"status","message":"Connecting to API..."}
{"type":"epack_progress","protocol_version":1,"kind":"progress","current":5,"total":100,"message":"Fetching repos"}
{"type":"epack_progress","protocol_version":1,"kind":"failure","code":"auth_failed","owner":"customer","vendor_code":"invalid_client","message":"signing in: token request returned 401"}
```

Progress message fields:
- `type`: Always `"epack_progress"`
- `protocol_version`: Progress protocol version (currently 1)
- `kind`: `"status"` (indeterminate), `"progress"` (determinate with current/total), or `"failure"` (why the collector is about to exit non-zero)
- `message`: Human-readable status message
- `current`, `total`: Progress counters (only for `kind: "progress"`)
- `code`, `owner`, `vendor_code`: The failure's code (see Codes), whose move it is, and the vendor's own error code when there is one (only for `kind: "failure"`)

Runners skip progress kinds they do not know, so a collector can print a failure line to any runner. SDK collectors print one before every non-zero exit, with the message redacted.

**Result message** (exactly 1, at end of execution):

```json
{"type":"epack_result","protocol_version":1,"artifacts":[{"data":{...},"schema":"evidencepack/posture@v1","path":"artifacts/posture.json"}]}
```

Result message fields:
- `type`: Always `"epack_result"`
- `protocol_version`: Protocol version (currently 1)
- `artifacts`: Array of collected artifacts

Each artifact in the array has:
- `data`: The collected evidence data (required unless `file` is set)
- `schema`: Schema identifier for typed artifacts (optional, e.g., `"evidencepack/cloud-posture@v1"`)
- `path`: Output path in the pack (optional for `data` artifacts, defaults to `"artifacts/{collector}.json"`; required for `file` artifacts)
- `file`: Path relative to `EPACK_COLLECTOR_OUTPUT_DIR` whose raw bytes become the artifact content (mutually exclusive with `data`; see File Artifacts)
- `display_name`: Human-readable name shown by `epack inspect` and `epack list` (optional)
- `description`: One-line description of the artifact (optional)
- `controls`: Array of control IDs this artifact supports (optional)

**Multi-artifact example:**

A collector can emit multiple artifacts with different schemas:

```json
{
  "type": "epack_result",
  "protocol_version": 1,
  "artifacts": [
    {
      "data": {"repos": [...], "teams": [...]},
      "path": "artifacts/github.json"
    },
    {
      "data": {"provider": "github", "controls": [...]},
      "schema": "evidencepack/vcs-posture@v1",
      "path": "artifacts/github.vcs-posture.json"
    }
  ]
}
```

**File artifacts:**

Use a `file` artifact when the artifact content should be stored as raw bytes
in the pack, such as PDFs, images, or archives. During collector execution,
epack sets `EPACK_COLLECTOR_OUTPUT_DIR` to a per-collector staging directory.
Write the file beneath that directory and emit its relative path in `file`:

```json
{
  "type": "epack_result",
  "protocol_version": 1,
  "artifacts": [
    {
      "data": {"documents": [{"name": "Security policy"}]},
      "path": "artifacts/documents.json"
    },
    {
      "file": "documents/security-policy.pdf",
      "path": "artifacts/documents/security-policy.pdf"
    }
  ]
}
```

Rules:
- `file` is a relative path and must stay within the staging directory; absolute paths and traversal are rejected.
- A file artifact writes raw bytes to the pack at `path`; `path` is required and `file` is mutually exclusive with `data`.
- The staged entry must be a regular file. Symlinks are rejected. On Unix (Linux, macOS), epack opens the staging root and every path component with `O_NOFOLLOW` under descriptor-pinned traversal. On Windows, containment uses a lexical check plus symlink walk and is **best effort, not atomic** against a concurrent swap (see `internal/safefile`); collectors are not currently distributed for Windows.
- Each staged file is subject to the per-artifact size limit (100 MB). Staged bytes count toward the pack's total-size and artifact-count budget as artifacts are added. They do not count against the per-collector stdout output limit.
- The staging directory has owner-only permissions and is removed after the pack is built.

Collectors that require file artifacts must return a configuration error (exit
2) when `EPACK_COLLECTOR_OUTPUT_DIR` is unset. Without that directory, the
runner cannot resolve emitted `file` entries.

SDK collectors obtain staging helpers with `componentsdk.Staging(ctx)`. Treat a
false result, or an empty `OutputDir()`, as "this epack does not support file
artifacts":

```go
staging, ok := componentsdk.Staging(ctx)
if !ok || staging.OutputDir() == "" {
    return componentsdk.NewConfigError("file artifacts require a newer epack; upgrade epack")
}

name, err := staging.WriteStagedFile("documents/policy.pdf", data)
if err != nil {
    return err
}

return ctx.Emit([]componentsdk.CollectedArtifact{
    componentsdk.FileArtifact("artifacts/documents/policy.pdf", name,
        componentsdk.ArtifactMeta{DisplayName: "Security policy"}),
})
```

For streaming writes, use `StageFile` and emit the returned name after closing
the file.

**Legacy format (backwards compatible):**

Collectors using the older `data` field are still supported:

```json
{
  "protocol_version": 1,
  "data": {
    "collected_at": "2026-02-19T14:30:00Z",
    "items": [...]
  }
}
```

The parser detects legacy format (has `data` instead of `artifacts`) and converts it to a single artifact.

**Plain JSON:**

Any valid JSON object or array without the envelope. The protocol version is inferred as 0.

**Output that is not evidence:**

A collector that exits 0 must print a result. epack fails the collector, with the code `invalid_output`, when its stdout (after progress messages) is empty, is JSON `null`, is not JSON, or is an envelope whose `artifacts` array is empty or `null`.

### Output Parsing

The parser handles output as follows:

1. **Protocol envelope with `artifacts`**: Extracts each artifact's data, schema, and path; an empty `artifacts` array is an error
2. **Protocol envelope with `data` (legacy)**: Converts to single artifact, preserving exact bytes (prevents float64 precision loss for large integers)
3. **Plain JSON**: Preserves as-is as single artifact with `protocol_version = 0`
4. **Anything else** (empty, `null`, or non-JSON): Fails the collector with `invalid_output`

### Artifact Storage

Collector artifacts are stored in the evidence pack at paths specified by each artifact:

```
artifacts/{path_from_artifact}
```

**Path resolution:**
- If artifact specifies `path`, use it directly
- If no path, default to `artifacts/{collector}.json` for the first artifact
- For additional artifacts without paths, use `artifacts/{collector}_{index}.json`

**Example:** A GitHub collector emitting two artifacts:

```
artifacts/github.json              # Detailed GitHub-specific output
artifacts/github.vcs-posture.json  # Normalized VCS posture format
```

Schema information (if provided) is recorded in the pack manifest for downstream tools.

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

## Partial Collection

A collector that signed in collects what it can. When it cannot read a value, it leaves the value out of the artifact, as an absent field or `null`, and records a gap for it. It never writes a default such as `0`, `false`, or an empty list in place of a value it could not read, because a reader cannot tell that default from a real answer. A rollup over items it read only in part, such as a percentage across users when one page of users failed, is left out the same way, with a `partial` gap that counts the items left unmeasured. The list itself may stay, holding the items that were read, with a `partial` gap of its own.

A list that was read and found empty is `[]` where the schema allows it. A list that is absent with no gap means there are none, unless the schema places it above the level the collector ran at (see Collection Levels). A collector's own artifacts write a percentage over an empty population as `null`, with the count of 0 that its `x-epack-denominator` names (see Output Checks). In a normalized artifact such a percentage is absent. When a normalized schema lists the count behind a percentage, the collector writes the count, 0 for an empty population.

A collection with gaps succeeds: the collector emits its artifacts and exits 0. A failure fails the run only when nothing collected would be worth emitting, such as invalid configuration or a rejected sign-in.

### Codes

Every gap and every failure carries one of nine codes. The owner says whose move it is. The exit code is the one a collector exits with when that code fails the run.

| Code | Owner | Exit | Meaning |
|------|-------|------|---------|
| `auth_failed` | `customer` | `3` | The credential was rejected |
| `permission_denied` | `customer` | `3` | The credential works but lacks a permission or role |
| `config_invalid` | `customer` | `2` | The configuration is missing or invalid |
| `not_licensed` | `nobody` | `1` | The account's plan does not include the feature |
| `rate_limited` | `vendor` | `4` | The vendor throttled the collector and retries ran out |
| `vendor_error` | `vendor` | `4` | The vendor failed: a 5xx status, a reset connection, or a DNS failure |
| `timeout` | `vendor_or_runner` | `4` | A call, or the collection as a whole, ran out of time |
| `invalid_response` | `publisher` | `1` | The response was not what the collector expects: an unexpected status, malformed or truncated JSON, or a missing field |
| `internal` | `publisher` | `1` | A bug in the collector |

### Collector Result

SDK collectors add one artifact when they emit, at `artifacts/{collector}.collector-result.json` with schema `evidencepack/collector-result@v1`. It records what the collector left out and how it called its APIs, so a reader can tell a value that could not be read from a value that does not exist.

```json
{
  "collector": {"name": "example", "version": "1.2.0"},
  "outcome": {"status": "partial", "code": "permission_denied", "owner": "customer"},
  "gaps": [
    {
      "path": "artifacts/example.json",
      "pointer": "/system_log",
      "status": "not_collected",
      "code": "permission_denied",
      "owner": "customer",
      "vendor_code": "E0000006",
      "operation": "logs.list",
      "call": 3,
      "source": "internal/collector/system_log.go:155",
      "missing_permission": "logs.read",
      "warning": "system log: access denied; grant logs.read"
    }
  ],
  "steps": [
    {"name": "people", "title": "People and sign-in methods", "start_ms": 300, "end_ms": 2100,
     "requests": 3, "calls": 2, "retries": 1, "failed": 1, "operations": [{"name": "users.list", "calls": 2}]},
    {"name": "system_log", "title": "Activity log", "start_ms": 2100, "end_ms": 2200,
     "requests": 1, "calls": 1, "retries": 0, "failed": 1, "operations": [{"name": "logs.list", "calls": 1}]}
  ],
  "calls": {
    "operations": [
      {"name": "logs.list", "calls": 1, "attempts": 1, "retries": 0, "statuses": {"403": 1}},
      {"name": "users.list", "calls": 2, "attempts": 3, "retries": 1, "statuses": {"200": 2, "429": 1}}
    ],
    "requests": [
      {"call": 1, "operation": "users.list", "step": "people", "method": "GET", "host": "api.example.com", "route": "/users",
       "attempt": 1, "start_ms": 300, "status": 429, "vendor_code": "E0000047", "duration_ms": 61},
      {"call": 1, "operation": "users.list", "step": "people", "method": "GET", "host": "api.example.com", "route": "/users",
       "attempt": 2, "start_ms": 1361, "waited_ms": 1000, "status": 200, "duration_ms": 58, "request_id": "Zx9mT5"}
    ],
    "problem_requests_dropped": 0
  },
  "signed_in_as": {"provider": "example", "kind": "service_app", "tenant_id": "contoso", "auth_method": "private_key_jwt",
                   "requested_scopes": ["logs.read", "users.read"], "scopes": ["users.read"], "read_only": true},
  "run": {"run_id": "6f1c...", "started_at": "2026-10-17T14:30:00Z", "finished_at": "2026-10-17T14:30:41Z", "proxy": false, "custom_ca": false}
}
```

- `outcome.status` is `collected`, or `partial` when there is a gap, with the first gap's code and owner.
- Each gap names a value by a JSON pointer into the artifact at `path`. Its `status` is `not_collected` for a value that could not be read, or `partial` for a rollup over items read in part, or a list or object that holds only the items that were read, with `unmeasured` counting the items left out. A gap recorded from an error the SDK's client returned, or from one built with `componentsdk.ResponseError`, names the `operation` whose failed call left the value out and the call's number in `call`, matching the call on its rows. So does a gap recorded from a failed DNS lookup or dial, or from a timeout or reset on a dialed connection. A partial gap names the first failed call it counts. `source` is the line of the collector's own code that recorded the gap, relative to its module root (see `Recorder.Helper`), and `missing_permission`, on a `permission_denied` gap, is the permission to grant in the vendor's own terms. At the `audit` and `internal` levels a gap also has a redacted `detail`, the error's text, and a redacted `warning`, the collector's message to the operator. A gap `Mirror` copies keeps all of these.
- `steps` lists the run's steps (see Calling APIs and Recording Gaps), in the order they started, at every level: each one's `name` and `title`, its `start_ms` and `end_ms` after the run's `started_at`, the `requests` sent in it, the `calls` they belong to, the `retries` among them, and the attempts that `failed`, counting rows left out of `calls.requests`, and the calls of each operation, in the order first called.
- `calls.operations` counts each named operation's calls, attempts, retries, statuses, and error codes, with any `Deprecation` or `Sunset` header the vendor sent. A response that `HTTPOptions.ClassifyResponse` gave a code counts under its status and under that code.
- At the `audit` and `internal` levels, `calls.requests` adds a row per request: the number of its `call`, from 1 in the order calls start and the same for each attempt of one call; its operation and `step`; its route with IDs replaced by `{id}` and its query keys without values; its `attempt`; `start_ms`, when it was sent after the run's `started_at`; on a retry, `waited_ms`, how long the SDK waited for a `Retry-After`, a rate limit reset, or its own backoff; its status and error code; the vendor's own error code, as `HTTPOptions.VendorCode` reads it, and never the vendor's message, which can name a resource; its duration; and the vendor's request ID. The first 1,000 rows are kept, and after them up to 1,000 more whose attempt failed, with an error code or a status of 400 or more, or was a retry. `requests_dropped` counts every row left out and `problem_requests_dropped` the failed and retried rows among them, so a 0 there means every problem in the run has a row. DNS lookups and dials count the same way, with a call, start, and step of their own (see DNS Lookups and Connections). Times come from the run's clock and waits from its jitter, which the test kit fixes and seeds, so two kit runs of one scenario match byte for byte.
- `signed_in_as` is the principal the collector signed in as. `auth_method` says how it proved its identity, `requested_scopes` lists the scopes it asked for, of which one missing from `scopes` was not granted, and `read_only` is true when the collector can show that its credential could only read. Its `id` is included at the `audit` and `internal` levels.
- `run.proxy` and `run.custom_ca` say whether a proxy or a custom CA bundle was configured.
- `checks` lists what the output checks found in the collector's artifacts (see Output Checks). It is left out when they found nothing.

Collectors name their sign-in methods with these `auth_method` values, which `componentsdk` has as constants. A sign-in that fits none names its own in the same form.

| `auth_method` | Constant | Sign-in |
|---------------|----------|---------|
| `api_token` | `AuthAPIToken` | A static token or key the vendor issued |
| `client_secret` | `AuthClientSecret` | OAuth 2.0 client credentials with a shared secret |
| `private_key_jwt` | `AuthPrivateKeyJWT` | OAuth 2.0 client credentials with a key assertion the collector signs, as RFC 7523 describes |
| `workload_identity` | `AuthWorkloadIdentity` | A token from the runner's own identity provider, such as a CI job's OIDC token, exchanged for the vendor's |
| `access_key` | `AuthAccessKey` | A cloud provider's access key pair, such as AWS's |

`Emit` fails when an artifact still has a value at a gap's pointer, so no field carries both a value and a gap. The one exception is a list or object under a `partial` gap. The schema is published as `componentsdk.ResultSchemaJSON()`. Every field this section names after the ones the first SDK result held is optional, so a result from an older SDK still matches it.

### Build File

SDK collectors also add a build file when they emit, at `artifacts/{collector}.collector-build.json` with schema `evidencepack/collector-build@v1`. It describes the build rather than the run: the collector's name as its spec declares it, its version and commit, the schemas in `CollectorSpec.Schemas`, keyed by artifact path or schema ID as the spec keys them, and the trace map in `CollectorSpec.TraceMap`. Every run of one build writes the same bytes at every level, so a reader can store it once per build. A collector without a trace map writes its schemas alone. An artifact of a normalized type with no schema there was checked against the SDK's own, which `componentsdk.NormalizedSchemaJSON` returns. `componentsdk.BuildSchemaJSON()` returns the build file's schema, which holds the trace map's under `$defs`.

```json
{
  "collector": {"name": "example", "version": "v0.4.0", "commit": "5d0c1e7f2a9b4c3d8e6f1a0b2c4d6e8f0a1b3c5d"},
  "schemas": {"artifacts/example.json": {"$schema": "https://json-schema.org/draft/2020-12/schema", "type": "object"}},
  "trace_map": {
    "artifacts": {
      "artifacts/example.json": {
        "/users/mfa_coverage": {
          "operations": ["example.users.factors.list", "example.users.list"],
          "code": [
            {"role": "assign", "line": "internal/collector/users.go:132"},
            {"role": "helper", "line": "internal/collector/collector.go:238", "end": 244},
            {"role": "input", "line": "internal/collector/users.go:288"},
            {"role": "condition", "line": "internal/collector/users.go:287"}
          ],
          "gaps": ["internal/collector/users.go:127"]
        }
      }
    },
    "lines": {"internal/collector/users.go:132": "\t\tp.Posture.MFACoverage = percent(m.mfaEnrolledCount, total)"}
  }
}
```

#### Trace map

The trace map links each field of the collector's artifacts, by artifact path and then by JSON pointer with each array index written as `*`, to:

- `operations`: the operations whose failure leaves the field out or changes it, from the test kit's fault matrix over each suite's clean scenario. Each one was tested, since those runs prove that each failure leaves a gap. A `Required` operation's faults fail the whole run, so the matrix cannot say which fields it feeds.
- `code`: lines that static analysis of the collector's own packages finds. `assign` is a line that assigns the field. `input` is a line that changes a value the assignment is computed from, followed through variables and fields. `condition` is the test of an if, loop, switch, or case one of those lines sits under, or a check before it that returns or skips the rest of a loop. `helper` is a function of the module that the assignment calls, such as a rounding function, from its first line to its `end`. Analysis can miss a line, so these are a guide for reading the source, not a proof.
- `gaps`: the lines that record a gap covering the field, from the gap sources the kit's runs record.
- `copies`: for a normalized field, the detailed field it copies, from the collector's `Mirror` calls.

`lines` holds the text of each line the fields name, keyed by the file, relative to the module root, and the line number. A reader can show the code without fetching the source, and the pack's signature covers what it shows. A gap's `source` is a key in it. A field's steps come from its operations and the steps in the collector result, so the map does not repeat them.

The SLSA builder builds a release straight from its tag, with no step that generates files, so the map is committed beside the schema and embedded in the binary:

```go
//go:embed trace-map.json
var TraceMap []byte
```

`CollectorSpec.TraceMap` takes it. `epack sdk map` writes it to `docs/schema/trace-map.json`, or the path `--out` names relative to the module root. It runs the module's tests with `COLLECTORTEST_MAP` set, so each collectortest suite writes what its fault matrix found, merges the suites, such as one per sign-in method, and adds what static analysis finds. It fails when the tests fail, and when an operation a suite lists in `Operations` feeds no field in any suite's runs, unless a suite lists it in `Insensitive` or `Required`. `epack sdk map --check` writes nothing, and fails when the committed map differs from the one the code gives, naming the command to run; collector CI runs it (see Collector CI in [Component Rules](component-rules.md)). Between runs of the command, each suite checks the committed map against its own runs and fails when they find a field or an operation the map lacks.

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

SDK collectors get these from the typed errors first: `ConfigError` exits 2, `AuthError` 3, and `NetworkError` 4, including when one is returned as a pointer or wrapped with `%w`. Any other error exits with its code's exit code (see Codes): an HTTP status, a deadline, a reset connection, or malformed JSON each map to a code. A collector stopped by SIGTERM or SIGINT exits 1.

### Collector Failures

When collectors fail, `epack collect`, `epack collector run`, and `epack run` stop before building a pack and report each failed collector with a code and an exit code:

| Code | Failure | Exit |
|------|---------|------|
| `config_invalid` | The collector exited 2 | `2` |
| `auth_failed` | The collector exited 3 | `3` |
| `network_error` | The collector exited 4 | `4` |
| `collector_error` | Any other non-zero exit, or a signal ended the collector | The collector's exit code, or `-1` for a signal |
| `invalid_output` | The collector exited 0 without a result (see Output Convention) | `1` |
| `timeout` | The collector ran past `--timeout` and was stopped | `13` |

A failure epack detects before the collector runs keeps its own code and exit code, such as `binary_not_found` (14) or `digest_mismatch` (11).

Each failure also says where its code came from, as `code_source`: `exit_code` when the runner inferred the code from the collector's exit code, and `runner` when epack observed the failure itself, as with a timeout, unusable output, or a missing binary. Both are the runner's best guess. When a collector that exited non-zero printed a failure line with one of the nine codes (see Codes), the failure takes that code instead, with `code_source` set to `collector` and the collector's exit code. A collector's `timeout` means its calls ran out of time; the runner's `timeout`, with exit code 13, means the collector ran past `--timeout`.

The command's error has the code `collect_failed`. Its message is `<collector>: <error>` for one failed collector and `N collectors failed: a, b` for several. When one collector failed, epack exits with that collector's exit code if it is between 2 and 9, or with epack's code for a failure epack detected, such as 13 for a timeout; otherwise, and when several failed, it exits 1. With `EPACK_ERROR_FILE` set, each failed collector also gets a `collector=` line (see the remote protocol's Lock Reporting section).

### Workflow Exit Codes

The `epack collect` workflow uses these exit codes:

| Code | Meaning |
|------|---------|
| `0` | Success |
| `1` | General failure |
| `2-9` | The exit code of the one collector that failed |
| `10` | Lockfile missing, invalid, or mismatched |
| `11` | Digest verification failed |
| `12` | Signature verification failed |
| `13` | Collector timed out |
| `14` | Collector binary not installed or not pinned |
| `15` | Network error while fetching |

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
- stderr sanitization (passed secret values replaced, truncated, control chars escaped, secret patterns redacted; a value shorter than six characters is not matched). The patterns redact a credential keyword's value after `=`, `:`, or spaces, bearer tokens, JWTs, and long base64 runs. A keyword followed by an ordinary word, as in "token endpoint returned 503", is left alone, and so is a 64-character hex digest

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
        return ctx.Emit([]componentsdk.CollectedArtifact{{
            Data: map[string]any{
                "collected_at": time.Now().UTC().Format(time.RFC3339),
                "source":       ctx.Name(),
                "items":        items,
            },
        }})
    })
}
```

SDK methods:
- `ctx.Status(message)` - Report indeterminate status (e.g., "Connecting...")
- `ctx.Progress(current, total, message)` - Report determinate progress (e.g., 5/100)
- `ctx.Emit(artifacts)` - Emit collected artifacts (handles envelope automatically)
- `ctx.Config()` - Access collector configuration from epack.yaml
- `ctx.Name()` - Get collector name

`CollectedArtifact` fields:
- `Data` (required unless `File` is set) - The evidence data (any JSON-serializable value)
- `File` (optional) - Staged file path whose raw bytes become the artifact (mutually exclusive with `Data`; see File Artifacts)
- `Schema` (optional) - Schema identifier for typed artifacts (e.g., `"evidencepack/cloud-posture@v1"`)
- `Path` (optional) - Output path in the pack (defaults to `"artifacts/{collector}.json"`)
- `DisplayName` (optional) - Human-readable name shown by `epack inspect` and `epack list`
- `Description` (optional) - One-line description of the artifact
- `Controls` (optional) - Control IDs this artifact supports

Build artifacts with the `JSONArtifact` and `FileArtifact` constructors, which set exactly one of `Data`/`File` and apply optional `ArtifactMeta`:

```go
componentsdk.JSONArtifact("artifacts/posture.json", data,
    componentsdk.ArtifactMeta{Schema: "evidencepack/cloud-posture@v1"})

componentsdk.FileArtifact("artifacts/documents/policy.pdf", stagedName,
    componentsdk.ArtifactMeta{DisplayName: "Security policy"})
```

### Calling APIs and Recording Gaps

`componentsdk.NewHTTPClient` returns the client SDK collectors call their APIs with. It retries safe requests, meaning GET and HEAD or an operation marked `Safe`, on 429, 5xx, and connection errors, up to 5 attempts with exponential backoff and jitter. A transport error is retried only when its code (see Codes) is `rate_limited`, `vendor_error`, or `timeout`, so a guard in `Base` whose refusal carries another code, such as `config_invalid` or `invalid_response`, is not asked again. A connection the server closed before the response arrived in full is retried too, and counts as `vendor_error`. A safe request built without `GetBody`, as AWS's SDK builds them, has its body held in memory, up to 1 MiB, so it can be sent again. It honors `Retry-After` up to 60 seconds and never waits past the collector's deadline. A throttled response without `Retry-After` waits, up to the same cap, until the rate limit resets, as `X-Rate-Limit-Reset` (Okta), `X-RateLimit-Reset` (GitHub), `RateLimit-Reset` (GitLab and the IETF draft), or `X-Sentry-Rate-Limit-Reset` gives it: a value above 1e9 is a time in epoch seconds, and a smaller one counts seconds from now. It sends a `User-Agent` with the collector's name, version, and run ID, and it refuses to send credential headers, or a URL or body that carries a value the collector read through `ctx.Secret`, to a host outside `CredentialHosts`, including on redirects and next-page links, or over plain http to any host but a loopback one, such as `127.0.0.1` or `localhost`, including after a redirect from https. Each call is counted under its operation name in the collector result.

`componentsdk.Records` returns the run's recorder, which takes the gaps described in Partial Collection:

```go
client := componentsdk.NewHTTPClient(ctx, componentsdk.HTTPOptions{
    CredentialHosts: []string{"api.example.com"},
})
rec := componentsdk.Records(ctx)

reqCtx := componentsdk.WithOperation(ctx.Context(), componentsdk.Operation{Name: "users.list"})
req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, "https://api.example.com/users", nil)
if err != nil {
    return err
}
resp, err := client.Do(req)
if err != nil {
    rec.NotCollected(componentsdk.Location{Path: "artifacts/example.json", Pointer: "/user_count"}, err)
}
```

- `rec.NotCollected(at, err)` records a value left out, with the code `componentsdk.Classify` gives `err`.
- `rec.NotCollectedCode(at, code, detail)` records one with a code the collector chose, such as `not_licensed`.
- `rec.Partial(at, unmeasured, err)` records a rollup left out because `unmeasured` items could not be read. At a list or object it records that the value holds only the items that were read, and the value may stay in the artifact.
- `rec.Mirror(from, to)` records at `to` the gap that covers `from`, at `from` itself or the nearest value that contains it, such as for a normalized value copied from a detailed one. It records nothing when no gap covers `from`. Call it for every value copied, gap or not: the kit reads the calls for the trace map's copies.
- `rec.SignedInAs(principal)` records the identity the collector signed in as, with its `AuthMethod`, `RequestedScopes`, and `ReadOnly`.

Each of the three record calls takes options. `componentsdk.MissingPermission(name)` names the permission a `permission_denied` gap's credential lacks, in the vendor's own terms, such as `okta.logs.read`; on a gap with another code it is dropped. `componentsdk.Warning(text)` gives a gap the collector's message to the operator about it, such as the role to grant, which is redacted and kept at the `audit` and `internal` levels only.

```go
rec.NotCollected(at, err, componentsdk.MissingPermission("logs.read"), componentsdk.Warning("system log: grant logs.read"))
```

A gap names the call it came from when its error carries one. Errors the SDK's client returns do, and so do errors from a failed DNS lookup or dial, or from a timeout or reset on a dialed connection. `componentsdk.ResponseError(resp, err)` gives one an error the collector builds from a response, such as a status it does not expect or a body it cannot decode, along with the vendor code `HTTPOptions.VendorCode` read from the response. A gap's `source` is the first line on the stack in the collector's own module. A collector that records its gaps through a helper of its own calls `rec.Helper()` in it, as a test helper calls `testing.T.Helper`, so the source names the line that called the helper:

```go
func (l gapLog) notCollected(err error, pointer string, opts ...componentsdk.GapOption) {
    l.rec.Helper()
    l.rec.NotCollected(componentsdk.Location{Path: artifactPath, Pointer: pointer}, err, opts...)
}
```

A collector opens a named step around each part of its run with `componentsdk.StartCollectorStep(ctx, name, title)`, which prints the title as a status line and returns a copy of the collector's context whose `Context()` carries the step, so the calls made with it belong to the step. A helper that records gaps or reports progress and makes the step's calls takes that one context. `componentsdk.StartStep(ctx.Context(), name, title)` does the same for a plain `context.Context`. Step names are part of the collector's contract, like operation names. A step still open when the collector emits ends then. Steps can overlap when a collector works on several things at once, and they do not nest: a call belongs to the step its context carries, or to none.

```go
people, step := componentsdk.StartCollectorStep(ctx, "people", "People and sign-in methods")
users, err := client.ListUsers(people.Context())
step.End()
```

An API error type can implement `HTTPStatus() int`, `HTTPHeader() http.Header`, and `VendorCode() string` so `Classify` reads its status, throttle headers, and vendor code. `componentsdk.CodeError(code, err)` gives an error a code outright. Token endpoints send most OAuth 2.0 errors with a 400, which alone reads as `invalid_response`, so `componentsdk.OAuthErrorCode(name)` returns the code for the error's name: `invalid_client`, `invalid_grant`, `unauthorized_client`, `invalid_dpop_proof`, and `expired_token` are `auth_failed`; `invalid_scope` and `access_denied` are `permission_denied`; `invalid_request` and `unsupported_grant_type` are `config_invalid`; `temporarily_unavailable` and `server_error` are `vendor_error`; `slow_down` is `rate_limited`.

`HTTPOptions.VendorCode` reads the vendor's own error code from a failed response for its row in the collector result, such as Okta's `errorCode` or an OAuth `error` like `invalid_client`. The client calls it with up to the first 64 KiB of the body of each response with status 400 or higher, and of a 2xx response that `ClassifyResponse` gave a code; the caller still reads the whole body. It returns the code alone. A value that is not a code of up to 64 letters, digits, and `. _ : / -`, or that holds a secret's value, is dropped, so a row never holds the vendor's message.

Some vendors fail under a status that misleads: AWS throttles some calls with a 400 whose body names the error code. `HTTPOptions.ClassifyResponse` reads such a response. The client calls it for each response with status 400 or higher, with up to the first 64 KiB of the body, and the caller still reads the whole body. When it answers with a code, that code decides whether a safe request is retried (`rate_limited`, `vendor_error`, and `timeout` are) and is the error code the collector result counts for the call. `componentsdk.ClassifyResponse(resp)` returns it as well, so an error built with `componentsdk.CodeError(componentsdk.ClassifyResponse(resp), err)` carries it to the gap. JSON-RPC and GraphQL APIs report errors inside a 200: set `HTTPOptions.ClassifySuccess` as well, and the client passes 2xx responses to the hook too, so a throttle in a 200 is retried like a 429.

```go
// awsThrottle reads the error code in an AWS error body, JSON or XML.
func awsThrottle(resp *http.Response, body []byte) (componentsdk.Code, bool) {
    var jsonErr struct {
        Type string `json:"__type"` // {"__type":"ThrottlingException",...}, at times after "namespace#"
    }
    var xmlErr struct {
        Code    string `xml:"Error>Code"`        // <ErrorResponse><Error><Code>Throttling</Code>
        EC2Code string `xml:"Errors>Error>Code"` // <Response><Errors><Error><Code>, from EC2
    }
    var code string
    if json.Unmarshal(body, &jsonErr) == nil {
        code = jsonErr.Type[strings.LastIndex(jsonErr.Type, "#")+1:]
    } else if xml.Unmarshal(body, &xmlErr) == nil {
        code = cmp.Or(xmlErr.Code, xmlErr.EC2Code)
    }
    switch code {
    case "Throttling", "ThrottlingException", "RequestLimitExceeded", "TooManyRequestsException":
        return componentsdk.CodeRateLimited, true
    }
    return "", false
}

client := componentsdk.NewHTTPClient(ctx, componentsdk.HTTPOptions{
    CredentialHosts:  []string{"*.amazonaws.com"},
    ClassifyResponse: awsThrottle,
})
```

`HTTPOptions.Base` is the transport requests go out through, such as one whose dialer refuses private addresses. It replaces the default, a clone of `http.DefaultTransport`, so it should honor proxy settings as that one does. `collectortest` runs replace `Base` with their replay, so they never reach the network and never exercise `Base`: a guard in `Base` needs a test of its own.

### DNS Lookups and Connections

A collector that reads DNS records or connects to hosts itself, such as one that checks email DNS records or TLS endpoints, does so through `componentsdk.NewResolver(ctx)` and `componentsdk.NewDialer(ctx)`. Each lookup and dial counts in the collector result like an HTTP call, and `collectortest` injects faults into them by operation name.

The resolver's `LookupTXT`, `LookupMX`, `LookupHost`, `LookupIPAddr`, `LookupCNAME`, and `LookupNS` have the signatures of `net.Resolver`'s. A name or record that does not exist, NXDOMAIN or NODATA, is an answer: the lookup returns `net.Resolver`'s `*net.DNSError` unchanged, with `IsNotFound` true, and the result counts it under the status `NXDOMAIN` with no error code. Anything else is a failure to record as a gap, never to read as "no record": SERVFAIL counts under the status `SERVFAIL` with `vendor_error`, a timeout as `timeout`, and other failures, such as REFUSED, as `vendor_error`. A failed lookup returns an error that carries its call, so a gap recorded from it names the call too. `errors.As` gets the `*net.DNSError` from that error.

```go
resolver := componentsdk.NewResolver(ctx)
spfCtx := componentsdk.WithOperation(ctx.Context(), componentsdk.Operation{Name: "dns.spf.lookup"})
txt, err := resolver.LookupTXT(spfCtx, domain)
var dnsErr *net.DNSError
if err != nil && !(errors.As(err, &dnsErr) && dnsErr.IsNotFound) {
    rec.NotCollected(componentsdk.Location{Path: "artifacts/example.json", Pointer: "/spf"}, err)
}
```

A lookup's operation is the one `WithOperation` names, as above, or `dns.` and the lookup: `dns.txt`, `dns.mx`, `dns.host`, `dns.ipaddr`, `dns.cname`, or `dns.ns`. The dialer's `DialContext(ctx, network, address)` works like `net.Dialer`'s, and its operation defaults to `dial`. Neither retries. A timeout or reset on a dialed connection, such as during a TLS handshake after the dial, counts as that dial's error code. At the `audit` and `internal` levels, a lookup's row has the method `DNS` and the record type, such as `DNS TXT`, the queried name as its host, and its `rcode`. A dial's row has the method `DIAL` and the host.

`dialer.RootCAs()` is the pool to verify certificates against: pass it to `x509.VerifyOptions.Roots` or `tls.Config.RootCAs`. It is nil in a real run, meaning the system's roots, and the test CA's pool under `collectortest`. Judge validity by `componentsdk.Now(ctx)`, through `x509.VerifyOptions.CurrentTime` or, when the handshake verifies the chain, `tls.Config.Time`, so a test's clock applies.

### Testing

`componentsdk/collectortest` runs a collector in process against canned responses, DNS records, and endpoints. It checks the output against its schemas, then injects faults into each named operation: 401, 403, 404, 429, 500, a timeout, a reset connection, a truncated 2xx body, and a malformed or empty body, on every call and then on the first, a middle, and the last. Under each fault every value must keep its clean value, or be left out with a gap whose code matches the fault. Items under a `partial` gap may differ, and an object or array whose members gaps cover may be left empty. A fault that reaches its operation must also leave at least one new gap with its code, even where the clean run found nothing: otherwise a failure read as "no record" passes whenever the clean answer was already none. A fault that fails the run on a `Required` operation, a fault on an operation listed in `Insensitive`, and a fault a `Semantics` entry declares are exempt. So is a fault that changed nothing the collector read, such as a cut body it never reads, and one that only turned calls that failed in the clean run into failures with the same code. When other data decides a value in the clean scenario, as an account-wide setting can override a per-resource one, a fault on the per-resource call changes nothing; make the first scenario one where that call decides the value, rather than leaving out a value the run does know. It also checks that no secret reaches an artifact, that no credential reaches another host, that every call is named, and that the output, or the result's `signed_in_as`, changes when a response does.

Each run stages file artifacts in a temporary directory of its own. `RunInProcess` records each file artifact's size and SHA-256, and the kit compares them like values: a file whose bytes change under a fault is a changed value, and a file left out needs a gap for its artifact path, with an empty pointer. Before removing the directory, the kit looks for the secrets in every file the run staged.

```go
func TestCollector(t *testing.T) {
    collectortest.Run(t, collectortest.Suite{
        Spec:       spec,
        Run:        run,
        Secrets:    map[string]string{"EXAMPLE_TOKEN": "example-token-0123456789"},
        Scenarios:  []collectortest.Scenario{clean},
        Required:   []string{"me.get"},
        Operations: []string{"me.get", "users.list"},
    })
}
```

`Required` lists the operations whose failure may fail the run, such as the sign-in. A status that is an answer rather than a failure, such as a 404 that means a feature is off, goes in `Semantics` with its meaning. A semantic's `ExpectFailure` says instead that the fault fails the run with that code, such as a 404 on the organization read, which means `config_invalid`; its operation must be in `Required`. A semantic's `Positions`, such as `collectortest.PositionAll`, limits its `Expect` to faults at those positions, for an operation called once per item, where a fault on one call leaves the other items' values in place; the meaning still exempts the other positions from the outcome rule. Two semantics for the same operation and fault may give different positions their own `Expect`; `Check` rejects two whose positions overlap, and a semantic without `Positions` covers every position.

The credentials check redirects the first operation's first call to another host. Then, for each operation whose response holds an absolute URL on the request's own host, in its body or a `Link` header, it points those URLs in one response at the other host, as a hostile or broken next-page link would. The client drops `Authorization` and `Cookie` on a redirect to another domain, but not from a request the collector makes to a link it was given; `CredentialHosts` refuses that request. A violation names each header that reached the other host once, by its canonical name, and says when a secret's value reached it in the URL or the body, as a client secret in a token request's form does when the client follows a 307. The check also reports an operation that sent a credential header through a client built without `CredentialHosts`, since no host check guards that client. `RunInProcess` results list the `CredentialHosts` each client was built with, and the check also flags a wildcard over a public suffix, such as `*.com`, which would let credentials reach any host under it.

`Faults` adds the collector's own faults to the matrix, such as a vendor's throttle sent as a 400. They run after the built-in ones. Build them with `collectortest.StatusFault(name, status, header, body, expect, transient)`, `BodyFault(name, body, expect)`, which answers 200 with the body, or `ErrorFault(name, err, expect)`, which fails the request with `err`. A transient fault hits only the first attempt of a call and must clear on retry. A fault's `Operations` limits it to those operations; empty means every operation.

```go
throttle := `{"__type":"ThrottlingException","message":"Rate exceeded"}`
suite.Faults = []collectortest.Fault{
    collectortest.StatusFault("400-throttled-once", http.StatusBadRequest, nil, throttle, "", true),
    collectortest.StatusFault("400-throttled", http.StatusBadRequest, nil, throttle, componentsdk.CodeRateLimited, false),
}
```

A scenario answers the collector's lookups from `DNS` and its dials from `Endpoints`, and `Expect` pins values its output must have:

```go
collectortest.Scenario{
    Name: "DMARC lookup fails",
    DNS: []collectortest.DNSRecord{
        {Name: "example.com", Type: "TXT", Values: []string{"v=spf1 include:_spf.example.net -all"}},
        {Name: "example.com", Type: "MX", Values: []string{"10 mx1.example.com."}},
        {Name: "_dmarc.example.com", Type: "TXT", Rcode: "SERVFAIL"},
    },
    Endpoints: []collectortest.Endpoint{
        {Address: "www.example.com:443", MinVersion: tls.VersionTLS10},
        {Address: "old.example.com:443", Cert: collectortest.Cert{NotAfter: -24 * time.Hour, Untrusted: true}},
    },
    Expect: map[string]map[string]any{
        "artifacts/example.json": {"/spf_valid": true, "/dmarc_policy": nil},
    },
}
```

- A DNS record has a `Name`, a `Type` (`TXT`, `MX`, `A`, `AAAA`, `CNAME`, or `NS`), and `Values`, with an MX value written as `"10 mx.example.com."`. An `Rcode` of `NXDOMAIN` or `SERVFAIL` answers lookups of that name and type with the code instead. Lookups follow CNAMEs, and a name with no record answers NXDOMAIN without a report.
- An endpoint is a TLS server at a `host:port` address, run in process over `net.Pipe`. `MinVersion` and `MaxVersion` bound the versions it accepts; zero means Go's defaults, TLS 1.2 and 1.3. Its ECDSA P-256 certificate covers `Cert.DNSNames`, or the host when that is empty, from `Cert.NotBefore` to `Cert.NotAfter`. Those are offsets from `Suite.Clock`, 30 days before and 60 days after it by default. A test CA signs it, and that CA's pool is what `Dialer.RootCAs` returns, unless `Cert.Untrusted` has another CA sign it. A `Plaintext` endpoint speaks no TLS and answers with an HTTP 400. A dial to an address with no endpoint is refused and reported; a `Refused` endpoint is a closed port, refused without a report.
- `Expect` maps artifact paths to JSON pointers and the values they must hold, compared as JSON, such as what a fixed collector reports for the incident a scenario replays. A pinned null also matches an absent value, and `collectortest.Absent` matches only an absent one. A value that differs is a `scenario` violation naming the pointer, the value wanted, and the value found.
- A response's `RequestBody` is a JSON document the request's body must contain: each key of an object it lists must match, recursively, and any other value must be equal. A form-encoded body, as AWS's Query and EC2 calls send, matches as an object of its fields, each a string. Calls to one URL that differ only in their bodies, such as per-item JSON-RPC or Query calls, then each get their own answer, and a fault on one cannot shift the answers of the rest.
- `Config`, `Secrets`, and `Env` override the suite's, key by key, for the scenario's runs. The fault matrix and the determinism, levels, credentials, and sensitivity checks run on the first scenario, with its overrides. Every scenario's secrets are canaries in every run.

A collector that polls, such as one waiting for a report the vendor builds in the background, waits with `componentsdk.Wait(ctx, d)` rather than `time.Sleep`. It sleeps in real runs; in kit runs it returns at once and moves the run's clock forward by `d`, so a loop bounded by a deadline read from `componentsdk.Now` still ends, and the suite does not sleep. The sensitivity check can change only JSON bodies; `Report.Unmutated` lists the operations it could not change, such as those answering in XML or CBOR, and `collectortest.Run` logs them.

`collectortest.NewReplay(scenario)` returns the replay the kit answers requests with, for a focused test of one run: pass it as `componentsdk.InProcessOptions.Transport`, and `Unmatched()` lists the requests no canned response matched.

`GapOperations: true` turns on a check that every gap a fault leaves names the faulted operation, which a gap recorded from an error the SDK's client returned, or from one built with `componentsdk.ResponseError`, does. A gap recorded from a failed DNS lookup or dial, or from a timeout or reset on a dialed connection, names it too. Faults a `Semantics` entry declares are exempt. With `CollectorSpec.TraceMap` set, the kit also checks the committed map against the suite's runs: a field the runs emitted, or an operation the fault matrix found changing a field, that the map lacks is a `tracemap` violation, which says to run `epack sdk map`. With `COLLECTORTEST_MAP` naming a directory, as `epack sdk map` sets it, the kit writes the suite's findings there instead of checking the map. The build file is checked against `componentsdk.BuildSchemaJSON`, as the collector result is against its schema.

Lookups get their own faults: `servfail` and `refused`, each with code `vendor_error`, and `timeout`. So do dials: `refused`, `reset`, a connection that fails on its first read, both `vendor_error`, and `timeout`. A timeout returns at once, as an error whose `Timeout()` is true. They hit calls at the same positions as the HTTP faults, and a name in `SkipFaults` skips the fault of that name for every kind of call. The credentials and sensitivity checks apply to HTTP operations only, so a collector whose calls are all lookups or dials skips them.

#### Recordings

A scenario can come from a real run rather than responses written by hand. `collectortest.Record` runs the collector once against its vendor through `componentsdk.RunInProcess`, with the real network and resolver beneath the SDK, and writes the response each HTTP call got, and the answer each DNS lookup got, to a file as a scenario. Dials are not recorded, since a certificate cannot be replayed, so a TLS scenario keeps endpoints written by hand. Record from a test behind a build tag, so a plain `go test` never needs credentials:

```go
//go:build record

package main

import (
    "os"
    "testing"

    "github.com/locktivity/epack/componentsdk/collectortest"
)

// go test -tags record -run TestRecord .
func TestRecordClean(t *testing.T) {
    token := os.Getenv("EXAMPLE_TOKEN")
    if token == "" {
        t.Skip("EXAMPLE_TOKEN is not set")
    }
    report, err := collectortest.Record(collectortest.RecordOptions{
        Spec:    spec,
        Run:     run,
        Config:  map[string]any{"organization": "acme-sandbox", "level": "internal"},
        Secrets: map[string]string{"EXAMPLE_TOKEN": token},
        Out:     "testdata/recordings/clean.json",
        Scrub: collectortest.ScrubRules{
            Literals: map[string]string{"acme-sandbox": "example-org"},
        },
    })
    if err != nil {
        t.Fatal(err)
    }
    t.Logf("recorded %d responses and %d DNS records", report.Responses, report.DNS)
}
```

Record at the `internal` level, so the recording holds every call any level makes. `collectortest.LoadScenario` loads a recording back as a scenario, with the fake secrets a suite gives as usual:

```go
clean, err := collectortest.LoadScenario("testdata/recordings/clean.json")
if err != nil {
    t.Fatal(err)
}
suite.Scenarios = []collectortest.Scenario{clean}
```

A recording is JSON: `name`, `recorded_at` (RFC 3339), `collector`, `collector_version`, the run's `config`, scrubbed, which becomes the scenario's `Config`, `responses`, and `dns`. A response has the fields of `collectortest.Response` in snake case: `operation`, `method`, `url` with the full query, `request_body`, `times`, `status`, `header`, and `body`. A URL without a query ends in `?`, which matches only a request without one. `request_body` holds a JSON or form request body as JSON and matches as `RequestBody` does, so deleting a member, such as a timestamp the collector takes from the clock, stops matching on it. A body that is a JSON object or array is stored as JSON, so it reads and diffs as JSON. When a later response matches the same requests, `times` is 1, so they answer in the order recorded. An attempt the SDK retried is left out, and a call or lookup that got no answer at all, such as one that timed out, fails the recording. Headers keep only `Content-Type`, `Link`, `Location`, `Retry-After`, `ETag`, rate limit headers (`X-RateLimit-*`, `X-Rate-Limit-*`, `RateLimit`, `RateLimit-*`, and `X-Sentry-Rate-Limit-*`), pagination headers (`X-Next-Page`, `X-Page`, `X-Per-Page`, `X-Prev-Page`, `X-Total`, `X-Total-Count`, `X-Total-Pages`, and `X-Ms-Continuation`), and those `RecordOptions.Headers` names; a name ending in `*` keeps every header that begins with the rest. A response body must be text.

The recorded run's clock stands still at the moment the recording starts, moving only as `componentsdk.Wait` waits, and `recorded_at` keeps that moment. When `Suite.Clock` is zero and the first scenario is a recording, the suite runs at that moment, so ages come out as they did and requests built from the time match.

Scrubbing keeps one mapping for the whole recording, so a value replaced in a response is replaced the same way in the later URLs and request bodies that carry it, and the replay still matches them. Fakes are numbered in the order their values first appear, so the same input always scrubs the same way.

- Secrets' values of six or more characters, as written and in their URL and JSON encodings, become `REDACTED`. So do signed JWTs, `Bearer` and Okta `SSWS` tokens, GitHub and Slack tokens, private key blocks, and the values of credential fields: JSON members, XML elements, and form or query parameters named like `access_token`, `client_secret`, `password`, or `SessionToken`, but not page cursors such as `NextToken`. Request headers are never recorded.
- In a request, a body member that carries a credential is left out, and so is a query that carries one, leaving a URL that matches any query, since the replay signs in with other values.
- Emails become `user1@example.com`, `user2@example.com`, and so on.
- Public IPv4 and IPv6 addresses become documentation addresses, such as `192.0.2.1` and `2001:db8::2`. Private, loopback, link-local, and other special addresses stay, since a collector tells them apart: `0.0.0.0/0` means the whole internet.
- GUIDs become `00000000-0000-4000-8000-000000000001` and up.
- 12-digit numbers, such as AWS account IDs alone or in ARNs, become `123456789012` and up, and AWS access key IDs become IDs such as `AKIAEXAMPLE000000001`.
- A run of base64 or hex characters over 40 long that looks random, mixing upper and lower case letters and digits or all hex, becomes `scrubbed-token-1` and up. Hex digests of 56, 64, 96, or 128 characters stay, and so do certificates and public keys. Base64 that decodes to text, such as an AWS credential report or a file from GitHub's contents API, is scrubbed inside and encoded again in its own alphabet and line width.

`ScrubRules.Literals` replaces the collector's own values, such as its organization's name or a domain, regardless of case and also in their URL and JSON encodings. `ScrubRules.Patterns` applies regular expressions with their replacements, in order, after the literals. `ScrubRules.Keep` lists values the built-in rules leave alone, such as a well-known role ID the collector compares against.

Then the scrub check reads the result. `Record` writes nothing and fails, naming where but never the value, when the recording still holds a secret's value, a signed JWT, a `Bearer` or `SSWS` token, an AWS `AKIA` or `ASIA` key ID other than an `EXAMPLE` one, a GitHub `ghp_`, `gho_`, `ghs_`, `ghu_`, or `github_pat_` token, a Slack `xox` token, a private key block, or a long random-looking run as above. A value in `Keep` gets no pass. `Check` runs the same check on every scenario `LoadScenario` loaded, looking for the suite's secrets, and reports each finding as a `recording` violation.

#### Scenario output

When `COLLECTORTEST_OUT` names a directory, each scenario run writes what it emitted under `$COLLECTORTEST_OUT/<suite>/<scenario>/`: each artifact at its path in a pack, file artifacts copied from staging, the build file, and the collector result. `epack-collector-diff` leaves the build file out of its comparison, since its trace map moves with every edit to the code. Fault runs and the other checks' runs write nothing. `<suite>` comes from `Suite.Name`, which defaults to `Spec.Name`, so two suites in one package give each its own name. `<scenario>` is the scenario's name in lower case, each run of characters other than letters and digits turned into a hyphen, with a number added when two scenarios share one. Each run of the suite first clears its directory, then writes `<suite>/scenarios.json`, which lists each scenario's directory, exit code, failure, and artifacts, each with its schema ID, empty for none:

```json
{
  "suite": "example",
  "scenarios": [
    {
      "name": "clean",
      "dir": "clean",
      "exit_code": 0,
      "artifacts": [
        {"path": "artifacts/example.json", "schema": "evidencepack/idp-posture@v1"},
        {"path": "artifacts/policy.pdf", "schema": "", "file": true},
        {"path": "artifacts/example.collector-result.json", "schema": "evidencepack/collector-result@v1"}
      ]
    },
    {
      "name": "token rejected",
      "dir": "token-rejected",
      "exit_code": 3,
      "failure": {"code": "auth_failed", "message": "signing in: the API returned 401"},
      "artifacts": []
    }
  ]
}
```

### Output Checks

A collector's JSON Schemas can say what a value means with `x-epack-*` keywords on any property. Validators ignore keywords they do not know, so a schema keeps its draft.

| Keyword | Meaning |
|---------|---------|
| `x-epack-level` | `trust`, `audit`, or `internal`: the lowest level whose output includes the field. Fields under it inherit it unless they name a higher level. |
| `x-epack-denominator` | The count the value is a percentage or ratio of. |
| `x-epack-numerator` | The count a percentage is taken of, as a reference in the same form as `x-epack-denominator`. On a boolean it is the count of "all of them": the boolean is true exactly when the numerator equals the denominator. |
| `x-epack-rounding` | How a whole-number percentage was rounded: `floor`, `ceil`, or `nearest`, which rounds halves up. |
| `x-epack-null` | When null is a real answer, such as `"No session policy sets a lifetime"`. |
| `x-epack-rollup` | `{"rows": ref, "where": "/pointer/in/row", "equals": value, "as": "count" or "pct", "truncated": ref}`. A count is the number of rows, or with `where`, of rows whose value there equals `equals` (`true` by default). A percentage is those rows out of all rows. `truncated`, when given, names a boolean that is true when the rows were cut short, such as at a cap on how many the collector lists. |
| `x-epack-as-of` | A timestamp field. When it is set, the rollup came from a report taken at another time, so it is not recomputed. |

A reference is a sibling property's name, an absolute JSON pointer such as `/summary/total`, or a relative one such as `1/total`: up one level from the object that holds the field, then `/total`. The annotations are read through `properties`, `patternProperties`, `additionalProperties`, `items`, `prefixItems`, local `$ref`s, and every `allOf`, `anyOf`, or `oneOf` branch that names the field.

`CollectorSpec.Schemas` holds the collector's schemas, keyed by artifact path or schema ID. Embed them with `go:embed` from a package in the schema directory, such as `docs/schema/embed.go`. Each schema must be self-contained, since refs to other files or URLs are not loaded. Artifacts of the types `evidencepack/idp-posture@v1`, `cloud-posture`, `vcs-posture`, `email-dns`, and `tls` are checked against the SDK's copies unless `Schemas` has a schema for the type or the path. Those copies require only the fields that say what was collected, such as the provider and account IDs, and allow null on every metric. `componentsdk.NormalizedSchemaJSON` returns them.

When the collector emits, the SDK checks each data artifact that has a schema and lists each finding in the result's `checks` with its `check`, `path`, `pointer`, and `message`. A finding never fails the run or changes its outcome. The list stops at 100, and `checks_dropped` counts the rest.

- `schema`: the artifact does not match its schema.
- `schema_unusable`: a schema in `Schemas` does not compile, so its artifacts went unchecked. The SDK also prints a warning.
- `population`: a value is set although its denominator is 0. It must be null or absent.
- `nulls`: a number or boolean is null with no gap covering it, no `x-epack-null`, and no denominator of 0.
- `rollups`: a count differs from its rows, or a percentage is off by more than 1. Rows cut short are not recomputed: those the rollup's `truncated` boolean marks, and those as many as their schema's `maxItems`. Nor is a rollup whose rows or `where` field the schema places above the level the collector ran at, where the rows exist without the field, such as per-person MFA flags kept for the `internal` level.
- `ratios`: where a value, its `x-epack-numerator`, and its `x-epack-denominator` are all present and the denominator is not 0, a percentage that is not 100 × numerator ÷ denominator rounded as its `x-epack-rounding` says, or within 1 of it when the schema states no rounding; a numerator larger than its denominator; a boolean that disagrees with its numerator; and a rounding that is not one of the three. A numerator works at every level, including for counts the collector takes from calls rather than rows, which a rollup cannot recompute.

`collectortest` reports each finding as a violation and runs the same checks itself on artifacts whose schema only `Suite.Schemas` gives. Sensitivity runs skip `population`, `nulls`, `rollups`, and `ratios`, since their changed responses make rows and rollups disagree. The `levels` check runs the clean scenario at each level: what one level emits, every higher level must emit too, and a field marked with a level must be absent, not even null, below it. `SkipChecks` turns off `levels`, `population`, `nulls`, `rollups`, `ratios`, or `tracemap` by name.

### Manual Implementation

For collectors not using the SDK:

```go
package main

import (
    "encoding/json"
    "os"
)

type Output struct {
    Type            string     `json:"type"`
    ProtocolVersion int        `json:"protocol_version"`
    Artifacts       []Artifact `json:"artifacts"`
}

type Artifact struct {
    Data        any      `json:"data,omitempty"`
    Schema      string   `json:"schema,omitempty"`
    Path        string   `json:"path,omitempty"`
    File        string   `json:"file,omitempty"`
    DisplayName string   `json:"display_name,omitempty"`
    Description string   `json:"description,omitempty"`
    Controls    []string `json:"controls,omitempty"`
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

    // Output with protocol envelope
    output := Output{
        Type:            "epack_result",
        ProtocolVersion: 1,
        Artifacts: []Artifact{{
            Data: evidence,
        }},
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
