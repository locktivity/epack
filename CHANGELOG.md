# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.9.4] - 2026-10-21

### ENHANCEMENTS

- collectortest: `Record` can record CBOR responses, such as those from AWS
  services on the Smithy RPC v2 CBOR protocol. It decodes each
  `application/cbor` body and scrubs its strings, map keys, and integers with
  the same rules as text bodies. The scrub check reads the decoded body too,
  and a body that does not decode fails the recording
- collectortest: recordings store a body that is not UTF-8 as base64 with
  `"body_encoding": "base64"`. Replays return the same bytes
- collectortest: the sensitivity check changes CBOR responses the same way it
  changes JSON responses. It used to skip them and list the operation as
  unmutated

### BUG FIXES

- epack is built with Go 1.26.10, which fixes GO-2026-6809 in `crypto/x509`

### UPGRADE NOTES

- collectortest imports `github.com/aws/smithy-go`. After bumping epack in a
  collector, `go mod tidy` adds it as an indirect requirement

## [0.9.3] - 2026-10-20

### BUG FIXES

- `epack sdk map` finds the code behind the fields of a type whose
  `MarshalJSON` marshals the value as a local type with the same fields, such
  as `type entry Entry` and then `json.Marshal(entry(e))`. This also works when
  the method deletes keys from the result, or embeds the value in a struct
  that overrides a field's `json` tag to drop `omitempty`

## [0.9.2] - 2026-10-20

### BUG FIXES

- `epack sdk map` finds the code behind a field whose type has a
  `MarshalJSON` of exactly `return json.Marshal(v.Field)`, such as a generic
  `Lookup[T]` that encodes as its record, and behind the fields under it.
  It used to stop at any type with its own `MarshalJSON`
- `epack sdk map` finds a write through a generic type that two of the
  collector's packages instantiate with the same type arguments

### ENHANCEMENTS

- `epack sdk map` prints a warning on stderr for each field that operations
  feed but that has no code. The warning does not change the exit code

## [0.9.1] - 2026-10-20

### BUG FIXES

- `epack verify --json` writes `log_id` as the log's hex-encoded key ID, such
  as Rekor's `c0d23d6a...`, instead of raw bytes

## [0.9.0] - 2026-10-20

### NEW FEATURES

- **Traceable run records** - Collectors on this SDK record enough about each
  run to trace a value to the calls and code behind it:
  - Request rows gain `call`, `step`, `start_ms`, `waited_ms`, and
    `vendor_code`, which the new `HTTPOptions.VendorCode` hook reads. Past
    the first 1,000 rows, up to 1,000 more failed or retried rows are kept,
    and `problem_requests_dropped` counts the ones left out
  - `componentsdk.StartStep` names the steps of a run, and the result lists
    each step's timing, requests, retries, and operations at every level
  - Gaps gain `operation`, `call`, `source`, `missing_permission`, and
    `warning`, with `componentsdk.ResponseError`, the `MissingPermission` and
    `Warning` gap options, and `Recorder.Helper`
  - `signed_in_as` gains `auth_method`, `requested_scopes`, and `read_only`
- **Build file** - Each run adds `artifacts/<collector>.collector-build.json`
  (`evidencepack/collector-build@v1`) with the collector's schemas and trace
  map. Its bytes are the same for every run of one build
- **Trace maps** - `epack sdk map` builds a collector's trace map from its
  collectortest suites and source: for each output field, the operations
  that feed it and the code lines that compute it. `--check` fails on a stale
  map, and collector CI gains a `trace-map` job that runs it
- **Checkable arithmetic** - `x-epack-numerator` and `x-epack-rounding`
  (`floor`, `ceil`, or `nearest`) schema keywords, and a `ratios` output check
  that each percentage matches its numerator and denominator
- **Signature details in `epack verify`** - Each signature's log entry, CI
  run, and source commit, in text output and as `log_index`, `log_id`, and
  `certificate` in `--json`, offline too
- **Conformance checks COL-075 to COL-080** - Run records and build files
  match their schemas and agree with each other, and nothing audit-only
  appears at the trust level. Each check skips what a collector does not
  write, so results from older SDKs pass

### ENHANCEMENTS

- collectortest: `Suite.GapOperations` checks that each fault's gaps name the
  faulted operation, a committed trace map is checked on every suite run, and
  `COLLECTORTEST_MAP` exports the traces `epack sdk map` reads
- The rollups check skips rows the run's level leaves out
- DNS lookups and dials get a call number, start time, and step
- `epack-collector-diff` ignores build files, so moving a line of collector
  code is not an evidence change
- `epack sdk new collector` scaffolds steps, a whole-number percentage with
  its numerator and rounding, the vendor code hook, and a committed trace map
- Suites with a large trace map run faster: the kit validates the build file
  once per suite, and only scenario runs carry the map

### UPGRADE NOTES

- A collector on this SDK adds a build file to every pack. Tests that count
  its artifacts see one more, and tools that list evidence may want to skip
  it, as they skip the collector result
- Errors from the SDK's HTTP transport now wrap their cause, so find it with
  `errors.As` or `errors.Is` rather than a type assertion
- `StartStep` prints the step's title as a status line, so drop status lines
  that repeat it
- Call `Recorder.Helper()` in a collector's own gap-recording helpers, or a
  gap's `source` names the helper instead of its caller

## [0.3.2] - 2026-09-03

### NEW FEATURES

- **Control Mappings** - Seal publisher-authored evidence-to-control mappings
  (`evidencepack/control-mapping@v1`) into packs:
  - `mappings:` section in `epack.yaml` declaring local mapping files
  - Mapping files are locked by digest in `epack.lock.yaml`, drift-checked,
    and verified under `--frozen`
  - `epack collect` seals each mapping into the pack as an ordinary embedded
    artifact (`artifacts/<name>.json`) stamped with the mapping schema; YAML
    input is emitted as deterministic JSON
  - `epack build --mapping <path>` seals a mapping in the core build path
  - Build-time warnings (never failures) for malformed entries, entries citing
    artifacts the pack does not carry, and mappings pinned to a profile digest
    that matches no locked profile
  - `epack inspect` shows a Control Mappings section; the collect summary
    reports sealed mapping entries
  - Lock provenance summaries gain a `mappings` section beside profiles and
    overlays

## [0.3.1] - 2026-08-25

### NEW FEATURES

- **Windows support (core build)** - `epack-core-windows-amd64.exe` and `epack-core-windows-arm64.exe` release binaries with the same SLSA Level 3 provenance as other platforms. Windows covers pack operations (build, sign, verify, inspect, list, extract, merge, diff); collector and tool execution remains macOS/Linux and fails closed on Windows

### ENHANCEMENTS

- Dependency updates for published advisories: sigstore-go v1.2.1 (multi-log threshold bypass GHSA-9vcr-p3rj-q5q6, signing key validity period GHSA-wqqc-jjcq-vfxm) and grpc-go v1.82.1 (GHSA-hrxh-6v49-42gf)
- Path validation rejects rooted paths (`/foo`, `\foo`, `C:foo`) on every platform, closing a Windows-only gap where such paths passed relative-path checks

### BUG FIXES

- Merge, `list --filter`, and `extract --filter` operate on canonical slash paths, fixing broken merges and glob matching on Windows
- Recursive `**` result globbing during push handles Windows drive-letter paths

### UPGRADE NOTES

- Config paths that begin with `/` or `\` or carry a drive prefix are rejected on every platform; use paths relative to the project root

## [0.1.11] - 2026-02-25

### NEW FEATURES

- **Unified Catalog Search** - `epack catalog search` command searches all component types (collectors, tools, remotes, utilities) with optional `--kind` filter
- **Catalog Refresh** - `epack catalog refresh` fetches latest catalog from registry with ETag/Last-Modified caching
- **Global Utility Management** - New `epack utility` command for managing user-installed utilities:
  - `epack utility install <name> <source>` - Install from GitHub releases with Sigstore verification
  - `epack utility list` - List installed utilities with version and signer info
  - `epack utility remove <name>` - Remove installed utilities
- **Utilities Lock** - Global utilities tracked in `~/.epack/utilities.lock` separate from project config

### ENHANCEMENTS

- Catalog schema extended to support all component kinds with backwards-compatible `tools` array
- `CatalogComponent` type replaces `CatalogTool` (alias maintained for compatibility)
- `SearchWithOptions()` method allows filtering search by component kind
- `AllComponents()` and `ComponentsByKind()` methods for flexible catalog queries

### UPGRADE NOTES

- The `epack tool catalog` subcommand is deprecated in favor of the top-level `epack catalog` command
- Catalog JSON format now supports `collectors`, `remotes`, and `utilities` arrays alongside `tools`

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
