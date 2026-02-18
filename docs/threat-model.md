# Threat Model

This document defines the attacker model, security objectives, and explicit non-goals for `epack`.

## System Context

`epack` has two build variants:

- `epack-core`: pack build/read/sign/verify operations only.
- `epack` (with `components` build tag): core features plus collector lock/sync/run orchestration.

The highest-risk surface is collector mode, because it downloads and executes external binaries.

## Assets We Protect

- Integrity of evidence packs (`manifest.json`, artifact digests, pack digest).
- Authenticity of signatures and identity constraints.
- Confidentiality of local credentials and secrets (env vars, tokens, keys).
- Integrity of local filesystem paths touched by build/extract/collector workflows.
- Reproducibility and trust of collector dependency state (`epack.yaml`, `epack.lock.yaml`).

## Trust Boundaries

Inputs crossing trust boundaries are treated as untrusted:

- CLI arguments and environment variables.
- Pack files and ZIP entries from external parties.
- Collector metadata, release assets, and binaries before verification.
- Collector runtime output and subprocess behavior.
- **Tool catalog data** (publisher names, descriptions, tool listings).

## Attacker Model

We assume attackers can:

- Supply malicious packs or malformed ZIP content.
- Control artifact paths and other user-facing inputs.
- Attempt path traversal, symlink abuse, and TOCTOU filesystem attacks.
- Attempt collector supply-chain compromise (malicious release asset, digest mismatch, signature confusion).
- Run a malicious collector binary if policy permits insecure install/execute modes.
- Influence runtime environment (hostile env vars, polluted `PATH`, hostile working directory).
- Trigger resource exhaustion attempts (large input, decompression abuse, hanging subprocesses).
- **Compromise or poison the tool catalog** (inject malicious tool listings, false publishers).

## Security Goals

- Fail closed on integrity/signature verification failures.
- Prevent writes or extraction outside intended directories.
- Minimize secret exposure in logs/errors by default.
- Keep unsafe behavior opt-in and explicitly named.
- Keep collector runtime separated from core pack operations.
- Preserve deterministic collector installs when using lockfile + frozen mode.

## Non-Goals

- Guaranteeing correctness or honesty of collector-produced evidence data.
- Preventing compromise of a host that already executes arbitrary untrusted code.
- Eliminating all denial-of-service vectors from local, privileged attackers.
- Defending against kernel/OS-level compromise or hardware attacks.
- **Sandboxing collector execution.** Collectors run as normal subprocesses with access to the working directory and inherited file descriptors. A malicious collector binary can read/write local files, make network requests, and perform any action the invoking user can. We verify collector binaries before execution (digest + signature), but once verified, the collector runs with full user privileges. Containment (chroot, namespaces, seccomp) is out of scope-operators requiring isolation should run collectors in containers or VMs.

## Secrets and Environment Handling

Collectors and tools only receive secrets explicitly listed in `epack.yaml`. This prevents malicious or compromised binaries from exfiltrating credentials not intended for them.

**How it works:**
- The operator lists secrets in the `secrets:` block (e.g., `GITHUB_TOKEN`, `AWS_ACCESS_KEY_ID`)
- Only those specific environment variables are passed to the binary
- All other environment variables are filtered out

**Reserved prefixes:** To prevent protocol hijacking and system compromise, these prefixes are blocked:
- `EPACK_*` - Protocol namespace (would override run_id, pack_path, etc.)
- `LD_*` / `DYLD_*` - Dynamic linker variables (could hijack binary execution)
- `_*` - Reserved by shells and runtimes

**Trust model:** The operator who writes `epack.yaml` is trusted - they control which collectors run and what credentials they receive. The protection is against malicious binaries accessing secrets not intended for them, not against malicious config authors (who already have RCE via `source:` or `binary:` fields).

## Tool Catalog Security

The tool catalog provides discovery and display functionality. Execution decisions come from the lockfile, not the catalog.

**Mitigations:**
- `internal/dispatch` cannot import `internal/catalog` (enforced by import guard test)
- Size limits prevent resource exhaustion (5 MB catalog, 64 KB metadata, 10K tools)

## Assumptions and Operational Requirements

- Operators run collectors with least-privilege credentials.
- CI and production pipelines pin configuration and use frozen lockfile flows.
- Consumers verify packs before trust decisions.
- High-assurance environments prefer `epack-core` where collectors are unnecessary.

## Resource Limits

To prevent resource exhaustion attacks, the following limits are enforced:

| Resource | Limit | Purpose |
|----------|-------|---------|
| Per-artifact size | 100 MB | Prevent single large artifact from exhausting memory |
| Pack size | 2 GB | Total pack size limit |
| Artifact count | 10,000 | Prevent manifest/ZIP central directory exhaustion |
| Manifest size | 10 MB | Prevent JSON parsing DoS |
| Compression ratio | 100:1 | Zip bomb detection |
| ZIP entries | 15,000 | Central directory DoS |
| Attestation size | 1 MB | Prevent signature parsing DoS |
| JSON nesting depth | 32 | Stack overflow prevention |
| Collector output | 64 MB each | Per-collector stdout limit |
| Aggregate collector output | 256 MB | Total retained output across all collectors |
| Collector timeout | 60s default | Prevent hanging subprocesses |
| Catalog file size | 5 MB | Prevent catalog parsing DoS |
| Catalog metadata size | 64 KB | Prevent metadata parsing DoS |
| Catalog tool count | 10,000 | Prevent search/display DoS |

## Misuse Cases to Test Continuously

- Malicious pack with traversal entries and symlink tricks.
- Collector lock/sync with tampered digests or version metadata.
- Collector execution with insecure install markers.
- Error/log paths that could leak secrets.
- Large/malformed inputs that attempt memory, CPU, or timeout exhaustion.
- Many collectors producing large outputs (aggregate budget exhaustion).
- Catalog with malicious entries attempting to influence execution (should have no effect).
- Oversized catalog files attempting DoS.

## Security Hardening Measures

### Digest Verification

Binary digests are verified using constant-time comparison (`crypto/subtle.ConstantTimeCompare`) to prevent timing side-channel attacks. Error messages only expose the expected digest (from the lockfile), not the computed digest, to avoid leaking information about binary contents.

### GitHub API Rate Limiting

The GitHub client implements token bucket rate limiting (10 requests/second with burst of 5) to:
- Prevent exhausting GitHub API limits in CI environments with parallel runs
- Avoid hitting secondary rate limits that could cause 403 responses
- Provide graceful degradation under high load

### Redaction

Output redaction is applied to error messages that may contain sensitive data:
- Bearer tokens and JWT patterns
- API keys and secrets in key=value format
- URL query parameters (token, api_key, secret, password)
- Long base64-encoded strings (excluding known safe patterns like SHA256 digests)

Redaction is enabled by default and can be disabled with `--no-redact` for debugging.

### Fuzzing Coverage

Security-critical parsing functions have fuzz tests to discover edge cases:
- `ziputil.ValidatePath` - Path traversal and encoding attacks
- `component/config.ParseConfig` - YAML alias bombs and malicious configs
- `component/config.ValidateCollectorName`, `ValidateVersion` - Name/version validation
- `component/lockfile` - Lockfile parsing edge cases
- `component/semver` - Semantic version constraint parsing
- `pack.ParseManifest` - Malformed manifest handling
- `pack/merge` - Pack merge operations
- `pack/verify` - Bundle and statement verification
- `jcsutil.Canonicalize` - JSON canonicalization edge cases
- `yamlpolicy` - YAML policy validation
- `catalog/schema` - Catalog schema parsing
- `timestamp` - Timestamp parsing and formatting
- `digest` - Digest parsing and comparison
- `safepath` - Path safety validation

Run fuzz tests with: `go test -fuzz=Fuzz ./...`
