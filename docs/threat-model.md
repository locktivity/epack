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
- Configuration, hooks, and lockfiles a remote hands over through `config.pull`, and the sign-in instructions it returns from `auth.login`.

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
- Operate a remote the person signed in to, or hold an admin account on one, and hand over hostile configuration.

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

## Remote-Authored Configuration

`epack remote clone <name>` and `epack run <name>` fetch a project from a remote through `config.pull` and run it. That makes the remote a configuration author with most of the powers the section above gives the operator: its `epack.yaml` decides which collectors and tools run and which `secrets:` reach them, and its lockfile decides which binaries are installed. In CI the lockfile pull request gives a person a look at every change. On a laptop the review is the summary epack prints after each fetch that changed something, and the person who signs in trusts the remote and the admins who configure it.

**What epack enforces regardless:**

- The adapter that performs `config.pull` is itself locked and digest-verified before it runs, and a project's own adapter configuration takes precedence over an adapter installed for the user.
- Written paths stay inside the folder, carry no control characters, and have no hidden segments other than `.locktivity/` and `.epack/hooks/<name>.sh`. A remote cannot write into `.epack/collectors/`, `.epack/remotes/`, or `.git/`, so it cannot plant a binary that sync would treat as already verified or a hook git would run.
- The folder is named by the person, never by the response, and a symlinked folder is refused.
- Every binary the lockfile names is still downloaded through the registry and checked against the Sigstore identity recorded in the lock before it runs.
- Managed files the person edited are never overwritten without `--force`. A hook script follows the remote's template only until the person edits it, and a hook that still matches the delivered template is never run, by `epack run` or by `epack hooks run`. A fetched configuration therefore cannot run shell on the machine; only the person's own hooks do.
- After a fetch that changed the configuration, epack prints what it will run and read, derived from the written files: each collector, tool, and remote with its publisher and version, the environment variables it reads and which are set, and whether the hooks are still templates. A later revision prints only the differences.
- Strings from the remote are stripped of control and formatting characters before they reach the terminal, and the sign-in link is opened only when it is an http or https URL. The browser sign-in listens on 127.0.0.1 only and for a bounded time, acts only on the first callback that carries the sign-in's state, and never prints or logs the code or the adapter's session.
- Adapters installed for the user are locked from the catalog once, with the source repository shown and recorded, and never upgraded on their own.
- A fetched configuration runs binaries only from publishers the person or the job named. A publisher is the GitHub owner of a component's source repository, the identity Sigstore attests when the binary is installed. `epack remote login` records the adapter's publisher as trusted, since signing in already means trusting what that publisher's remote sends. Before the install stage of `epack run`, a folder that carries a pull record must draw every collector, tool, and remote from a trusted publisher: in a terminal a new publisher is shown with its repositories and trusted once on a yes, recorded in `~/.epack/config.yaml`; without a terminal the run stops before any download and names `EPACK_TRUSTED_PUBLISHERS`. That variable and a repeatable `--trust-publisher` add trust for one process, `--yes` never widens it, and a fetched configuration that names a `binary:` is refused. In CI, trust therefore comes from the job environment, never from fetched files or from `--yes`. Folders without a pull record, which is every committed repository, are unaffected.

**What remains the person's trust decision:** the collectors, tools, secrets, and hooks the remote names, within the publishers they trusted. A compromised remote account can still direct a laptop run to exfiltrate any environment variable the configuration lists to a collector from a trusted publisher. Treat admin access on the remote accordingly.

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
- A `config.pull` response with hidden paths, traversal, control characters, a hostile folder name, or a symlinked target folder (all refused).
- An `auth.login` response with a non-web link, an unbounded lifetime, or terminal escape sequences in the link, and terminal escape sequences in the signed-in subject or a callback's error description.
- A sign-in callback with a wrong state, on another path, or after the sign-in finished (turned away without reaching the adapter).

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
