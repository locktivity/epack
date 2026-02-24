# Hardening Guide

This guide focuses on minimizing attack surface when operating `epack`.

## 1. Pick the Right Binary

- Prefer `epack-core` wherever you do not need component orchestration (collectors, tools, remotes, utilities).
- Use full `epack` only on hosts that must run components.

Security impact:
- `epack-core` removes downloader + subprocess execution paths entirely.
- No component binaries can be installed, synced, or executed.

## 2. Understand Component Verification

Source-based components (those with `source:` in config) are verified with SLSA Level 3 provenance:

- **Sigstore signature** must come from the declared GitHub repository
- **Certificate issuer** must be GitHub Actions OIDC
- **Binary digest** must match the lockfile
- **Signer identity** must match what was recorded at lock time

This verification happens automatically during `epack sync`. See [Concepts: SLSA Level 3 Verification](concepts.md#slsa-level-3-verification) for details.

**External binaries** (those with `binary:` in config) are only digest-verified, not signature-verified.

## 3. Treat Components as Untrusted Code

Collectors, tools, remotes, and utilities are all third-party binaries. When using `epack` (full):

- Run components on dedicated hosts or ephemeral CI runners.
- Use least-privilege credentials (read-only scopes, no write APIs).
- Filter network egress with a domain-allowlisting proxy.
- Do not run components as root.
- Use AppArmor/seccomp to restrict filesystem and syscall access.

**Component-specific guidance:**

| Component | Key Risks | Mitigations |
|-----------|-----------|-------------|
| Collectors | API credential access, network egress | Least-privilege tokens, egress filtering |
| Tools | Pack content access, output file creation | Sandboxed execution, output directory restrictions |
| Remotes | Registry credentials, network access | Scoped auth tokens, TLS enforcement |
| Utilities | User data access, arbitrary file operations | Install only from trusted sources |

## 4. Enforce Reproducibility

- Commit `epack.yaml` and `epack.lock.yaml`.
- Specify all CI platforms in `epack.yaml`:
  ```yaml
  platforms:
    - linux/amd64
    - darwin/arm64
  ```
- In CI, use frozen mode:
  ```bash
  epack collect --frozen
  ```
- For fine-grained control:
  - `epack sync --frozen`
  - `epack collector run --frozen`
- Require lockfile updates through code review.

## 5. Keep Unsafe Flags Disabled

Do not use these except for short-lived local debugging:

- `--insecure-skip-verify` (sync/install path)
- `--insecure-allow-unverified` (run path)
- `--insecure-allow-unpinned` (all component types) - allows execution without lockfile verification
- `--no-redact` or `EPACK_NO_REDACT` (logging path)

If used temporarily, remove immediately and rotate any potentially exposed credentials.

## 6. Harden Runtime Environment

- Pin explicit `PATH` in automation.
- Store credentials in scoped CI secrets, not shell history or dotfiles.
- Set per-collector timeouts with `epack collect --timeout` or `epack collector run --timeout`.
- Only list necessary secrets in `epack.yaml` - collectors can't access env vars not explicitly listed.
- Use specific credential names (e.g., `GITHUB_TOKEN`) rather than broad names that might be reused.

## 7. Verify Before Trusting Artifacts

- Always run `epack verify` before consuming third-party packs.
- Use identity constraints (`--issuer`, `--subject`) in policy-driven environments.
- Reject packs that fail integrity checks or violate expected identity.

## 8. Secure Remote Adapter Transport

### file:// URLs require file_root

Adapters returning `file://` URLs require `transport.file_root` to constrain file operations:

```yaml
remotes:
  local-storage:
    adapter: filesystem
    transport:
      file_root: /storage/packs
```

### HTTP loopback requires opt-in

HTTP to localhost is disabled by default. Enable only for local development:

```yaml
remotes:
  local-minio:
    adapter: s3
    transport:
      allow_loopback_http: true
```

Note: Authentication headers are never sent over HTTP.

## 9. Component Catalog and Installation

The catalog is for discovery and display only. Execution decisions come from lockfiles.

**Project components (collectors, tools, remotes):**
- Review new components before adding them to `epack.yaml`
- Use `--dry-run` with `epack install` to preview dependencies before installation
- Review transitive dependencies that will be installed (shown in dry-run output)
- After installation, review and commit lockfile changes (`epack.lock.yaml`)

**User utilities:**
- Utilities are installed globally to `~/.epack/` and tracked in `~/.epack/utilities.lock`
- Use `epack utility install <name>` with the same verification as project components
- Run `epack utility list` to audit installed utilities
- Remove unused utilities with `epack utility remove <name>`

## 10. Recommended Workflow Split

- **Collection stage**: full `epack` on isolated runner (`epack collect --frozen`).
- **Tool analysis stage**: full `epack` in sandboxed environment for policy checks.
- **Review/sign stage**: restricted environment with signer controls.
- **Consumer/verification stage**: `epack-core` in CI and audit tooling.

## 11. Local Development vs CI

- **Local development**: Use `epack collect` (auto-locks, auto-syncs).
- **CI pipelines**: Use `epack collect --frozen` (strict verification, no network downloads).
- When the lockfile is updated locally, commit it before pushing to CI.
