# Concepts

This guide explains how epack works and the key ideas behind it.

## What is an Evidence Pack?

An Evidence Pack is a ZIP file (`.pack`) containing:

```
evidence.pack/
├── manifest.json              # Metadata and digests
├── artifacts/                 # Evidence files
│   ├── github-posture.json
│   └── aws-config.json
└── attestations/              # Sigstore signatures (optional)
    └── manifest.json.sigstore.json
```

**Key properties:**
- **Portable**: A single file you can email, upload, or store
- **Verifiable**: SHA-256 digests for every artifact
- **Signed**: Optional Sigstore attestations prove who created it
- **Diffable**: Compare packs to see what changed

## How epack Works

```
                           ┌─────────────────────────────────────────┐
                           │             Evidence Sources            │
                           │  GitHub  │  AWS  │  Okta  │  Files     │
                           └─────┬────┴───┬───┴───┬────┴─────┬──────┘
                                 │        │       │          │
                                 ▼        ▼       ▼          ▼
                           ┌─────────────────────────────────────────┐
         epack collect     │             Collectors                  │
              or           │  (Download evidence via APIs)           │
         epack build       └─────────────────┬───────────────────────┘
                                             │
                                             ▼
                           ┌─────────────────────────────────────────┐
                           │           Evidence Pack                 │
                           │  manifest.json + artifacts/             │
                           └─────────────────┬───────────────────────┘
                                             │
         epack sign                          ▼
                           ┌─────────────────────────────────────────┐
                           │           Sigstore                      │
                           │  Fulcio (cert) + Rekor (timestamp)      │
                           └─────────────────┬───────────────────────┘
                                             │
                                             ▼
                           ┌─────────────────────────────────────────┐
                           │        Signed Evidence Pack             │
                           │  manifest.json + attestations/          │
                           └─────────────────┬───────────────────────┘
                                             │
         epack push                          │         epack pull
              │                              │              │
              ▼                              ▼              ▼
         ┌────────┐                    ┌──────────┐   ┌──────────┐
         │ Remote │◄──────────────────►│ Registry │──►│ Consumer │
         │Adapter │                    │          │   │          │
         └────────┘                    └──────────┘   └──────────┘
```

## The Pack Digest

Every pack has a **pack digest** — a SHA-256 hash computed from all artifact digests:

```
Pack Digest = SHA256(
  sorted([
    "artifacts/aws-config.json:sha256:abc123...",
    "artifacts/github-posture.json:sha256:def456..."
  ])
)
```

This creates a single fingerprint for the entire pack. If any artifact changes, the pack digest changes.

## Sigstore Signing

epack uses [Sigstore](https://sigstore.dev/) for keyless signing:

1. **You authenticate** via OIDC (Google, GitHub, Microsoft)
2. **Fulcio issues** a short-lived certificate binding your identity
3. **You sign** the manifest digest with that certificate
4. **Rekor records** the signature with a timestamp

This proves:
- **Who** signed the pack (identity from OIDC)
- **When** it was signed (Rekor timestamp)
- **What** was signed (manifest digest)

No keys to manage. Signatures are verifiable forever via Rekor.

## Collectors

Collectors are standalone binaries that gather evidence from external systems:

```
┌───────────────┐     ┌────────────────────┐     ┌─────────────┐
│  epack        │────►│  epack-collector-  │────►│   GitHub    │
│  collect      │     │  github            │     │   API       │
└───────────────┘     └────────────────────┘     └─────────────┘
        │                      │
        │                      ▼
        │              JSON to stdout
        │                      │
        ▼                      ▼
┌─────────────────────────────────────────┐
│            artifacts/github.json        │
└─────────────────────────────────────────┘
```

**Collector protocol:**
- Receives config via environment variables
- Writes JSON evidence to stdout
- Exit code indicates success/failure

Collectors are Sigstore-signed and digest-pinned in your lockfile for supply chain security.

## Tools

Tools process existing packs and produce derived outputs:

```
┌─────────────┐     ┌────────────────────┐     ┌─────────────┐
│  signed     │────►│  epack-tool-       │────►│  policy     │
│  pack       │     │  policy            │     │  report     │
└─────────────┘     └────────────────────┘     └─────────────┘
```

**Tool protocol:**
- Receives pack path via `EPACK_PACK_PATH`
- Writes outputs to a sidecar directory
- Produces `result.json` with run metadata

Tools can declare dependencies on other tools (e.g., `ai` requires `index`).

## Remotes

Remotes handle publishing and consuming packs:

```
┌────────┐     push      ┌────────────────────┐     pull      ┌──────────┐
│ Local  │──────────────►│     Registry       │──────────────►│ Consumer │
│ Pack   │               │  (S3, Locktivity)  │               │          │
└────────┘               └────────────────────┘               └──────────┘
              ▲                    │                    ▲
              │                    ▼                    │
         ┌────────────────────────────────────────────────────┐
         │                Remote Adapter                      │
         │  epack-remote-s3, epack-remote-locktivity, etc.   │
         └────────────────────────────────────────────────────┘
```

Adapters handle authentication and storage. epack verifies pack integrity on pull.

## Utilities

Utilities are standalone helper applications installed globally per user:

```
┌─────────────────┐     install     ┌─────────────────────────┐
│  Catalog        │────────────────►│  ~/.epack/bin/          │
│  (discovery)    │                 │  (installed utilities)  │
└─────────────────┘                 └───────────┬─────────────┘
                                                │
                                    ┌───────────▼─────────────┐
                                    │  ~/.epack/utilities.lock│
                                    │  (digests + versions)   │
                                    └─────────────────────────┘
```

Unlike project-scoped components (collectors, tools, remotes), utilities:
- Are installed globally to `~/.epack/` rather than per-project
- Are invoked via `epack utility <name>` rather than project config
- Useful for viewing, exporting, or analyzing packs interactively

## Two Build Variants

| Variant | What it includes | Use case |
|---------|------------------|----------|
| `epack` | All components: collectors, tools, remotes, utilities | Evidence collection pipelines |
| `epack-core` | Pack operations only | Verification, CI, auditors |

`epack-core` removes all component orchestration (no subprocess execution, no binary downloads). Use it when you only need to verify packs.

## Lockfile: Pinning Dependencies

The lockfile (`epack.lock.yaml`) pins exact versions and digests:

```yaml
collectors:
  github:
    source: github.com/locktivity/epack-collector-github
    version: v1.2.3
    signer:
      issuer: https://token.actions.githubusercontent.com
      source_repository_uri: https://github.com/locktivity/epack-collector-github
    platforms:
      darwin/arm64:
        digest: sha256:abc123...
      linux/amd64:
        digest: sha256:def456...
```

This ensures:
- **Reproducibility**: Same lockfile = same binaries
- **Verification**: Digests are checked before execution
- **Auditability**: You can review exactly what runs

## SLSA Level 3 Verification

When you install a component via `source:`, epack verifies [SLSA Level 3](https://slsa.dev/spec/v1.0/levels) provenance through Sigstore:

```
┌─────────────────┐     download     ┌─────────────────────────────────────┐
│  GitHub Release │─────────────────►│  Binary + .sigstore.json bundle    │
└─────────────────┘                  └──────────────────┬──────────────────┘
                                                        │
                                     ┌──────────────────▼──────────────────┐
                                     │         Sigstore Verification       │
                                     │  1. Validate signature via TUF root │
                                     │  2. Check certificate issuer (OIDC) │
                                     │  3. Match source repository URI     │
                                     │  4. Match source repository ref     │
                                     │  5. Compare to lockfile signer      │
                                     │  6. Verify binary digest            │
                                     └──────────────────┬──────────────────┘
                                                        │
                                     ┌──────────────────▼──────────────────┐
                                     │         Execution allowed           │
                                     └─────────────────────────────────────┘
```

**What this proves:**

| Claim | Verification |
|-------|--------------|
| Binary came from declared source repo | Certificate `SourceRepositoryURI` must match |
| Binary was built at declared version | Certificate `SourceRepositoryRef` must match tag |
| Binary was built by GitHub Actions | Certificate issuer is `https://token.actions.githubusercontent.com` |
| Binary wasn't tampered with | SHA-256 digest matches lockfile |
| Signer identity is consistent | Matches signer recorded at lock time |

**This requires component authors to:**
1. Use the [SLSA GitHub Generator](https://github.com/slsa-framework/slsa-github-generator) in their release workflow
2. Attach `.sigstore.json` bundles to their GitHub releases

Components without Sigstore bundles will fail verification unless you pass `--insecure-skip-verify` (not recommended).

## TOCTOU-Safe Execution

epack prevents time-of-check to time-of-use (TOCTOU) attacks:

1. Binary is opened read-only (no symlinks)
2. Contents are copied to a sealed temp file while computing the hash
3. Hash is verified against the lockfile
4. Only the verified copy is executed

The bytes executed are exactly the bytes that were hashed.

## What's Next?

- [Quickstart Guide](quickstart.md): Hands-on tutorial
- [Hardening Guide](hardening.md): Secure deployment practices
- [Threat Model](threat-model.md): Security objectives and non-goals
