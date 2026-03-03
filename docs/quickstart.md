# Quickstart

Build, sign, and verify your first evidence pack.

## Install

```bash
brew install locktivity/tap/epack
```

Or with Go:

```bash
go install -tags components github.com/locktivity/epack/cmd/epack@v0.1.23
```

For a minimal verify-only build (no component commands), install without tags:

```bash
go install github.com/locktivity/epack/cmd/epack@v0.1.23
```

## Create a Project

```bash
epack new my-project
cd my-project
```

This creates a project with a sample pack you can explore immediately:

```
my-project/
├── epack.yaml      # Configuration
├── sample.epack    # Demo pack to explore
└── packs/          # Output directory
```

## Explore the Sample Pack

Inspect the pack contents:

```bash
epack inspect sample.epack
```

```
Evidence Pack: sample.epack

  Stream:        demo/sample/quickstart
  Pack Digest:   sha256:7395a655...
  Generated At:  2025-02-24T03:16:46Z

Sources
  sample-generator v1.0.0

Artifacts (3)
  artifacts/compliance.json    623 B  application/json
  artifacts/dependencies.json  394 B  application/json
  artifacts/system-info.json   179 B  application/json

Attestations (0)
  none
```

Verify the pack integrity:

```bash
epack verify sample.epack
```

```
✓ Verification passed

  Artifacts:     3 verified
  Attestations:  none
```

List the artifacts:

```bash
epack list artifacts sample.epack
```

## Build Your Own Pack

Create some evidence files:

```bash
echo '{"mfa_enabled": true, "sso_configured": true}' > security.json
echo '{"packages": 42, "vulnerabilities": 0}' > deps.json
```

Build a pack:

```bash
epack build my-evidence.epack *.json --stream myorg/security
```

## Sign the Pack

Sign with Sigstore (opens browser):

```bash
epack sign my-evidence.epack
```

Your browser opens for OIDC authentication. Sign in with Google, GitHub, or Microsoft.

## Verify with Identity

Verify the signature and enforce who signed it:

```bash
epack verify my-evidence.epack \
  --issuer "https://accounts.google.com" \
  --subject "you@example.com"
```

```
✓ Verification passed

  Artifacts:     2 verified
  Attestations:  1 verified
    Signer: you@example.com
    Issuer: https://accounts.google.com
```

## What's Next

- **Automated collection**: Edit `epack.yaml` to configure collectors, then run `epack collect`
- **Compare over time**: Use `epack diff old.epack new.epack` to see changes
- **Share packs**: Configure a remote in `epack.yaml` to push/pull packs
- **CI/CD**: Use `epack collect --frozen` for reproducible builds

## Learn More

- [Concepts](concepts.md): How evidence packs work
- [Hardening](hardening.md): Secure deployment practices
