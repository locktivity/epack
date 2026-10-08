# Container Image

`ghcr.io/locktivity/epack` carries the `epack` binary for `linux/amd64` and
`linux/arm64`; `ghcr.io/locktivity/epack-core` carries `epack-core`, the same
without collector support. Every release publishes both, tagged with the
release version, and lists each image's digest as a release asset
(`epack-image-digest.txt`, `epack-core-image-digest.txt`) so a job can pin the
image by digest rather than by tag.

## Contract

| Promise | What it means for a job |
|---------|-------------------------|
| CA certificates | TLS to GitHub, registries, and remotes works with no extra setup. |
| A shell | CI systems that run `script:` lines inside the image (GitLab CI, most Kubernetes job wrappers) have `/bin/sh`. |
| Non-root | The image runs as uid 65532 (`epack`). Any other uid works too, as long as its home is writable. |
| Two writable paths | `HOME` is `/home/epack`; epack keeps its user-level state there (`~/.epack`: adapters installed for the user, their lock, `config.yaml`). `/tmp` is scratch for locking and extraction; set `TMPDIR` to move it. The project folder holds everything else (`.epack/` inside it). Nothing else needs to be writable. |
| Working directory | `/work`. Mount or copy the project there, or `cd` to wherever the job checked it out. |
| Both architectures | One multi-arch tag; the digest asset lists the manifest list digest. |

The image sets no entrypoint other than `epack`; `docker run ghcr.io/locktivity/epack:<version> version` prints the version.

## Running read-only

The contract is checked by running the image with a read-only root
filesystem and an arbitrary uid, which is how hardened schedulers run jobs:

```sh
docker run --rm --user 65534 --read-only \
  --tmpfs /home/epack:uid=65534,gid=65534 --tmpfs /tmp \
  -v "$PWD/northwind/production:/work" \
  ghcr.io/locktivity/epack:<version> sync --locked
```

`/work` is the project folder, the only path a run writes outside `HOME` and
`/tmp`. Mount a named volume at `/home/epack` instead of a tmpfs to keep the
user-level cache between runs.

## GitLab CI

```yaml
evidence-pack:
  image: ghcr.io/locktivity/epack@sha256:<digest from the release>
  script:
    - cd northwind/production
    - epack run --yes
```

GitLab's executor runs the script with the image's user and makes the
checkout writable to it, so no `user:` override is needed.
