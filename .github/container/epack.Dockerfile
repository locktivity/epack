# The image contract (docs/container-image.md): CA certificates, a shell for
# CI job scripts, a non-root user, and two writable paths: HOME for the
# cache and /tmp for scratch.
FROM alpine:3.21
ARG TARGETARCH
RUN apk add --no-cache ca-certificates \
 && addgroup -S -g 65532 epack \
 && adduser -S -u 65532 -G epack -h /home/epack epack \
 && mkdir -p /work \
 && chmod 0777 /home/epack /work
COPY binaries/epack-linux-${TARGETARCH} /usr/local/bin/epack
ENV HOME=/home/epack
WORKDIR /work
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/epack"]
