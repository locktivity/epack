# Same contract as epack.Dockerfile (docs/container-image.md), without collectors.
FROM alpine:3.21
ARG TARGETARCH
RUN apk add --no-cache ca-certificates \
 && addgroup -S -g 65532 epack \
 && adduser -S -u 65532 -G epack -h /home/epack epack \
 && mkdir -p /work \
 && chmod 0777 /home/epack /work
COPY binaries/epack-core-linux-${TARGETARCH} /usr/local/bin/epack-core
ENV HOME=/home/epack
WORKDIR /work
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/epack-core"]
