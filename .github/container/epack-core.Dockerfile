FROM scratch
ARG TARGETARCH
COPY binaries/epack-core-linux-${TARGETARCH} /usr/local/bin/epack-core
ENTRYPOINT ["/usr/local/bin/epack-core"]
