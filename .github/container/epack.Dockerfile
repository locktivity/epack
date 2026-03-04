FROM scratch
ARG TARGETARCH
COPY binaries/epack-linux-${TARGETARCH} /usr/local/bin/epack
ENTRYPOINT ["/usr/local/bin/epack"]
