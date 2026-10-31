FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        coreutils \
        nodejs \
        python3 \
        python3-setuptools \
        strace \
    && rm -rf /var/lib/apt/lists/*

LABEL org.opencontainers.image.title="kalascan-sandbox"
LABEL org.opencontainers.image.description="Minimal isolated runtime for KalaScan opt-in sample execution and install-hook tracing"
LABEL org.opencontainers.image.source="https://github.com/wahidhendrawan/KalaScan"

WORKDIR /work

CMD ["sh", "-c", "echo 'kalascan sandbox image'; exec sh"]
