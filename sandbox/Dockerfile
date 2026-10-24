FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        coreutils \
        strace \
    && rm -rf /var/lib/apt/lists/*

LABEL org.opencontainers.image.title="kalascan-sandbox"
LABEL org.opencontainers.image.description="Minimal isolated runtime for KalaScan opt-in sample execution"
LABEL org.opencontainers.image.source="https://github.com/wahidhendrawan/KalaScan"

WORKDIR /work

CMD ["sh", "-c", "echo 'kalascan sandbox image'; exec sh"]
