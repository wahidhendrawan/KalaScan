# ---- Stage 1: Build ----
FROM rust:1.97-slim-bookworm AS builder

WORKDIR /app

RUN apt-get update -qq && \
    apt-get install -y -qq --no-install-recommends pkg-config libssl-dev git && \
    rm -rf /var/lib/apt/lists/*

# Cache deps
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src templates && \
    echo 'fn main() {}' > src/main.rs && \
    echo '' > src/scanner.rs && \
    echo '' > src/ai_analyzer.rs && \
    cargo build --release --locked && \
    rm -rf src

COPY src/ src/
COPY templates/ templates/

RUN touch src/main.rs src/scanner.rs src/ai_analyzer.rs && \
    cargo build --release --locked

# ---- Stage 2: Runtime ----
FROM debian:bookworm-slim

RUN apt-get update -qq && \
    apt-get install -y -qq --no-install-recommends ca-certificates git && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/kalascan /usr/local/bin/kalascan
COPY templates/ /app/templates/

WORKDIR /app
EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -sf http://127.0.0.1:3000/ || exit 1

ENTRYPOINT ["kalascan"]
