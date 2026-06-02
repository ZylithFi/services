FROM rust:1-bookworm AS builder
WORKDIR /src
COPY Cargo.lock ./
COPY core ./core
COPY renewal_relayer ./renewal_relayer
RUN printf '%s\n' \
  '[workspace]' \
  'members = ["core", "renewal_relayer"]' \
  'resolver = "2"' \
  '' \
  '[workspace.package]' \
  'edition = "2024"' \
  'license = "MIT"' \
  'version = "0.1.0"' \
  'authors = ["Zylith"]' \
  > Cargo.toml
RUN cargo build --release -p zylith-renewal-relayer

FROM debian:bookworm-slim
RUN useradd --system --create-home --home-dir /var/lib/zylith-renewal-relayer zylith \
  && apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates \
  && rm -rf /var/lib/apt/lists/*
COPY --from=builder /src/target/release/zylith-renewal-relayer /usr/local/bin/zylith-renewal-relayer
USER zylith
EXPOSE 3400
ENTRYPOINT ["/usr/local/bin/zylith-renewal-relayer"]
