# Both binaries, one image. They are separate processes, not separate builds - the
# control plane links the edge crate on purpose, so building them together is a single
# cargo invocation and one layer of dependencies instead of two.
#
# Which one runs is the command:
#   docker run cloudflint cloudflint-edge /etc/cloudflint/cloudflint.yaml
#   docker run cloudflint cloudflint-api 0.0.0.0:9000 /var/lib/cloudflint/cloudflint.db

FROM rust:1-slim-bookworm AS build

WORKDIR /src

# Dependencies first, in their own layer, so editing our own code doesn't rebuild the
# world. The dummy sources exist only to give cargo something to compile.
COPY Cargo.toml Cargo.lock ./
COPY crates/edge/Cargo.toml crates/edge/
COPY crates/api/Cargo.toml crates/api/
RUN mkdir -p crates/edge/src/bin crates/api/src \
    && echo 'fn main() {}' > crates/edge/src/main.rs \
    && echo 'fn main() {}' > crates/edge/src/bin/cert.rs \
    && echo 'fn main() {}' > crates/api/src/main.rs \
    && touch crates/edge/src/lib.rs crates/api/src/lib.rs \
    && cargo build --release --workspace \
    && rm -rf crates/edge/src crates/api/src

COPY crates crates
COPY rulesets rulesets
# cargo will not rebuild a source whose mtime looks older than the artefact
RUN touch crates/edge/src/lib.rs crates/api/src/lib.rs \
    && cargo build --release -p cloudflint-edge -p cloudflint-api \
    && strip target/release/cloudflint-edge target/release/cloudflint-api target/release/cloudflint-cert

# debian-slim rather than distroless or scratch: the binaries are dynamically linked
# against glibc, and TLS to an origin over https needs the system root certificates.
FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --create-home --shell /usr/sbin/nologin cloudflint \
    && mkdir -p /etc/cloudflint /var/lib/cloudflint \
    && chown cloudflint:cloudflint /var/lib/cloudflint

COPY --from=build /src/target/release/cloudflint-edge /usr/local/bin/
COPY --from=build /src/target/release/cloudflint-api /usr/local/bin/
COPY --from=build /src/target/release/cloudflint-cert /usr/local/bin/

# Nothing here needs root. Ports below 1024 are the load balancer's problem, not ours.
USER cloudflint
WORKDIR /var/lib/cloudflint

# edge traffic, edge https, edge admin (health, metrics, purge), control plane
EXPOSE 8080 8443 9001 9000

# The edge handles SIGTERM itself: drains, then exits. No init shim needed, and no
# `sh -c`, which would swallow the signal.
STOPSIGNAL SIGTERM

ENTRYPOINT []
CMD ["cloudflint-edge", "/etc/cloudflint/cloudflint.yaml"]
