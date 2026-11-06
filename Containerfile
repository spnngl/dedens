# The release build and the dedensd image (D153): static musl binaries (D151) linked by lld (D150), the dependency
# list embedded by cargo-auditable, built on the architecture of the machine running this file.
#
#   binaries  the two binaries alone: `--target binaries --output type=local,dest=DIR` (just release)
#   (last)    the dedensd image, FROM scratch, run as an unprivileged user: just image

# The tag is rust-toolchain.toml's channel (checked by crates/dedens-bench/tests/repo.rs); Renovate keeps the digest.
FROM docker.io/library/rust:1.99.1-alpine@sha256:98e4492621c23872a502a7171b7d2b105fdc114276856f71051f38bf94ee26aa AS build

# lld: Alpine's own, see `.cargo/lld-cc`; ca-certificates: the bundle the image carries (D57).
RUN apk add --no-cache lld ca-certificates

# renovate: datasource=crate depName=cargo-auditable
ARG CARGO_AUDITABLE_VERSION=0.7.7
RUN cargo install cargo-auditable --locked --version "$CARGO_AUDITABLE_VERSION"

# Constant paths: the binaries come out the same wherever the file runs (`.cargo/config.toml` remaps them).
WORKDIR /src
COPY . .
RUN target="$(uname -m)-unknown-linux-musl" \
    && cargo auditable build --release --locked --target "$target" -p dedensd -p dedens \
    && mkdir /out \
    && cp "target/$target/release/dedensd" "target/$target/release/dedens" /out/ \
    && /out/dedensd validate --config deploy/dedensd.yaml

# What the scratch image gets and a shell is needed to make: one unprivileged user, a directory for it to write.
RUN mkdir -p /rootfs/etc /rootfs/var/cache/dedensd \
    && echo 'dedens:x:10001:10001:dedens:/nonexistent:/sbin/nologin' > /rootfs/etc/passwd \
    && echo 'dedens:x:10001:' > /rootfs/etc/group

FROM scratch AS binaries
COPY --from=build /out/ /

FROM scratch
COPY --from=build /rootfs/etc/passwd /rootfs/etc/group /etc/
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build --chown=10001:10001 /rootfs/var/cache/dedensd /var/cache/dedensd
COPY --from=build /out/dedensd /dedensd
COPY deploy/dedensd.yaml /etc/dedensd/dedensd.yaml
# The source label links the package to the repository on ghcr.io, which the push needs to keep its access.
LABEL org.opencontainers.image.source="https://github.com/spnngl/dedens" \
      org.opencontainers.image.licenses="Apache-2.0"
USER 10001:10001
# Port 53 binds through the runtime's net.ipv4.ip_unprivileged_port_start (Docker sets it to 0), so the user stays
# unprivileged from the first instruction and D122's drop has nothing to do: the config sets no `user:`.
EXPOSE 53/udp 53/tcp
ENTRYPOINT ["/dedensd", "--config", "/etc/dedensd/dedensd.yaml"]
