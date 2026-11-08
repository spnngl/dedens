# The release build and the dedensd image (D153): static musl binaries (D151) linked by lld (D150), the dependency
# list embedded by cargo-auditable, built on the architecture of the machine running this file.
#
#   binaries  the two binaries and their notices alone (just release)
#   (last)    the dedensd image, FROM scratch, run as an unprivileged user: just image

# The tag is rust-toolchain.toml's channel (checked by crates/dedens-repo/tests/repo.rs); Renovate keeps the digest.
FROM docker.io/library/rust:1.99.1-alpine@sha256:98e4492621c23872a502a7171b7d2b105fdc114276856f71051f38bf94ee26aa AS build

# lld: Alpine's own, see `.cargo/lld-cc`; ca-certificates: the bundle the image carries (D57).
RUN apk add --no-cache lld ca-certificates

# renovate: datasource=crate depName=cargo-auditable
ARG CARGO_AUDITABLE_VERSION=0.7.7
RUN cargo install cargo-auditable --locked --version "$CARGO_AUDITABLE_VERSION"
# renovate: datasource=crate depName=cargo-about
ARG CARGO_ABOUT_VERSION=0.9.3
RUN cargo install cargo-about --locked --features cli --version "$CARGO_ABOUT_VERSION"

# Constant paths and time: the binaries come out the same wherever and whenever the file runs (`.cargo/config.toml`
# remaps the paths; mimalloc's `options.c` embeds `__DATE__` and `__TIME__`, which gcc takes from this variable).
ENV SOURCE_DATE_EPOCH=0
WORKDIR /src
COPY . .
RUN target="$(uname -m)-unknown-linux-musl" \
    && cargo auditable build --release --locked --target "$target" -p dedensd -p dedens \
    && mkdir /out \
    && cp "target/$target/release/dedensd" "target/$target/release/dedens" /out/ \
    && /out/dedensd validate --config deploy/dedensd.yaml
# The notice each binary travels with: the licences of the crates it links (D158), from the sources just built.
# Offline, so no licence text comes from a crate's repository, but `cargo metadata` wants every platform's crates.
RUN cargo fetch --locked \
    && for binary in dedens dedensd; do \
        cargo about generate --locked --offline -c deploy/about.toml -m "apps/$binary/Cargo.toml" \
            -o "/out/THIRD-PARTY-$binary.txt" deploy/about.hbs || exit 1; \
    done

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
COPY --from=build /out/THIRD-PARTY-dedensd.txt /usr/share/licenses/dedensd/THIRD-PARTY.txt
COPY LICENSE /usr/share/licenses/dedensd/LICENSE
COPY deploy/dedensd.yaml /etc/dedensd/dedensd.yaml
# The source label links the package to the repository on ghcr.io, which the push needs to keep its access.
LABEL org.opencontainers.image.source="https://github.com/spnngl/dedens" \
      org.opencontainers.image.licenses="Apache-2.0"
USER 10001:10001
# Port 53 binds through the runtime's net.ipv4.ip_unprivileged_port_start (Docker sets it to 0), so the user stays
# unprivileged from the first instruction and D122's drop has nothing to do: the config sets no `user:`.
EXPOSE 53/udp 53/tcp
ENTRYPOINT ["/dedensd", "--config", "/etc/dedensd/dedensd.yaml"]
