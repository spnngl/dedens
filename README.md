# dédéns

A DNS library, a dig-like CLI, `dedens`, and a server, `dedensd`, written in Rust. Work in progress, not
released.

- `dedens`: dig's arguments (`@server name type +opts`) and long flags, over UDP, TCP, TLS (`+tls`,
  `tls://host#name`), QUIC (`+quic`, `quic://host#name`) and DoH over HTTP/3 (`+https`, `https://host/path`), and, built with the experimental `doc` feature, unprotected DoC
  (`+coap`, `coap://host/path`, or `+doc-discover` to find the path in the server's `/.well-known/core`);
  several servers, `--repeat`, `+trace`, `-x`; human, short, JSON and YAML output; YAML query files with
  expectations (`dedens --help`).
- `dedensd`: a caching forwarder (serve-stale, prefetch) with hosts and blocklist stages, listening on UDP, TCP,
  TLS, QUIC and DoH over HTTP/3 (and `coap://` with the `doc` feature), asking upstreams over any of them but CoAP; one YAML file, reloaded on SIGHUP
  (example and keys in `apps/dedensd/src/config/mod.rs`). On Linux it needs kernel 6.0 or later for `io_uring`; on an
  older one, or where `io_uring` is refused, it serves on `poll`, slower, and warns at start (D107, D174).

## Development

- [rustup](https://rustup.rs) and [just](https://github.com/casey/just); `just` lists the recipes, `just check` is
  the gate.
- `just toolchains`: the pinned stable (`rust-toolchain.toml`) and the pinned nightly's rustfmt and rust-src
  (`justfile`).
- Linux builds link with lld (`.cargo/config.toml`, D150): rustup's toolchain carries it, nothing to install.
  Homebrew's `rust` does not: put rustup's `cargo` ahead of it in `PATH`. macOS builds link with Apple's `ld` (D166).
- `just musl <target>`: the suite on the static musl targets we ship (D151), in a `rust:alpine` container of your
  architecture (docker, or `DEDENS_CONTAINER=podman`); `just musl <target> build --release` builds them.
- `just release`: the release binaries of your architecture and their licence notices in `dist/`, built twice and
  compared; `just image`: the `dedensd` image (D153); then `just packages`: their deb and rpm (D156). A tag `v*`
  publishes all three from CI. `just man` writes the man pages again after a change to a command line (D158).
- [taplo](https://taplo.tamasfe.dev), [typos](https://github.com/crate-ci/typos),
  [cargo-shear](https://github.com/Boshen/cargo-shear) and [cargo-nextest](https://nexte.st), for `just check`:
  `brew install taplo typos-cli cargo-shear cargo-nextest` or
  `cargo install taplo-cli typos-cli cargo-shear cargo-nextest`.
- Optional, for `just hack`, `just msrv` and `just deny`: `cargo install cargo-hack cargo-deny`.
- Optional, for `just cov`: `cargo install cargo-llvm-cov`; for `just fuzz` and `just fuzz-all`:
  `cargo install cargo-fuzz`; for `just careful`: `cargo install cargo-careful`.
- Optional, for `just rapx` (static analysis): Z3 (`brew install z3`), then `just rapx-install`; for `just kani <package>`
  and `just kani-fast` (proofs): `just kani-install`.

Crates, data flow and documents: [`ARCHITECTURE.md`](ARCHITECTURE.md).

## License

Apache-2.0.
