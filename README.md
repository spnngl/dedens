# dédéns

A DNS library, a dig-like CLI, `dedens`, and a server, `dedensd`, written in Rust. Work in progress, not
released.

- `dedens`: dig's arguments (`@server name type +opts`) and long flags, over UDP, TCP, TLS (`+tls`,
  `tls://host#name`), QUIC (`+quic`, `quic://host#name`) and DoH over HTTP/3 (`+https`, `https://host/path`), and, built with the experimental `doc` feature, unprotected DoC
  (`+coap`, `coap://host/path`);
  several servers, `--repeat`, `+trace`, `-x`; human, short, JSON and YAML output; YAML query files with
  expectations (`dedens --help`).
- `dedensd`: a caching forwarder (serve-stale, prefetch) with hosts and blocklist stages, listening on UDP, TCP,
  TLS, QUIC and DoH over HTTP/3 (and `coap://` with the `doc` feature), asking upstreams over any of them but CoAP; one YAML file, reloaded on SIGHUP
  (example and keys in `apps/dedensd/src/config.rs`).

## Development

- [rustup](https://rustup.rs) and [just](https://github.com/casey/just); `just` lists the recipes, `just check` is
  the gate.
- `just toolchains`: the pinned stable (`rust-toolchain.toml`) and the pinned nightly's rustfmt (`justfile`).
- [taplo](https://taplo.tamasfe.dev) and [typos](https://github.com/crate-ci/typos), for `just check`:
  `brew install taplo typos-cli` or `cargo install taplo-cli typos-cli`.
- Optional, for `just hack`, `just msrv` and `just deny`: `cargo install cargo-hack cargo-deny`.
- Optional, for `just cov`: `cargo install cargo-llvm-cov`; for `just fuzz` and `just fuzz-all`:
  `cargo install cargo-fuzz`.
- Optional, for `just rapx` (static analysis): Z3 (`brew install z3`), then `just rapx-install`.

Crates, data flow and documents: [`ARCHITECTURE.md`](ARCHITECTURE.md).

## License

Apache-2.0.
