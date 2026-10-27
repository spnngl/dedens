# dédéns

A DNS library and a dig-like CLI, `dedens`, written in Rust. Work in progress: nothing usable yet.

## Development

- [rustup](https://rustup.rs) and [just](https://github.com/casey/just); `just` lists the recipes, `just check` is
  the gate.
- `just toolchains`: the pinned stable (`rust-toolchain.toml`) and the pinned nightly's rustfmt (`justfile`).
- [taplo](https://taplo.tamasfe.dev) and [typos](https://github.com/crate-ci/typos), for `just check`:
  `brew install taplo typos-cli` or `cargo install taplo-cli typos-cli`.
- Optional, for `just hack`, `just msrv` and `just deny`: `cargo install cargo-hack cargo-deny`.
- Optional, for `just rapx` (static analysis): Z3 (`brew install z3`), then `just rapx-install`.

Design decisions: [`docs/decisions.md`](docs/decisions.md). RFC coverage:
[`docs/rfc/coverage.md`](docs/rfc/coverage.md).

## License

Apache-2.0.
