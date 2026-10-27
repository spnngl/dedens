# dédéns

A DNS library and a dig-like CLI, `dedens`, written in Rust. Work in progress: nothing usable yet.

## Development

- Rust stable (`rust-toolchain.toml`) and nightly rustfmt:
  `rustup toolchain install nightly --profile minimal --component rustfmt`.
- [just](https://github.com/casey/just); `just` lists the recipes, `just check` is the gate.
- Optional, for `just hack`, `just msrv` and `just deny`: `cargo install cargo-hack cargo-deny`.
- Optional, for `just rapx` (static analysis): Z3 (`brew install z3`), then `just rapx-install`.

RFC coverage: [`docs/rfc/coverage.md`](docs/rfc/coverage.md).

## License

Apache-2.0.
