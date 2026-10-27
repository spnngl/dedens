# dédéns

DNS library, dig-like CLI (`dedens`) and, later, server (`dedensd`). ASCII name `dedens` wherever "é" is not allowed.

Read `PLAN.md` before any task: it holds every numbered decision, the phase order, and each phase's "Done when".
`PLAN.md` is git-ignored and local. Update it in the same change whenever the code deviates from it.

## Rules

- Write Rust per the `rs-coding` skill.
- Follow the RFCs of `docs/rfc/list.md`. Cite RFC and section in the docs of the item that implements it, and
  update its row in `docs/rfc/coverage.md` in the same change.
- Keep `dedens-proto` free of I/O; only `dedens-net` depends on the runtime (compio).
- `unsafe` only in a measured hot path: a bench shows the gain, every block has a `// SAFETY:` comment, the crate
  gets a Miri job.
- Each `AGENTS.md` has a `CLAUDE.md` symlink beside it.
- Finish a change when `just check` passes. CI also runs `just hack`, `just msrv`, `just minimal-versions` and
  `just deny`, and weekly `just rapx` (never required; when `unsafe` changes, run it and read its findings).
- Commit per phase using the `git-commit` skill; the human pushes. Pull requests fail CI unless every commit
  subject is a Conventional Commit (`type(scope)!: description`; types feat, fix, docs, style, refactor, perf,
  test, build, ci, chore, revert).

## Layout

- `crates/dedens-proto`: wire format. Topic modules (`name`, `header`, `message`, `wire`, `edns`), one RDATA file
  per type named after its RFC (`rdata/rfc2782_srv.rs`), conformance tests per RFC (`tests/rfc1035.rs`).
- `crates/dedens-net`: UDP and TCP transports.
- `crates/dedens-scenario`: query files (JSON, YAML) with expected results.
- `apps/dedens`: the CLI.

## Toolchain

Stable from `rust-toolchain.toml`; MSRV is `rust-version` in `Cargo.toml`. Nightly is needed for rustfmt
(`rustup toolchain install nightly --profile minimal --component rustfmt`). The justfile calls nightly through
`rustup which` and `rustup run`, never `cargo +nightly`, so it works when a Homebrew cargo shadows rustup's.
