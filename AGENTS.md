# dédéns

DNS library, dig-like CLI and, later, server. Write the ASCII `dedens` wherever "é" is not allowed.

Read `docs/decisions.md` before any task: numbered decisions (`Dn`) with their reasons. Record a new or changed
decision there in the same change as the code; mark a replaced one superseded instead of reusing its number.

Plans (`PLAN.md`, `plan/`) are local and always git-ignored: phase order and each phase's "Done when". Read
`PLAN.md` when present; keep decisions and anything worth remembering out of it, in `docs/`.

## Rules

- Write Rust per the `rs-coding` skill, and agent-facing documents (`AGENTS.md`, `PLAN.md`, `docs/`) per the
  `writing-for-agents` skill. Each `AGENTS.md` has a `CLAUDE.md` symlink beside it.
- Work from the RFC text in `docs/rfc/archive/rfcNNNN.txt`, and cite RFC and section in the docs of each item
  implementing one. When an RFC section lands, update its row in
  `docs/rfc/coverage.md` in the same change.
- `dedens-proto` is sans-IO: it encodes and decodes byte slices. Sockets, timers and compio live in `dedens-net`.
- `dedens-cache` is sans-IO too: the caller passes the time in seconds (D22).
- `dedens-proto` layout: topic modules (`name`, `header`, `message`, `wire`, `edns`), one RDATA file per type
  or per group of types sharing a format, named after the defining RFC (`rdata/rfc2782_srv.rs`,
  `rdata/rfc1035_domain_name.rs`), conformance tests per RFC (`tests/rfc1035.rs`).
- Test data is real: `just capture` saves responses into `crates/dedens-proto/tests/testdata/`, which `tests/captured.rs`
  and the fuzz smoke test (`fuzz/`, `just fuzz`) read. A parser of outside data gets a fuzz target in `fuzz/src/lib.rs`.
  `just bench` compares decoding and encoding with hickory-proto, `domain` and Go's `miekg/dns` (D14); the benches
  live in `crates/dedens-bench` so `cargo deny` checks what they pull in. `just cov` shows coverage.
- `unsafe` belongs to a hot path a bench has measured: a `// SAFETY:` comment on each block, a Miri job for the
  crate, and `just rapx` read before committing.
- Use the justfile's pinned `nightly`, called the way the justfile does (`rustup which`, `rustup run`): a
  Homebrew cargo may shadow rustup's.
- A change is done when `just check` (the gate) passes.
- Commit per phase using the `git-commit` skill; the human pushes. CI requires every commit subject to be a
  Conventional Commit (`type(scope)!: description`; types feat, fix, docs, style, refactor, perf, test, build,
  ci, chore, revert).
