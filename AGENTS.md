# dédéns

DNS library, dig-like CLI and, later, server. Write the ASCII `dedens` wherever "é" is not allowed.

Read `PLAN.md` before any task: numbered decisions, phase order, each phase's "Done when". It is git-ignored and
local; update it in the same change whenever the code deviates from it.

## Rules

- Write Rust per the `rs-coding` skill, and agent-facing documents (`AGENTS.md`, `PLAN.md`, docs reached by a
  pointer) per the `writing-for-agents` skill. Each `AGENTS.md` has a `CLAUDE.md` symlink beside it.
- Work from the RFC text in `docs/rfc/archive/rfcNNNN.txt`, and cite RFC and section in the docs of each item
  implementing one. When an RFC section lands, update its row in
  `docs/rfc/coverage.md` in the same change.
- `dedens-proto` is sans-IO: it encodes and decodes byte slices. Sockets, timers and compio live in `dedens-net`.
- `dedens-proto` layout: topic modules (`name`, `header`, `message`, `wire`, `edns`), one RDATA file per type
  named after its defining RFC (`rdata/rfc2782_srv.rs`), conformance tests per RFC (`tests/rfc1035.rs`).
- `unsafe` belongs to a hot path a bench has measured: a `// SAFETY:` comment on each block, a Miri job for the
  crate, and `just rapx` read before committing.
- Call nightly the way the justfile does (`rustup which`, `rustup run`): a Homebrew cargo may shadow rustup's.
- A change is done when `just check` (the gate) passes.
- Commit per phase using the `git-commit` skill; the human pushes. CI requires every commit subject to be a
  Conventional Commit (`type(scope)!: description`; types feat, fix, docs, style, refactor, perf, test, build,
  ci, chore, revert).
