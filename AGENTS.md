# dédéns

DNS library, the dig-like CLI `dedens` and the server `dedensd`. Write the ASCII `dedens` wherever "é" is not
allowed. [`ARCHITECTURE.md`](ARCHITECTURE.md) maps the crates and documents; the `//!` docs say what each module
holds; a folder's `AGENTS.md` holds what its code cannot say: invariants, traps, where a change must also go.

Read the decisions' index, `docs/decisions/README.md`, before any task, then the section files the task touches.
Record a new or changed decision in the same change as the code, in its section file and the index, by the index's
rules (`crates/dedens-repo/tests/repo.rs` checks them, D140, D171). Open questions go to `docs/TODECIDE.md`.

`PLAN.md` and `plan/` are local and git-ignored: phase order and each phase's "Done when". Read `PLAN.md` when
present; anything worth keeping goes to `docs/`.

## Rules

- Write Rust per the `rs-coding` skill, and agent-facing documents (`AGENTS.md`, `ARCHITECTURE.md`, `PLAN.md`,
  `docs/`) per the `writing-for-agents` skill: small, concise, one source of truth. Each `AGENTS.md` has a
  `CLAUDE.md` symlink beside it.
- Work from the RFC text in `docs/rfc/archive/rfcNNNN.txt` and cite RFC and section in the docs of each item
  implementing one. When an RFC section lands, update its row in `docs/rfc/coverage.md` in the same change (`repo.rs`
  checks the row's paths, and that each RFC a test file cites in its module docs has a row naming it).
  A package's integration tests are one binary, `tests/tests.rs`, a module per topic citing its RFCs and sections in
  its docs; a new test of an RFC section starts with it (`s4_1_4_...`) (D162). Its insta snapshots are in
  `tests/snapshots/`, named `tests__<module>__<test>`; after a review, accept a change with
  `INSTA_UPDATE=always cargo test -p <package>`.
- Test data is real: captured responses and RFC example zones, never invented bytes. A parser of outside data
  gets a fuzz target. A performance claim gets a bench, recorded in `docs/benchmarks.md`.
- `unsafe` belongs to a hot path a bench has measured: a `// SAFETY:` comment on each block, a Miri job for the
  crate, and `just rapx` read before committing.
- Call the justfile's pinned `nightly` the way the justfile does (`rustup which`, `rustup run`): a Homebrew
  cargo may shadow rustup's.
- A change is done when `just check` (the gate) passes.
- `just mutants-diff <base>` lists the changed code no test catches, as the pull request's `mutants` job does (D103,
  informational, outside the gate); a mutant no test can observe goes in `.cargo/mutants.toml` with its reason.
  `just mutants-stale` names the patterns there that match no mutant any more (D168).
- Commit per phase step with the `git-commit` skill; the human pushes. CI requires Conventional Commit subjects
  (`type(scope)!: description`; types feat, fix, docs, style, refactor, perf, test, build, ci, chore, revert).
