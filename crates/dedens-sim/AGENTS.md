# dedens-sim

Simulation tests (D133), test-only: `src/lib.rs` says what the driver is, each module's `//!` doc what it offers a
scenario. A run must replay from its seed; these rules keep it so.

- Every `select!` is `biased`: tokio draws the order of its branches from a generator that is not seeded.
- A panic in any task fails the run: a server host spawns into a `JoinSet` (`Port::spawn`); a task of the
  client's pools, spawned by `Sim::spawn`, fails the `Client::exchange` that follows.
- No `HashMap` and no clock in the driver: `BTreeMap`, and `tokio::time` only.
- TLS in a scenario uses fixed certificates (`certificates` of `tests/pools.rs`), never `dedens_testkit::certificates`,
  whose keys are new on every run.
- Stages that hash with a per-process seed (rate limits, budgets, the blocklist) and the validator's hash maps are
  D133's determinism list: a family that adds one calls `seed::in_two_processes(module_path!(), ..)` from its own
  module, with a scenario that uses it.
- Scenarios go through `seed::each`, never a literal seed alone.
- A run that ends before the time of a fault fails (`World::run`): a client whose work may end first waits for
  the last fault (`sleep_until(begun + at)`, `begun` taken when its body starts).
- A scenario that needs something the driver lacks adds it to `src/`, small, rather than a copy in `tests/`.
- An upstream server or an event count two families use is in `tests/util.rs` (`answers`, `served`, `forwarded`); a
  family's own variant is named for how it differs (`forwarded_to`, `tried_over_udp`), never a shared name.
- A scenario that changes the cache's `min_ttl` or `stale_answer_ttl` sets the oracle's `Rules::floor` and
  `stale_ttl` to match.

Each family is a module `tests/<family>.rs` of the one binary: scripted tests under the fixed seeds of
`tests/util.rs`, within the time budget `just sim-time` measures (D162, D164); one property test whose seed picks
the faults, which `just sim` runs under many random seeds. A failing seed becomes a fixed seed of the scripted
tests, with a comment naming what it caught.
