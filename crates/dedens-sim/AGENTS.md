# dedens-sim

Simulation tests (D133): the sans-IO cores, `dedens_net::exchange` and `dedens_server::Pipeline`, as hosts of a
seeded [turmoil](https://docs.rs/turmoil) network. Test-only, `publish = false`; the driver in `src/` mirrors
`dedensd`'s glue and leaves out what D133 lists. Scenarios use captured responses (`crates/dedens-proto/tests/testdata`).

- `src/seed.rs`: `Seed`, `each` (runs a scenario under the fixed seeds, `DEDENS_SIM_SEED` or `DEDENS_SIM_RUNS`, and
  prints a failing seed), `Rng` (IDs, cookies and fault times of a host).
- `src/client.rs`: `Client`, one `Exchange` over turmoil UDP and TCP, with cookies; `Carrier`.
- `src/resolver.rs`: `Resolver`, a `Pipeline` served on port 53 as `dedensd`'s `start` and `answer` do.
- `src/upstream.rs`: `Answers`, `serve`: an upstream server answering from captured responses; `Expected`, the data
  the oracle compares with.
- `src/stub.rs`: `Stub`, a client asking the resolver, and the oracle: its `CheckError`s. `Stub::payload` sets the
  EDNS size of its queries (a small one makes TC).
- `src/topology.rs`: `Topology` (upstreams, `epoch`), `World` (clients, `fault`, `pick`, `choose`, `run`).
- `src/fault.rs`: `Fault`, `Node`, `Server`: what a scenario does to the network and the hosts.
- `src/attacker.rs`: `Attacker`, `Injection`: datagrams sent from an upstream server's own socket.
- `src/trace.rs`: `Trace`, `Event`, `digest`: what the hosts did, in order, for assertions and for comparing runs.
- `src/port.rs`, `src/framing.rs`: port 53 over UDP and TCP with its tasks; the 2-byte TCP framing.
- `tests/baseline.rs`: perfect network, then each fault and the attacker once, then the seed picking the faults.
- `tests/replay.rs`: one seed in two processes gives one trace.

What a scenario uses, so it adds test files and no driver code:

- Faults, at `World::fault(at, fault)` with `at` from `World::pick(from, to)`: `Loss` (link flapping at a rate per
  tick, not a packet at a time), `Latency` (min to max a message: reordering), `Partition` and `Repair`,
  `PartitionOneWay` and `RepairOneWay`, `Hold` and `Release`, `Crash` and `Bounce` (a `Server`: its memory is gone).
- Attacker: `Answers::attacked_by(Attacker::new(|seen| ..))` returns `Injection { after, wire }`s for each query
  `seen` (it holds the query, its sender and the genuine answer); it shares the server's port, and cannot spoof a
  source address.
- Oracle: every `Stub::ask` is checked; a scenario asserts on the `Outcome` and the `Trace` beyond that.
- `Topology::epoch` sets the date of `turmoil::since_epoch`, for signatures valid for one date.
- `World::sim` for what `Fault` does not say, such as a link's fail rate for a family of its own.

Rules for a driver and a scenario:

- Every `select!` is `biased`: turmoil's random branch order is not seeded, and a run must replay.
- Every task is spawned into a `JoinSet` (`Port::spawn`): a panic in a task fails the run.
- Scenarios go through `seed::each`, never a literal seed alone.
- A scenario that needs a different upstream or fault adds to `src/` here, small, rather than a copy in `tests/`.
- A `HashMap` or a clock in the driver would break replay: `BTreeMap`, and `tokio::time` only. Stages that hash with a
  per-process seed (rate limits, budgets, the blocklist) and the validator's hash maps are D133's determinism list:
  a family that adds one runs its scenario in `tests/replay.rs`.

Each family (a step's `tests/<family>.rs`) has scripted tests under fixed seeds, which `just check` runs in under 2 s
(this crate under 10 s), and one property test where the seed picks the faults, which `just sim` runs under many
random seeds. A failing seed becomes a fixed seed of the scripted tests, with a comment naming what it caught.
