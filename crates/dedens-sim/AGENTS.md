# dedens-sim

Simulation tests (D133): the sans-IO cores, `dedens_net::exchange` and `dedens_server::Pipeline`, as hosts of a
seeded [turmoil](https://docs.rs/turmoil) network. Test-only, `publish = false`; the driver in `src/` mirrors
`dedensd`'s glue and leaves out what D133 lists. Scenarios use captured responses (`crates/dedens-proto/tests/testdata`,
`crates/dedens-dnssec/tests/testdata`).

- `src/seed.rs`: `Seed`, `each` (runs a scenario under the fixed seeds, `DEDENS_SIM_SEED` or `DEDENS_SIM_RUNS`, and
  prints a failing seed), `in_two_processes`, `Rng` (IDs, cookies and fault times of a host).
- `src/client.rs`: `Client`, one `Exchange` over turmoil UDP and TCP as the real client runs it (cookies, TCP retried
  once on a new connection, `ClientError`s); `Carrier`.
- `src/resolver.rs`: `Resolver`, a `Pipeline` served on port 53 as `dedensd`'s `start` and `answer` do (D45's stale
  timer, `abandon`, D91's drops); `pipeline`, `pipeline_with`, `pipeline_forwarding`, `pipeline_validating`, `wall_clock`.
- `src/upstream.rs`: `Answers`, `serve`: an upstream server answering from captured responses (cut to the query's
  EDNS size, REFUSED for a question it holds nothing for, no signatures without DO); `Verdict`, `Behaviour`.
- `src/oracle.rs`: `Expected`, `Rules`, `judge`: what a client may get.
- `src/stub.rs`: `Stub`, a client asking the resolver, with the oracle's `CheckError`s and `Outcome`s.
  `ask` accepts any I/O error as `Outcome::Io`: only `expect` and the scenario assert on it.
- `src/topology.rs`: `Topology`, `World`: hosts, `fault`, `pick`, `choose`, `run`.
- `src/fault.rs`: `Fault`, `Node`, `Server`: what a scenario does to the network and the hosts.
- `src/attacker.rs`: `Attacker`, `Reaction`, `Injection`: datagrams sent from an upstream server's own socket.
- `src/trace.rs`: `Trace`, `Event`, `What`, `digest`: what the hosts did, in order, for assertions and for comparing
  runs.
- `src/port.rs`, `src/framing.rs`: port 53 over UDP and TCP with its tasks; the 2-byte TCP framing.
- `tests/baseline.rs`: perfect network, then each fault and the attacker once, then the seed picking the faults.
- `tests/partition.rs`: upstream servers and clients cut off, healed and held; the seed cuts and heals links.
- `tests/replay.rs`: one seed in two processes gives one trace.
- `tests/loss.rs`: loss, delay and reordering on the stub's and the upstream's links; the seed picking both.
- `tests/crash.rs`: each host crashing or restarting under queries in flight, over UDP and TCP.
- `tests/forged.rs`: forged and duplicated responses from an attacker on the upstream's host; the seed draws them.

What a scenario uses, so that it adds test files and no driver code:

- Faults, `World::fault(at, fault)` with `at` from `World::pick(from, to)` (`World::choose` picks among faults or
  hosts): `Loss`, `Latency`, `Partition` and `Repair`, `PartitionOneWay` and `RepairOneWay`, `Hold` and `Release`,
  `Crash` and `Bounce` (a `Server`: its memory is gone). turmoil's loss is not a packet at a time: each message sent
  breaks the link with probability `rate`, which loses what is on it and the message; the next message repairs it
  with `Topology::repair_rate` (1 by default, so at rate 1 about half the messages arrive). It undoes a one-way
  partition, so the two do not share a link. A lost TCP segment is not sent again: the stream stalls. `Latency`
  draws a message's delay from `min` toward `max` (exponentially, mostly near `min`): messages reorder, TCP segments
  are put back in order. `Repair` does not deliver what `Hold` kept; `Release` does.
- Attacker: `Answers::attacked_by(Attacker::new(|seen| ..))` returns a `Reaction` for each query `seen` (the query,
  its sender and the genuine answer): `Reaction::beside(injections)` races the server's answer,
  `Reaction::instead(injections)` silences it. An `Injection { after, wire }` leaves from the server's own port 53
  socket, so the source address is the server's: a spoofed source is out. turmoil gives ephemeral ports in sequence: a scenario of
  forged answers that must guess the resolver's port may as well know it.
- Upstream server faults: `Answers::faulty(|question, rng| Verdict)` sends, drops or delays each response from the
  host's own seeded stream; `silent` sends none over UDP; `tcp(Behaviour::{Answer, Silent, Close(n)})` answers,
  ignores or closes after `n` queries of a connection.
- Resolver: `Topology::resolver(|upstreams| pipeline)` builds the pipeline at each start (stages, access lists, rate
  limits, cookies, a validator). A cache in it must have `shards: 1`: `pipeline_with`, `pipeline_forwarding` (a `Forward` of the
  scenario's timeout and tries) and `pipeline_validating` force it. A validating stage takes `wall_clock()` as its clock, with `Topology::epoch` at the time of the
  captures (`captured_at` of `crates/dedens-dnssec/tests/testdata`). The oracle's `Rules::floor` and `stale_ttl`
  must be the cache's `min_ttl` and `stale_answer_ttl` where the scenario changes them. A forward target other than
  plain DNS panics. `Answers::file`,
  `directory` hold any captures (`<id>.bin` of `crates/dedens-dnssec/tests/testdata` too); `Answers::cookies` has the
  server set a cookie of its own.
- Clients start 5 ms into the run, after the hosts bound their ports (turmoil starts hosts in no fixed order, and a
  datagram to a port not bound yet is lost). `World::client`, or `World::client_at(ip, ..)` for sources in chosen networks (outside 192.168.0.0/16,
  where the other hosts are). `Stub::payload` sets the EDNS size of its queries (a small one has the resolver truncate
  and the stub ask again over TCP), `Stub::ask_query` sends a query of its own to any server, `Stub::options` the tries and timeouts, `Stub::rules` what the oracle accepts
  besides the data (`accept` response codes, `authentic` for AD, `dnssec` to set DO, `live`); `Stub::expect` fails on
  SERVFAIL and on no response.
- Trace: `Sent` (each send of an exchange, with its ID and its count), `Served` (an upstream server answered),
  `Stored` (the cache grew), `Replied` (the resolver answered, stale or not), `Answered`, `Failed`, `Errored`,
  `Injected`, `Fault`, with the length of each message.
- `Topology::epoch` sets the start date (`turmoil::since_epoch`, for signatures valid for one date; 2026-01-01 by
  default), `duration` the length of a run, `repair_rate` the loss's repair.
- `World::sim` for what `Fault` does not say.

Rules for a driver and a scenario:

- Every `select!` is `biased`: tokio's picks the order of its branches from a generator that is not seeded, and a
  run must replay.
- Every task is spawned into a `JoinSet` (`Port::spawn`): a panic in a task fails the run.
- Scenarios go through `seed::each`, never a literal seed alone.
- A scenario that needs something the driver lacks adds it to `src/` here, small, rather than a copy in `tests/`.
- A `HashMap` or a clock in the driver would break replay: `BTreeMap`, and `tokio::time` only. Stages that hash with a
  per-process seed (rate limits, budgets, the blocklist) and the validator's hash maps are D133's determinism list: a
  family that adds one calls `seed::in_two_processes` from its own file, with a scenario that uses it.

Families of tests, each in its own `tests/<family>.rs`: scripted tests under fixed seeds, which `just check` runs in
under 2 s for the family (this crate under 10 s); one property test where the seed picks the faults, which `just sim`
runs under many random seeds; and one `seed::in_two_processes` test. A failing seed becomes a fixed seed of the
scripted tests, with a comment naming what it caught.
