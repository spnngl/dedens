# Simulation tests

Decisions; the rules and the index are in [`README.md`](README.md).

- D133 (amends D26; amended by D134, D162, D164, D182, D202) Simulation tests: the sans-IO cores run as hosts of a simulated network,
  `turmoil` 0.7.2, so lost, late, reordered and forged packets, partitions and crashes meet the real `Exchange`,
  `Pipeline` and cache together, and a failing run replays from its seed. A crate `crates/dedens-sim`
  (`publish = false`): a test-only driver in `src/` that mirrors `dedensd`'s glue (`apps/dedensd/src/serve/`,
  `start` and `answer`) and runs `dedens-net`'s own client (D134), and one scenario family a `tests/<family>.rs`.
  The compio layer of the server stays tested over loopback (D26). What the driver offers and what a scenario uses are
  in the crate's `//!` docs, the rules for both in `crates/dedens-sim/AGENTS.md`.
  - Why turmoil: hosts crash and bounce, links partition, hold, lose and reorder, the clock is simulated and every
    random choice follows one seed. Rejected: `turmoil-net` (no crash or bounce, no per-link faults); `madsim`
    (replaces tokio and the system calls under it for the whole dependency tree); `shuttle` (explores thread
    interleavings, which D135's loom does; the network is what is missing here); running compio on turmoil as it is
    (D134 puts the client's side behind a seam); a hand-rolled event loop (the network model is the work turmoil
    already did).
  - Oracle: each query of a client ends by its deadline (the tries of its options, and one more each for the
    fallbacks) with a response that decodes, answers its question, and is one of: the data of an upstream server for
    the question (same response code and records, each once, no more authority or additional record, TTLs no higher
    than the server's, or the `floor` of the scenario's rules when it is higher, which must be the `min_ttl` of
    the pipeline's cache; the SOA of a negative answer; AD as the scenario says; RRSIG, NSEC and NSEC3 records only
    when the stub set DO, then all of the authority section's, as the upstream server sends them); a stale copy (EDE 3, RFC 8914, its TTLs bounded by
    the rules' `stale_ttl`, which must be the cache's `stale_answer_ttl`); SERVFAIL, or a response code the
    scenario accepts (never NOERROR), with no answer, no AD and no record the servers did not send; a SERVFAIL is
    refused when the scenario says the path is up; or the failure or I/O error the real client returns. A TC
    response over TCP is a failure. A panic in any task of a host fails the run.
  - Left out, as the server's compio layer's concern: D86's shared flights, the cap on connections and on upstream
    queries, `dedensd`'s few reading tasks (here a task answers each datagram), compio's timers (tokio's, which
    turmoil advances, stand in) and threads (one thread runs every host). The client's socket pools (D50), D108's
    inboxes, connection reuse and idle timeouts run on turmoil since D134. The driver forwards over plain DNS and over
    TLS, mapping each target as `dedensd`'s `target` does (D65); a pipeline whose forward targets are QUIC or HTTPS
    panics.
    A panic of a host after the last client finished is not seen, and a task that spins without waiting hangs the
    run: there is no guard.
  - What goes wrong is injected by the scenario: `Fault`s of the network and of hosts at a time it picks from the
    seed; for an upstream server, `Answers::faulty` (each response sent, dropped or delayed, from the host's seeded
    stream), `silent`, `tcp(Behaviour::{Answer, Silent, Close(n)})`, the same over TCP and over TLS (`World::dot_server`
    for a client, `Topology::dot_upstream` for the resolver, its own seeded stream, the queries of a connection
    pipelined, the fixed certificates of `dot::certificates`); an attacker on a server's socket that sends
    what the scenario gives it and may silence the server (`Reaction`). Turmoil's loss is a link going down and
    coming back, not a per-packet rate; its latency range is what reorders. A validating stage runs on the run's
    clock (`resolver::wall_clock`) from a start date `Topology::epoch` sets, so the captures of `dedens-dnssec`
    validate at the time they were made (`dedens-dnssec` is a dev-dependency of the crate).
  - Seeds: one seed drives turmoil's network, the faults a scenario has it pick, and the IDs and cookies of each
    host's queries (SplitMix64, one stream a host). `just check` runs fixed seeds; `DEDENS_SIM_SEED=<n>` one alone;
    `DEDENS_SIM_RUNS=<n>` that many random ones; a failure prints its seed, which becomes a fixed one with a
    comment on what it caught. The run starts at a fixed date (`Topology::epoch` changes it).
  - Determinism, every source that could make one seed's runs differ:
    - turmoil's rng and host order follow `rng_seed`; tokio's `select!` picks the order of its branches from a
      generator of its own, so every `select!` in the driver is `biased`. Pinned.
    - Hosts are tasks of one thread in `JoinSet`s; IDs, cookies, faults and times come from the seeded streams; the
      driver keeps no `HashMap`; `getrandom` only draws the seeds of `DEDENS_SIM_RUNS`, outside a run. Pinned.
    - Clocks: the cores read none (`Exchange` and `Pipeline` take the time as an argument; checked in
      `dedens-proto`, `-cache`, `-server`, `-dnssec` and `dedens-net`'s `exchange`); the driver passes tokio's
      simulated one. A core that read the real clock would escape simulated time: a bug here.
    - `NEXT_ID` (`crates/dedens-server/src/pipeline/mod.rs`): D118's mark of a pipeline, compared with its own entries
      only. Its value cannot change a trace.
    - D112's per-process seed of the encoder's name table: it picks slots for compression pointers, and the decoded
      content is the same; a locally built reply may differ in length by a few bytes from one process to another,
      which a trace (decoded content) does not hold. A scenario must not sit within that margin of a size limit. It
      cannot be pinned from outside; the two-process test is the check.
    - The cache's `RandomState` (the shard of a key, so which entries a full cache evicts): pinned by `shards: 1`,
      which `resolver::pipeline_with` forces and a pipeline built by hand must keep.
    - The slots of rate limits and budgets (`rrl.rs`, `budget.rs`): a scenario keys them with a fixed key
      (`with_key`), as a per-process key let two networks share a slot in one run out of a million (a CI run of
      `limits` at seed 7). The blocklist's keys, the default shares of `Validating` and `dedens-dnssec`'s `HashMap`s
      and `HashSet`s: not in the default pipeline; a family that adds them sizes the tables so that its clients do
      not share a slot, and runs `seed::in_two_processes` over its scenario.
      Lookup-only maps of `dedens-proto` and `-cache` are never iterated.
    - `seed::in_two_processes` runs a scenario here and in a second process of the test binary and compares the
      digests of the traces (`tests/replay.rs`).
  - Time: the tests of a family run under 2 s in `just check` (debug build), the crate under 10 s (12 s: D202); a
    family over the budget runs fewer fixed seeds, not a smaller scenario. `just sim-time` measures it (D164).
  - `just sim 100` runs every scenario under `runs` random seeds, as `fuzz-all` runs the fuzz targets; the
    `sim` jobs of `.github/workflows/deep.yml` run it on pull requests, one per family (`just sim 100
    dnssec`, 30 minutes each), informational, outside the gate as `mutants` (D103); the workflow's `loom` job is
    D135's. One job for them all took 19 minutes, and past 30 when GitHub's runners ran 2.5 times slower
    (2026-11-03).
- D134 (amends D26, D133; amended by D182) The client side of the compio layer behind a seam, `dedens_net::io::Io`, so that a
  simulation can run the real `UdpPool` (D50, D108), `TcpPool` (D27, D53) and `Client` on its own network and clock.
  - `crates/dedens-net/src/io.rs`: `Io` (`now`; `timeout_at`, the one timer, a pause being a timeout on a future
    that never ends; `spawn`; `random`; `udp_bind`; `tcp_connect`; and `sending`, a hook with no body for a trace)
    and the `Udp` and `Stream` traits. Buffers are owned as compio's (`BufResult`) and a stream's halves are
    compio's `AsyncRead` and `AsyncWrite`, which a substitute implements: the seam abstracts the runtime, not
    compio's I/O traits, so the pools' reads and writes do not change and there is no second set of buffer traits.
  - Production: `Compio` is zero-sized, each method one `#[inline]` forwarder; `UdpPool<N>`, `TcpPool<N>` and
    `Client<N = Compio>` are generic, `Client::new()` is `Client<Compio>`, and `dedensd` and `dedens` name nothing
    else: one instance of each, no `dyn`. Cost in `docs/benchmarks.md`.
  - An instance (`&self`) for each host, not a static one, so that a simulation holds a host's seeded RNG and trace.
    `Io::random` is the client's only entropy (IDs, the UDP socket's pick, cookies). A `Task` cancels on drop, as
    compio's `JoinHandle` does.
  - Only the UDP and TCP pools and the exchange loop: the QUIC, HTTPS, ODoH and DoC transports of `Client<N>` still
    call compio and run on its runtime alone, their deadlines taken from `N::now()`.
  - Gate: clippy's `disallowed-methods` (`crates/dedens-net/clippy.toml`: the clock, compio's timers and spawns,
    `getrandom`, and opening a socket) is denied in `udp.rs`, `tcp.rs` and `client.rs`, so only `io.rs` reads a
    clock, draws entropy, spawns or opens a socket for them. The lint is allowed in the rest of the workspace (QUIC,
    HTTPS, ODoH, CoAP and DoC still call compio, D26), clippy having no scope finer than a crate's file.
  - Left out: the serving loop of `dedensd` (D42, D121, D123: `UdpSocket`, `TcpListener`, the multishot receive
    and the send queue go behind the seam in a later decision), the QUIC family (`compio-quic` has its own endpoint
    and clock: DoQ, DoH/3, ODoH), DoC.
  - Determinism: a seeded simulation replays only if the pools act in the same order on every run. Their hash maps
    are looked up, never iterated where the order shows (`State::busy` only asks whether any query waits), and the
    queries waiting on a TCP connection are a `BTreeMap`, so that a close wakes them in ID order: in a `HashMap`,
    seeded per process, two replies at one instant swapped (`an_attacked_run_replays_in_two_processes`, seed 7,
    `crates/dedens-sim/tests/forged.rs`, once the simulation runs the real pool).
  - In `dedens-sim` (D133): `io::Sim` implements `Io` on turmoil, from the host's seeded `Rng`, tokio's paused clock
    and turmoil's sockets, a stream's tokio halves copied through a buffer into compio's traits; the driver's client
    is `Client<Sim>`, so every family runs the real pools. `tests/pools.rs` reaches what the sans-IO exchange could
    not: connections opened, reused, closed when idle or stalled (D27), the inbox of a query (D108), socket errors,
    and DNS over TLS, rustls over the simulated stream. Its certificates are fixed (Ed25519 keys from fixed bytes),
    so a run over TLS replays from its seed: rustls' own draws change bytes on the wire, not lengths or times.
  - What the real client changed in the families: an upstream server reads a TCP connection's queries as they
    come and answers each in a task of its own, as the pool pipelines (RFC 7766 §6.2.1.1); a TCP query to a
    host that does not answer ends in `TcpError::Connect(TimedOut)` at the pool's idle timeout (`docs/TODECIDE.md`);
    the IDs are drawn in another order, which changed some fixed seeds.
- D164 (amends D133; builds on D103; amended by D165, D167, D202) D133's time budget is measured, outside the gate: `just
  sim-time` times each family of `dedens-sim`'s `tests` binary run alone (the filter `<family>::`, its tests on the
  harness's threads), then the binary whole, in `just check`'s build under the fixed seeds, and fails when a family
  takes over 2 s or the binary over 10 s (12 s: D202). The gate's build is `cargo test --workspace --all-features`,
  whose features unify over the workspace (`dedens-bench`'s `metrics` turns on the cache's counters): `-p dedens-sim` alone
  would time other code, where the workspace's build reuses the gate's artifacts. The crate's time is the binary's:
  `src/`'s unit tests take milliseconds. The binary runs once (`--list`) before the timings: macOS checks a new
  executable on its first run, 0.5 s and more. Wall time is the machine's and its load's, so a gate on it would fail
  on a slower or busier one; the `sim-time` job of `deep.yml` runs the recipe on each pull request, informational as `mutants` (D103).
  - First measure (Apple M5, `docs/benchmarks.md`): `dnssec` took 3.2 s, the others 0.06 to 1.6 s, the binary
    7.2 s. Its two shed scenarios ran seed 0 and the two seeds that had failed one of them, the client-share one 2.8 s
    alone; each now runs the seed that failed it: `dnssec` 1.9 s, the binary 6.6 s. The module is near its
    floor, its tests at one seed setting it (D165).
  - `benches/driver.rs` (divan) times the driver: a run whose one query is answered, its fixed cost, and one whose
    upstream server is silent, six simulated seconds that turmoil steps a millisecond at a time. The silent run's
    median moves by 1% between runs, where the families' wall times move with the load. The scenarios stay `#[test]`s of
    `tests/`: a bench of each family's would need them in `src/`, or a family included by `#[path]`, its tests gone
    outside the harness and its helpers dead code.
  - Rejected: a timeout per test in the gate (the machine's speed again); libtest's `--report-time` (nightly).
- D165 (amends D164; builds on D133, D162) A family over its 2 s budget with no fixed seed left to cut splits in
  two: two modules of `dedens-sim`'s `tests` binary, each timed by `just sim-time` and run by a `sim` job of its own
  (`deep.yml` lists the binary's modules). `dnssec` is the first at its floor (D164): when `just sim-time` puts it
  over, its limit scenarios (`a_query_past_*`, `a_client_over_its_share_*`, D117's allowance and shares) go to a
  second family, `dnssec_limits` (`limits` is taken), and the verdicts and the cache stay in `dnssec`.
  Until then it stays one module. Rejected: a smaller scenario (D133 cuts seeds, never the scenario); a split ahead
  of the measure (two modules to keep for a family still within its budget).
- D167 (amends D164; builds on D133; amended by D172) `just sim-time` multiplies both budgets by
  `DEDENS_SIM_TIME_SCALE`, a positive decimal, 1 when unset; any other value fails the recipe before it builds. The
  budgets stay the Apple M5's (D164); the `sim-time` job of `deep.yml` sets 2.5, so a family may take 5 s there and
  the binary 25 s. 2.5 is D133's figure, GitHub's runners on a slow day against their usual pace (2026-11-03), not
  yet a runner's time of the families against the M5's: the job's first runs check it, and a change of the scale
  changes this decision. Rejected: a job that only reports the times, never red, so nobody reads it.
- D172 (amends D167) The `sim-time` job of `deep.yml` sets `DEDENS_SIM_TIME_SCALE` to 7, measured: the job's first run
  (ubuntu-26.04, 2026-11-09) took 3.8 to 6.2 times the M5's time per family and 6.8 times for the binary (48.8 s
  against 7.2 s; dnssec 10.9 s against 2.0 s), so at 2.5 five families of nine and the binary failed. At 7 a family
  may take 14 s and the binary 70 s, about 30% over that run's slowest. Rejected: a larger scale, which hides more of
  a slowdown.
- D182 (amends D133, D134, D181) `dedensd`'s serving loop of UDP and TCP goes behind D134's seam, so that a simulation
  runs it on its network and clock, which the driver of D133 leaves out.
  - `crates/dedens-net/src/io.rs`: `Io` gains `Listener` (a bound TCP listener's `accept`) and `detach` (a task
    nobody waits for: a query's, a connection's); `Udp` gains `recv_multi` (a stream of `Datagram`s, data and peer:
    compio's multishot receive) and `send_to`; a `Stream`'s write half is `Outbound`. Only what the loop calls;
    `Compio` forwards each to compio, `#[inline]`, but for `timeout_at`: a `Deadline` future polls the future and
    compio's `sleep_until` in place. Forwarded, compio's `timeout_at` (two nested `async fn` over the future, two
    clock reads) behind our own `async fn` cost TCP 14% (`memmove` of the futures: 10% of the server's time, 2.5%
    before). Rejected: forwarding, measured.
  - `dedensd`: `Thread<N: Io = Compio>` holds the `io`, a `Client<N>` and the start of the cache clock; `udp`,
    `tcp`, `connection`, `answer`, `supervise` and `Origin` take `N`. `serve` and the QUIC, HTTP/3 and CoAP
    listeners name `Thread` and get `Compio`: one instance, no `dyn`. A connection's writer is an `Io::Task`; the
    reader waits for its end by its `room` channel closing, `Io` offering no join.
  - Sockets: bound before the threads start (D42), socket2's, which `serve` hands compio (`from_std`); the loop takes
    an `N::Udp` and an `N::Listener` already made, so the simulation binds turmoil's itself. Rejected: an `Io` method
    adopting a bound socket, which turmoil has no counterpart for.
  - Entry: `dedensd::simulated`, `#[doc(hidden)]`, the one entry beside D181's: a plain listener's UDP and TCP loops,
    each supervised (D121), on one thread; no reload (`follow`), no `first_end`. Rejected: a copy of the loop in
    `dedens-sim`, which the driver of D133 is, kept for the families that count its events.
  - Gate: `apps/dedensd/clippy.toml` (the clock, compio's spawns, timers, binds and socket calls) is denied in
    `serve/udp.rs`, `tcp.rs`, `upstream.rs` and `isolate.rs`. `serve/mod.rs` converts the sockets and starts the
    runtime, ungated. `Listener::panicked` reads the system clock, for the log's rate only, under an `expect`.
  - `dedens-sim`: `Sim` implements the new methods (`SimListener`; `SimDatagram`, a datagram copied out of turmoil's,
    through one scratch buffer per socket and cut at 4096 bytes, as compio's pool cuts it on `io_uring`, D49).
    `Topology::dedensd` runs `Resolver::serve_dedensd` on the resolver host. `tests/serving.rs` runs the baseline,
    partition, loss and crash scenarios that concern the server against the loop, and TCP queries pipelined on one
    connection, answered out of order (RFC 7766 §6.2.1.1) where the driver answers in turn. The loop records none of
    the driver's `Replied`, `Forwarded` and `Stored`. `World::run` fails on a panic the loop caught or a listener
    restart, read from D121's counters by a local `metrics` recorder (turmoil runs every host on the test's thread);
    `Sim::detach` watches nothing.
  - Left out: QUIC (DoQ, DoH/3, ODoH: `compio-quic`'s endpoint and clock), DoC, the TLS listener (generic, with no
    scenario), reload, several threads, D86's flights (validator questions only; no scenario validates here).
    Run but reached by no scenario yet: the caps (`TCP_CONNECTIONS`, `UPSTREAM_QUERIES`, `TCP_PENDING`,
    `TCP_QUEUED`), the idle close (`TCP_IDLE`), the write timeout (`TCP_WRITE`), a listener restart (D121). Not
    simulated: the buffer pool and its `ResourceBusy` (D107), as `SimUdp` has none.
  - Cost in `docs/benchmarks.md` (dnsperf on Linux, `io_uring`): TCP 8% faster, forwarding 25-35%, UDP within its
    noise.
- D189 (builds on D133, D184, D188) `dedens-sim` hosts the authoritative servers of D188's captures at their addresses,
  IPv4 and IPv6, so that a recursive pipeline resolves from the root in a simulation, and a server at a time
  misbehaves as broken ones do.
  - API: `Topology::authoritative_at(addr, answers)` hosts a server at `addr` (the host is named by it; `Node::Host`
    names it to a fault) answering from `Answers::exchanges(exchanges)`: per question, the UDP capture over UDP and
    the TCP one over TCP (`truncated`), REFUSED to any other question. `Topology::resolution(&Resolution)` loads every
    server of a capture, appending to servers already loaded (the first capture of a question wins, as `Authorities`
    replays), and starts the run at the capture's time. The server is `upstream::serve`, the upstreams' (one server:
    its faults, trace and attacker apply). Its stream of the seed is `3 << 62` and up.
  - What a behaviour may change, `Answers::conduct(Conduct)`, each a captured response changed as broken servers
    change it, nothing invented: `Refuses` and `Fails` (REFUSED, SERVFAIL to every query: lame), `Truncates` (every
    UDP response its header and question, TC set, no records; TCP whole), `NoEdns` (FORMERR without OPT to a query
    with EDNS, the capture without OPT to one without, RFC 6891 §7), `FoldsCase` (the question in lower case, not
    the client's: D184's random case catches it), `Unauthoritative` (AA cleared: a zone it is not authoritative for,
    RFC 4697 §2.1.1). Silent is `Answers::silent`. Rejected: an upward referral or another zone's data, which a
    capture does not hold.
  - Oracle: `Expected::resolved(&Resolution)` is the answer a recursive resolver may give: a final server's (AA,
    not truncated) for the name, then for the target of a CNAME or DNAME chain that leaves the data to another
    server (RFC 1034 §4.3.2 step 3.a); one per way through the final servers, as servers of one zone answer apart
    (`cname`: one `akamaiedge.net` server answers the CNAME, the other the address). Rcode, authority and additional
    of the last. TTLs no higher, as D133's. The servers' own captures are not expected: a referral is no answer.
  - Hosts: a port binds the unspecified address of its host's family (turmoil refuses a mismatch), and `Sim`'s
    `udp_bind` maps the client's `[::]:0` to its host's family. Clients start after `max(5 ms, 2 steps)`: at a
    coarse step a client polled first sent before a server had bound its port.
  - Tests: `crates/dedens-sim/tests/internet.rs` loads every capture in one run (29 servers, at a 10 ms step for
    D164's budget) and a client asks each exchange again with 0x20; then one server of each conduct and a
    silent one, the seed picking which.
- D196 (amends D190, D191; builds on D133, D164, D182, D189, D194, D195) Recursion in the simulator (recursive step
  09): `crates/dedens-sim/tests/recursion.rs` runs `dedensd`'s own loop (D182) with a cache stage then a recurse stage
  (D195) on D189's Internet, every capture's servers hosted, and a client asks each capture's question in turn. The
  stage does not minimise its questions (D198): the captures' were not, and the servers refuse any other.
  - Scenarios: all servers well; each losing one UDP response in 10 (`Answers::lossy`: the first at random, then
    evenly, never two in a row, as three would skip a zone's only server, D194; over TCP a lost segment is sent
    again, so a TCP response is never lost); one server of each zone with two, the seed picking the family,
    silent, truncating each UDP response, FORMERR to EDNS, or folding the question's case (D189's conducts); one
    zone, the seed picking among those whose servers serve no other, all its servers refusing; `dedensd` restarted
    between two rounds of questions (`Fault::Bounce`).
  - Oracle: D133's checks of each answer against `Expected::resolved` (D189), live rules: an answer from no captured
    way, or SERVFAIL, fails. The RRSIG question is answered NOTIMP (D195). Under the refusing zone the questions
    that reach it are SERVFAIL within the client's 5 s timer (RFC 4697 §2.1, `Limits::time` 4.5 s, D191).
    Each question sends at most `Limits::queries` (D191) to the servers, priming not counted (D195). After the
    restart, `dedensd` primes again (RFC 8109 §3) and the round asks the servers again, its caches empty.
  - Steering: the resolver is to draw among the run's hosts alone. Every address the root's hints and the captures
    show but the zones' servers is backed off as timing out (D194) until its probe is past the run, as step 04 marks
    them lame for the iteration tests: lame, they would be asked once the zone's servers were (RFC 4697 §2.2.1).
    Each server of a zone answers every question the zone was asked: servers of one zone refer to different
    servers of a child (Akamai's), and a capture asked those of the first referral alone. netmeister.org's servers
    were found by a lookup of one of its three names, the others refused: its IPv6 server is the broken one, as
    the AAAA may be past `Limits::targets` when that name is drawn last. A silent server drops the questions its
    zones were asked and refuses the others, as the other server does: a lookup of a name no capture holds would
    wait on it, asked again with its timeout doubled, where the Internet's other server answers (seed
    16147968738952915998 spent `Limits::time` on net.'s).
  - Links: each message takes 20 to 30 ms (`Topology::latency`), at a 10 ms step. Turmoil's 0 to 100 ms spread a
    round trip past the RTO the infra cache derives from its first samples, from 50 ms (D194): live servers timed
    out, and with a silent server in each zone of a CNAME chain the question spent `Limits::time`.
  - Found by the scenarios, amending D190: a query moved to TCP, on TC or a case mismatch, waits until
    `TCP_TIMEOUT` (3 s, Unbound's `tcp-auth-query-timeout`, `serviced_tcp_initiate`) after the move when that is
    later than its deadline, which the infra cache measured over UDP: two round trips more (connect, query) than an
    RTO near the RTT timed out every TC answer (`microsoft.com. TXT`). A query over TCP from the start keeps its
    deadline, its RTO measured over TCP: a server marked for TCP (BADCOOKIE) has its UDP estimate dropped as the
    mark is set (`InfraCache::answered`), its timeout the unknown server's until the first answer over TCP, and a
    timeout of a query over TCP from the start backs it off; the recurse stage bounds the whole by the resolution's
    end. That timeout is `UNKNOWN_TIMEOUT`, 376 ms (D194), and a query over TCP from the start takes two round trips
    at least (connect, query): a server more than about 190 ms away times out once on it, the back-off covering the
    next. Accepted: it costs one query, within `Limits::servers`.
  - Found by the scenarios, amending D191: a server timed out is asked again (RFC 1035 §7.2, Unbound's
    `outbound-msg-retry`), its timeout backed off, until the infra cache skips it (D194), each send counting
    against `Limits::servers`: after the servers not tried and a name's AAAA whose A was looked up, before a name
    not looked up yet, which costs queries. Asked once, a zone of one server (microsoft.com) failed on one lost
    datagram.
  - Seeds: 1 and 42 (each failed a draft), within D164's budget: the family took 1.5 s, the binary 1 s more.
  - Deviations from the step's plan, which predates step 08: `dedensd`'s loop, not the driver, which refuses a
    recurse stage (D195); lame as refusing servers, since a server answering without AA (`Unauthoritative`) still
    refers, and its referrals still resolve the captures.

- D202 (amends D133, D164; builds on D172) The crate's time budget of `just sim-time` is 12 s, 84 s at D172's scale of 7;
  a family's stays 2 s. 10 s was set for nine families (D164, binary 7.2 s); at fifteen, main's binary took about
  10.1 s on the Apple M5 and 70.6 s on a runner (2026-11-21), so every new family failed the job without being slow
  itself: `attacks` (D189) adds 0.4 to 0.7 s, 2.0 to 2.3 s on a runner, and its pull request measured 70.5 and 72.0 s.
  A family over its 2 s still runs fewer seeds (D133). Rejected: fewer seeds in the heaviest families (`dnssec`,
  `crash`, `baseline`, `recursion`), each within its own budget, so the cut would buy time no family overspent; a
  budget growing with the number of families, which would never fail on the binary.
