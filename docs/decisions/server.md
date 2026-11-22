# Server

Decisions; the rules and the index are in [`README.md`](README.md).

- D23 (amended by D54) Pipeline: each listener runs an ordered chain of stages; a stage answers, passes the query on, or passes
  it on and sees the response back. Order from the config, not the build (CoreDNS's fixed `plugin.cfg` order
  confuses users). Branching is a router stage (zone, client CIDR, listener, qtype, view), no general graph: a
  query has one response. Declarative matchers compiled at load; scripting costs microseconds against a
  150 ns cache hit. Built-in stages are enum variants behind Cargo features; custom binaries register extra
  stage types (trait objects) on the server library. Stages before the cache are synchronous, without
  allocation or copy of the query. (Not yet: features, router stage; custom stage types are D54 plugins.)
- D24 (narrowed by D44) Configuration: a directory of TOML, YAML or JSON files, one serde model (as D36), merged;
  components named, typed by a `type` key. Errors, not warnings: unknown field, duplicate name, unused component.
  `${VAR}`, `${VAR:-default}` (`$$` escapes), `SECRET[backend.key]`. `dedensd validate` builds the pipeline without
  binding; JSON Schema from the types (schemars); config tests run D36 query files. Reload (SIGHUP, file watch)
  builds the new pipeline, then swaps it (`ArcSwap`); in-flight queries finish on the old one; cache and upstream
  connections survive.
- D41 (amended by D43, D46, D77, D111, D114, D185, D186) Server core (`dedens-server`), sans-IO as D26: `Pipeline::query` takes the query's
  bytes and transport and returns a step: a reply in the caller's buffer, nothing, or a request for an upstream
  server whose response goes back through `Pipeline::receive`; `apps/dedensd` does the I/O. Before the stages the
  core answers what none should see: responses and bytes shorter than a header are dropped; FORMERR to a query it
  cannot read (the header alone, no OPT), that breaks a rule (D9) or has no question; NOTIMP to opcodes other than
  QUERY; BADVERS to EDNS versions above 0; REFUSED to AXFR and IXFR, and when no stage answers. A reply has the
  client's ID, opcode and question in its case; QR and RA set, RD and CD copied, AA clear, AD only for a query with
  AD or DO (RFC 6840 §5.8); our OPT (1232 bytes, DO copied) only when the query had one (RFC 6891 §6.1.1, §7),
  so a FORMERR to OPT records breaking a rule has ours too: several (§6.1.1), one outside the additional section,
  not owned by the root or with an option running past it (§6.1.2), one with an invalid option (§7); with no OPT
  read, DO is clear and the payload 512.
  Over UDP it fits the client's payload, 512 to 1232 bytes, 512 without EDNS, truncated as D10; over TCP it comes
  whole. The forward stage asks its servers in order, the next on no response, one undecodable or breaking a rule,
  or TC; an Oblivious DoH target is one server, and its proxy's failure or a response that does not open is no
  response (D185). An upstream response is usable only with RCODE NOERROR, NXDOMAIN or YXDOMAIN (RFC 6672 §2.2). Any other
  RCODE — SERVFAIL, REFUSED, NOTIMP, FORMERR, the update codes, and the extended codes from the upstream's own OPT
  (BADVERS, BADCOOKIE, …) — sends the query to the next server (RFC 1035 §7.3). None of them speaks about the
  client's query. After the last, SERVFAIL. Upstream gets the client's question, RD set,
  AD and CD copied, our EDNS with DO and none of the client's options: the client subnet never leaves (privacy),
  cookies are per hop (D27). Rejected: an async stage trait over a mock upstream (sans-IO tests are exact, as D26).
- D42 (amended by D45, D47-D49, D52, D65, D66, D84, D115, D122) `dedensd` I/O around D41: one compio thread per core on Linux, each with its
  own UDP socket and TCP listener on every `listen` address (`SO_REUSEPORT`, the kernel spreading queries), one
  thread elsewhere, where `SO_REUSEPORT` does not spread; IPv6 sockets IPv6-only, so `[::]` and `0.0.0.0` bind
  together. Every socket is bound before any thread starts, so a taken address fails the start. A reply the
  pipeline builds at once goes out from the socket's task; a query for upstream gets a task owning its `Upstream`
  and asks with the thread's `dedens_net::Client`, over the client's transport, with the forward stage's timeout
  and tries (D45). TCP (RFC 7766): queries read in turn, each answered when ready, replies in any order through one
  writer (§6.2.1.1); reading stops after 10 s without a query, the connection closes once pending replies are
  written (§6.2.3). Listeners and upstreams from the configuration (D44). Rejected: one socket shared by all
  threads (contention on one receive queue); a task per query on the cached path (an allocation per hit).
- D43 (amends D41; amended by D45, D46, D77, D96, D114, D124) Cache stage (D22 in D41's pipeline): `Stage::Cache` looks the query up at `now`,
  seconds the caller passes (`dedensd`: since start), so `Pipeline::query` and `Pipeline::receive` take it. A hit
  is the stored bytes patched by `dedens-cache`, then D41's flags (AA clear, RA set, AD as asked, TC kept) and our
  OPT when the query had one; room for the OPT is kept before the lookup, and a stale hit leaves 6 more bytes for
  its EDE option (`Cache::STALE_ROOM`), since freshness is known only after. A miss runs the later stages, and the
  forward stage's usable response is stored under the client's query (its DO and CD bits), then answers as a hit,
  not encoded again (`miss` bench, mx: 1.5 → 1.1 µs), through `Cache::stored`: no use counted for eviction nor in
  the lookup metrics, else every name asked once would look asked twice, defeating S3-FIFO's scan resistance;
  unstored responses (D22) are still the reply, encoded. After the last server fails, the failure is held (RFC 9520
  §3.2); during a hold the reply is SERVFAIL, upstream unasked. Expired data answers while failing
  (`StalePolicy::IfFailing`), and on the client timer (D45): after the last server fails, and during the hold, with
  TTL 30 and EDE 3, or 19 for NXDOMAIN (RFC 8767, RFC 8914 §4.4). A fresh hit under 10% of its TTL is
  `Step::Refresh`: the reply now, then the same upstream query whose response is only stored, ending in
  `Step::Drop`; a failed refresh is not held. `Upstream` owns what it needs (a copy of the query's bytes, read
  again on the way back; stage and server indices), so it outlives the query's buffer, and `Pipeline::receive`
  takes it back. Rejected: reading the query again in `dedensd`'s upstream task (a second cache lookup, a miss
  counted twice, and no way to tell a refresh from a reply).
- D44 (narrows D24; amended by D64-D66, D84, D91, D113, D115, D116, D122) `dedensd` configuration, D24 narrowed for the first server: one YAML file (`--config`), as D36's query
  files; `listen` addresses, `pipeline` (stage names in order), `stages` (name to settings
  under `type`: `cache` with `dedens_cache::Config`'s fields, `forward` with `servers`, `IP` meaning port 53),
  `upstream_ca` (D65).
  `${VAR}` is replaced in the text before YAML reads it; a value spanning lines is refused, as it would add YAML.
  Errors: unknown fields, duplicate names, a stage listed and not defined, defined and not listed, listed twice or
  after a forward stage (which answers every query). `dedensd validate` reads the file and builds the pipeline
  without binding; SIGHUP reloads it (D55). Later, with need: a directory merged, `SECRET[..]`, JSON Schema.
- D45 (amends D42, D43; amended by D77, D115) Upstream patience and the client response timer (RFC 8767 §5), changing D42 and D43: a forward stage
  waits `timeout_ms` per query (default 3000, slow authoritative chains take over 1 s) and sends each server
  `tries` queries (default 2), carried on `Upstream` (`Upstream::patience`). A cache stage's
  `stale_answer_after_ms` (default 1800, the RFC's suggestion; 0 waits for resolution) is the client response
  timer: `dedensd` races it against the upstream exchange, and when it ends first calls `Pipeline::stale`,
  which answers with expired data (`StalePolicy::Always`, TTL 30, EDE 3 or 19) if the cache keeps any. The
  exchange goes on: its response only refreshes the entry, so the next query has it fresh; its failure is held,
  with no second reply. A refresh of a fresh entry (D43) has no timer. Rejected: a stale answer without
  resolution going on (the next query would wait again); a second task per query for the timer (the exchange
  future is polled with a deadline, then awaited).
- D46 (amends D41, D43; amended by D121) Review fixes to D41-D45. A query without RD gets fresh cached data only (RFC 1034 §4.3.1: no recursion;
  RFC 8767 §5: no expired data), else REFUSED with EDE 20 (Not Authoritative, RFC 8914 §4.21); it never goes
  upstream, so it cannot start a hold every client shares. Upstream queries set RD (a refresh started by such a
  query too) and copy the client's AD (RFC 6840 §5.7), so AD can come back. `dedensd` turns the EDNS fallback
  off: a response without OPT would be stored for clients with DO (RFC 3225). A failure of ours
  (`ClientError::is_local`: no randomness, no socket, any socket error but the network or server refusing,
  resetting or unreachable) is `Pipeline::abandon`: SERVFAIL, no next server, no hold. The configuration refuses
  a second cache stage (it would never be filled). A panicking serving thread ends `dedensd` with an error (a task's panic no longer does: D121).
  The client response timer of D45 runs only when the cache keeps expired data for the query
  (`Lookup::Expired`). A cache hit allocates nothing (`benches/server.rs`). The exchange checks a response with
  `Query::read`, and the pipeline decodes it once.
- D47 (amends D42; amended by D64, D90, D91, D113, D186) `dedensd` limits, per thread (RFC 7766 §10, D42 had none): 1024 upstream queries in flight (past them a
  UDP query is dropped, a TCP one answered SERVFAIL), 256 TCP connections (past them a new one is closed at once);
  per connection, 64 queries in flight (reading waits; a bounded channel is the semaphore), 128 KiB of queued
  replies (reading waits), and 10 s for each write of the queued replies (a client that stops reading loses its
  connection; one that reads slower than it asks waits on the 128 KiB). A query waiting upstream holds no reply buffer until a reply is made. A QUIC
  Initial from an address not yet validated is answered with a Retry (RFC 9000 §8.1.2) and takes no connection
  slot, so forged sources cannot fill them; always on, at the cost of a round trip for a first connection (a
  client holding a token from an earlier one skips it). A QUIC connection (DoQ, HTTP/3) is a TCP one in these
  limits: no new stream within the idle time, none being answered, ends it, pings or not (the idle time counted as
  D84 says), and a reply not written within the write time is given up with its stream reset: a client granting
  no flow control credit keeps the connection and its slot for the write time and then the idle time at most. No per-address cap, for TCP either. Constants for now; configuration with need. Client
  allow and block lists come later (`docs/TODECIDE.md`); per-address caps are the deployment's (D90; UDP is limited per network by D113).
- D48 (amends D42; amended by D123) Several tasks answer on each UDP socket of a thread, so a receive does not wait while one
  answers: one task waited for its reply to go out before receiving again. Four at first; two since D123 queued the
  replies, which no task waits to see sent; one since D123 sends a reply at once: two woke each other through the
  lock on the socket's datagrams at every query, a turn of the runtime more. `just bench-dnsperf` (Linux, io_uring,
  one core, cache hits) measures `dedensd` against a git ref: 1 task about 310k queries/s, 2 about 340k, 4 about
  415k, 8 and 16 no better. A TCP connection's writer writes the replies queued meanwhile together, up to 65535
  bytes: one write a reply held TCP to about 185k queries/s, batches reach about 1.8M (dnsperf pipelines 500
  queries). Copying each reply for the writer costs nothing measurable there (copying it twice did not move the
  numbers), so replies keep their copy and the writer task, which reads on while writing and keeps the replies
  of concurrent queries whole.
- D49 (amends D42) UDP queries arrive in buffers made once per thread (256 of 4240 bytes, 1.04 MiB, compio's buffer pool): on Linux one
  io_uring multishot receive per socket fills them, and the socket's tasks (D48) take turns at its stream
  of datagrams behind a lock, each giving its buffer back before its reply waits to be sent. About 400k →
  480k queries/s (`just bench-dnsperf`); 16 tasks no better. A query of up to 4096 bytes, the most a DNSCrypt packet
  is, is read whole: `io_uring` writes a 16-byte header and the sender's address, 128 bytes (compio asks for a
  `sockaddr_storage`), before the datagram in its buffer, so a buffer is 16 + 128 + 4096 = 4240 bytes. The kernel and
  compio ask no page or alignment (each buffer is an allocation of its own, of any length). A thread holds 256 × 4240 =
  1,085,440 bytes, 36,864 more than the 256 buffers of 4096 that cut a query at 3952 bytes (read as broken, so D100
  padded relayed queries to 3908); the benches show no change (`docs/benchmarks.md`). A longer query is cut short and read as broken; the socket keeps datagrams while
  every buffer is taken. Rejected: a receive asked for each datagram into the task's own 64 KiB buffer (one submission
  and one buffer per receive).
- D50 (amends D27; amended by D108) Upstream UDP queries share a fixed pool of 256 sockets per server and client (`dedens-net::udp`), each opened
  on first use on port 0 and connected, then kept: a query takes one at random and waits for datagrams with its
  ID, which the socket's task receives for every query on it. An off-path attacker guesses the ID and the
  socket: 16 + 8 bits (RFC 5452 §9.2), against about 32 with a socket per query; cookies (RFC 7873) and `0x20`
  stay the way to win more. Matching stays D27's: a datagram goes to each query waiting for its ID (four kept for
  each, D108), and the exchange drops those of another question. A datagram is received whole, up to 65535 bytes, whatever
  size the queries advertised, into one buffer per pool, so per serving thread, as Unbound's `outnet->udp_buff`: a
  socket waits for readiness, holding no buffer, then receives without waiting and hands the bytes over before the
  next await. One buffer per socket held 256 × 64 KiB a thread: the 3-core `miss` run's loaded memory falls 170 →
  105 MiB with transparent huge pages, 103 → 88 without; the readiness wait and the `recv` call per datagram, where
  one `io_uring` receive did both, cost no CPU or latency the runs see (`docs/benchmarks.md`, "One receive buffer
  per pool"). A socket error goes to the queries that sent on
  it, each counting it as a lost try, as does a send refused for an earlier datagram's ICMP error (another send
  error ends the exchange, and the socket is left: the next query on its slot opens another, as a socket connected
  from an address the host lost fails every send, the route of its source gone; audit 4); errors in a row pause the socket's task 10 ms. Forwarding to a second `dedensd` (`just bench-dnsperf HEAD forward`): about 125k → 127k queries/s,
  the upstream on one core being the limit there. Rejected: renewing sockets on a timer (no attack measured
  against a kept port yet); muxing by question too (the exchange checks it).
- D51 (amended by D107, D123) The io_uring of a serving thread runs completion work cooperatively (`COOP_TASKRUN` and `TASKRUN_FLAG`,
  Linux 5.19; `dedensd` serves on `io_uring` from Linux 6.0, older kernels on `poll` with a warning at start, D174): when the thread enters the kernel, instead of interrupting it as a signal does. Forwarding
  (`just bench-dnsperf HEAD forward`): 135k → 158k queries/s; cache hits over UDP and TCP unchanged. Rejected:
  `SINGLE_ISSUER` with `DEFER_TASKRUN` (Linux 6.1), no better (160k); `SQPOLL` (cache hits over UDP 475k → 230k,
  forwarding 155k → 82k). Measured again with D123 (Linux 6.12, six vCPUs, one server core): no better, still
  rejected, and no fallback to write.
- D52 (amends D42; superseded by D63) A TCP query answered after upstream writes its reply into a 65535-byte buffer the thread kept from an
  earlier one (up to 32, 2 MiB), not a new one. The buffer is zeroed first unless `zero_buffers: false` in the
  configuration: no byte of an earlier reply stays in it, should a bug ever send past the reply's length (the
  encoder writes before it reads, so nothing leaks today). Only these spare buffers are: the buffer each UDP
  task and each TCP connection reuse for the replies made at once (cache hits, plugins) keeps earlier replies'
  bytes past the current one's length; whether to zero or drop them is open. Forwarding over TCP (`just bench-dnsperf HEAD forward-tcp`):
  84k zeroing new buffers → 90k-92k reusing them unzeroed; zeroing them again costs part of it (79k-88k against
  87k-90k). Rejected: skipping the zeroing of new buffers (uninitialized memory behind `unsafe`).
- D63 (supersedes D52; amended by D123) A `dedensd` thread makes its TCP replies and its replies after upstream in one 65535-byte
  buffer, allocated at its start, and copies each reply's bytes out to send them: behind its length for TCP, as
  framing already copied it. Making a reply never waits, so the buffer is borrowed only meanwhile and one serves
  every task. Only a reply's bytes leave it, never those of an earlier reply, so there is nothing to zero:
  `zero_buffers`, the spare buffers and each TCP connection's own 65535-byte buffer (16 MiB a thread at 256
  connections) are gone. Each UDP task keeps its 1232-byte buffer for the replies it makes at once: it is owned
  by the send in flight and reused, and only the reply's length is sent. Forwarding over TCP (`just
  bench-dnsperf HEAD forward-tcp`): 230k-270k → 303k-305k queries/s; over UDP and from the cache unchanged.
- D53 (amends D27) Upstream TCP: the connection's writer task writes the queries queued meanwhile together, up to 65535 bytes,
  as D48's writer does for replies: one write and one wake-up of the server for many. Forwarding over TCP
  (`just bench-dnsperf HEAD forward-tcp`): about 87k → 275k queries/s, average latency 5.7 → 1.8 ms.
- D108 (amends D27, D50) Bounds on the client's queues and the evidence of a live server. UDP: a query keeps four
  datagrams with its ID until it reads them, a response and the late ones of its tries, and drops the next; the
  socket's one shared inbox of 64 let a query flooded, or slow to read, take the room of the others: the 65th
  concurrent query on a socket lost its response. TCP: a connection queues 1024 messages for its writer, where a
  server that stopped reading held up to 65536 (4 GiB of 64 KiB queries); the query that finds it full goes on a new
  connection, as one that finds every ID taken (D27), and the full one drains and closes. Only a message with the
  ID of a query sent counts as a response read: frames for IDs nobody waits for neither kept the connection from
  idling nor hid a stalled one (D27), so a server could trickle them and never answer. Not done: freeing the ID
  of a query that stopped waiting (RFC 7766 §6.2.1: no reuse of the ID of a query in flight, which a late response
  may still answer; the 65536 IDs and the stall check bound them); waiting for room in a full queue (it holds an ID, freed on every way to give up).
  Not measured: no Linux bench host here; the changes add no work per message on the TCP read path, and UDP's
  per-query lookup replaces the scan of the shared inbox.
- D54 (amends D23; amended by D64, D110, D118, D120, D128) Plugins (D23's custom stage types, for built-in stages too): `dedens_server::Plugin`, a trait object in
  `Stage::Plugin`, answers a query at once from what it holds, or passes it on; no upstream, no cache entry.
  Plugins live in `dedens-plugins`, configured in `dedensd` under their own `type`; cache and forward stay core
  stages, tied to the upstream steps. An answer is a response code, records already in wire form
  (`dedens_server::Records`, written once after a question for their name, so their compression pointers hold
  in any reply to that name), AA, and an extended error: the reply copies the records after the client's
  question, allocating nothing; records that do not fit are left out with TC (RFC 2181 §9). AA when the plugin
  holds the name's data as local knowledge (RFC 1035 §4.1.1, RFC 9499 §6), clear when it applies a policy.
  Plugins answer queries without RD too: their data is local. Rejected: a stage enum per plugin in the core
  (each plugin would grow `dedens-server`); plugins writing the reply themselves (each would redo D41's flags,
  OPT and sizing). A plugin may also refuse the response of a stage after it (D118). Files are read at start and
  on each reload (D55).
  - `hosts`: lines in the `/etc/hosts` format, inline then from a file; A, AAAA and the PTR of each address to
    its first name, TTL 3600 unless set (as `CoreDNS`); ANY gets one RRset of the name, A then AAAA then PTR
    (RFC 8482 §4.1); a listed name asked another type has no data (RFC 2308 §2.2) unless `fallthrough` passes it on; addresses with a zone (`fe80::1%lo0`) are left out.
    The no data has AA and no SOA, as `tlds`' (D128): the stage holds names, not a zone, so a SOA would be invented,
    and an answer has no authority section to carry it; RFC 2308 §3's SOA binds a server authoritative for a zone.
    The cost (§5): no cache downstream keeps it, so each repeat is a lookup in memory here (and an edit shows at once).
    Rejected (audit 4): a SOA made per name, or one for the root (it would claim a zone's authority for local data).
  - `blocklist`: names, one a line or in the `/etc/hosts` format of published lists, blocking themselves and
    their subdomains; `action` NXDOMAIN (default), NODATA, REFUSED or the unspecified address, each with EDE 15
    Blocked (RFC 8914 §4.16), AA clear. Of hosts lines only those of `0.0.0.0`, `::`, `127.0.0.1`, `::1` count,
    without names of one label or starting with `localhost`: such files open with their host's own entries
    (`127.0.0.1 localhost`, `127.0.0.1 local`), and blocking `local` would block all of mDNS's `.local`. A plain line
    of one label: D56.
    Any class asked (D110). Formats, duplicates and the allowlist in D56.
- D55 (amended by D64, D96, D107, D122) `dedensd` reloads its configuration file on SIGHUP (systemd's `ExecReload=kill -HUP $MAINPID`): the file
  is read and the pipeline built as at start, then swapped in. Each serving thread compares a generation counter
  before each query (one atomic load) and takes the new pipeline under a lock only when it changed (a thread no query reaches takes it when woken by the reload, D107), holding it in
  an `Rc` so a query touches no count shared between threads; a query waiting on upstream ends on the pipeline it
  started on. The cache stage is an `Arc<Cache>` kept while its settings are unchanged, else a new empty one. A
  file that does not read, or a hosts or blocklist file it names, leaves the running pipeline and logs an error;
  `listen` takes a restart (a warning), as does the thread count. Counted in
  `dedensd_reloads_total{result="ok|error"}`. The handler comes from `signal-hook`, installed before the
  server logs that it serves, so no SIGHUP ends the process. Rejected: compio's `signal`, which restores the
  default action between two waits, so a second SIGHUP during a reload would end the process; `arc-swap`,
  whose guards may not be held across an await and whose `Arc` clones share a count between threads. Later:
  watching the file, and upstreams pushed while running (D-Bus, for a systemd-resolved replacement).
- D56 (amended by D118, D120) Blocklist contents. `*.name`, hagezi's format for Blocky, is read as `name`: Blocky's documentation says it
  blocks the name and its subdomains, as any entry here does. A plain line holds one name of two labels at least:
  `com` or `*.com` would block a top-level domain, an error in the server's own configuration and a skipped line in a
  downloaded list, unless the stage says `tlds: true` (D118); hosts lines keep leaving one-label names out (D54). Names are host names,
  not zone-file names, which read nearly anything (`<html>`, `||ads.example^`, URLs) so that an error page passed
  as a list: ASCII letters, digits, `-` and `_` between dots, a label not all digits (no address is a name), an
  optional trailing dot, `*.` only first; no escapes, no root (`.`, `@`). Hosts lines leave out addresses as
  names (StevenBlack's `0.0.0.0 0.0.0.0`) and lines of an address with a zone (`fe80::1%lo0`), of the host's
  own entries. A byte order mark opening a list or hosts file is dropped. An `allow` list
  (entries, file) lets a name through when it or a parent is listed, whichever parent is blocked, as numa and
  Blocky do; looked up only for blocked names. Names listed twice count once, counted in the log. Lines
  from the server's own configuration must all read; downloaded ones (`Origin::Downloaded`) skip lines that do
  not, and the text is refused when it has none or fewer than half read, as an error page served with status
  200 does (numa's rule). Adblock syntax (`||name^`, `@@`) later, with need.
- D57 (amended by D64, D104, D115, D118, D120) `dedensd` downloads blocklist and allowlist `urls` (`https://`, or `http://` for a server of one's own)
  with `ureq` 3, blocking, on the thread that reloads on SIGHUP: off the query path, and one thread so a refresh
  never swaps in a pipeline older than a reload's. Rejected: `cyper`, compio's client (hyper, a 0.10 beta).
  Certificates are checked against the OS trust store (`rustls-platform-verifier`); list hosts are resolved by
  the system resolver, possibly `dedensd` itself, which forwards them. Each list is kept in `downloads.dir`
  (`/var/cache/dedensd`) under the 64-bit FNV-1a hash of its URL, written to a `.part` file then renamed, with
  its `ETag` beside it: a start or reload reads the copies and serves at once (a list not downloaded yet is
  empty), and fetching sends `If-None-Match`, so an unchanged list is neither downloaded nor read again (304).
  An `https://` list is fetched with `https_only`: a redirect cannot take it to `http://`. A text replaces the
  copy only when it reads as a downloaded list (D56), at most 256 MB, within 30 s. Lists are fetched once the
  server serves, on each SIGHUP after its reload, and every `downloads.refresh_minutes` (1440, as numa and
  Pi-hole); a failure keeps the copy and retries after 1 min, doubling up to the interval. A change rebuilds the
  pipeline as a reload does (D55; the cache kept). Counted in
  `dedensd_list_fetches_total{result="changed|unchanged|error"}`. Later, with need: a list swapped alone instead
  of the pipeline, per-list intervals.
- D58 (amended by D110, D120) A blocklist holds a 64-bit `SipHash` of each name (D110 defines the hash: chained from the
  root over the lowercase wire labels) under a key drawn once per process (std's `RandomState`; D120), in a `HashSet<u64>`
  hashing them no further: 8 bytes a name instead of the name and its allocation. Published lists of 2.29M names:
  110 MB resident instead of 240 MB, read in 0.64 s instead of 0.87 s, lookups as fast (`benches/blocklist.rs`;
  the chain of D110 changed the load time, `docs/benchmarks.md`). A false match needs two names of equal hash
  (D110 gives the odds), and the key, unknown outside the process, keeps a client from aiming at one. The cost: names cannot be listed back, so a blocked name under a blocked parent is no longer
  dropped (2% of those lists, 0.4 MB). Rejected: names in one buffer with offsets (~55 MB, exact, more code); a
  sorted `Vec<u64>` (18 MB instead of the set's 37 MB, a binary search per label); a trie or FST (a dependency,
  slower to build).
- D110 (amends D54, D58; amended by D120) The blocklist blocks a name in any class, and finds a name's suffixes in a walk linear in
  its labels (audit L11, P4).
  Class: it looked up IN queries only, so a query of class ANY (QCLASS 255), NONE, CH or HS for a blocked name
  went to the next stage: the list is a policy on names, and the class is no longer read. `Action::Null` answers A
  and AAAA with records of class IN, so only to questions of class IN or ANY; the other classes get no data.
  Rejected: reading ANY and NONE as IN (CH and HS would still go on).
  Walk: each suffix was hashed from scratch, labels² bytes of `SipHash` for a name of 127 labels. The hash of a name is
  now chained from the root, `h = SipHash(parent ‖ length byte and label)` under the same per-`Lists` key (the
  root's `h` is 0), so a name's walk hashes each label once and each suffix's hash is the one reached on the way.
  The key stays: a client chooses the names it asks, and an unkeyed or weak hash (a rolling hash, FNV) lets it
  aim at collisions (D22's reason for keyed hashing). A set also keeps which label counts its names have, a
  `u128`: a lookup hashes no deeper than the longest name of the lists that can still decide, probes only counts
  present, and does not walk a name with fewer labels than the shortest blocked name. Collision odds: a collision
  at a label carries to the names below it, so two names share a hash with a chance of at most 2^-64 per label,
  about one wrong answer in 10^11 queries of a few labels against 2M names (D58 had 10^12). Rejected: a trie of
  reversed labels (D58 rejected a trie: a node per label, 8 bytes a name becomes tens); label offsets alone (the
  hash of each suffix is still computed from its bytes). What stays linear in the labels is finding where each
  label starts, from the front of the wire name; `docs/TODECIDE.md` asks if that is enough. Measures: `docs/benchmarks.md`.
- D87 (amended by D88) Published blocklists live in `docs/blocklists/blocklists.yaml`, as D67's resolvers: a source's facts
  (maintainer, licence, how it is built) and its main lists, each with its URL, what it holds, how often it
  changes and its `format`, measured: names, `*.name` and hosts lines, which `dedensd` reads (D56), adblock rules,
  URLs, and addresses or networks (IP feeds, kept for their information: `dedensd` blocks names, not
  addresses). `apps/dedensd/tests/lists.rs` reads it into typed structs: `cargo test` checks the file
  offline; `just blocklists` (ignored, outside `just check`) downloads each list as `dedensd` does (D57; 120 s,
  3 tries since oisd answers 503 now and then) and checks that most of its lines are of its format, and that a
  list of a format `dedensd` reads reads as a downloaded list. Licences differ: several forbid commercial use or
  redistribution (OpenPhish, Maltrail, Binary Defense), which the file quotes; none is a default of `dedensd`.
  Rejected: list sizes in the file (they change daily; the test prints them).
- D88 (amends D87) The blocklist file is parsed, not read as prose. `updated` is an ISO 8601 duration of weeks
  to seconds (`P1D`, `PT30M`; years and months have no fixed length) or `irregular`. A source has a `status`:
  `active`, `frozen: <date>` (unchanged since that day: 1Hosts, ipanalytics, botvrij), or `retired`, the only one
  with `lists: []`. Its `license` is an SPDX id of a short known set, `custom` or `none`, the quoted `terms`
  going with the last two only; `use` (`free`, `no-resale`, `non-commercial`, `ask`, `unknown`) is our reading of
  the terms, an SPDX licence being `free`. `just blocklists` also checks freshness: a list's date is its
  `Last-Modified`, else, on `raw.githubusercontent.com`, its last commit from GitHub's API (60 requests an hour,
  more with `GITHUB_TOKEN`); an active list older than 3 updates and a day, or a frozen one changed after its
  day, fails, so a list that stops or resumes shows. A list `dedensd` does not read is checked on its first
  MiB, its format being in every line. Dates are parsed by hand in the test, a date crate being a dependency for
  three formats.
- D64 (amends D44, D47, D54, D55, D57; amended by D104, D107, D121) Review fixes to D44, D47, D54, D55 and D57.
  - Limits (D47): a TCP connection bounds the bytes of its queued replies, not their count: reading waits while
    more than 128 KiB wait for the writer, and each write of the queued replies must end within 10 s, else the
    connection closes (a client that stops reading). Not 10 s for the queue to empty: a client that keeps asking
    and reads all it is sent keeps it from emptying, and lost its connection at 10 s of steady load. Replies of upstream queries are queued without
    waiting, so none holds its 65535-byte buffer meanwhile; the worst left is 64 replies of 64 KiB in flight past
    the bound. A TCP query the thread has no upstream slot for gets SERVFAIL (`Pipeline::abandon`) instead of
    closing the connection; a UDP one is still dropped. A UDP receive that fails right after another waits
    100 ms, as `accept` does, instead of spinning.
  - Panics (amended by D121 for tasks and listeners): a serving thread waits on the tasks of its sockets, so one that
    panics (compio catches the panic and keeps it silent) fails the thread, and `dedensd` (D46). The reload thread runs each fetch and each reload
    under `catch_unwind`: a panic is logged and counts as a failure, and later reloads still run.
  - Configuration (D44): a hosts or blocklist stage after a cache stage is refused: the cache, kept across
    reloads (D55), would keep answering a name a reload newly blocks until its TTL ends. `refresh_minutes` above
    a year (527040) is refused. `${VAR}` values with `\r` are refused as those with `\n`; lines whose first
    non-blank character is `#` are comments, left as written.
  - Reloads (D55, D57): a list change rebuilds the pipeline from the configuration text last loaded, not the file,
    which may be half edited; only SIGHUP reads the file, and its lists are fetched at once after.
  - Downloads (D57): an `https://` list is fetched with `https_only`, so a redirect cannot take it to `http://`;
    `http://` URLs stay for a server of one's own. A copy and its `ETag` never disagree: the old tag is removed,
    then the copy and the new tag are each written to a `.part` file, flushed, renamed and the directory flushed;
    the list counts as changed once its copy is renamed, a tag that cannot be written only logged.
- D104 (amends D57, D64; amended by D120, D122, D128) List downloads, from the audit (S4, S15.a, S15.c, L13, L16):
  - Size: `ureq` is built without `gzip` (`default-features = false`, keeping `rustls` and `platform-verifier`) and
    asks for `Accept-Encoding: identity` (RFC 9110 §12.5.3: no header would let a server send gzip, which is no
    list). The 256 MiB cap counted the compressed bytes, so a gzip body of that size could inflate about a
    thousandfold in memory. Rejected: keeping gzip and capping the decoded body (`take(MAX + 1)` on the decoder).
    Gzip saves bandwidth only, about 4× on a list; without it a 36 MB list within the 30 s timeout needs about
    10 Mbit/s, and a bounded decoder is code to keep. Revisit if a list server needs it. `ureq`'s limit is
    inclusive since 3.5.2: a body of exactly 256 MiB is saved, one byte more refused.
  - Retry: a pipeline reload that fails after a list was saved is retried. The copy and its `ETag` are saved
    before the reload (D64), so the next fetch is a 304 and nothing else would say the pipeline is behind. The reload
    thread keeps a `pending` flag, set when a fetch changed a list and cleared by a reload that serves (a SIGHUP
    one too, which reads the copies as well); while set, each fetch is followed by a reload, waiting as after a
    failed download: 1 min, doubling up to the refresh interval. A fetch that panics counts as changed too: it may
    have saved a copy, and a reload that finds nothing new is cheap.
  - Logs: a list URL is logged as `scheme://host[:port]path`, parsed as the client parses it (`http::Uri`; a text
    that does not parse shows as `(not a URL)`); credentials, query and fragment may be secrets. A secret in the
    path stays logged. Each `scheme://` token of an error message is redacted the same way, up to the closing quote
    or bracket around it, else to the end of the message: an error may quote a redirect target or a raw `Location`
    header, which can hold spaces. The config error of a mistyped URL is redacted too, and a config error carries
    no YAML snippet (`serde-saphyr`'s `with_snippet` is off), as a snippet could echo the `urls`: line and column
    stay, the field name in the snippet is lost.
  - Files: the `.part` file is created exclusively (`create_new`, by `tempfile`) in the copy's directory, named by
    the copy's file name, a dot and a random part, mode `0o666` less the umask as any new file (a privilege drop,
    S5, would make copies of 0600 unreadable), and removed on failure; the rename stays atomic. The old name, the
    copy's plus `.part`, was predictable, and `File::create` followed a symlink left there. Once at start, before
    the first fetch, the reload thread removes the `.part` files of the copies and tags of the configured URLs that
    a killed process left, the old name included; those of a URL since removed stay.
  - Concurrency: the lists are fetched four at a time, on named scoped threads, no `unsafe`. Four, as the lists in
    memory at once stay within 4 × 256 MiB. One slow server delays the lists queued behind it, no longer all of
    them. A SIGHUP still waits for the fetch in progress, up to ⌈n/4⌉ × 30 s for n lists; SIGHUPs queued meanwhile
    are drained after the reload, as each asks for what it did. A download that panics is caught per URL, logged
    with the redacted URL and counted as an error, and its worker goes on. The configuration keeps each URL once
    (`urls` of `Downloads`): two downloads of one URL would save one copy at once.
  - No draining on SIGTERM, by design: an in-flight download is dropped with the process, and its saved copy and
    `ETag` stay consistent as both are replaced atomically (D64).
- D65 (amends D42, D44; amended by D84, D185) Each upstream server of a forward stage has its own transport, written as in the CLI (D60,
  D61): `IP[:PORT]` over the client's (UDP for a query over UDP, TCP for one over a connection), `tls://` over TLS
  and `quic://` over QUIC, port 853 unless set, `#NAME` for the name the certificate must hold, else the address
  (RFC 8310 §8.1). An address only: a host name would need resolving before `dedensd` can resolve. One stage
  can mix transports, the first server over TLS and the next plain. Upstream certificates are checked against
  the OS trust store, or the PEM file of a top-level `upstream_ca`, which a reload cannot change (each thread's
  `dedens_net::Client` holds it; changing it logs that it takes a restart), and checks an Oblivious DoH proxy and
  target alike (D185). `dedens-server` only carries the
  transport and name (`Server`, `Via`), staying sans-IO. Rejected: transport settings per stage (`transport:
  tls`, `tls_name`), which cannot mix servers.
- D66 (amends D42, D44; amended by D115, D122) `dedensd` answers over TLS (RFC 7858) and QUIC (RFC 9250) on `listen` addresses behind
  `tls://` and `quic://`, port 853 unless set; with a top-level `tls: {certificate, key}` of PEM files, required
  with such an address and refused without one. A reload reads the files again and the next handshakes present
  the new certificate (`dedens_net::tls::Presented`, a rustls certificate resolver); a bad file fails the reload, one
  over 1 MiB too (as `upstream_ca`'s), the error naming it.
  rustls with ring, ALPN `dot` or `doq` alone, TLS 1.3 alone over QUIC, no 0-RTT (RFC 9250 §4.5). Over TLS a
  connection is a TCP one (D47's limits, its handshake within the idle time), its halves polled as the client's
  (D60). Over QUIC each query is alone on a stream the client opens, read to its end: a stream that is not one
  query behind its length, a Message ID other than 0, or an edns-tcp-keepalive option closes the connection with
  `DOQ_PROTOCOL_ERROR` (§4.3.3); a stream left with no reply (a query the pipeline drops, one not read whole, one
  the client reset) is reset with `DOQ_INTERNAL_ERROR`, never finished empty (§4.3.1, §4.3.2); a connection
  holds 64 streams at once and counts as a TCP one against the thread's connections; each thread's QUIC socket
  takes `SO_REUSEPORT`, so a client changing address may land on another thread and lose its connection. Replies to padded queries are padded (D60).
- D84 (amends D42, D44, D65; completes D82, D83; amended by D94) `dedensd` serves DNS over HTTPS on HTTP/3 (RFC 8484, RFC 9114) and
  forwards to DoH upstreams. A `listen` address `https://ADDR[:PORT][/PATH]` (port 443, path `/dns-query`; a path
  with a query, a fragment or a template expression is refused) takes UDP, as `quic://` does: the certificate of
  `tls` (D66) is required with it, ALPN `h3`, TLS 1.3 alone, no 0-RTT, the connection counted against the thread's
  TCP ones, idle time and write time D47's (no new request within the idle time, none being answered, ends it, pings or not; the idle time counts from the later of the last request taken and the last reply sent, decided by the owner: counted from the request alone, a reply 5 s late left the connection 5 s of idle time, and one that came as the idle time ran out a whole idle time more; DoQ's streams likewise, 2026-11-20: counted from the last stream alone, a stream opened past it while a slower query was being answered was never taken), 64 request streams and 16 unidirectional ones (control and QPACK, D83) at once, the
  connection set up and each request read within that idle time. A request goes through D82's `server_request`,
  then the pipeline as any query (over `Transport::Https`: padding as D60 says); a request for another path is 404
  whatever its method, a query the pipeline drops is 400 (RFC 8484 §4.2.1: the status says the request is bad,
  not the DNS answer), the other statuses are D82's. The reply is D82's `server_response`: `cache-control` for a
  GET only. Stats (D30): `dedensd_doh_queries_total{method, status}`, the method `get`, `post` or `other` and the
  status one of those above or `other`, so labels stay few. An upstream `https://IP[:PORT][/PATH][#NAME]`
  (`Via::Https`, port 443, path `/dns-query`) is asked over D83's connection by GET, whatever transport the
  client came over; `#NAME` is the certificate name (D65) and the authority of the URL, else the address is. An
  address only, as D65: a host name would need resolving first (docs/TODECIDE.md). Rejected: HTTP/2 or
  HTTP/1.1 listeners (step 23), and `Listen` matching the request's authority, which the path alone serves.
  Checked against an independent client, aioquic 1.7.1 (2026-11-01, two listeners with a test CA, forwarding to
  8.8.8.8): GET with `dns=` and POST are 200 with `application/dns-message`; `cache-control: max-age=300` on a
  GET of an answer (its TTL), `max-age=1800` on a GET of a no data (the SOA's TTL and MINIMUM), none on a POST; the
  ID is echoed; 415 for a POST of another or no content type, and a content type in other case with a parameter is
  accepted; 400 for garbage or no body, a missing, malformed, padded (RFC 8484 §6 forbids the padding) or
  non-DNS `dns`; 404 for another path, also `/.well-known/odohconfigs` without `odoh`, and for the other listener's
  path; 405 for PUT and DELETE; 413 for a 70000-byte POST. A request the pipeline cannot parse as a query (a wrong
  label length) is 200 with FORMERR (§4.2.1).
- D90 (amends D47, D77; superseded by D113 for UDP and DoC: kept for TCP, TLS, QUIC and HTTPS; amended by D91) Rate limits per client address are the deployment's: nftables `hashlimit` or `dnsdist` in
  front of `dedensd` limits queries and connections per address, for UDP, DoQ and DoT alike (a general reverse
  proxy such as nginx `stream` does TCP only, and a proxy hides the client's address unless PROXY protocol or the
  like carries it). `dedensd` keeps what only it can weigh: the validation cost of one query (256 units) and the
  allowance all queries draw on (D77), and the per-thread connection cap (D47). No per-address query limit and no
  per-address connection cap in `dedensd`. RRL (response rate limiting, a defence against reflection) belongs to
  the authoritative phase, where the server answers from its own data; a stub or forwarder has nothing to
  amplify. The client's address enters the pipeline only for the allow and block lists (`docs/TODECIDE.md`).
- D113 (supersedes D90 for UDP and DoC; amends D44, D47, D91, D105; audit S1; amended by D136) `dedensd` limits the rate
  of responses over UDP and DoC per client network, and gives Server Cookies that exempt a client from the limit.
  D90 left both to the deployment on the ground that a forwarder has nothing to amplify; a cache hit answers a
  ~40-byte query with up to 1232 bytes (a 1.2 kB TXT, `benches/server.rs`), to a source address anyone can forge, so a daemon safe by default
  cannot leave the limit to a firewall it may not have. Decided by the user. TCP, TLS, QUIC and HTTPS stay as D90 says:
  the handshake proves the address (QUIC answers Initial with Retry, D47) and a per-address cap stays the deployment's.
  The settings are `rrl` and `cookies` in `apps/dedensd/src/config/limits.rs`, the code `rrl.rs` and `cookie.rs` of
  `dedens-server`; both are on by default.
  - What is limited. A UDP query, before any check but the access lists, so a FORMERR is limited too; a REFUSED of the
    access lists (D91) as well, since the default lists refuse every Internet source and that REFUSED is as spoofable
    as an answer, and past the limit it is dropped, never truncated. A response (QR set) or a header-less datagram is
    dropped before, so forged responses spend no bucket. DoC is limited too: unprotected CoAP over UDP is as spoofable,
    and D105 left the rate of a source to this step. A DoC discovery or DNS query counts; an error does not (it is no
    larger than its request), nor a request for a later block (no body, Block2 number over 0): it follows a query that
    counted and D105 bounds it. CoAP has no TC, so a limited DoC request gets nothing, slip or not.
  - Not limited: connection-oriented transports, as above; sources in `rrl.exempt` (default loopback, which cannot be
    forged from outside; a proxy or a monitor on another address goes in the list, as BIND's `exempt-clients`); a query
    with a valid Server Cookie, which proves the address.
  - Limit. Token bucket per client network, `/24` IPv4 and `/56` IPv6 (BIND `ipv4-prefix-length` and
    `ipv6-prefix-length`, `doc/arm/reference.rst`; Knot's levels, `src/knot/modules/rrl/functions.c`); IPv4-mapped
    IPv6 counts as IPv4 (D91). Every query counts whatever the name: Unbound's `ip-ratelimit` does too, and BIND's
    `responses-per-second` counts identical responses, which its documentation warns hurts recursive servers.
    Defaults, Knot's (`rate-limit` 50 and `instant-limit` 125 per address, `rrl.c`) times its multipliers for those
    prefixes (32 for `/24`, 3 for `/56`, `functions.c`): IPv4 1600 a second, burst 4000; IPv6 150, burst 375. A burst
    left out is 2.5 times the rate; one below the rate is refused at read (the bucket would never fill). BIND and
    Unbound ship it off; here it is on, because this one protects others. A network sending more than 1600 queries a
    second gets slips and falls back to TCP or a cookie: raise `rrl.ipv4.rate`, or turn it off.
  - Slip (BIND `slip`, Knot `slip`). Of the queries over the limit, one in `slip` is answered, the rest dropped. Default
    2 (BIND's; Knot's is 1), 0 to 10. A deterministic count per bucket, not Knot's random roll, so tests are exact. The
    answer is an empty reply with TC=1 (RFC 1035 §4.2.1, never larger than the query), or, for a query with a Client
    Cookie, BADCOOKIE with a fresh Server Cookie (BIND's rule; RFC 7873 §5.2.3): a real client retries with the cookie
    and is no longer limited. A slip is never larger than its query plus the 16 bytes of the Server Cookie (a test
    asserts it): at most 1.4 times a 40-byte query, 0.7 averaged over slip 2, where a hit gives up to 30 times.
  - Table. A fixed array of `table_size` (default 65536, 512 KiB) `AtomicU64` buckets, indexed by a keyed hash of the
    network (SipHash-1-3 under a key random to the process, as D22 and D58: an attacker cannot aim at a bucket; a
    simulation passes a fixed one, `with_key`, D133). Memory never grows, whatever
    sources are spoofed (BIND bounds its table, `max-table-size` 20000; Knot's is fixed, `table-size`). Networks sharing a
    slot share a bucket, so a flood from many networks can limit an innocent one at about `table_size` times the rate in
    all. Rejected: a map with eviction (the flood chooses what stays), a lock per bucket (a CAS loop on one word needs
    none and no `unsafe`), key tags (the table would hold more than a word per bucket). A reload keeps the `RateLimit`,
    table and all, while its settings are unchanged: a new one would hand every source a full bucket.
  - Cookies (RFC 7873 §5.2, RFC 9018). A query with a COOKIE option gets a fresh Server Cookie in its reply, on every
    transport, after its own cookie is checked: version 1, SipHash-2-4 (`siphasher`) of the Client Cookie, version,
    reserved bytes, timestamp and client address, so servers of other makes sharing the secret accept it (§4.4;
    Appendix A.1-A.4 are the tests of `tests/access.rs`). Valid is version 1, 16 bytes, from at most an hour ago and
    five minutes ahead (§4.3), hash matching one of the secrets; reserved bytes are hashed as received (§4.2). Only the
    first COOKIE option of a request counts (RFC 7873 §5.2; `Options` in `dedens-proto` skips the others). A cookie is
    not forwarded upstream.
  - Invalid Server Cookie: answered normally, with a fresh cookie, as a Client Cookie alone (RFC 7873 §5.2.4, §5.2.3
    option 3), not BADCOOKIE: a stub whose cookie went stale (restart, secret change, anycast skew) would get no
    answer without a retry, and BIND does the same by default (`require-server-cookie no`). The cookie only buys the
    exemption from the limit. A bad length stays FORMERR (§5.2.2), with no cookie; a query breaking another rule is
    FORMERR with its well-formed cookie answered, Client Cookie and fresh Server Cookie (§5.2.2 drops only a
    malformed COOKIE option; decided by the user, audit 4). A cookie and no question is a request for a cookie
    (§5.4): NOERROR with it, BADCOOKIE if the Server Cookie sent was invalid.
  - Secrets (RFC 9018 §5). `cookies.secret` (32 hexadecimal digits, quoted in YAML, `${VAR}` keeps it out of the file)
    and `cookies.accept` (others accepted) roll as §5 says for anycast: stage 1 secret OLD, accept NEW; stage 2 secret
    NEW, accept OLD; stage 3 secret NEW. Without them, one random secret is drawn at the first read of the
    configuration and kept for the process, so a reload keeps cookies good and a restart makes them invalid once.
    Rejected: a master from which a secret per day is derived (a rotation by itself): a secret that
    changes at restart or by configuration gives no less (a cookie's timestamp bounds its life to an hour) and the
    code is twice as long. `accept` without `secret` is an error. `Secret` is zeroed on drop and prints nothing.
  - Counted: `dedensd_rrl_limited_total{action=slip|drop}` (CoAP counts under `drop`) and
    `dedensd_cookies_total{outcome=none|client_only|invalid|valid}`.
  - Cost (`benches/rrl.rs`, `docs/benchmarks.md`): about 11-20 ns on a cache hit for the limit, 50-60 ns more for a
    cookie; a limited query costs half a hit. A query reads the clock once, when it first needs it, for the check of
    its cookie and the one made for its reply (`cookie::Reading`; twice for a valid cookie before audit 4, about
    13 ns).
  - Not done: the limit counts queries, not responses by name; cookies are not required (`require-server-cookie`); a
    Server Cookie is made anew for each reply, not kept until half an hour old (§4.3 SHOULD only).
- D93 (amends D77; amended by D124) An answer a validating stage proved insecure is cached a day at most, as keys are (D86), not for
  `max_ttl`'s 7 days (2 since D124): a zone that turns secure gets AD on its answers within a day, as its keys do. The cap is
  `dedens_cache::Config::max_insecure_ttl`, applied by `Response::build` to what `Checked::Insecure` stores, on top
  of `max_ttl` and `max_negative_ttl` (a negative answer is under three hours anyway); `Unchecked` and `Secure`
  keep `max_ttl`, so a secure answer, which the signatures bound, is not shortened. Serve-stale and prefetch see
  the capped TTL as any other. The CD copy of a bogus response is stored `Insecure` and so under the cap too, within
  `bogus_ttl`. The setting is an `Option<u32>`, not a `u32` defaulting to 86400 beside a refusal above `max_ttl`:
  that pair would refuse every configuration with a `max_ttl` under a day that does not also lower the new key
  (`max_ttl: 3600` is a configuration the tests read). `None`, the default, is a day or `max_ttl` if less
  (`Config::insecure_ttl`); a value is refused as `ConfigError::InsecureTtl` when 0 (a response kept for no time) or
  above `max_ttl`. Rejected: capping in `dedens-server`
  (the cache owns every stored TTL); a TTL for secure answers too (nothing asks for it). Tests:
  `dedens-cache/tests/checked.rs`, the configuration tests of `apps/dedensd/src/config/`.
- D124 (amends D22, D43, D77, D93) The cache keeps a response at least `min_ttl` (default 60 s) and at most `max_ttl`
  (default 2 days, was 7), so that a flood of short-TTL names is not asked upstream again and again, and stale data is
  bounded by two days (audit step 23, Unbound's `cache-min-ttl`). `Response::build` raises the smallest TTL of the
  response to `min_ttl` before the caps (`max_ttl`, `max_negative_ttl`, the insecure cap, `bogus_ttl`): the raised
  lifetime is the one stored, so a hit serves TTLs counting down from it (D22: every record gets the entry's
  remaining lifetime, so a record of 3 hours beside one of 10 s is served with the entry's lifetime, as before), and
  prefetch (D43's tenth of the lifetime), serve-stale and the failure hold start from it with no code of theirs. The
  hit path is unchanged, so no bench. Negative answers are raised too (RFC 2308 §5), within `max_negative_ttl`.
  A smallest TTL of 0 is not raised: the answer stays uncached (`NotCached::ZeroTtl`, RFC 1035 §3.2.1, RFC 2181 §8).
  `min_ttl: 0` turns it off. Refused as `ConfigError::MinTtl` above the least of `max_ttl`, `max_negative_ttl` and the
  insecure cap, which would otherwise cut the stored TTL under it.
  - DNSSEC: RFC 4035 §5.3.3 bounds a validated TTL by the signatures' expiration. The cache does not see it: the
    validator has already lowered the TTLs of the message to the verdict's (D77), and a TTL it lowered for the
    expiration reads like any short one. So a `Checked::Secure` answer is **not raised**: it keeps the validator's
    TTL, and a flood of short secure answers is not absorbed (open: `docs/TODECIDE.md`). `Unchecked` and `Insecure`
    are raised (`Insecure` within its cap, D93); a bogus response keeps `bogus_ttl`, the least of the caps. An insecure
    answer's TTL may have been lowered by the validator for the keys it walked (D86): the minimum can keep it up to
    `min_ttl` past that.
  - RFC deviation: the zone's TTL says how long a record may be reused (RFC 1035 §3.2.1, RFC 2181 §8, RFC 2308 §5);
    a TTL below `min_ttl` is raised, and clients see the raised one. An owner who shortens a TTL to move traffic waits
    up to `min_ttl` longer. Hence 60 s, and 0 to turn it off.
  - Rejected: raising TTL 0 (it forbids caching, and the 0 of an SOA is a zone saying so for a negative answer); a
    separate minimum for negative answers (Unbound's `cache-min-negttl`; one setting until a deployment asks);
    raising only the lifetime and serving the zone's TTLs (clients would re-ask at once: the flood stays); bounding
    `Secure` by a guess of the expiration (a validator change, TODECIDE).
  - Tests: `dedens-cache/tests/{rfc,cache,checked}.rs` on the captured responses of `dedens-proto`, the
    configuration tests of `apps/dedensd/src/config/`. Tests that count the zone's seconds set `min_ttl: 0`.
- D94 (amends D79, D84, D91; amended by D117) `dedensd` is an Oblivious DoH proxy too (RFC 9230 §4, `odoh` feature): `odoh: {proxy: {targets:
  [HOST[:PORT]], timeout_ms}}` makes each `https://` listener forward the requests that name a target. `targets` is
  required and not empty, a port is 443 unless given; a name is read strictly (UTS 46 with STD3 rules and the label
  and 253-byte limits, as A-labels in lower case, one trailing dot dropped) and a name or port that does not read is
  refused at start; targets are kept sorted and without duplicates. `timeout_ms` (default 5000) bounds a forward: the
  name's resolution, the connection and the response together. A restart applies a change (D79: `odoh` is fixed at
  start). No proxy section, no proxy.
  - Routing: at the listener's path, a request whose query has `targethost` or `targetpath` is the proxy's; any other
    is the target's (D79) or plain DoH's, as before. The query form of §4.1's template is the one served
    (`/dns-query?targethost=H&targetpath=P`, percent-decoded, `+` kept): the path form `/{targethost}/{targetpath}`
    would need a listener path with expressions, which D84 refuses and which would shadow the paths of a DNS
    server. A proxy's request is a POST of the media type with a body (405 with `Allow: POST` (RFC 9110 §15.5.6), 415,
    400, 413 as D79's target), each variable once, `targethost` a `HOST[:PORT]`, `targetpath` an absolute path of
    the characters RFC 3986 allows in a path and a query once decoded (a decoded `é` or DEL is not re-encoded: 400);
    else 400 (§4.1). The body is the same bytes both ways: the proxy never opens it.
  - Policy (§11.2): only listed targets (403 `http_request_denied` with `details`, as §4.1 words it, also for a port
    not listed: the non-standard ports §4.1 allows refusing), and only for the clients D91's access lists allow: one
    they deny, with either action, gets the same 403 and error with `details="client not allowed"` before any
    resolution, counted in `dedensd_access_denied_total{action}` (D91); RFC 9209 §2.3.17 says the intermediary
    rejected the request by its policy and forwarded nothing, which is this, so no token of its own. A `drop`
    client mostly never gets this far: its connection is ignored or closed at accept. A listed IP literal is forwarded as written (the tests'
    loopback target). A name is resolved by the system resolver (D83's client does too: `getaddrinfo` through compio)
    rather than the pipeline, which may block or rewrite it; so a host whose system resolver is `dedensd` itself
    sends the lookup through the pipeline and back, and waits for the forward's time. The first address that is global
    (not in the IANA special-purpose registries, RFC 6890, nor multicast; IPv6 outside 2000::/3, 6to4, documentation;
    mapped and NAT64 addresses judged by the IPv4 inside; the whole of 192.0.0.0/24, which includes 192.0.0.9 and
    192.0.0.10, and 192.88.99.0/24 on purpose) is used, and a name with none is 502 `destination_ip_prohibited`: a
    listed name that points inside the network is not an open door to it. The address a name was checked as is kept
    60 s per thread, so a forward within that time, and any on a connection that is still up, does no lookup.
  - Forward: a new POST to `https://targethost/targetpath` over HTTP/3 through `Http3Pool` (D83), one connection per
    address and name kept 30 s idle and shared by requests (§11.2 recommends it: a connection of a client's own would
    let the target link its queries), checked against `upstream_ca` or the system (D65). The request is built, not
    copied: media type as content type and accept, `content-length`, no `Forwarded`, `Via`, cookie or other header of
    the client (§4.5; the pool adds none), no address. Forwards have their own limit, 256 in flight per thread,
    apart from the resolver's upstream queries (D47), so a target that does not answer cannot starve resolution: one
    more is 503 `connection_limit_reached`. No redirect is followed.
  - Response: the target's status and body, its content type only (a `Location` would send the client to the target
    directly), `Cache-Control: no-cache, no-store` (§4.1) and `Proxy-Status: dedensd; received-status=N` (§4.3; RFC
    9209 §2.1.4). A success of the target with another content type than the media type is 502 `http_protocol_error`
    (§4.3 gives the client no other reading). The client's `proxy_error` (D79) reads only `error`, so a target's 401
    stays the target's and leads to the refetch. A failure is a response of its own with `Proxy-Status: dedensd;
    error=TOKEN` (RFC 9209 §2.1.1, and `details` on a 403) and no body: 400 `http_request_error`; 403
    `http_request_denied`; 502 `dns_error`, `dns_timeout` (§4.1 says 502 for it where RFC 9209 says 504),
    `destination_ip_prohibited`, `connection_refused` (the QUIC `CONNECTION_REFUSED`), `tls_protocol_error` (any TLS
    alert of the handshake, a certificate not trusted included: no finer `tls_certificate_error`),
    `connection_terminated`, `http_protocol_error`, `http_response_body_size` (RFC 9209 §2.3.21); 503
    `connection_limit_reached`; 504 `connection_timeout` while the connection is not up and `http_response_timeout`
    (§2.3.26) once the request is out; 500 `proxy_internal_error`. They live in `dedens_net::odoh::proxy` (`route`,
    `forward_request`, `forwarded`, `failure`, `rejection`, `ProxyError`) over `http` types, tested without a socket,
    as D79's functions, and fuzzed with `read_odoh_http`; the `dedensd` part (`apps/dedensd/src/odoh/proxy.rs`)
    resolves, checks and sends.
  - Privacy: no log line at info or below tells a client address and a target together; a failure logs its `error`
    token at debug, with neither. Stats: `dedensd_odoh_proxied_total{status}`, the status one of those above or
    `other`. No rate limit per client on the forwards: the deployment's (D90; D113 limits UDP only; the target's decapsulations are D117's). The pool keeps
    a slot per address a listed name resolved to (`docs/TODECIDE.md`).
  - Tests: `apps/dedensd/tests/odoh.rs` (a real `dedensd` as proxy to a real one, or to a test HTTP/3 server that
    records what it sees: the client's query answered, the proxy answering as a target too, the target's 200 and its
    401 returned with their `received-status`, never cached, two forwards on one connection and no header of the
    client at the target, each of the statuses above with its `Proxy-Status` except `dns_timeout`, which no test can
    make without a resolver that hangs, and the ones for which no port is free to be silent: refused by a QUIC
    server, silent by a UDP socket nobody reads, a target that connects and never answers, untrusted by another
    authority), unit tests of the routing, the target syntax and the address classes.
  - Checked live (2026-11-01): the brief's command needs a proxy certificate a public store trusts, and `dedens` has
    one trust for both hops (`--tls-ca` replaces the store for the target too: `docs/TODECIDE.md`), so a local
    `dedensd` listened on `https://0.0.0.0` (an unprivileged process cannot bind UDP 443 on one address here) with
    a certificate of a throwaway authority and the targets listed, and `dedens --tls-ca CA
    +odoh-proxy=https://127.0.0.1/dns-query +odoh-config=FILE @https://TARGET/PATH example.com A`, the
    configurations fetched with `curl` and pinned, answered NOERROR over ODoH (HTTP/3 200) from
    `odoh.cloudflare-dns.com`, `odoh.crypto.sx` and `doh.tiar.app` (path `/odoh`). `odoh.cloudflare-dns.com:8443`, not
    listed, was 403: the CLI exits 10 with "the proxy answered HTTP status 403". Not checked live: a client other than
    ours against this proxy, `dns_timeout`, a host with one IP family only.

- D91 (amends D44, D47, D90; amended by D94, D113) Client access lists: `dedensd` answers the networks it is told to, so it is no open
  resolver (RFC 5358 §4). The client's address enters `Pipeline::query` with the transport, from every listener
  (UDP, TCP, TLS, QUIC, DoH, DoC, and ODoH where `dedensd` is the target, the proxy's address being the client's
  there), an IPv4-mapped IPv6 address read as its IPv4 one. A `Pipeline` holds an optional `Access`: the library
  and its tests, benches and fuzz targets build none and answer everyone; `dedensd` always builds one, so a reload
  (D55), which rebuilds the pipeline, changes the lists with it. Top-level `access: {allow: [networks], deny:
  [networks], action: refuse|drop}`, `refuse` by default. The longest network holding the address decides, `deny`
  wins a tie, an address in no network is denied. Unset `access` is the loopback (`127.0.0.0/8`, `::1/128`),
  RFC 1918, RFC 4193 (`fc00::/7`) and link-local (`169.254.0.0/16`, `fe80::/10`) networks allowed, so a fresh
  install on a public address answers nobody; `dedensd` warns at start for each listen address outside them. A
  network is `ADDRESS/LENGTH`; the config is refused for text that is none, for bits past the length
  (`192.0.2.1/24`, the error names `192.0.2.0/24`), for an IPv4-mapped IPv6 network (`::ffff:10.0.0.0/104`, the
  error names `10.0.0.0/8`, since clients are read as IPv4), for an IPv6 network that starts in
  `::ffff:0:0/96` and is shorter than /96 (`::ffff:0:0/95`; `::/0` stays valid and holds IPv6 clients only) and for
  an unknown action. A denied query is answered before any stage, from the query in place: `refuse` writes REFUSED
  with EDE 18 (Prohibited, RFC 8914 §4.19) carrying the query's ID and question with `Client::answer`, with no
  `Message` and no allocation (FORMERR's rule: a response, or under 12 bytes, gets nothing; a query with no
  readable question gets the `Client::reply` fallback), `drop` sends nothing. Over DoH a refused query is still 200
  with the REFUSED message (RFC 8484 §4.2.1); a dropped one gets no connection (below), or, on a connection a
  reload found open, 400 without a message, as any query the pipeline does not answer. `Pipeline::drops(from)`
  tells a denial that sends nothing from a protocol drop, and `Pipeline::denial(from)` is the verdict alone,
  uncounted. The transports use them:
  - `drop`: TCP and TLS close the connection at accept, before a connection slot (D47) and the handshake; QUIC
    calls `Incoming::ignore`, before Retry and a slot, so a forged source gets nothing; DoC sends nothing, not
    the 4.00 a protocol drop gets (RFC 9953 §4.3.1).
  - `refuse`: the connection is accepted and every query on it is answered REFUSED, so a denied client costs a
    slot and a handshake. Accepted, because a client that is told it is refused does not retry, and checking
    before the handshake would be `drop` in effect; the deployment's firewall (D90) is what keeps denied clients
    off the slots.
  - ODoH proxy (D94): a request to forward is served only to a client the lists allow, whatever the action
    (`Pipeline::denies`, which counts); a client they drop is closed at accept, as for any request, and on a
    connection a reload found open, or one they refuse, the answer is 403 and nothing goes to the target.
  - DoC Block2 follow-ups (RFC 7959) are served from the kept response only to a client the lists still allow,
    so a reload takes effect on a transfer under way; a confirmable request the duplicate filter replays a reply to
    is not checked, as the filter keeps it for the exchange lifetime only. `breaks_doq` runs before the check: breaking DoQ ends the connection and
    answers nothing, so a denied client gains nothing.

  Warnings: at start and at each reload that succeeds, `dedensd` warns for each listen address outside the local
  networks when `access` is unset, and when `access` is set with an empty `allow` (it answers nobody). Stats
  (D30): `dedensd_access_denied_total{action}`, counted in `dedens-server` behind its `metrics` feature, where the
  verdict is made. The lookup is a longest-prefix tree, never a scanned list: `prefix-trie` 0.10 (`JointPrefixMap`
  over `ipnet::IpNet`; MIT OR Apache-2.0, in `deny.toml`'s list; updated July 2026, 19M downloads in 90 days)
  over `ip_network_table` 0.2 (BSD-2-Clause, which `deny.toml` does not allow; last release in 2021; a forked
  treebitmap underneath). It pulls `array-const-fn-init` (a proc-macro, with the legacy licence `MIT/Apache-2.0`,
  read as either), `either`, `num-traits` and `smallvec`. Cost in `docs/benchmarks.md`: a verdict is 1.4-24 ns in a
  table of 10 000 networks, a denied query 42 ns with no allocation (161 ns and two allocations when built from a
  `Message`). Not here: blocking by answer address (`docs/TODECIDE.md`).
- D107 (amends D51, D55, D64; amended by D122, D147, D174) Runtime fixes of audit step 04.
  - QUIC datagrams (RFC 9221 §3): both the server (`endpoint`) and `Dialer` set `datagram_receive_buffer_size(None)`.
    quinn's default of 1.25 MB made both advertise `max_datagram_frame_size` and buffer DATAGRAM frames nothing
    reads (RFC 9250 uses streams alone). Now a peer sees `max_datagram_size()` as `None`, which the tests check
    (`tests/quic.rs` of `dedens-net` and `dedensd`). That quinn then closes the connection on a DATAGRAM frame
    (PROTOCOL_VIOLATION, as RFC 9221 §3 requires) is its behaviour, not tested here.
  - Driver (amends D51): the ring is made with `COOP_TASKRUN` and `TASKRUN_FLAG` (Linux 5.19), with no retry
    without those flags on EINVAL; Linux 6.0 is the floor for `io_uring` (D174). compio falls back to `poll` when
    the ring cannot be made (a seccomp filter, `kernel.io_uring_disabled`), with a `warn!` nobody sees, so the "serving" event has a `driver`
    field (`io_uring`, `poll`, or `mixed` if the threads differ), and on Linux a thread on `poll` is a warning at
    start, with the count of threads on it. compio's own logging (its `enable_log` feature) stays off: it
    instruments the driver's hot path, unmeasured. `tests/listeners.rs` expects `io_uring` on Linux, unless
    `DEDENS_TEST_ALLOW_POLL` is set (a container whose seccomp filter refuses it); the fallback itself is tested
    by forcing it (D147).
  - UDP receive (amends D64): the pause after a failed receive is per task, and the lock on the socket's stream is
    released before it, so the socket's other tasks keep receiving. A first error is retried at once and a second
    in a row after 100 ms, as D64 has it. `ResourceBusy` (`ENOBUFS`: the pool's 256 buffers, D49, are held by
    datagrams the kernel filled and the tasks have not read) is no failure but a wait for the tasks to read:
    `Receiving`, per task, yields 4 times, then sleeps 1 ms between tries, reset by a datagram. Yielding alone
    spins: on `io_uring` each retry is a submission the kernel refuses at once while the pool is empty.
    `just bench-dnsperf BASE two-sockets` (one core, two UDP ports, the first flooded, the second asked at 2000
    queries/s, `docs/benchmarks.md`) shows no loss and the same latency before and after (0.3 ms on average, 10-13 ms
    at most): the flood never emptied the pool, so it does not reach the case; the unit tests do.
  - A runtime is never dropped (`ManuallyDrop` in the thread's closure, `lib.rs`): dropping one on a thread that
    panicked or failed closes the ring and frees the buffers of operations the kernel may still write to, while the
    other threads serve on. The process ends right after the first thread does, and the kernel then closes the
    ring. No `unsafe`: `ManuallyDrop` is safe, a leak being so.
  - Reloads (amends D55, D64): `Current::replace` also wakes each thread, through a `flume` channel of one per
    thread (`Current::follow`, which subscribes before it reads the generation and the pipeline); a `follow` task
    per thread takes the new pipeline on it. An idle thread held the old one, its lists included (about 110 MB with
    the largest), until its next query. The hot path is unchanged: one atomic load of the generation per query, no
    bench needed. Rejected: a periodic check (a wake-up per thread each period for nothing, and the old one held
    till the next).
- D147 (amends D107) On Linux's `poll` fallback, UDP queries were answered with nothing: compio-driver 0.12.5's
  fused driver did not pass `set_result` on to the `poll` side of an operation, so `recv_from_multi` (D49) gave
  each datagram a length of 0 and the pipeline dropped it. TCP, DoT, DoQ, DoH and CoAP read otherwise and were
  answered. Any host refusing the ring hit it: Docker's default seccomp profile, `kernel.io_uring_disabled`. Fixed
  in compio (commit `8b82dbc` on `spnngl/compio` branch `fix/fusion-poll-set-result-v0.19`, on top of 0.19.2), taken
  through `[patch.crates-io]` of `compio-driver` at that commit, the one git source `deny.toml` allows, until a
  compio release has the fix; then the patch goes. Rejected: reading one datagram at a time on `poll` in dedensd
  (a second receive path to keep). `serve/mod.rs` tests the fallback by building the runtime on `poll`
  (`a_udp_socket_answers_on_the_poll_driver`), which every Linux and macOS run of the gate does.
- D174 (amends D107) Linux 6.0 is the floor for `io_uring`: before it, `dedensd` asks for `poll`. compio-driver
  (D147's commit `8b82dbc`) receives UDP by multishot `recvmsg` from 6.0 only (`sys/op/managed/iour.rs`); before,
  it pops a buffer from its pool by hand, which the `io_uring` pool refuses (`Unsupported`), so on 5.19 a UDP socket
  received nothing, its tasks retrying at debug level forever. `serve::runtime` reads the release by `uname` (nix's
  `feature` feature) and asks for `poll` below 6.0, or when the release does not read
  (`a_kernel_before_6_0_serves_on_poll`); the start's warning says 6.0. A UDP receive error that repeats is a
  warning, once a minute at most per task, so a deaf socket shows (`a_receive_error_that_repeats_is_warned_about`);
  a lone one, or a lack of free buffers, stays at debug. Rejected: a second UDP receive path for 5.19 in `dedensd`;
  fixing compio's fallback in the D147 patch (upstream's to fix, the patch kept to one fix).

- D106 (amends D71, D74, D75, D77; amended by D117) Validation cost counts what it costs: the debt of the admission bucket stops at
  one burst and a query in debt asks no more, and NSEC3 hashing is counted in SHA-1 blocks, as the salt and the name
  make them.
  - Debt: `Budgets::charge` (`dedens-server/src/budget.rs`; `Bucket::charge` of `validate.rs` until D117) floors the units at `-burst` (default -20 000). Before,
    2 000 expensive queries admitted together left about -770 000 units and validation shed for about 77 s after the
    flood stopped; now it admits again `burst / per_second + 1` s after (3 s by default: `admit` wants a unit above
    zero, and the clock counts whole seconds). The floor forgives the units above it, so a query is also stopped
    from spending them: `Check::next` charges the step it ran and, if the bucket is then in debt and the query would
    ask another question, ends it with `Progress::Shed`, answered as a query refused at `admit` is: SERVFAIL with
    EDE 14 (Not Ready), nothing held or cached (the response is not at fault, so not `Indeterminate`, which holds
    the failure), counted in `dedens_validations_total{verdict="shed"}` as a refusal is. The real bound: the work
    past the first debt is one validation step of each query in flight at that time, a step at most 130 units (the
    validator's `Budget` of 128 verifications and 8192 blocks, 2 units), and a few units for the common step; the
    floor then forgives it. A query in flight took a unit at `admit`, so they are at most `burst` plus the refill
    while they run. `per_query` bounds one query to within the step that goes over it, as `Check::next` checks
    after the step. Rejected: reserving `per_query` at admission and refunding the rest (the audit's first fix): it
    adds an exit path to each query's life in the pipeline to refund from, and a query that costs 2 units would
    still hold 256 while it runs. `charge` and `in_debt` take the second, as `admit` does, and count the refill
    earned until then first; `charge` moves the bucket's second to it. Before (audit 4), the seconds a bucket was
    idle before a charge repaid that charge at the next `admit`.
  - NSEC3 blocks: `Budget::nsec3_hash(salt, iterations, owner)` is the one way to hash with a budget: it spends the
    SHA-1 blocks the hash computes (RFC 5155 §5), then hashes (`spend_nsec3_blocks` is private, so no hash is
    unpaid): `blocks(owner wire length + salt length) + iterations * blocks(20 + salt length)`, with `blocks(n) =
    ceil((n + 9) / 64)`, the 9 being SHA-1's `0x80` and 64-bit length (FIPS 180-4 §5.1.1). The first computation
    hashes the owner name, the later ones a 20-octet hash, so a long name costs on the first only: `(iterations + 1)
    * blocks(max(owner, 20) + salt)` is an upper bound of this, and charges a name's first block to every
    iteration. A name with 55 octets or fewer with its salt, and a salt of 35 or fewer, cost one block a
    computation, `iterations + 1`, as before: that is every zone that follows RFC 9276 §3.1 (empty salt). The
    limits keep their numbers and change their unit, blocks: `Budget::DEFAULT_NSEC3_BLOCKS` 8192 (D71),
    `BLOCKS_PER_UNIT` 4096 an `Allowance` unit (D77), `Cost::nsec3_blocks` (D75), `Nsec3Blocks`. So 8192 blocks
    cover 54 names at 150 iterations and no salt as before, but 10 with a salt of 255 octets (755 blocks each): a
    salt is no longer a free multiplier of 5 on the CPU a response costs. `Unproven::UnsupportedHash` (D74) is gone:
    the chain keeps only SHA-1 records (RFC 5155 §8.1), so nothing made it. A block takes 93 ns at no salt, a little
    above the 90 ns the defaults were sized with, and less with a long salt (`docs/benchmarks.md`): 8192 blocks are
    0.8 ms and a unit 0.4 ms, kept. Rejected: refusing a salt over 64 octets as insecure (the audit's alternative):
    RFC 9276 §3.1 only tells zone operators to use none, RFC 5155 §3.1.4 allows 255, and refusing would change the
    verdict of zones that validate today, where counting changes only what a response may cost. Each chased CNAME
    name starts a validation with a fresh `Budget` (D77), so one query may spend 9 of them (the first and
    `MAX_CHASES`), 73 728 blocks, 18 units, 6.6 ms of hashing at most; the `Allowance` charges it as it goes.
  - Tests: `the_debt_of_a_flood_stops_at_one_burst`, `the_bucket_is_in_debt_only_below_zero` and
    `an_idle_period_does_not_repay_a_later_charge` in `budget.rs`,
    `the_debt_of_queries_in_flight_is_at_most_a_burst` and `a_flood_in_flight_asks_no_more_than_the_burst_allows` in
    `dedens-server/tests/dnssec.rs` (captured chains), `a_long_salt_costs_the_blocks_it_makes` in
    `dedens-dnssec/tests/denial.rs` (RFC 5155 Appendix A's records, salt rewritten) and the unit tests of
    `crypto/budget.rs` (block boundaries, the paid hash).

- D111 (amends D41) `Pipeline::receive` checks each upstream response against the question sent, as `dedens-net`
  does (D27, D50; RFC 5452 §9.1), so the core is safe on its own, driven by a transport of tomorrow or a test: QR
  set, opcode QUERY, exactly one question, equal to the one sent with its name in any case (RFC 4343 §4; `0x20` is
  the transport's, the core never sees the case sent). The question sent is the validator's while one of its
  questions is upstream (D77), the client's otherwise. A response failing a check is that server failing, as a
  timeout or SERVFAIL: the next server is asked, and after the last the failure is held (D43); nothing is stored
  from it. The ID is not checked: the transport picks it (D27), the core never knows it. Through `dedensd` this is
  the second check: the transport already drops such a datagram and goes on waiting. No new parsing, the decoded
  message is read: `miss` bench a/mx/txt_large 0.67-0.72/1.25-1.30/1.88-1.92 µs against 0.71/1.26/2.00 µs before,
  15 allocations in both. Rejected: leaving the check to `dedens-net` (the audit's L1: an unchecked transport
  sends uncached replies out as they came).

- D114 (amends D22, D27, D31, D41, D43, D77) Checks on what answers carry (audit step 15; L2, L3, S1.2):
  - AD is ours alone (L2): set only on data our validator checked secure, which is `dnssec: validate` (D77); RFC 6840
    §5.8, RFC 4035 §3.2.3. A forward stage without a validator clears upstream's AD in `Pipeline::receive`, over any
    transport, and the cache keeps such a response as `Checked::Unchecked`, which serves AD clear like `Insecure`
    (its TTL stays uncapped, D93). RFC 4035 §4.9.3 lets a stub trust AD from a trusted recursive server over a
    secure channel; rejected here, as the configuration says nothing of which servers are trusted, a stage may mix
    plain and encrypted ones, and the cache would then serve one server's AD for another's data. Migration: a
    forward to `tls://9.9.9.9` with `dnssec: off` no longer passes AD; set `dnssec: validate`. An opt-in
    `trust_upstream_ad` is in `docs/TODECIDE.md`.
  - Fallbacks (L3). A query changed by a fallback (TC to TCP, EDNS dropped, BADCOOKIE) goes with another ID (RFC
    5452 §9.2); it was the next one, which a forger that saw one ID guessed. `Exchange::start` takes four spare IDs
    from the caller, the most such changes in one exchange, and `Client` draws them at random with the first ID, so the
    exchange stays sans-IO (D31). A spare ID equal to the one before is not used. EDNS is dropped (RFC 6891 §7) only
    on a FORMERR or NOTIMP that has the question and no OPT, and never once a response of the exchange had an OPT
    (`EdnsState`). A FORMERR or NOTIMP without the question is the response: no downgrade, no second query. This
    does not make the downgrade unforgeable: a forger still needs the ID and the port (RFC 5452 §9 is the defence),
    and now the question too, in its case when `0x20` is on, which a question-less response spared it. Cost: a legacy
    server that answers an EDNS query with FORMERR and no question is no longer asked again without EDNS; its
    FORMERR is the result, and `+noedns` asks without.
  - ANY (S1.2): a query of QTYPE ANY over UDP or CoAP is answered by the forward stage, after the plugins (which
    keep their local answers) and the RD check, with NOERROR, TC set and no record: the question and our OPT, so
    never larger than the query. No upstream query, no cache read or write: the cache key has no transport, so
    the entry a TCP client stored would answer UDP clients in full. The client asks again over TCP (RFC 7766 §3).
    Over TCP, TLS, QUIC, HTTPS and ODoH ANY is answered as any query, from upstream or the cache: RFC 8482 §4.4
    lets a responder differ per transport, and those transports show the source address. The class is not
    looked at: ANY of QCLASS CH or ANY is truncated like one of IN. An empty, truncated response is not one of
    the modes of RFC 8482 §4.1-4.3, only a use of §4.4's freedom with RFC 7766's retry.
  - ANY, limits: a client that does not retry over TCP, such as DoC over CoAP (D81, no TCP), gets no ANY answer
    at all; ANY to a resolver is a diagnostic, and over TCP it works.
  - ANY, rejected: §4.2, a synthesized HINFO (or §4.1, one cached RRset): it needs a record for names that do not
    exist or are CNAMEs, a signature for DO, and a TTL, each a new claim by a forwarder that does not know the zone;
    §4.3, a guess: needs upstream. Truncation says nothing about the data.
  Tests: `dedens-server/tests/{dnssec,wire}.rs`, `dedens-net/tests/exchange.rs`,
  `dedens-cache/tests/checked.rs`.
- D115 (amends D42, D44, D45, D57, D66, D79; amended by D120, D122) Configuration bounds, from the audit (L14, L15, E5): what the file
  says is held to what the server can bear, and what a variable holds cannot become configuration.
  - Key files. One check, `config::guard_key`, on the open file (no swap between check and read), for the TLS key
    and the ODoH key (D79, which warned on any group or other bit): a key others can access (`& 0o007`) is refused,
    at start and at a reload, which then serves the previous configuration on (D55, D66); one its group can access
    (`& 0o070`) is read with a warning, for a key shared through a group (Debian's `ssl-cert`). `ssh` and PostgreSQL
    refuse a key others can access; PostgreSQL allows its group on a root-owned key. Nothing is checked off Unix.
    A Kubernetes Secret volume is 0644 by default: set `defaultMode` 0400 (or 0440 with `fsGroup`).
  - Patience (D45). A forward stage's `timeout_ms` is at most 30000 and `tries` at most 5; above, the file is
    refused. 30 s is the cap of the system resolver's `timeout` (`resolv.conf(5)`), between the 4 s a BIND stub
    resolver starts at and the 45 s ceiling of BIND's backoff (RFC 1536 §1); 5 is the cap of its `attempts` and
    Unbound's `outbound-msg-retry` default. A query waits at most servers × `tries` × `timeout_ms` and holds its
    slot (D47) all that time; a typo (`timeout_ms: 300000000`, 3.5 days, or `tries: 255`) held it for good.
    The ODoH proxy's `timeout_ms` (D94) is not capped here.
  - Variables (D44). A `${VAR}` value is one YAML value, never YAML. A plain value (ASCII letters and digits,
    `_./:@+=%~#-`, not starting with `#`, `@` or `%` or a document marker, not ending in `:`) stays as it is, so
    ports, addresses, URLs and paths work anywhere, in a number or beside text. Any other value must stand alone
    as a value (after `key:`, `-`, `[`, `,`, `{`, before the end, a comment, `,`, `]`, `}`) and is written in single
    quotes, or sit right between quotes of the template, and is escaped for them; elsewhere it is refused. Where it
    stands is read from the template's YAML up to it, across lines: the quoted scalar open (a quote opens one only
    where a scalar may start), flow depth outside quotes, a plain or block scalar going on; adjacent characters
    alone let `{k: 'a"${V}"b'}` escape for double quotes inside single ones, an injection. A plain value
    YAML reads as null (`~`, `null`, `Null`, `NULL`) is quoted too when alone: `user: ${USER}` with `USER=null`
    would read as no `user`, no drop of root (`a_value_that_reads_as_null_is_text`). A control
    character or line break is refused. `${VAR:-default}` text is the template's and stays as written. Rejected:
    quoting every value (breaks a number and a value inside the template's own quotes) and substituting in the
    parsed tree (loses the line numbers of errors and numbers' types).
  - Saved lists (D57, D104). A copy that does not exist yet is an empty list, so a blocklist fails open until the
    first fetch; a copy that is no list is warned about and left out, a copy not in UTF-8 too (the downloader saves
    only text: it was changed on disk). Unless it reads as a list with TLDs, as the downloader checks it, its version
    tag is removed: kept, each fetch got a 304 and the copy stayed out for good. A copy that exists and cannot be read (permissions, a directory) refuses
    the start or the reload, as before: serving without the list would not mend when the next fetch runs. Now tested and documented.
  - `threads` (D42). Serving threads, 1 to 1024, fixed at start (a reload warns, as for `listen`). Default as before:
    one per core on Linux, one elsewhere; above 1 off Linux is refused, where `SO_REUSEPORT` spreads nothing and a
    second thread would serve no query. Each thread costs about 1 MiB of buffers (D49), 64 KiB of scratch and a 4 MiB
    receive buffer per UDP socket, so fewer threads than cores serve a small host; 1024 stops a typo.
  - Tests: `a_key_readable_by_others_is_refused` (`tests/listeners.rs`: refused, kept on a reload, group warned),
    `a_long_key_file_is_refused_and_an_exposed_one_too` (`odoh/mod.rs`), `forward_patience_is_bounded`,
    `a_variable_cannot_inject_yaml`, `a_value_is_the_text_it_stands_for` (every text of up to three characters
    from an alphabet of YAML's syntax, in five templates: read back as that text or refused, which stands for a
    fuzz target, `dedensd` being a binary), `an_unreadable_saved_list_refuses_the_start`, `threads_are_bounded`,
    `threads_default_to_the_cores_on_linux` (`config/limits.rs`), `threads_set_the_serving_threads` (`tests/listeners.rs`).
    Test and bench key files are written 0600 (`util::write_key`). No hot path touched, no bench.
- D116 (amends D22, D44; amended by D118, D193) The cache's memory, evictions and truncated hits (audit step 18; L12, E8, P1):
  - Memory (L12). `capacity` counts everything a shard holds: the keys and responses, and `SLOT_COST` for each slot
    of the slab, live or free. `SLOT_COST` is the sum of what a slot takes in each table at the worst moment of its
    growth, rounded up to 16: the slab slot (`size_of::<Option<Entry>>()`, the `u64` cache mark of D118 in its
    response, grown by an eighth at a time); its bucket in the index (a `(u64, u32)` and a control byte, 16
    buckets for 7 items just after the table doubled); the two queues and the free list (a `u32` each, twice as many
    places as items); its ghost (a stamp as the index's bucket, and two `(u64, u64)` places of the ghost queue,
    twice as many as ghosts). The constants are in `shard.rs`; `a_slot_costs_what_the_tables_take_at_worst` finds
    each one's worst ratio on the real tables. Free slots count too, so the slab cannot take memory the budget does
    not see; it stops at the slot count the budget allows beside one largest entry. The allocator's own rounding
    and the transient buffers of an insert and of a compaction are not counted.
  - A shard that has gone mostly free is compacted (`Shard::compact`): at the end of an insert, when more than half
    the slots are free, the live entries are renumbered, the slab is rebuilt at its length and the index, the queues
    and the ghosts give back what they hold. Without it a flood of failure records (a slot and a key) left the
    slab at its peak, charged for good, and 1 KB responses after it found a tenth of the room. It is O(entries)
    under the lock, and happens after as many frees as there are live slots, so each insert pays a constant on
    average. `tests/memory.rs` counts the bytes held by the allocator (`stats_alloc`, a safe dev-dependency: no
    `unsafe` of ours) over five workloads, the last failures then large responses (it holds at least 80% of the
    entries the budget allows), and the worst it sees is below the capacity (`docs/benchmarks.md`). It reads the
    memory between operations, so it does not see the worst growth: the unit test above holds that. Rejected: a rule
    of thumb of 20-25% on top of the capacity, true for one workload only.
  - `Config::max_entry_bytes` (`Option<usize>`): the most an entry's key and response take, as stored
    (`Response::cost`: the wire, 2 bytes a record, and the bits of the cuts). A larger response is answered and not
    stored (`NotCached::TooLarge`, found by `Response::build` before the lock), and the stored one under that key,
    its failure count and its hold go (an answer too large to store must not leave an older one to be served, nor
    a hold to refuse it; so do an answer of TTL 0, a negative one without SOA and one for a client subnet, which
    outdate the stored one as much, RFC 8767 §4; a response refused as broken or as no answer to the query, which
    may be forged, leaves it). It was refused only when it was larger than a whole shard, so one 60 KiB response could
    empty the small queue, a tenth of the shard, of the entries asked once. Unset, the limit is 8 KiB (about 450 A
    records), or a tenth of a shard's share of `capacity` less `SLOT_COST` when that is less: no default
    `capacity` is refused for it. Refused: a set value under the longest key (a failure record is a key and nothing
    else, so one always fits) or over a shard's share less `SLOT_COST`; a derived one under the longest key, naming
    the least capacity (`ConfigError::EntryBytes`, `Capacity`). Raising it past a tenth of a shard's share brings the
    churn back; the doc says so, the code does not refuse. In `dedensd`: `cache: max_entry_bytes`.
  - The slots count against the budget, so a given `capacity` holds fewer entries: a response of one address under
    a short name counts 344 bytes, 200 before, 42% fewer of them; one of 1.2 KB about 10% fewer. The old count left
    the tables out, and the memory it let a cache hold was 1.06x to 2.06x the capacity: `capacity` is now the memory
    a deployment gives, not the bytes of payload.
  - Evictions (E8). `Shard::evict` spares an entry of main with hits by sending it to the back and taking a hit
    off, at most `MAX_ROTATIONS` = 32 times in a call. It passed over an entry up to three times before (3n for n
    entries, under the shard lock: `insert_evicting_hot`). After the
    bound the eviction takes from small when it holds entries other than the one coming in, else the front of main,
    hits or not: an attack of hot names must not push out the entries asked once while the hot ones stay hot
    (`a_spent_eviction_takes_from_small_before_main`). An entry of small with hits moves to main once and does not
    count: a warm-up of many hit names, then a scan, must still keep the names
    (`serving_what_was_just_stored_keeps_scan_resistance`). K is a bound on the work under the lock, not a tuning
    of the ratio: `examples/hit_ratio.rs` (`docs/benchmarks.md`) gives the same ratio to four digits for any K from
    1 to unbounded, and lower for 0. 32 keeps the scan short. The sweep is on Zipf draws of equal-size entries, which
    say little of resolvers' traffic (sizes, bursts, one-off scans): replaying a real
    capture is in `docs/TODECIDE.md`, and the example reads one (`--trace`). Rejected: aging all entries at once
    (as much work, in one call), a cap in bytes (an entry costs the same to pass over, large or small).
  - Truncated hits (P1). A response larger than the client's buffer (no EDNS: 512 bytes) is cut from the stored
    wire, in the lookup and under the lock, with no allocation: the stored bytes hold, after the wire and the TTL
    offsets, one bit for each count of additional records that leaves no `RRset` split, built at insert as
    `Message::encode_truncated` does (D10). The end of each record is its TTL offset, plus 6, plus its RDLENGTH. The
    cut keeps the records that fit, and only whole `RRset`s of the additional section when only those are lost: the
    bytes of `encode_truncated`, and TC set exactly when it sets it (an answer or authority record lost).
    `tests/rfc.rs` (RFC 2181 §9) holds the two to each other for random messages and sizes and for every buffer
    size over the captured responses; the fuzz target `cache_insert` compares the bytes and whether anything was
    cut. `hit_truncated` allocates nothing and is within 1.1x of a hit that fits whole (the audit asked for 2x;
    `docs/benchmarks.md`). `Shared`, its `Arc` and the second phase of `Cache::lookup` are gone: a response is one
    `Box<[u8]>`. A response with a stray OPT record (no TTL offset) is refused as `Violations`. A stale hit
    leaves room for its EDE option (`STALE_ROOM`) only for a query with EDNS, the only one the server appends it
    for; without EDNS the whole 512 bytes are the answer's.
  Tests: `dedens-cache/tests/{memory,allocations,rfc}.rs`, `Shard` unit tests
  (`an_eviction_passes_over_a_bounded_number_of_entries`,
  `a_spent_eviction_takes_from_small_before_main`, `a_shard_mostly_free_is_compacted`),
  `tests/cache.rs` (`an_entry_over_max_entry_bytes_is_refused`, `max_entry_bytes_is_inclusive`,
  `max_entry_bytes_is_checked_against_the_other_bounds`, `an_unset_max_entry_bytes_follows_the_capacity`,
  `a_response_too_large_clears_what_was_held`, `a_stale_hit_leaves_room_only_for_a_query_with_edns`).
- D117 (amends D77, D79, D94, D106; builds on D91, D113; amended by D186) Client budgets, from the audit (S3, S14): what one client can
  spend of a shared limit is bounded before the shared limit is. Two places had one budget for all: the validation
  allowance (D77) and the ODoH target's decapsulations (D79).
  - One keyed table (`Budgets`, `dedens-server/src/budget.rs`) for both: a client's key is its network, a /24 of
    IPv4 and a /48 of IPv6 (an IPv4-mapped address counts as IPv4), hashed with a random key into a fixed table
    of 2^16 words (512 KiB). Memory does not grow with the clients; two networks that collide share a bucket, as
    in D113. A word is one `AtomicU64`, the last second and the debt of D106; no lock, and a refusal that changes
    nothing writes nothing, so a flood does not make the cores fight for the line. The global allowance is the
    same type with one slot, so D106's debt is one piece of code. The prefix is /48 where D113's is /56: a site is
    given a /48, and a holder of one would otherwise have 256 buckets of work; D113 limits answers, which a
    holder of many /56 does not gain from the same way.
  - The key has a proven bit: a connection or a valid Server Cookie (D113) cannot be spoofed, so those queries
    have a bucket of their own and a flood from spoofed UDP sources of a network does not shed them. DoC, CoAP
    over UDP, is no connection: its source is unproven without a valid cookie.
  - Validation (S3). `Pipeline::query` passes the source (address, proven bit) and its `now` (the cache's clock,
    D43, monotonic; the validator keeps reading the wall clock for signatures) to `Validating::admit`, which takes
    one unit of the network's share, then one of the global allowance; if the second refuses, the query keeps the
    first while it waits for the allowance and gives it back if shed (D186; ODoH and DNSCrypt, which do not wait,
    call `Budgets::admit_within`, which gives it back at once). `Check::next` charges both with what the validation spent (D106) and sheds when either is in debt:
    SERVFAIL with EDE 14, nothing held, counted `verdict="shed_share"` for the share and `verdict="shed"` for
    the allowance. Cache hits, CD and classes other than IN cost neither, as before. A source on D113's
    `rrl.exempt` list has no share and still spends the allowance. `client_share: {rate, burst}` on the forward
    stage, default 1000 and 2000, a tenth of the allowance of a server of one or two threads (D77 scales it by the
    threads, not the share), so that ten networks at their share spend all of it there and no one network can:
    2000 units are about 160 cold validations (`docs/benchmarks.md`). A reload keeps the
    key cache and restarts the shares only when the setting changed.
  - ODoH (S14). Before `dedens_odoh::Message::parse` and the HPKE open, `odoh::Service::open` takes one unit of the
    client network's budget (`odoh.client_budget`, default 1000 and 2000: 3.5% of a core at 34.6 µs a
    decapsulation) and one of the global one (`odoh.budget`, default 10 000 and 20 000: a third of a core), and
    gives the first back if the second refuses. A QUIC peer completed its handshake: its address is proven.
    Exempt sources pay no network unit. Past a budget the request is 503 (RFC 9230 §4.3 leaves errors to DoH's),
    counted `dedensd_odoh_limited_total{budget}` and logged at debug, whatever the body: the refusal says nothing
    about the message. Read at start with the rest of `odoh` (D79). A target sees its proxy's address, not the
    client's (D91), and the pipeline its source address likewise: all the clients of one proxy spend one network
    budget and one validation share, so a target behind a busy proxy raises them, or lists the proxy in
    `rrl.exempt`.
  - Why these numbers: a decapsulation is 34.6 µs, a cold validation 12 units of about 10 µs, and taking a unit
    from the table a few ns (`docs/benchmarks.md`): the check costs thousands of times less than what it guards.
  - Rejected: a map of clients with eviction (an attacker evicts); tables per thread (a client spreading over
    threads gets the budget of each); a budget per connection (a connection is cheap to open); places per thread
    for decapsulations held through the exchange (the open is synchronous on the thread, so places bound the
    exchanges in flight and not the CPU, and a global budget bounds the CPU; the upstream queries in flight have
    their own slots); no exemption for validation shares either way (a proxy hiding clients is in `rrl.exempt`, as
    D113 says).
  - Limits are in `docs/TODECIDE.md`. Tests: `a_client_over_its_share_cannot_shed_another_client`,
    `a_proven_client_is_not_shed_by_the_unproven_ones_of_its_network`, `an_exempt_source_has_no_share`
    (`crates/dedens-server/tests/dnssec.rs`, the first written first),
    `a_query_the_allowance_refuses_keeps_its_unit_of_the_share` (`crates/dedens-server/src/validate.rs`), the unit
    tests of `crates/dedens-server/src/budget.rs`, `a_flood_from_one_network_does_not_stop_the_others`,
    `many_networks_open_no_more_than_the_global_budget`, `an_exempt_source_pays_only_the_global_budget`
    (`apps/dedensd/src/odoh/mod.rs`), `d117_a_flood_of_posts_past_a_budget_is_503_before_it_is_opened`
    (`apps/dedensd/tests/odoh.rs`), `a_client_share_is_set_per_stage_and_reload_keeps_the_keys`
    (`apps/dedensd/src/config/upstream.rs`), `an_odoh_target_has_limits` (`apps/dedensd/src/config/keys.rs`). No
    fuzz target: the key is an address; the ODoH parser has its own. Benches: `serve_shed_share`, `serve_cold`,
    `serve_warm`, `serve_shed` (`crates/dedens-bench/benches/dnssec.rs`), `budget_admit`, `budget_admit_within`,
    `budget_refuse`, `budget_refuse_one_network`, `decrypt_query_message` (`crates/dedens-bench/benches/odoh.rs`).

- D118 (amends D22, D54, D56, D57, D116; amended by D120) Blocklist targets, from the audit (S13, S15): a name is no longer reached by a CNAME to
  a blocked one, and a one-label entry no longer blocks a top-level domain unless asked.
  - Response hook (D54). A plugin may also review the responses of the stages after it: `Plugin::reviewer` returns
    `Option<&dyn Reviewer>` (none by default; it must not change over the plugin's life, the pipeline reads it
    once when built), and `Reviewer::review(query, response)` inspects the decoded response and may return an
    `Answer`, which replaces it. It cannot alter a response, only refuse it, so D54's rule (a plugin answers from
    local data) holds. It runs on a response of the forward stage after the plugin and on a hit of a cache stage
    after it. A plugin's own answer never reaches it (the pipeline returns at once), nor does a replacement, and
    no plugin reviews any plugin's answer. A refused response from a prefetch or a stale refresh (D45) is
    dropped. One refused hit may set the entry's prefetch flag without a prefetch following: harmless, and the
    hit still counts in the cache metrics.
  - Where it runs, what is stored. A validating forward stage (D77): the first upstream response is reviewed
    before the validation starts (a refused one is not worth its DS and DNSKEY questions; its admission's unit stays
    taken, D117: the response was read and reviewed), and not stored when refused: unvalidated, it has no verdict to
    be stored with. The answer `Finish::deliver` ends with (a validated one: the first response again, which the
    chase leaves as it is; a client's with CD, unvalidated; a recursion's) is reviewed before it is stored, and one
    refused is stored with its verdict, as below (audit 4: it was not, and a repeat with CD went upstream each
    time). A stage without validator: the response is reviewed before it is stored; a refused one is stored all the
    same, unmarked, and refused again on each hit, as the block answer itself is never cached (a block action may
    change at a reload, a response is the cache's only unit): not storing it would send each repeat upstream. Not
    stored when the refusing plugin is after the cache stage, which a hit does not ask.
  - Cost of a hit. The cache's reply is wire bytes, and `dedens-proto` has no allocation-free walker, so a hit
    reviewed decodes it. Each pipeline takes an id from a process-wide counter (a reload builds a new pipeline, so
    a new id); a response that passed the review is stored with the id as the cache's opaque mark (`Cache::insert`,
    `Hit::mark`), and a hit with the pipeline's id is served as it is, without decoding. A hit with another mark
    (stored before a reload, or unmarked) is decoded and reviewed once, then marked (`Cache::mark`, set only if
    the entry still has the mark that was read). Per stage, the pipeline knows when no plugin before it reviews, and
    a hit there is served as before. The race left: a query in flight from an older pipeline stores a response
    marked with its old id between a hit and its marking, which then takes the new id; it passed the older
    pipeline's review, whose lists are those of the previous configuration: one query's response, until its TTL.
    The mark is a field of the entry's response, so `SLOT_COST` counts it through `size_of::<Option<Entry>>()` (the
    `u64` D116 had reserved for it is that field, not an extra); a compaction moves entries whole and keeps it, and
    an insert refused as too large clears the response and its mark with it (`a_mark_follows_the_stored_response`
    and `a_response_too_large_clears_what_was_held` hold both).
    Rejected: (b) an allocation-free walker in `dedens-proto` read on each hit (a public wire-walking API to
    maintain, and a cost on every hit, not once per entry); (c) flushing the cache when the lists change (a cold
    cache on each list refresh and SIGHUP, a thundering herd upstream). Numbers in `docs/benchmarks.md`.
  - Blocklist. The chain is followed from the query name: each hop is the CNAME owned by the name reached, whose
    target is looked up as a query name is, allowlist included (D56); a DNAME above that name (RFC 6672 §2.1, its
    RDATA read by `Name::from_uncompressed`, a malformed one left to the client) has its target looked up too,
    and the DNAME with the CNAME synthesized from it (RFC 6672 §2.2) is one hop. Records on no chain are
    ignored, and so is a second CNAME for one name (RFC 1034 §3.6.2). The first blocked target gives the reply of a
    blocked query name for the client's question, EDE 15 Blocked included. At most `MAX_HOPS` (16, above any
    mainstream resolver's chain limit) hops are followed; a response whose chain goes on after them, or loops,
    is answered SERVFAIL (EDE 0 Other), not Blocked: a client following it would reach names nobody looked up.
    A query name the allowlist lets through is not reviewed (one lookup): the user allowed it, and what it points
    to is the list's decision at the name's owner's request. Not looked at: targets of MX, SRV, NS, SVCB and HTTPS
    records (a query for those names is a query for a name of the list when the client follows them), and records
    outside the answer section. Not checked against Pi-hole's behaviour here: no source access in this work.
  - One label (S15). A plain line of one label (`com`, `*.com`) is an error in the server's own configuration,
    a skipped line (counted in `Read::skipped`) in a downloaded list (D56), whose line number the error carries
    (`LineErrorKind::SingleLabel`). The rule is single-sourced in D56. Opt-in: a blocklist stage with `tlds: true`
    reads one-label lines as names, in all its sources, for the lists of top-level domains that exist (`zip`,
    `mov`); the cost is that a mistake blocking `com` is then read as asked. A download is checked, before it is
    saved, as a format only (`Names::check(Tlds::Allow)`: one-label lines are names), because the stage reading the saved copy
    decides: on a stage without `tlds` those lines are skipped and the copy of a list made of them is left out
    with a warning. Hosts-format lines keep leaving one-label names out, as D54 says.
  - Test data. Real captures where a capture holds the shape (`cname_to_insecure`, `dname_answer` and the
    `dedens-proto` chains); the chains of 16, 17 hops and the loop are hand-built: no real server sends so long
    a chain.
  - Rejected: reviewing in the plugin's `answer` (it sees the query only; a CNAME comes from upstream); checking
    the chain by recursion (D54: no upstream from a plugin); a reviewer chain applied to every stage (a plugin
    after the forward stage cannot have seen the response).
  - Tests: `a_listed_cname_target_blocks_the_response`, `a_listed_dname_target_blocks_the_response`,
    `the_allowlist_decides_for_targets_as_for_names`, `a_blocked_response_is_answered_as_the_action_says`,
    `a_blocklist_of_allowed_names_only_reviews_nothing`, `a_chain_over_the_bound_is_servfail`,
    `a_dname_and_its_cname_are_one_hop`, `a_chain_to_a_listed_name_is_not_served`,
    `a_top_level_domain_is_no_plain_entry`, `a_top_level_domain_is_an_entry_when_the_lists_take_them`,
    `a_hosts_line_leaves_a_top_level_domain_out` (`dedens-plugins/tests/blocklist.rs`);
    `blocklists_take_top_level_domains_when_told` (`config/sources.rs`); `a_mark_follows_the_stored_response`
    (`dedens-cache/tests/cache.rs`); `dedens-proto/tests/rdata.rs` (`Name::from_uncompressed`);
    `a_response_a_plugin_replaces_is_stored_and_refused_on_a_hit`,
    `a_response_a_plugin_after_the_cache_replaces_is_not_stored`,
    `a_response_no_plugin_replaces_is_cached_and_reviewed_once`, `a_reload_reviews_an_entry_again_once`,
    `a_plugin_does_not_review_its_own_answers`, `a_plugin_after_the_forward_stage_is_not_asked`,
    `a_validated_response_is_reviewed`, `a_delivered_response_refused_is_stored_and_refused_on_a_hit`,
    `a_delivered_response_kept_is_reviewed_once` (`dedens-server/tests/stages.rs`); fuzz `parse_lists` runs a chain of
    arbitrary names through a blocklist, a cache and a forward stage, the reply and the hit checked against a
    plain model. Bench: `benches/blocklist.rs` `review`, `hit`.
- D119 (amends D61, D83, D109; amended by D121; builds on D117) What a QUIC peer can make the server hold, from the audit (S2): h3
  0.0.8 reads a stream into memory while it waits for the end of a frame whose length the peer declared, and the
  read returns the QUIC credit. A reserved frame of 2^61 bytes on the control stream, or a HEADERS frame of 2^30 on
  each request stream, filled slowly (any packet resets the idle time), is buffered without limit;
  `max_field_section_size` (D109) is checked only once the frame is whole. Quinn's defaults (1.25 MB a stream, no
  limit a connection) bound nothing either.
  - Windows (RFC 9000 §4.1), `dedens-net/src/quic.rs`. The server's QUIC endpoint (DoQ and HTTP/3):
    `RECEIVE_WINDOW` and `STREAM_RECEIVE_WINDOW`, sized from the largest DNS message, 65535 bytes behind its
    two-byte length (RFC 9250 §4.2) plus the HTTP/3 framing: one stream holds one message whole, a connection holds
    a few, with the control and QPACK streams. A larger message waits for credit, it is not refused. The client's
    (`Dialer`): `STREAM_RECEIVE_WINDOW` and `CLIENT_RECEIVE_WINDOW`, larger, since the replies of every client of a
    forwarder share one connection to an upstream (D61, D83) and the window over the round trip caps its throughput.
    The windows bound what is in flight, not what h3 buffers (above).
  - Budget (`apps/dedensd/src/serve/h3_budget.rs`): the server counts the bytes an HTTP/3 connection received (quinn's
    `stats().udp_rx.bytes`, the datagrams, before they are decrypted) and, at `BUDGET`, sends `GOAWAY` (RFC 9114
    §5.2, h3's `Connection::shutdown(0)`): the connection rotates, as a long one does, and the memory h3 holds for
    it goes with it. It is closed with `H3_EXCESSIVE_LOAD` (0x107, §8.1, §10.5) once it passes `BUDGET` plus
    `RECEIVE_WINDOW`, or does not end `DRAIN` after `GOAWAY`. An honest client is not cut: the requests accepted
    before `GOAWAY` are answered (the connection ends only once none is in flight, and `DRAIN_QUIET` after both the
    last request taken and the last reply: finishing a stream only queues the reply, which the close would drop),
    and dedens' client opens a new connection for the next query (`http3.rs`: a rejected or closed connection is
    set aside, not reused).
  - Bound: one sweeper task per serving thread (`Thread::h3`) checks its HTTP/3 connections every `CHECK` (quinn has
    no event for bytes received), whatever their number; it ends when none is left, and holds them weakly, so a
    connection is checked as long as its service or a request on it lives. A peer returning its credit at once sends
    `RECEIVE_WINDOW` a round trip, so a connection is closed holding at most `BUDGET` + `RECEIVE_WINDOW` × (1 +
    `CHECK` / round trip): 9.25 MiB at a round trip of 1 ms, 4.5 MiB at 20 ms. Per thread, `TCP_CONNECTIONS` times
    that: 2.3 GiB and 1.1 GiB, reached only by 256 attackers each past Retry; before D119 it had no limit. `BUDGET` trades that
    memory against rotation: a client at 1 000 queries a second changes connection every 25 s. DoQ needs no budget: a stream is read up to one message, within `TCP_IDLE`.
  - Costs: a datagram counted before decryption means junk addressed to a connection can make it rotate, which costs
    its client a handshake. Rejected: a maximum lifetime (bounds time, not bytes: an attacker's rate is the window
    over the round trip, so a minute holds gigabytes); a hard close at `BUDGET` (it kills the requests of an honest
    connection in flight, which lost queries in the first version); a timer per connection (a task for each; one
    per thread does as well); a budget of the bytes of unfinished frames (h3 does not tell); the windows alone (h3
    reads on); a budget on the client's side (the servers it dials are its operator's choice; open in
    `docs/TODECIDE.md`).
  - The h3 fix (hyperium/h3 branch, not in 0.0.8): a declared length above a bound is refused before the frame is
    buffered (RFC 9114 §7.1, §10.5), unknown frames are discarded as they arrive. The budget goes when a release
    carries it (`docs/TODECIDE.md`).
  - Tests (`apps/dedensd/tests/doh.rs`, `h3_frames`): `s10_5_a_control_frame_that_never_ends_closes_the_connection`,
    `s10_5_request_headers_that_never_end_close_the_connection` (written first, red without the budget: 27 MiB and
    64 MiB sent, no `H3_EXCESSIVE_LOAD`; green: closed before the sent bytes pass the bound), and
    `s5_2_a_busy_connection_is_rotated_not_closed` (60 000 queries over dedens' own client, all answered, the
    server rotating at least twice). No fuzz target: nothing new is parsed. Bench: `docs/benchmarks.md`.
- D120 (amends D54, D56, D57, D58, D104, D110, D115, D118) Lists read once, kept across reloads (audit step 19, E3):
  - Decision. A list is parsed once per load, into `dedens_plugins::Names`: its name hashes sorted and
    deduplicated (8 bytes a name) with their label counts, one-label lines apart (D118). `dedensd` keeps a `Store`
    (`src/lists.rs`) across reloads, owned by the thread that reloads, with one `Names` per source: inline
    `entries` (same text, same `tlds`), a `file` (same `tlds`, and the stamp of the open handle it is read through:
    size, mtime, device, inode, ctime, as git stamps), a saved copy (the same stamp, or put there by the
    downloader, which parses a text once, to check it (D57) and to hand it over). A source whose stamp changed, or
    that cannot be opened (D115), is read again; a source no stage uses is dropped. A stage side (block, allow) is
    one `Merged` set, the union of its sources, as D110 looks up: the store keeps it for the same sources in the
    same order and `tlds`, so a stage whose sources did not change keeps its set (stages naming the same sources
    share one) and a changed list rebuilds only the sets of the stages that use it. The set is sized from the
    deduplicated union, and the names in more than one source or repeated in one are the logged duplicates (D56).
  - Rationale (E3, six published lists, 2.68M lines, 2.14M names, as one stage): a reload after one list changed
    parsed all six and took 0.64-0.80 s (peak +52 MB); it parses one and takes 0.14-0.19 s (peak +37 MB), the
    downloaded list is parsed once, not twice, and the reload after it reads nothing; lookups are D110's
    (`docs/benchmarks.md`). One hash key per process, drawn once, so any `Names` fits any `Merged` (D58).
  - Memory: the store holds 8 B a name of each source (21 MB for those six) beside the merged set of the stages
    (9 B a bucket, 38 MB); a reload builds the new set while the old one serves. A text is read with
    `read_to_string`; the 256 MiB bound (D104) is unchanged.
  - Unchanged: answers, errors (`entry N`, `` `file` line N ``, `reading `copy```), a copy that is missing, not a
    list or unreadable (D115); a failed reload keeps the store as it was, bar the sources it had read.
  - Observable: info `list parsed` (`kind` entries, file or saved copy) and `lists merged` (sources, names).
  - Rejected: a set per source looked up in turn (a lookup costs sources × labels: 0.2-1.5 µs a suffix with 20
    large sets against 7-46 ns, and keeping the names of duplicates across sets made a reload quadratic: 2.1 s for
    50 × 200k names against 0.35 s); a Bloom filter in front (more code, still a lookup per source); the
    content hash of a file (reads every list at every reload, the cost removed); mtime and size alone (a file
    rewritten within the clock's granularity, or with its time restored, is served stale); sharing the store
    with the downloader's threads behind a mutex (the workers hand their results back when they are done).
  - Tests: `a_reload_reads_the_lists_that_changed_only` (`tests/reload.rs`), `a_downloaded_list_is_read_once`
    (`tests/lists.rs`), `lists::tests` and `config::tests::a_list_named_twice_in_a_stage_is_held_once` (`src`),
    `published_lists_read_apart_and_merged_answer_as_read_together` (`dedens-plugins/tests/blocklist.rs`), fuzz
    `names_read_once`. Numbers in `docs/benchmarks.md`.

- D121 (amends D46, D64, D119; builds on D47, D107) A panic ends one task, a listener loop that ends starts again, and a
  thread whose runtime panics ends the process (audit S6). compio already catches and hides a task's panic, so the
  loss was narrower than written: a listener loop that ended, and the runtime.
  - Tasks and listeners (`serve/isolate.rs`): each task runs under `catch_unwind` (`Origin::spawn`, and `guard_async` for the
    whole turn of a UDP datagram); a panic is logged with listener, peer and location, counted by
    `dedensd_task_panics_total{listener}` and never propagated. A panic hook sends uncaught ones to `tracing`, and the
    log is limited per listener to one a second, with `suppressed`. A query gives back its place on its connection
    when it panics. Each listener runs under `supervise`: it starts again after 10 ms, doubling to 5 s, from 10 ms
    after a minute of service (a crash loop pays the pause, a rare panic does not), logged and counted by
    `dedensd_listener_restarts_total{listener}`. Sockets and endpoints are kept, so a restart rebinds nothing: bind
    errors stay start errors. Unwinding stays (no `panic = "abort"`). The catch is a future of its own (`Marked`,
    `futures-util`'s `catch_unwind`), not an `async fn`: two nested ones held a spawned task three times, a forwarded
    query's 23 KiB for 8, moved and allocated whole on each spawn (`docs/benchmarks.md`, "Where the time goes at the
    common rate").
  - Runtime or driver panic (`poll_with` on `EBADR`: completions lost): the process logs it and exits 1, for systemd or
    Kubernetes. A new runtime on the same sockets is rejected: D107 keeps the old ring, whose in-flight receives would
    take datagrams of sockets still in their `SO_REUSEPORT` group, a share of queries lost with no sign.
  - Open (`docs/TODECIDE.md`): a panic inside a compio-quic worker is hidden in compio's task; bare `spawn`s in
    `dedens-net`. Rejected: forking compio.
  - Tests: `serve/mod.rs` (65 queries panic on one connection, the 66th is answered; a listener panics and answers again;
    100 restarts under load, Linux), `serve/isolate.rs`. Cost: `hit_guarded` equals `hit` (0 allocations), `bench udp` within
    noise (`docs/benchmarks.md`); not measured on `io_uring`.

- D122 (amends D42, D44, D55, D66, D104, D107, D115; amended by D128) `dedensd` drops root once its sockets are bound, from the audit (S5): a
  server started as root to bind :53, :443 and :853 kept root while it parsed hostile input.
  - Configuration: top-level `user:` (a name or a numeric id, number or string) and `group:` (the same; only with
    `user`). Linux only: `PR_SET_NO_NEW_PRIVS` and the `/proc/PID/status` that the checks read are Linux's, and
    nothing else is tested; elsewhere either key is refused when the file is read, `validate` included. The target is
    resolved before any socket is bound, so a name that does not exist, a `user` or a group that is root, or a numeric
    uid with no passwd entry and no `group` ends the start at once.
  - Order (`src/privileges/mod.rs`, called from `src/lib.rs`): after the sockets are bound and the keys, lists and
    certificates of the start are read, before the first thread starts (a second thread is refused: `NO_NEW_PRIVS` is
    inherited by the threads started after it): `initgroups` (the groups that list the user, plus `group`; none for
    a numeric id with no entry), `setgid`, `setuid`. Then the real, effective and saved ids are read back, no group
    is root, `setuid(0)` and `setgid(0)` must fail, `PR_SET_NO_NEW_PRIVS` is set and read back, and `CapPrm`,
    `CapEff` and `CapAmb` of `/proc/self/status` must be 0, or the start ends; a status that cannot be read ends it
    too (2026-11-20: it passed the checks unread). The kernel clears them on `setuid`
    from root, `AmbientCapabilities=CAP_NET_BIND_SERVICE` included, the sockets being bound already.
  - Root without `user`: a warning, not a refusal (containers, development). Not root with `user`: refused, naming
    the uid, unless it is the user and the group already running (real, effective and saved ids all the same: a
    saved id of root is a way back and is refused): nothing is dropped, `NO_NEW_PRIVS` is set, the kept capabilities
    are logged.
  - Read again as the user: right after the drop the start reads the configuration, and the files it names, once
    more as the user; a file it cannot read ends the start with a message naming `user:`, not the first reload. It
    reads as a reload does, after the read as root (D120, D55): each file opened as the user, a list parsed again
    only if it changed, the caches kept, and what was read as root replaced, not kept beside it (with a fresh store,
    each list was parsed twice and both sets kept for the life of the process).
  - Reload (D55) runs as the user: the certificate and key (D66), the files of `blocklist` and `hosts` stages,
    `upstream_ca`, the saved downloads (D104) must be readable by it. The recommended key is `root:<group>` 0640 with
    `<group>` the user's group, which D115 accepts quietly (as PostgreSQL does a root-owned key: as the user, when it
    is in the group); others stay refused. A file it cannot read fails the reload, the old configuration keeps
    serving (D55, D115). A change of `user` or `group` at reload is warned and ignored, as `listen`: `Fixed` in
    `src/reload.rs`; it compares what is written, so `user: 990` for `user: dedens` warns too.
  - Downloads directory (D104): with `downloads.urls`, a missing `dir` is made before the drop (parents included,
    0755 whatever the umask: a parent made 0700 under `UMask=0077` shut the user out), its last directory given to the user by `lchown`; an existing one is never touched (a `dir` that names
    `/etc` must not be given away), and after the drop the user must be able to create a file in it, or the start ends
    with the `chown` to run. A `urls` added at reload needs a `dir` writable by the user already. The directories of
    the root files used, `dir` and `state_dir`, are made the same way, but one not writable is only warned of (D128).
    Moving a server from root to `user`: `chown -R` its `/var/cache/dedensd` and `/var/lib/dedensd`; the saved
    copies are 0666 less the umask (`UMask=0077` makes them root's alone).
  - io_uring (D107): the rings are made after the drop; with `kernel.io_uring_disabled=1` the user must be in
    `kernel.io_uring_group`, or the threads serve on `poll`, warned at start.
  - Rejected: dropping capabilities only (`CAP_NET_BIND_SERVICE` kept: uid 0 still owns and reads every file, and
    the `prctl` keep-caps sequence is more to get wrong than `setuid`); `chroot` (the process needs `/etc`, the
    certificates and the lists, and the reload must read the real ones; the unit's `ProtectSystem` does it without
    copies); refusing root without `user` (breaks containers); a privileged helper that passes the sockets (a second
    process; socket activation does it with no code: `docs/TODECIDE.md`); `user` off Linux (nothing there is tested).
  - Open (`docs/TODECIDE.md`): the systemd unit, and Kubernetes `securityContext`.
- D123 (amends D48, D51, D63; builds on D107, D121) Replies to UDP queries go through a queue and one sender a
  socket, the tasks answering on it drop from four to one, and the `io_uring` flags of D51 stay (audit P2, P12). Each
  of D48's tasks waited for its reply to go out before receiving again, so each reply cost its own `io_uring_enter`.
  Now `Outbox` (`serve/udp.rs`), made with the socket beside its supervised loop so a restart (D121) keeps it, takes the
  replies, made at once or after upstream, in a bounded queue (64) that `send_replies`, one more future of
  the socket's task, sends from, up to 64 at once: the replies of one turn of the runtime go out in one submission,
  when they go on the ring (below).
  A task whose reply finds the queue full waits, so nothing grows. The reply buffers move with the replies (D63: a
  task's buffer is no longer owned by its send) and come back as spare ones, at most 64 of 1232 bytes: a socket
  holds at most 1 + 64 queued + 64 sending buffers, 129 × 1232 B ≈ 159 KB a thread, of which 79 KB stay after a
  burst.
  - Measured (VPS, Linux 6.12, one server core, five rounds, base and tree alternating; `docs/benchmarks.md`): with
    64 queued, cache hits over UDP 192.4k queries/s median against 163.1k-172.0k for the base over four sessions,
    `io_uring_enter` a query 0.255 → 0.016; forwarding within noise (37.4k against 35.5k-36.0k, 0.082 enters); TCP and
    forwarding over TCP unchanged, no query lost. 256 queued gave UDP +11-17% (0.006 enters) and forwarding +10-17%
    (0.066). Two tasks serve as well as four with the queue (1, 2, 4: 197k, 194k, 190k medians over UDP, 39.5k-41.3k
    forwarding, within noise): a receive no longer waits on a send, so two are kept, not one, for a query that takes long.
  - Why 64, not 256: under a flood on one port the average latency of a second port on the same core rises from
    0.1-0.4 ms to 0.5-1.3 ms with 64 queued, 1.2-2.1 ms with 256 (D107's scenario, `two-sockets`: its reply waits
    behind up to that many of the flood's in one submission); no query is lost. 64 keeps most of the UDP gain and a
    quarter of the memory; the forwarding gain of 256 is given up for the latency of a port beside a flooded one. 16
    gives the latency back (0.2-0.3 ms) and most of the UDP gain too (180k).
  - Rejected: a detached task for each reply (`spawn`), on the measurement alone: 0.033 enters a query over UDP, no
    gain forwarding (every reply allocates a task, as the queue allocates a `FuturesUnordered` one, and compio a
    cell for each send).
  - Rejected: `SINGLE_ISSUER` with `DEFER_TASKRUN`, with or without `COOP_TASKRUN` (D51 measured again): within
    noise of `COOP_TASKRUN` in all four modes, no fewer enters; so no `EINVAL` fallback to write, and the flags
    stay unconditional (D107). Measured again on the final code (2 tasks, 64 queued, five rounds): medians within 0.6% in every mode, and
    `tcp` 0.0045 → 0.0083 enters a query with `DEFER_TASKRUN`, the other modes equal (`docs/benchmarks.md`).
  - Rejected: `SQPOLL` (D51 again): on the server's core the rates halve; on a core of its own it gains over one core
    but spins it, and two serving threads on the same two cores (D42) gain more in every mode: it loses at equal cores.
  - A reply goes out at once, by one non-blocking `sendto` (`Udp::try_send_to`), while no send is in flight on the
    ring; on `WouldBlock` it goes on the ring, with the replies queued behind it until those sends end. On the ring,
    a lone reply's completion ended the runtime's next wait at once: two `io_uring_enter` and two turns a wake-up at
    a low rate, where Unbound makes one `sendto`. With it the queue is a `VecDeque` and two wakers, not `flume`: a
    reply queued by the sender's own task wakes no one, and one task answers a socket, not two (D48). Measured (VPS,
    five rounds, `docs/benchmarks.md`, "Where the time goes at the common rate"): cache hits at the common rate,
    1 core, 21.3 → 18.1 µs a query in `forward`'s second pass (Unbound 18.3), 22.3 → 18.2 in `udp` (17.5); at
    saturation, the compare harness, 1 core `udp` 84.3k → 92.4k, the rest within noise; this decision's harness,
    `udp` 196.0k → 225.9k, `forward` within noise, the second socket of `two-sockets` 0.52-0.55 → 0.42-0.48 ms on
    average, no query lost.
  - Tests: `serve/udp.rs` (`a_full_outbox_makes_the_next_reply_wait`, `queued_replies_are_all_sent_and_their_buffers_reused`,
    `a_failed_send_costs_only_its_reply`, `a_new_sender_sends_what_the_last_one_left_queued`,
    `replies_with_no_send_in_flight_go_out_at_once`, `replies_a_full_socket_refuses_go_out_on_the_ring`).
- D135 (builds on D86, D107) Loom tries every interleaving of the threads of the reload wake-up (`Current`) and of the
  query flights (`Flights`), the two places where `dedensd`'s threads share state by a protocol of their own. D86's
  and D107's tests run real threads, which pass whenever the scheduler misses the bad order; loom runs each order.
  - `src/sync/mod.rs` names the types of those two: std's and `flume::bounded(1)` in the server (the same types
    re-exported, so no change of behaviour or cost), loom's under `--cfg dedens_loom`. The cfg is `dedens_loom`, not
    `loom`: `--cfg loom` also switches tokio, `event-listener` and `concurrent-queue` in the dependencies. `loom` is
    a dev-dependency under that cfg and `unexpected_cfgs` declares it; the tests that run sockets and a runtime
    are left out under it, and a build of the binary under it fails on purpose.
  - The slot, the channel of one message of the wake-up and of a flight's response, is `sync/loom_slot.rs` under the
    cfg: a loom `Mutex` around the message and the waker. So the tests prove the protocol of `Current` and `Flights`
    given a slot that holds one message, wakes its receiver and closes with either end; not flume's internals.
    Rejected: flume itself under loom, whose atomics and locks loom cannot see, so no interleaving of it would be
    tried; `loom::sync::Notify` and `mpsc`, which have no `Future` to receive from, so no query could wait on them
    as it does in `serve/upstream.rs`. The `Arc<[u8]>` of a response stays std's: loom's `Arc` has no `From<&[T]>`.
  - What the threads run is the server's own code: `Current::newer` (the generation check of `Thread::pipeline`) and
    `Flights::enter` (the join and rejoin of `fetch`) were moved out of `serve/` for it.
  - `just loom` lints the loom-only code with clippy, then runs the `loom_tests` modules beside the code under
    `[profile.loom]` (release without LTO, with assertions on: a build in seconds), in its own `target/loom` as the
    cfg rebuilds the dependencies. The preemption bound is four (`sync::model`): unbounded, the tests of `Flights`
    run past a minute, and the whole run takes 1.1 s at a bound of 3, 7.4 s at 4, 43 s at 5. It is outside
    `just check`; the `loom` job of `.github/workflows/deep.yml` runs it on pull requests (30 minutes at most),
    informational as `mutants.yml` is (D103). `loom_slot.rs` is excluded from `just mutants`: only the cfg builds it.
  - Not modelled: `budget.rs` and `rrl.rs`, where each update is one atomic read-modify-write that sequential tests
    cover, and loom's atomics have no `update` or `try_update`.
- D136 (amends D113) A Server Cookie's hash is compared with `subtle`'s `ConstantTimeEq`, not a hand-written fold of
  XORs: the fold was constant-time only as long as the optimizer kept it so, `subtle` puts a barrier in its way.
  `subtle` (BSD-3-Clause, no dependencies) is no new crate in the build: rustls already pulls it. Other comparisons
  stay `==`: the Client Cookie of a response (`dedens-net`'s exchange) is checked against a value an off-path forger
  never sees the timing of, an ODoH key id is public, and AEAD tags are checked inside `hpke` and `aes-gcm`.
- D137 (builds on D22, D43) Rejected: a read lock for the cache's hits. The shard's `Mutex` stays; the 8 threads on
  one name that took 364 ns a hit against 78.6 ns on one stay as they are (`docs/benchmarks.md`, "Read lock").
  - Tried: a `std::sync::RwLock` per shard; a hit takes it for reading and writes two atomics of its entry,
    `freq: AtomicU8` (stored only below `MAX_FREQ`) and `prefetched: AtomicBool` (the hit that wins the swap asks
    for the prefetch, so one per stored response as D43 has it); an insert, `mark` and `fail` take it for writing.
  - Why not: 30 rounds of 300 samples, `before` and `after` alternated on an Apple M5 and a 6-vCPU Linux VPS, the
    medians of 4 and 8 threads on one name moved 1-20% while the rounds of one binary range 3-5x, and `after`
    won 15-22 of 30 paired rounds: not beyond the spread, the rule the step set. A read lock still writes its lock
    word, so the cache line moves between the cores as the mutex's did. One thread is within the spread too (the
    cost the rule bounded). `dedensd` on three cores answering one name over UDP: 365 k/s against 391 k/s, rounds
    280-414 k/s: nothing seen. A store while 7 threads hit its shard (`insert_under_hits`): faster on the M5,
    slower on Linux.
  - Kept: the `insert_under_hits` bench and `tests/cache.rs` `racing_hits_ask_one_prefetch_per_response`, which
    holds D43's one prefetch per response under racing threads; both pass on the mutex.
  - Open: a read path that writes no shared line (per-core copies, a lock-free read), and the shard count from
    `threads`: `docs/TODECIDE.md`.

- D96 (amends D43, D55; builds on D47, D56, D77, D115, D124) Prewarm: a cache stage's `prewarm: {entries, file, types}`
  names the questions kept answered in the cache with no client asking, so a client's first query for one is a hit
  and stays one past its TTL. `prewarm` sits beside `dedens_cache::Config` in the stage (`CacheFile`), not in it, so a
  reload that changes only the list keeps the cache (D55 replaces a cache whose settings change); serde's `flatten`
  ignores `deny_unknown_fields`, so a map takes the keys no field reads and the stage says `unknown field` itself.
  - Names: `entries`, then `file`, one name a line, read as D56 reads a plain blocklist line
    (`dedens_plugins::host_names`); `*.name` is refused, a wildcard cannot be asked. `types` is any of A and AAAA, both
    by default, and not empty. At most 1000 names (`MAX_PREWARM_NAMES`, a bound as D115's: each name is up to four
    questions and a schedule entry). The arithmetic: 1000 names, 2 types, and DO as well when validating make 4000
    questions; at the default `min_ttl` of 60 s and `prefetch_percent` 10, each is asked every 54 s, 74 a second. With
    16 in flight that holds while the upstream answers within about 200 ms (800 a second at 20 ms, 320 at 50 ms); a
    longer list or a slower upstream falls behind, and an entry then expires and is asked as a client's is. A `file` that does not read fails the read, so a reload leaves the running
    pipeline (D55). No `urls`: a download is a blocklist's (D57), and a name list a download feeds to the resolver is
    an attack surface for nothing. A prewarm with no forward stage after the cache is refused: nothing could ask.
  - Questions: the pipeline carries them (`Pipeline::with_prewarm`): each name and type without DO, and again with DO
    when a forward stage validates (D77), so that a later client with DO hits too and the entry keeps its verdict (AD
    on the hit); CD stays clear (D43's key holds DO and CD). `Pipeline::prewarm(warm, now)` runs the stages as a
    client's query goes: a stage before the cache answering the name (blocklist, hosts) is `Local`, nothing to
    keep; a fresh entry is `Fresh(at)`, with the time to ask again; else the forward stage's `Upstream`, as a prefetch
    (`Purpose::Prefetch`): no reply, and a failure is not held (RFC 9520 §3.2: the hold is for a failure a client's
    query met; no client asked). The query is the server's own: no access list, rate limit or cookie. It goes over
    UDP, as a client's does, and falls back to TCP on a truncated answer (`Warm::TRANSPORT` is the one place that
    says so: the in-flight key of D86 holds the transport). It spends a share of the validator's allowance of its
    own (D117: the share of the unspecified address, `OWN`), so that a long list cannot starve the clients' shares,
    nor they it; a question that share sheds is `Warmth::Shed`, asked again a second on. A name the stages cannot
    ask is `Warmth::Unaskable`, nothing to keep, as `Local`. The slot of the thread's upstream queries (D47) is taken
    before the pipeline is asked, so that a question left unasked spends no unit.
  - Freshness: `Cache::refresh` says when the entry reaches `prefetch_percent` of its TTL left (the TTL the cache
    keeps, after D124's `min_ttl` and `max_ttl`, negative answers too), when it expires, and whether it is bogus,
    read with no metrics and no use: a prewarm lookup is no client's hit, and S3-FIFO's counts are the clients'. The
    name is asked at the earlier of that time and 2 s (`MARGIN`) before the expiry, the second the clock ticks in
    being the grain (D43): a TTL of 10 s or less at 10% would otherwise be asked at its expiry, and the first client
    after it would wait. No entry is served stale (D22) for want of a client, down to a TTL of 3 s; under that the
    schedule never goes faster than once a second. `Pipeline::warm_until` reads the same time with no allowance
    spent, to check that a query's answer was kept. A bogus entry (D77) is not kept: only a client's query stores it
    (a prefetch's bogus verdict leaves the entry it refreshes), for 60 s; it is `error`, retried as a failure.
  - Schedule (`apps/dedensd/src/serve/prewarm.rs`): one task, on serving thread 0, the cache being shared, so a name
    is asked once whatever the threads. At most 16 queries in flight, of the thread's 1024 upstream queries (D47): a
    list of thousands leaves the rest to clients. A query counts `ok`
    when the cache holds a good answer after it, `error` when not (none, a SERVFAIL, a bogus one), in
    `dedensd_prewarm_queries_total{result}`. A failure is asked again after 1 minute, doubling up to the cache's
    `failure_max` (RFC 9520 §3.2: 5 minutes at most). The task sleeps until the next name is due, or a reload (D107)
    wakes it, and takes the reload wake-up in the place of the thread's `follow` task, so that a server with no
    prewarm wakes no task each second; full, it waits for an end. A name taken out and listed again while its query
    is in flight is a new entry: the end of the old query is not heard.
  - Reload: the new pipeline's names are taken at once. While the cache stays (`Arc::ptr_eq`), the schedule of names
    still listed stays (no burst per SIGHUP), new names are asked, removed ones dropped; a replaced cache is empty,
    so every name is asked again and the answers of queries begun for the old one are not heard.
  - Tests: `crates/dedens-server/tests/prewarm.rs` (sans-IO, with the captured signed zones: the DO and the non-DO
    hits, AD, blocklist before cache, failure not held); `apps/dedensd/tests/prewarm.rs` (a loopback upstream counting
    queries, D89: asked once before any client, hit past the TTL, a reload asking the new name alone, a blocked name
    never asked, the refusal); `crates/dedens-sim/tests/serving.rs` (D182: refresh before expiry and the retry
    backoff on simulated time, `dedensd::simulated` running the prewarm task); the schedule's reload in
    `serve/prewarm.rs`'s own tests, `simulated` having no reload. The real-clock `dedensd` tests prove a hit
    with a query with RD clear (D46: fresh data or REFUSED, never upstream), not the upstream's count, which comes
    before the store. They cannot validate to a good verdict: the captured signatures have expired, so AD is
    checked at the pipeline, and the shed test (the own share at one unit) counts questions only.
  - Rejected: a plugin of D54 (it needs the cache and the upstream, which a plugin has not); asking only when an
    entry has expired (the first client after it waits); counting prewarm lookups as hits; one task per thread
    (every thread asking each name).


- D184 (amends D27, D31, D77; builds on D50, D86, D111, D114, D133) `dedensd` asks a plain server over UDP with
  `0x20` (draft-vixie-dnsext-dns0x20 §5.1): each letter of the question goes in a random case, which the response's
  question must repeat, else the response is dropped as one of another ID is (D27) and the wait goes on (§5.5).
  An off-path forger guessed the ID and the socket, 16 + 8 bits (D50); it now guesses one bit more per letter
  (`example.com`: 10). Cookies (RFC 7873) win more, but only with a server that sends one.
  - Where: `Upstream::random_case`, a plain server over UDP alone. A connection is beyond an off-path forger,
    and TLS, QUIC, HTTPS, Oblivious DoH (D185) and DNSCrypt authenticate the server: there the bits would buy nothing and a server that
    lowercases the question would cost a timeout.
  - Bits: `Client::random_case`, 32 bytes from the randomness the IDs come from (D27, D114), one draw a server
    asked; the exchange owns no randomness (D31). The simulator's client draws them from its host's `rng`, as its
    IDs, so a run stays one per seed (D133), and its upstream copies the question as asked.
  - Case: the exchange checks the echo byte for byte (D31), then writes the question's name back in the case it
    was given before it hands the response out (§5.4), so the names compressed against it, the answer's owners as a
    rule, read in that case too: the client's in the reply and the cache, the validator's for its questions. A
    flight's follower (D86) gets the lead's bytes in that case, never the lead's random one. A name the server
    writes in full keeps the server's case, the random one if it copied it there: RFC 4343 compares names in any
    case and the cache keys them so; Unbound lowercases the question alone too (`pkt_dname_tolower`).
    `Pipeline::receive` still checks the question in any case (D111): the case sent is the transport's.
  - A server that does not copy the case: each try times out, then the next server is asked, then SERVFAIL;
    the exchange fails with `Failure::CaseMismatch` when the dropped responses were all it got, which
    `dedensd_upstream_case_mismatches_total` counts (2026-11-20: they were debug-logged alone, the operator blind
    to a server that folds the case or a forger at work); `random_case: false` in the forward stage (on by default) asks it in the client's case. Per stage, not per
    server: a server is an address and a way (`Via`), and a stage of its own takes one that answers otherwise.
    Rejected: a fallback as Unbound's (`use-caps-for-id`, off by default; on a mismatch it asks every server
    again without `0x20` and takes the answer when all agree, `iq->caps_fallback` in `iterator/iterator.c`, with a
    `caps-exempt` list), the draft's §6.4: a forger that sends a mismatch would turn it on, and it holds a state a
    question; the resolvers a forwarder asks copy the question (§6.1), and a mismatch is more likely a forgery.
    Rejected too: off by default, as the library (D27): the lowercasing servers of §6.2 are authoritative ones a
    recursive resolver asks, not the resolvers `dedensd` forwards to.
  - Cost: a 32-byte draw from the IDs' buffer, a copy of the question's name and its write back, a query; forwarding
    over UDP under `just bench-dnsperf` within the noise, the tree winning 6 of 12 paired rounds (`docs/benchmarks.md`,
    "`0x20`").
  - Tests: `crates/dedens-net/tests/exchange.rs` (`random_case_gives_the_response_back_in_the_case_asked`, the
    answer's owner compressed against the question), `crates/dedens-server/tests/stages.rs`
    (`random_case_is_for_a_plain_server_over_udp`), `apps/dedensd/src/serve/upstream.rs`
    (`a_server_that_changes_the_case_is_dropped_unless_random_case_is_off`, a loopback server sending the
    captured case back), `crates/dedens-sim/tests/forged.rs` (`Flaw::Case`, the question in the other case and
    all else right, taken without `0x20` and dropped with it).
- D186 (amends D41, D47, D77, D117; builds on D43, D45, D96, D106, D113, D182) A validating forward stage's query that
  the global allowance (D77) refuses waits for it on its serving thread, then is shed as before if it still has none:
  past the allowance the saturation runs of the comparison (D183, `dnssec` mode) were void, every query beyond it
  answered SERVFAIL at once, where TelltaleDNS and Unbound queue and answer late.
  - Step: `Pipeline::query` returns `Step::Park(Parked)`, the query's `Upstream` boxed as for `Step::Upstream`, its
    share's unit kept (D117). The driver asks `Pipeline::unpark(parked, now)` again, which takes a unit of the
    allowance alone and gives the `Upstream` to send, or gives up with `Pipeline::shed(parked, now, out)`, which
    gives the share's unit back, counts `verdict="shed"` and writes the reply. The sans-IO core holds no queue and
    no timer (D41): the bucket refills at each second of `now` (D106), so the driver knows when to ask.
  - Wait: `Parked::wait()`, the cache stage's client response timer when it has one (D45: its stale data is then the
    reply, RFC 8767 §5), else `Parked::WAIT`, 1800 ms, the same default: under the 2 s after which a stub asks
    again, so the wait does not outlive the client's interest. Counted from the query's step.
  - Line: `dedensd` keeps one line a thread (`dedens_server::Parking`, FIFO), at most `PARKED` (512) waiting,
    each holding its place of the 1024 upstream queries (D47): half of them, so that half are left to queries
    that ask; a thread's half of 10 000 units a second admits 512 cold validations (3 or 4 units each since D75's
    shortcut) in under half a second, well within the wait. The newest past the line is shed at once. Only the
    first of the line asks the allowance, as it comes first and then at each second of the thread's clock (one
    timer of the thread's `Io`, D182, no polling); a query given up wakes the next. A query the allowance admits
    while the line is not empty gives its unit back and goes behind it (`Pipeline::defer`): first come, first
    served. Every transport goes through `serve::start` and `upstream::answer` (UDP's loop and DNSCrypt's step
    too), so all wait the same way.
  - Not parked: a network over its share (D117) is shed at once and takes no place (a flood of one network must
    not fill the line of the others); a prefetch, a stale refresh (D43) and a prewarm (D96) refused by the
    allowance are not made, as before: their client has its reply, and a place is a client's. The questions of
    a validation under way still shed it when the allowance is in debt (D106): it already took its unit.
  - Metrics: `dedens_validations_parked_total` counts the queries that waited; `verdict="shed"` stays the
    queries shed, now past the line or the wait.
  - Rejected: a queue in the pipeline (a timer and a waker in the sans-IO core, shared by every thread); a ready
    time on the step (the bucket's second is the answer, and the line already orders who asks); waiting as long
    as the upstream patience (D45, 3 s by default: past the stub's retry, the wait would answer a client that
    left); parking a share's overflow (one network would then hold places of all).
  - Tests: `crates/dedens-server/tests/dnssec.rs` (`limits::parking`), `crates/dedens-server/src/park.rs`,
    `apps/dedensd/src/serve/upstream.rs` (`a_query_past_the_allowance_waits_and_is_asked_once_it_refills`,
    `a_query_past_the_line_is_shed_at_once_and_one_waiting_too_long_once_its_time_is_up`),
    `crates/dedens-sim/tests/dnssec.rs` (`a_burst_past_the_allowance_waits_and_what_waits_too_long_is_shed`),
    `a_query_that_waits_for_the_allowance_is_counted_parked` of `crates/dedens-server/tests/metrics.rs`.
- D128 (amends D54, D104, D122, D126, D127; amended by D200) The `tlds` stage answers, with no upstream query, the special-use top-level domains and those
  not in the root zone: `type: tlds`, `dedens_plugins::TopLevel` over a `dedens_roots::Tlds`. Its table,
  `SPECIAL`, holds each special-use TLD of IANA's list with what item 4 of its RFC asks of a caching server:
  `localhost` and its subnames the loopback addresses to A, AAAA and ANY (one RRset, RFC 8482 §4.1), no data to
  other types and classes, AA set (RFC 6761 §6.3); `invalid` (§6.4), `test` (§6.2), `local` (RFC 6762 §22.1)
  and `onion` (RFC 7686 §2, a MUST) NXDOMAIN, DO or not; `example` (RFC 6761 §6.5), `alt` (RFC 9476 §2),
  `internal` (no RFC: ICANN reserved it for private use in 2024) and `arpa` as any TLD, as their RFCs ask not to
  treat them as special. These rows hold in every class: the RFCs name the names, not a class, and an `onion`
  query in CH or ANY must not leave either. Any other TLD of class IN is in the root zone when the list holds it
  `active`; other classes go on (`version.bind` in CH is no TLD of the root): else a query without DO is NXDOMAIN,
  one with DO passed on (no proof could come with the denial, and a validating client would take it for bogus), so
  `example`, `alt` and `internal`, `reserved`, get the NXDOMAIN the root would give. A test checks that every
  special-use TLD of the bundled list has a row: a new one in a fresh list is answered as its status says, and
  `dedensd` warns of it. The stage's NXDOMAIN carry no SOA and AA is clear: it holds no zone, and a SOA would be
  invented. The cost (RFC 2308 §5): no cache downstream keeps them, so a stub or a forwarder in front asks again
  each time, a lookup in memory here; `dedensd`'s own cache stage comes after. A name of one's own network under
  `internal` or `test` comes from a stage before it, as a hosts stage. It goes before a cache stage, as hosts and
  blocklist do (D64). `dedensd_tlds_answers_total{kind}` counts its answers, `special_use` or `unknown`. No EDE comes with
  them: none of RFC 8914 says a policy's answer for a name that exists nowhere (15 Blocked and 17 Filtered say the
  name exists). Rejected: NXDOMAIN for `example`, `alt` and a special-use TLD of no known use whatever DO (the RFCs ask the
  first two be resolved normally, and a DO client cannot check the denial); a SOA of the root in the NXDOMAIN (it
  would claim a zone's authority for a policy).

  `dedensd` keeps the root's files fresh, from `roots:` (`off`, or the URLs of `tlds` and `anchors`, IANA's by
  default; the signature is the anchors' URL in `.p7s`). It fetches only what serves: the TLD list when a `tlds`
  stage is in the pipeline, the anchors when a validating forward stage has no `trust_anchors`. They join D104's
  downloads: same thread, `refresh_minutes`, loopback-testable over HTTP, the leftover sweep. The TLD list is a
  cache, kept in `downloads.dir` named by its URL (`tlds-<hash>.json`, its ETag beside it: a 304 keeps it, and
  a new URL never gets another's ETag); it is read by `Tlds::read` before it is saved, so a short or broken one
  never replaces the copy, and handed to the reload that follows. A saved copy that does not read is warned of, the
  bundled list serves, and its ETag is removed so the next refresh fetches it whole; one IANA generated before the
  bundled one is not used either, the newer of the two serves. The anchors are state: the
  pair is fetched whole each refresh (10 KB, no ETag), checked by `TrustAnchors::verified` (D127) with the signing
  time of the anchors kept as the floor (the bundled one with none), so a replayed older pair is refused (RFC 9718
  §3). Of a pair that verifies, `dedensd` keeps one file, `root-anchors` in `state_dir` (default
  `/var/lib/dedensd`, systemd's `StateDirectory`), written atomically (D104): `dedens_dnssec::RootAnchors`, a
  versioned text of every key with its validity and the signing time, as unbound-anchor keeps its own. It is
  written when its keys or time change; the same keys signed again advance the floor and reload nothing. A start
  and a reload read it without the signature, as trusted as `state_dir`: no file is the bundled anchors; one that
  cannot be read or parsed refuses the start (D115) and, at a reload, leaves the anchors in use, warned of. The
  validators trust the keys valid at the load; each refresh compares those valid then, so a key that ends or
  starts within a kept file reloads without a restart. A kept file with no key valid at the load has every key
  trusted, dates ignored, warned of at each load: a wrong clock is likelier than ICANN ending every key, and
  refusing would stop a server a clock set back, as `RootAnchors` was read from a verified pair; the next refresh
  brings the keys of now. Root files are read at start as the starting user, then
  again as `user` once dropped (D122), a regular file of a capped length only (32 MiB for the list, 64 KiB for the
  anchors), the file itself never a symbolic link (`O_NOFOLLOW`; the directories above it are the operator's, as
  `downloads.dir` is). The drop makes the directories of the root files used for `user`,
  as `downloads.dir` (D122); one that cannot be made or written is warned of at each load and not fetched into:
  the copy there, or the bundled one, serves, and the server starts. A validator's tag is its anchor set itself
  (`TrustAnchors`'s canonical text, negative anchors included), whatever its source: a new set builds a fresh
  validator, whose keys are proven again, and flushes the caches behind it (D77); the same set kept keeps both. A
  TLD list older than 30 days by its `meta.generated` (`dedens_plugins::MAX_LIST_AGE`) has the stage pass on a
  TLD outside it instead of NXDOMAIN, as it may since have been delegated: `dedensd` warns of it at each load, per
  `tlds` stage, `dedensd_tlds_stale_total` counts those passed on. `dedensd_roots_age_seconds{file}`, `tlds` or `anchors`, is
  the age of the copy in use, since IANA generated the list or ICANN signed the anchors, set at each refresh: the anchors' from the kept
  file, whose signing time a pair signed again advances. A list generated in the future is 0 seconds old. The
  bundled copies age: 30 days after `just roots` a server with `roots: off`, or IANA out of reach, passes on the
  TLDs outside the list; a container without a volume for `state_dir` (and `downloads.dir`) starts again from the
  bundled anchors' floor and list. No test compares the real clock with the bundled list's age: the stage takes
  a clock, and `dedensd`'s tests fetch the captured list with its `meta.generated` edited to now. The
  Landlock plan must let `downloads.dir` and `state_dir` be written. Rejected: keeping the signed pair and
  verifying it at each load (the signing certificate expires, a crash between two renames splits the pair, and
  the bundled anchors would replace newer ones); the floor in memory only, or in the cache directory (a restart, or
  a cache cleared, would accept a replayed pair); an ETag for the anchors (a 304 on the XML says nothing of the
  signature); refusing a start for a root directory that cannot be written (`roots` is on by default, the bundled
  copies serve); separate settings of refresh (one schedule, one thread).
- D191 (builds on D188, D190, D192, D193, D194; amended by D196, D197) The recursive resolver's iteration,
  `dedens_resolver::Resolution` (recursive step 04): one client question from the closest delegation known down the
  referrals to the answer (RFC 1034 §5.3.3), sans-IO, one query in flight.
  - Driving: `Resolution::start(question, Arc<Caches>, now, limits)` refuses a question it cannot resolve
    (`Unsupported`: ANY and the other QTYPEs and meta types, RRSIG, part of the `RRset` it covers (D176), a class
    other than IN); `step(now, rng)` gives `Next::Send(&Query)` or `Next::Done(&Resolved)`, the same query again
    until `receive(Reply, now)` takes its reply. `Query { question, server, zone, marks, timeout }` is typed: the
    transport (D190's `Authoritative::query`) owns the wire, the ID, DO, `0x20`, TC then TCP and the EDNS fallback,
    and matches the response to the query. `Reply` is `Response { message, seen, rtt }` (the matched response, the
    server's `Marks` seen, D190's `Response::rtt`), `Undecodable` (matched, but not a message: the next server,
    nothing remembered, as Unbound's `process_response`), `Timeout`, `ServerError` (D190's `ServerError`:
    unreachable, forged, TCP failing) or `LocalError` (D190's `LocalError`). The plan's `Send` is named `Query`:
    `Send` would shadow `std::marker::Send`; its `Outcome` is `Resolved`, beside the scrubber's. Time is a
    `Duration` of any origin; the caches get its seconds.
  - `Caches { rrsets, infra, roots, tlds }`: the start is the cache's answer (a rank that may answer, D193) or CNAME,
    else the closest zone at or above the name, strictly above for a DS (the parent's, RFC 4035 §3.1.4.1, Unbound's
    `processInitRequest`), whose NS `RRset` is cached with an address cached for one of its servers (any rank: glue
    serves to reach a server), else the TLD's servers of `dedens-roots` when `tlds` is set, else the root hints
    (D126).
  - Every response goes through `scrub` (D192), its `Outcome` alone deciding the next move: `Answer` ends the task,
    `Cname` restarts at its target, `Referral` goes down, `NoData`, `NxDomain` and `YxDomain` end the task, and
    `Signatures`, `NoSoa`, `Lame` and `Unusable` have the next server asked. A DS referred to the name asked is not
    followed: the child has no DS, the referral's proof is the validator's (step 10).
  - Infra cache: a response the scrubber reads as serving the question (all outcomes but `Signatures`, `NoSoa`,
    `Lame` and `Unusable`) credits the server its round trip, the transport's `rtt`: the time since `step` gave the
    query counts waits, the TCP retry and the EDNS fallback. A response after the query moved to TCP (truncated,
    BADCOOKIE twice, a case mismatch: `Response::moved`) carries no `rtt` (`Reply::Response { rtt: None }`): its
    time is the connection's and the response's size, not the UDP time `Query::timeout` estimates, so it clears the
    server's timeouts and merges its marks (`InfraCache::answered`) but leaves its RTO as it was. `Lame` marks the
    server lame for the zone. `Timeout` and `ServerError` back the server off (RTO doubled, skipped after three,
    D194). REFUSED, SERVFAIL and any other unusable response leave it as it was, as Unbound's `THROWAWAY`
    (`iter_resptype.c`) and BIND's `add_bad`, per fetch: the infra cache is keyed by address alone, and a back-off
    would let three REFUSED for one zone shut a server out of all of them. `LocalError` is ours: the server is not
    touched.
  - Caching: every `RRset` of `Scrubbed::ranked` at the scrubber's rank (D192, D193); the referral's NS as of the
    resolution's start when the delegation asked came from the cache, else now (Unbound's `store_rrsets`, D193).
    Negative answers are cached by D199's entries. An address that came as glue keeps the glue's rank when answered
    (D193's pin), so a later client question for it is asked again.
  - Servers: the first `servers` names of a referral's NS `RRset`; each name's addresses are its glue, else those
    cached; `InfraCache::select` draws among those not tried (and those timed out, D196). When none is left, a
    server without an address, drawn at random with the resolution's `rng`, is looked up, A then AAAA, by a
    sub-resolution on the same stack sharing the limits; its result is memoised by its question for the whole
    resolution, but for a bound reached (`depth`, `targets`, `servers`, time), which is the place's, not the name's:
    asked from another it may resolve. A lookup whose closest delegation or referral is a zone an ancestor on the
    stack is waiting on ends at once, its name given no address (the loop of a zone reachable only through itself
    costs one query per name), which leaves an address the name's A lookup found. An A lookup ending NXDOMAIN skips
    the name's AAAA.
  - Addresses: an address at one of the special-purpose ranges below (RFC 6890's, but for those named after the
    list) is not asked unless `Resolution::asking_local_addresses` (`Recurse::asking_local_addresses`,
    `dedensd`'s `recurse` switch `query_local_addresses`, default false; the resolution's, not `Limits`' (counts)
    or the caches', which a reload keeps while the switch changes): loopback (127/8, `::1`), "this network" (0/8,
    `::`), private (10/8, 172.16/12, 192.168/16, fc00::/7), shared (100.64/10), link-local (169.254/16, fe80::/10),
    IETF protocol assignments (192.0.0/24), benchmarking (198.18/15), multicast (224/4, ff00::/8), reserved
    (240/4), broadcast, and of IPv6 also: every IPv4-mapped address (`::ffff:0:0/96`, a public IPv4 too, as
    Unbound's `do-not-query-localhost`: the same host would take two infra entries, and a `V6ONLY` socket cannot
    reach it), the deprecated site-local `fec0::/10`, the IPv4-compatible `::/96`, the local-use NAT64
    `64:ff9b:1::/48` (RFC 8215, not globally reachable, the embedded IPv4's place depends on the prefix length of
    RFC 6052 §2.2), and a well-known NAT64 (`64:ff9b::/96`) or 6to4 (`2002::/16`) address embedding one of the
    IPv4 ranges above (RFC 6052 §3.1 has a NAT64 gateway refuse them, but a zone can still aim the resolver at
    one that does not). A NAT64 or 6to4 address embedding a global IPv4 is asked, and so is every range of RFC
    6890 not listed, on purpose: documentation (192.0.2/24, 198.51.100/24, 203.0.113/24, `2001:db8::/32`), the
    IPv6 protocol assignments `2001::/23` (Teredo `2001::/32` included) and the discard prefix `100::/64` aim at
    no host of ours, nor at its network. A zone's glue, a name's addresses or a delegation cached could otherwise
    aim the resolver at its own host, its network or many hosts (SSRF, amplification). Every address enters
    through `Delegation::add`, which drops those; a cached delegation with no address left to ask is skipped for
    the TLD's or root hints. This goes beyond Unbound's `do-not-query-localhost` (on by default: loopback, "this
    network" and `::ffff:0:0/96` only; its `private-address` hides private addresses from answers, not from
    queries) on purpose: `dedensd` is a public resolver, and no stub zones exist yet (a stub zone is how Unbound
    reaches an internal server). Cost: an internal server reached through a public
    delegation, or authorities on a test's own host, need the switch. Config load refuses `root_hints` none of
    whose addresses is asked unless the switch is on: every query would fail, and SERVFAIL would be the only sign.
  - Limits (`Limits`, each a field with its number, a test in `tests/iteration.rs` reaching its default):
    `queries` 32 per client question, its sub-resolutions included, Unbound's `max-sent-count` (BIND 50): the cap
    of what a client costs; `restarts` 11, Unbound's and BIND's `max-query-restarts`, every CNAME hop counted, from
    the cache or a response, a DNAME and the CNAME synthesized from it one hop, as the scrubber's `MAX_CHAIN`;
    `referrals` 30, below Unbound's `MAX_REFERRAL_COUNT` 130 and above hickory's 24: the captures' deepest follows
    4; `depth` 4 sub-resolutions waiting on one another, Unbound's `target-fetch-policy` (BIND
    `max-recursion-depth` 7); `servers` 13 addresses asked and NS names used per delegation, BIND's
    `max-delegation-servers`, no address looked up once 13 were asked; `targets` 5 address lookups per delegation,
    A and AAAA each counted, after Unbound's `MAX_TARGET_NX` 5 (NXNSAttack, CVE-2020-12662), which counts NXDOMAIN
    lookups per client question, and its `MAX_DP_TARGET_COUNT` 16 per delegation (BIND counts them within its 13);
    `MAX_ADDRESSES` 100 addresses known per delegation, not per server name, glue, lookups and cache together,
    Unbound's `delegpt_max_addr` (the scrubber keeps 100 glue records already), the servers shunned (D197) not
    counted, so that a bogus answer does not take an address from the retry: an answer of thousands costs the draw
    no more (one name with 100 addresses fills it, as in Unbound); `time` 4.5 s, a stub's 5 s (glibc
    `RES_TIMEOUT`) less the SERVFAIL's way back. `queries`, `restarts`, `referrals` and `time` end the resolution;
    `servers`, `targets` and `depth` end the branch, the delegation asked trying its other servers, and are
    reported if the question fails.
  - Failure: SERVFAIL with `Failure::info_code` (RFC 8914 §4), from what the servers of the delegation that failed
    did: a limit, or every query timing out, 22 No Reachable Authority; server or local errors and no response, 23
    Network Error; responses, none usable (lame, refusing, failing, undecodable), 0 Other Error. Each limit reached
    is a `debug!` naming it and a count in `dedens_resolver_limits_total{limit}` (D30); each query, referral,
    restart and unused response a `debug!`.
  - Tests: each capture of `testdata/recursion/` (D188) but the RRSIG question's resolves to its captured answer
    through `Authorities`, sending exactly the captured questions but validation's (DS, DNSKEY, priming), one
    server per question: the infra cache marks lame every other address for each zone, so the draw falls on the
    server the capture followed; the test harness is the transport (UDP, TCP after TC). The defaults are reached on
    referrals built from the captured ones, every query timing out, or captured responses changed; each change is
    written in its test.
  - Not here: the stage and its transport binding (08), DNSSEC (10), QNAME minimisation (11, D198), negative
    caching (D199), a last resort to the root when a cached delegation fails.
- D192 (builds on D188) The recursive resolver scrubs each response before anything reads it:
  `dedens_resolver::scrub(response, question, zone)`, a pure function, keeps what a server asked as authoritative for
  `zone` may say (RFC 2181 §6.1, RFC 5452 §6) and sorts it into an `Outcome`: `Answer`, `Signatures` (the answer
  to an RRSIG question), `Cname` (a chain the zone cannot finish), `Referral { child, ns, proof, glue }`,
  `NoData { soa, denials }`, `NxDomain { chain, soa, denials }`, `YxDomain { chain }`, `NoSoa` (a negative answer
  without its SOA: no negative TTL, so not cached, RFC 2308 §5), `Lame` or `Unusable(why)`. A negative outcome
  holds its SOA, not an `Option`: one without is `NoSoa`. Each record dropped is returned with its section, index
  and `Reason`, for the iteration to log and count; those kept, but `Signatures`' records, are grouped into
  `RRsets` (D193), each with the RRSIGs covering it and its `Rank`, what `RrsetCache::insert` takes
  (`Scrubbed::ranked`; `Scrubbed::records` lists them one by one). A signature shares its `RRset`'s owner and
  section, so its rank: the scrubber pairs them, not the cache. `Rank` is one type, in `rank.rs`, the scrubber's
  output and the cache's input. The rules, as Unbound's `iterator/iter_scrub.c` (`scrub_normalize`,
  `scrub_sanitize`) and `iter_resptype.c` (`response_type_from_server`) have them, but for the deviations below:
  - unusable, nothing kept: QR unset or an opcode other than QUERY, TC set (asked again over TCP, RFC 7766 §5), a
    code other than NOERROR, NXDOMAIN and YXDOMAIN, a YXDOMAIN without the DNAME that makes it, not exactly the
    question (name, type, class), the name outside `zone`;
  - every section: a record of another class, or owned outside `zone`, is dropped (RFC 2181 §6.1); so is one of a
    type `dedens-proto` decodes whose RDATA does not parse (decoded `Opaque`, D9), and a DNAME whose target is
    compressed or no name (RFC 6672 §2.5), or whose owner has an answer DNAME to another target (a singleton type,
    §2.4; Unbound's `scrub_normalize` rejects the response), with the CNAME the server made of it: `Malformed`
    (Unbound dfc00271d drops
    A and AAAA of the wrong size; every typed type here, as the cache would serve them); so is one of a QTYPE, meta
    type or QCLASS (RFC 6895 §3.1, §3.2), `NotData`, which no `RRset` holds: nothing kept is lost in grouping;
  - AA: only authoritative data from the zone's servers is trusted (RFC 2181 §5.4.1). A response without AA that
    is not a referral is `Lame`, NXDOMAIN and NODATA included, RA set or not; a response referring nowhere below
    `zone` (an NS `RRset` of the zone itself, above it or a sibling, and nothing else) is `Lame` whatever AA says
    (RFC 4697 §2.2);
  - a referral (NOERROR, no SOA and no answer within `zone`, AA or not): the first NS owner strictly below `zone` and
    at or above the name (RFC 1034 §4.3.2 step 3b) is the child; its NS records are kept, any other NS `RRset`
    dropped (a sibling, the zone itself, a second one); its DS, or the NSEC and NSEC3 proving none (RFC 4035
    §3.1.4); as glue, the A and AAAA records at its name servers' names within `zone`, the parent's to give, sibling
    glue too (as Unbound's `harden-glue`), not only within the child: a parent that may redirect the child may give
    its addresses. A DS question answered by a referral to the name asked, with the DS at it, is answered by that DS
    (RFC 4035 §3.1.4.1, Unbound 6cb75924d): the DS is the parent's, the child would deny it;
  - an answer: from the name, a DNAME above it then the records of the type asked then a CNAME at it (RFC 1034
    §4.3.2 step 3a, RFC 6672 §2.2), hop after hop; a DNAME's CNAME is synthesised (RFC 6672 §3.4), unsigned, and the
    server's kept only when it is the same; a qtype of CNAME is answered by the synthesised CNAME (RFC 6672 §2.3). A
    chain leaving `zone`, or ending without data in a NOERROR, is `Cname { target }`: the zone's servers say nothing
    past it, and the target is asked again, also when it is within the zone (a NODATA there costs one more query);
    answer records off the chain are dropped. A DNAME whose synthesis passes 255 bytes ends the chain in
    `YxDomain`, the answer of RFC 6672 §2.2, whatever the code the server gave. An RRSIG question's answer, the
    RRSIG records at the chain's end, is `Signatures { chain, records }`: an RRSIG is no `RRset` of its own but
    part of the one it covers (D176, RFC 4035 §2.2), so the resolver answers with them and no cache takes them;
    `ranked` and `records` hold the chain alone, and grouping loses nothing;
  - a negative answer keeps one SOA at or above the chain's end and the NSEC and NSEC3 records (RFC 2308 §2, RFC
    4035 §3.1.3); an answer keeps its NSEC and NSEC3 records (wildcard proofs). NS records beside an answer or a
    negative answer are dropped (Unbound's `iter-scrub-promiscuous`, CVE-2025-11411), and every other type of the
    authority section; an NSEC whose next name is outside `zone` is dropped (Unbound's `sanitize_nsec_is_overreach`);
  - additional: only the A and AAAA records at the names of the NS records kept (a referral or an NS answer);
  - an RRSIG stays with the `RRset` it covers, in its section, or is dropped.
  Bounds, Unbound's defaults (`util/config_file.c`): `MAX_NS` = 20 NS or DS records an `RRset` (`iter-scrub-ns`);
  `MAX_CHAIN` = 11 CNAME and DNAME hops (`iter-scrub-cname`); `MAX_SIGNATURES` = 8 RRSIGs an `RRset`
  (`iter-scrub-rrsig`); `MAX_GLUE` = 100 addresses (`iter-scrub-glue-count`); past each, the rest is dropped.
  Ranks (RFC 2181 §5.4.1, as Unbound's `get_rrset_trust`): the records of the answer section at the name asked and
  at the owner of its first record (a DNAME above it) answer authoritative, the rest of the chain answer
  non-authoritative (AA covers the first owner, RFC 1035 §4.1.1), the authority section authority authoritative, the
  additional additional authoritative. A referral's NS and proof are authority non-authoritative, its glue additional
  non-authoritative, whatever AA says; the DS of a referral answering a DS question answer authoritative, AA or not:
  the parent holds it as authoritative data (RFC 4035 §2.3). No rank is that of a non-authoritative answer, which is
  `Lame`: answer non-authoritative means the chain past its first owner only. Deviations from Unbound, and why:
  every response without AA but a referral is `Lame` (Unbound's `response_type_from_server` accepts an answer, an
  NXDOMAIN or a NODATA without AA, ranked non-authoritative, and calls it lame only with RA set, `REC_LAME`; it reads
  NS records without AA in the answer section to an NS or ANY question as a referral): no answer is trusted from a
  server not authoritative for it, and a non-authoritative answer with RA clear is a stale copy or a forwarder
  answering, which a cache must not rank beside the zone's data. The cost: a misconfigured server answering its zone
  without AA is lame, and the iteration tries the next server, failing the zone if every server does so. A NOERROR
  whose DNAME synthesis is too long is `YxDomain` (Unbound fails it as a scrub error): the zone said what RFC 6672
  §2.2 makes of it; an NS `RRset` of the zone itself without SOA and without answer is `Lame` even with AA (Unbound
  reads an AA one as an answer): it delegates to itself, nothing to cache; a referral's ranks ignore AA (Unbound
  ranks an AA referral's NS authority authoritative): a parent is not authoritative for the child's NS; the DS of
  a referral answering a DS question is answer authoritative without AA (Unbound moves it to the answer section,
  where `get_rrset_trust` ranks it `rrset_trust_ans_noAA`): the parent holds the DS `RRset` as authoritative data
  (RFC 4035 §2.3), as in its AA answer to the same question; an RRSIG question's signatures are answered, not
  cached (Unbound's `msgparse.c` keeps them as an `RRset` of type RRSIG, which it caches): an RRSIG is part of
  the `RRset` it covers (D176). Forwarding
  is not scrubbed: an upstream resolver answers for every zone, so no zone bounds it; and forwarded data never enters
  the recursive resolver's `RRset` cache (MaginotDNS, USENIX Security 2023: a server both forwarder and resolver let
  its forwarded answers, checked against no zone, poison the cache its recursion reads). Rejected:
  editing the message in place as Unbound does (a decoded message borrows its bytes; the caller gets the drops);
  `Message::referral`, which checks no zone; an RRSIG question's answer `Unusable` (the resolver could not answer
  one), or an `Answer` whose RRSIGs grouping drops; glue only within the child (refuses sibling glue the parent holds);
  trusting the server's CNAME beside a DNAME; following a chain out of the zone (Kaminsky, RFC 5452 §6); keeping an
  answer without AA ranked lower, as Unbound (a cache would hold data no zone's server vouched for; reopened if real
  captures show servers answering their zones without AA, `docs/TODECIDE.md`).
- D193 (amends D116; amended by D199; builds on D22, D124) The recursive resolver's `RRset` cache, `dedens_resolver::RrsetCache`
  (recursive step 06), in the new crate `dedens-resolver`:
  - Key and value. An `RRset` (RFC 2181 §5) under its owner name lowered (RFC 4343), type and class; the value an
    `Arc<Rrset>` (records and the RRSIGs covering them, owned), its rank, the validator's verdict
    (`dedens_cache::Checked`: unchecked, secure, insecure, bogus) and its expiry. The value is an enum (D199 adds negative
    answers and failures held), so every kind of entry shares the key space. `Rrset::group` builds the `RRsets` of a section, each
    record finding its `RRset` by hash and each RDATA its duplicate by hash (work linear in the records but for the
    sort of each `RRset`, memory linear): the QTYPEs, meta types and QCLASSes dropped (RFC 6895 §3.1, §3.2),
    duplicates dropped, names in RDATA compared in any case, the RDATA sorted by its bytes with ASCII letters folded
    so that the same data compares equal whatever order and case it came in, the TTL the smallest of the records and
    their signatures (RFC 2181 §5.2); equality is the data, not the TTL. RDATA that folds the same but differs (TXT
    strings, signatures, differing in case only) stays apart, and a run of it is compared by hash: an attacker's
    4096 case variants of one TXT string cost no quadratic work.
  - Ranks (RFC 2181 §5.4.1), least trusted first: additional non-authoritative (referral glue), authority
    non-authoritative (referral NS), additional authoritative, answer non-authoritative (the chain of an authoritative
    answer past its first owner, never a response without AA, which is lame, D192), authority authoritative,
    answer authoritative. The RFC's last bullet puts three of them at one level; they are split as Unbound's
    `rrset_trust` does (`util/data/packed_rrset.h`): authoritative first, authority over additional. No zone-data ranks:
    the resolver holds no zone. Secure data is trusted above every rank (the RFC's closing paragraph). Step 05's
    scrubber ranks what it keeps: `insert` takes its `Scrubbed::ranked` `RRsets`, in the bailiwick of the server they
    came from, and trusts the rank given. `get` returns any rank: only answer-section data (answer non-authoritative or
    authoritative) may answer a client (RFC 2181 §5.4.1), which `Ranked` says and its caller checks; the rest serves
    the resolution, authority authoritative included and proved secure too: the parent's NSEC or NSEC3 at a cut does not
    answer `child. NSEC`. A DS of a referral to the name asked is answer authoritative (`Rank`), so it answers a DS
    question; a DS of a referral to another name is no answer, and the validator asks for the DS it judges (answer
    rank), so none is held secure at an authority rank to answer from (Unbound's rrset path would serve one,
    `dns_cache_lookup`).
  - Replacement, Unbound's `need_to_update_rrset` (`services/cache/rrset.c`): an expired entry gives way to anything;
    more trusted data replaces, except data equal to bogus data that is not itself secure (it would lengthen the
    bogus data's life, RFC 4035 §4.7); other data of equal trust replaces (the last heard of); the same data of equal
    trust keeps the entry and its running time; less trusted data does not replace, unless the entry is bogus and
    the data other and not bogus. `insert` says which (`Inserted::Stored`, `Verdict`, `Kept`) with what the cache
    holds after. An `RRset` refused (`NotCached`) leaves the entry of its key as it was, where a refused response ends
    the response cache's: the trust of the entry decides alone.
  - Verdicts. The validator (step 10) records one by inserting the `RRset` again with it, at the rank it holds: the same
    data held unchecked, fresh, takes the verdict whatever the ranks, at the greater of the two unless pinned as glue
    (below), and lives the least of its time left and the verdict's lifetime (`Inserted::Verdict`); data already checked
    takes no other verdict but through the replacement rules. Unbound updates in place too (`rrset_update_sec_status`),
    but sets the TTL the validator gives on types other than NS, which may lengthen it. Before caching a secure `RRset`
    the validator lowers its TTL to the RRSIG's Original TTL and the time left to its Signature Expiration
    (`Rrset::cap_ttl`, RFC 4035 §5.3.3): secure lifetimes have no floor, so it is never kept past its signature.
    `Checked` has no indeterminate: the validator records none, and the `RRset` stays unchecked (as D77 caches none).
  - Ghost domain names (Jiang et al., NDSS 2012): a delegation is renewed from its parent only once expired. An NS
    `RRset` replacing one not expired lives no longer than the time it had left, whatever the verdicts: Unbound does
    so since CVE-2026-40622 (8d8fa4226), but lets secure data replacing data not secure, and data replacing bogus
    data, live their own TTL; stricter here, one rule, the cost a delegation asked for again sooner (tested on a
    secure NS `RRset` replacing a bogus one). An A or AAAA `RRset` replacing referral glue, or a verdict on it, with
    more trust and not secure, is pinned: it keeps the glue's rank and lives no longer than the glue had left, so
    that an answer does not keep a deleted domain's servers alive through their addresses, as Unbound since
    CVE-2026-42955 (13ec8d0f2). One predicate (`Cached::pins`) decides both. Stricter than Unbound, which pins only
    when it shortens the TTL and raises the rank on a verdict (`rrset_update_sec_status`): there an answer of a
    shorter TTL, or an insecure verdict (every answer of an unsigned zone gets one), lifts the address to answer
    rank, and the next answer of equal trust lives its own TTL. Here the pin holds whatever the TTL, which is
    shortened only when longer; the cost is an address asked for again sooner. A pinned `RRset` is ranked as glue,
    so it never answers a client from the `RRset` cache until it expires (`Ranked`); only the response cache serves the
    answer it came in, as in Unbound (`services/cache/dns.c:930`): step 08 must not expect it there. Step 04 inserts
    each NS `RRset` at the time its resolution started, not at its answer's, as Unbound's `qstarttime` since
    CVE-2022-30698 and CVE-2022-30699 (f6753a0f1): an NS `RRset` that expires during a resolution still counts as
    held, so that the answers of the servers it named do not renew it. Step 04 keeps Unbound's one exception
    (`!pside`, `dns.c:91`; the iterator passes `dp->has_parent_side_NS`): an answer from servers found through the
    parent's NS records, not the child's NS `RRset`, has its NS `RRset` inserted at its answer's time, so that a
    prefetch may update it (`dns.c:68`): no child NS `RRset` led there to protect.
  - TTLs: one source with the response cache, `dedens_cache::Config::lifetime` (D124): raised to `min_ttl` unless
    secure, capped by `max_ttl`, by the insecure cap when insecure and by `bogus_ttl` when bogus; TTL 0 is not
    cached (`NotCached::ZeroTtl`, RFC 1035 §3.2.1), a TTL past 2^31 - 1 was read as 0 (RFC 2181 §8). `RrsetCache::new`
    takes the response cache's `Config`, validated whole, its `capacity` included, and a capacity of its own. No
    stale data (RFC 8767): an expired entry holds its bytes until evicted or replaced.
  - Sizing (amends D116). The response cache's store is extracted from `Cache` as `dedens_cache::Store<V>`: the
    shards, their locks (held for one call, never across an `.await`), keyed SipHash, S3-FIFO and the byte budget,
    generic over a value that says its heap bytes (`Cost`); `SLOT_COST` is per value type (`Shard::<V>::SLOT_COST`),
    and the sizing rules of D116 (`capacity`, `shards`, `max_entry_bytes`, the derived entry limit, the longest key
    a tenth of a shard's share must hold) are one pair of functions both use. `Store::upsert` stores a value or
    changes the one held, and hands back what it lets go of to be dropped once the lock is released. The `RRset`
    cache holds `Store<Entry>`; an `RRset` over the entry limit is not cached (`NotCached::TooLarge`).
    `DEFAULT_CAPACITY` is 128 MiB, twice the response cache's 64 MiB, as Unbound's performance guide sets
    `rrset-cache-size` to twice `msg-cache-size` (its defaults are 4 MiB each, `util/config_file.c`); BIND bounds all
    its caches together by `max-cache-size`, 90 % of memory. An `RRset` a `Ranked` still holds after its eviction is the
    caller's, outside the budget.
  - What the budget counts: the bytes asked of the allocator, the `Arc`'s allocation, the owner name, the two RDATA
    slices and each RDATA (`tests/memory.rs` checks `Rrset::cost` against the allocator's
    count, and holds the count within 1.05 times the capacity on a referral churn). The allocator's rounding and
    headers are not counted, most on small allocations: a glue A `RRset` asks 128 bytes in four allocations (80, 20,
    24 and 4), which take 160 from macOS's malloc (16-byte quanta) and 192 from glibc's (an 8-byte header, 16-byte
    granules, 32 bytes at least), 1.25 and 1.5 times (computed from the allocators' rules, not measured). Rejected
    for now: one allocation for the RDATA and offsets into it, which needs
    `dedens-proto` to read RDATA borrowed from a buffer without decoding it again; revisit if a heap profile of a
    resolver shows the overhead.
  - Counters (feature `metrics`, D30): `dedens_resolver_rrset_lookups_total{outcome=hit|miss}`,
    `dedens_resolver_rrset_inserts_total{outcome=stored|verdict|kept}`, `dedens_resolver_rrset_evictions_total`.
  - Measured: `crates/dedens-bench/benches/rrset_cache.rs` (insert, replace, evict, hit, group, equality on case
    variants), and the response cache before and after the store's extraction, no change, in `docs/benchmarks.md`.
    The response cache's slot stays 272 bytes (`SLOT_COST`, a `const` assert on 64-bit targets): its `failures` count became a `u16` to undo
    the generic entry's padding. Fuzzed: `rrset_cache_insert`. Tests:
    `crates/dedens-resolver/tests/rrset_cache.rs`.
  - Rejected: a second S3-FIFO in the resolver (two evictions to keep right); moka or another cache crate (a
    dependency for what the store does, and no byte budget of our making); `dedens_dnssec::RrSet` as the value (its
    `Vec`s' capacity is not the bytes the budget sees, and it would make the cache depend on the validator); the
    RFC's three-way tie (glue would replace an authoritative additional section); zone-data ranks (no zones); a
    public `Rank::of(section, authoritative)` (an answer's section and AA do not rank it alone).
- D194 (builds on D116, D193) The recursive resolver's infra cache, `dedens_resolver::InfraCache` (recursive
  step 07): what the resolver knows of each authoritative server, and which one to ask next.
  - Per server address (IP and port): the round-trip time smoothed per RFC 6298 §2 (SRTT, RTTVAR, RTO = SRTT +
    4 RTTVAR, in ms), the timeouts in a row, the time of its next probe and its marks (`Marks`): EDNS
    (`Edns::Unknown`, `Supported`, `Unsupported { rejected, answered }` with the rcodes D190's carry), no `0x20`
    echo, TCP needed (BADCOOKIE twice over UDP: a truncation alone marks nothing, D190). Per address and zone
    (lowered, RFC 4343): lameness, with its own expiry. Unbound keys everything by (address, zone)
    (`services/cache/infra.c` `infra_lookup_nottl`); a server's time and marks are its own, so they are kept once whatever zones it serves, and
    only lameness, which is per zone (RFC 4697 §2.2.1), is keyed by zone. Cookies stay in the transport's jar
    (recursive step 03, per source and server, RFC 7873 §4.1), not here.
  - Numbers, each an associated constant of `InfraCache`, against Unbound (and BIND where it differs):
    `UNKNOWN_TIMEOUT` 376 ms, Unbound's `UNKNOWN_SERVER_NICENESS` (`iterator/iterator.c`, RFC 6298 §2.1 says 1 s);
    `MIN_TIMEOUT` 50 ms, Unbound's `RTT_MIN_TIMEOUT` (`util/rtt.c`, RFC 6298 §2.4 says 1 s: a DNS answer is no TCP
    segment); `MAX_TIMEOUT` 120 s, Unbound's `RTT_MAX_TIMEOUT` (`util/rtt.c`) and RFC 6298 §2.5's 60 s or more;
    `BAND` 400 ms, Unbound's `RTT_BAND` (`iterator/iterator.h`); `TIMEOUT_LIMIT` 3 timeouts in a row, Unbound's
    `TIMEOUT_COUNT_MAX` (`services/cache/infra.h`) and BIND's `MAX_EDNS0_TIMEOUTS` (`lib/dns/resolver.c`);
    `SERVER_TTL` 900 s, Unbound's `infra-host-ttl` (`util/config_file.c`), BIND keeps an entry 60 s past its last use
    (`lib/dns/adb.c` `dns_adb_entrywindow`); `LAME_TTL` 1800 s, RFC 4697 §2.2.1's 30 minutes or more, Unbound 900 s
    (lameness lives with its host entry), BIND none (`lame-ttl` defaults to 0, the lame cache off).
  - Times: an answer sets the estimate (§2.2 the first, §2.3 the next); a timeout of a query sent with a timeout no
    less than the server's RTO doubles that timeout, at most `MAX_TIMEOUT` (§5.5, Unbound's `rtt_lost`), so queries
    in flight together back off once, and so does a timeout on an entry made anew since its query left (expired or
    evicted: Unbound's `infra_rtt_update` takes the timeout sent); the first answer after `TIMEOUT_LIMIT` timeouts starts the estimate anew
    (§5.7). BIND smooths 7/10 old and 3/10 new (`adb.c` `adjustsrtt`), unknown servers first by a random 1-31 µs:
    RFC 6298 gives the timeout too, which BIND takes elsewhere (800 ms, then backed off).
  - Choice, `select(servers, zone, remaining, now, rng)`: servers skipped (`TIMEOUT_LIMIT` timeouts in a row, until
    their probe time, now + their RTO rounded up to the second) and servers lame for the zone (unless every one left
    is, RFC 4697 §2.2.1) set aside, one is drawn at random (`CryptoRng`, RFC 5452 §4.4: the fastest alone is
    predictable) among those whose RTO is within `BAND` of the least; an unknown server's 376 ms puts it in the band
    of any server under 776 ms, so it is tried. None left: `None`, the iterator's failure. The timeout is the
    server's RTO, at most `remaining` (the resolution's time left, under D45's client timer). Unbound skips a server
    only once its RTO reaches `PROBE_MAXRTO` 12 s (`util/config_file.h`) and its probe delay is `(rto + 1999) / 1000`
    s; counting timeouts in a row skips a dead server at its third timeout, 3 s in from unknown. Unbound counts
    timeouts per query type (A, AAAA, other); one count here.
  - Marks, the transport's quirks (recursive step 03) as the resolver's own type, the recurse stage (step 08)
    turning one into the other, are merged into the entry, never cleared by a later answer: `Supported` is not
    downgraded by `Unsupported` (one answer without OPT proves nothing, RFC 6891 §7, Unbound's `infra_edns_update`), `Unknown`
    keeps what is held, no `0x20` and TCP stay set. They go with the entry: `SERVER_TTL` runs from its creation, not
    its last use, so a server fixed is asked plainly again within 15 minutes; the entry of a server backed off to
    `MAX_TIMEOUT`, renewed, keeps its times and probe, as Unbound's `infra_host` keeps them from
    `USEFUL_SERVER_TOP_TIMEOUT` (its `RTT_MAX_TIMEOUT`, 120 s) up. One backed off less is heard anew: its timeout,
    out of the band of a faster server, would leave it out for good, no query to it ever bringing it back.
  - Sizing (D116): one `dedens_cache::Store<Entry>` (D193) for both kinds of entry, a server's 20-byte key (kind,
    family, 16 address bytes, port) and a lame entry's with the zone's wire form, changed by `Store::upsert`;
    `Entry`'s `Cost` is 0, all of it inline in the slot. `new(capacity, shards)`; a server takes 260 bytes, slot
    and key, so `DEFAULT_CAPACITY` 4 MiB holds about 16,000 servers (measured: 16,128 once full, 64 shards),
    Unbound's default 10,000 hosts (`infra-cache-numhosts`); a test holds 10,000 in it.
  - Counters (feature `metrics`, D30): `dedens_resolver_infra_selections_total{outcome=chosen|none}`,
    `dedens_resolver_infra_evictions_total`. Tests: `crates/dedens-resolver/tests/infra_cache.rs`.
  - Rejected: Unbound's (address, zone) key for times and marks (a server is as slow for one zone as another, and
    13 root servers times every TLD would fill it); BIND's random initial time (no timeout from it); the fastest server
    always (RFC 5452 §4.4); a `480 s` blacklist, which Unbound's `BLACKLIST_PENALTY` is not: 480,000 ms added to a
    server's RTT for one query (`iterator/iterator.c`), the iterator's (step 04) to apply.
    Open: times per (address, zone) if a server is measured slow for one zone only (TODECIDE).
- D195 (amended by D197, D199, D200, D201; builds on D41, D86, D117, D190, D191, D193, D194) The recurse stage (recursive step 08): `dedensd` resolves
  from the root, `Stage::Recurse` behind the cache stage where a forwarder has a forward stage.
  - Shape: `dedens_server::Recurse` holds the resolver's caches (`Arc<Caches>`: RRsets D193, servers D194, the root
    and TLD hints D126), `Limits` (D191), the locally served zones and the client budget. Sans-IO as the rest of the
    pipeline: a miss returns `Step::Resolve(Box<Resolving>)`, which the driver steps (`Resolving::step(now, rng)`,
    `Turn::Send(&Query)` or `Turn::Done`), sending each query with D190's authoritative mode and handing back the
    reply, then `Pipeline::resolved` writes the client's reply through the forward path's `Finish`: stored in the
    cache stage, a failure held (D43) with stale data served if any, SERVFAIL with D191's EDE (22, 23, 0) else.
    The resolution takes the driver's clock (a `Duration`) and randomness at each step, which `Pipeline::query`
    (seconds, no randomness) has not: so the step returns and the driver resolves, as it forwards. One query of a
    resolution is in flight at a time (D191); `dedensd` draws a fresh `Entropy` (D190) for each step, and ends the
    resolution, its query unsent and withdrawn, when a step drew more than it holds (`Entropy::finish`: zeros past
    it).
  - Replies: RD clear REFUSED with EDE 20 and ANY over UDP truncated (RFC 8482), as the forward stage; a type or
    class the resolver does not ask (RRSIG, meta types; not IN) NOTIMP and REFUSED. The answer is built from
    `Resolved`: chain and data in the answer section, the SOA in the authority section of NXDOMAIN and NODATA, the
    RRSIGs when the client set DO, each TTL bounded once: one fresh from a reply by the response cache's `lifetime`
    (D124: `min_ttl`, `max_ttl`, the insecure and bogus caps) of the cache stage before, so the cache and the reply
    agree, the RRset cache reading under the same `Config`; one from the RRset cache is its time left, bounded when
    stored, never raised again to `min_ttl` (a record served past its owner's TTL plus the floor). The cache stage
    stores the reply as it is (`Cache::insert_bounded`: capped, not floored). A negative answer lives min(SOA TTL,
    SOA MINIMUM), not floored to `min_ttl` as a forwarded one is (D124), and MINIMUM 0 is not cached: Unbound's
    `cache-min-negative-ttl` and BIND's `min-ncache-ttl` default to 0. AA clear, RA set.
  - Priming (RFC 8109 §3): when a resolution starts and the root's NS RRset is not in the RRset cache, the stage
    hands the driver a priming resolution of `. NS` too, one at a time per stage (an atomic flag, cleared when the
    priming ends either way), its queries paid by no client; the RRset cache keeps the answer for its TTL, and the
    next resolution after its expiry primes again (§3.1); `dedensd` logs what the priming came to
    (`Resolving::resolved`), a warning when it got no answer. Meanwhile resolutions go on from the hints: D191 asks the
    TLD hints for a TLD's servers, the root hints for the rest, so no client waits for the priming (§3's choice).
    The hints are the bundled ones (D126) unless `root_hints` names a `named.root`-style file (D201: the root of a
    private network, the bench's; the TLD hints are then not used either). D128 refreshes the TLD list and the
    root's trust anchors into `state_dir`, not `named.root`, so the step file's "refreshed copy" is not built
    (TODECIDE).
  - Locally served zones, class IN's, answered by the stage with AA and no query (another class goes on to the
    resolution, which refuses it): RFC 6303 §4's reverse zones (the RFC 1918
    ranges, 0, 127, 169.254, the TEST-NETs, 255.255.255.255, `::`, `::1`, `fe80::/10`, `fd00::/8`, the IPv6
    documentation prefix), each an empty zone per §3 (`SOA @ nobody.invalid. 1 3600 1200 604800 10800`, `NS`
    itself, TTL 10800: SOA and NS at the apex, NODATA for other types, NXDOMAIN below); `home.arpa` the same (RFC
    8375 §4 4.B) but its DS with DO resolved, so the insecure delegation proves; `resolver.arpa` NODATA for every
    name (RFC 9462 §6.4: no designated resolver known); `localhost` the loopback addresses for A and AAAA, NODATA else,
    its DS too, as no query goes out for it (RFC 6761 §6.3 item 4); `invalid` NXDOMAIN (§6.4) with the empty zone's
    SOA to cache it by (RFC 2308 §5), as Unbound's static zone. `local_zones.resolve` lists apexes to resolve
    instead (RFC 6303 §3's switch per zone); an apex not in the list, or listed twice, is a load error. Unbound's
    defaults (`services/localzone.c` `local_zone_enter_defaults`) less `test` and `onion`, which D128's `tlds`
    stage answers.
  - Shared queries (RFC 5452 §5): one query in flight per (server address, question) per thread, Unbound's mesh per
    thread (`services/mesh.c` `mesh_new_client`), not D86's process-wide flights: a thread's resolutions wait on its
    own query, no lock between threads. At most `WAITERS` 100 resolutions wait on one, BIND's
    `max-clients-per-query` default, the bound its `clients-per-query` 10 grows to (`lib/dns/resolver.c`
    `dns_resolver_createfetch`), past which BIND drops the client; past them a resolution here is shed as D117's and
    D186's (`Resolving::shed`): nothing sent, its query's unit given back, nothing counted as sent, SERVFAIL with EDE
    14 (Not Ready), counted by `dedensd_recurse_shed_total`. Taking the query as not sent and asking the next server
    instead would turn a hot question into a hundred queries to its other servers. The waiters take the reply with
    `Resolution::receive_shared`, which leaves the infra cache alone: the sender's `receive` judged the server once,
    and a timeout shared by a hundred would back it off a hundred times. A local error is shared too (D190's
    `NoSocket` comes at the deadline: each waiter sending again after it would wait its own timeout in turn). A waiter
    waits for the reply until its resolution ends (`Query::left`, so `Limits::time` holds), not its own estimate of
    the server's timeout: learnt meanwhile, it may be shorter than the sender's, and each waiter timing out would
    send the query again (`just sim` showed it). Past its end it takes a timeout, judging no server. The sender, or
    a waiter sending after its sender was cancelled, waits `Query::timeout` from then, within its resolution's end.
    A timeout cut short by the sender's own end, over UDP or TCP (a query moved to TCP may have its `TCP_TIMEOUT`
    fall on that end), or one that came after an ICMP error (`ServerError::Unreachable` with a send made, which
    waited for the deadline as a timeout: `Outcome::Unreachable`, `Reply::Unreachable`; no route, `sends` 0, comes at
    once and stays a `ServerError`), is not the server's: it is not shared, the waiters sending again
    with their own time, and `Resolution` judges no server for a timeout that comes as the resolution's time runs
    out.
  - Client budget (D117): each query a resolution sends costs its client network one unit of the stage's
    `client_share` (default 1000/s, burst 2000, as the forward stage's); one refused ends it, SERVFAIL with EDE 14
    (Not Ready), as validation's shed. The rate limit's exempt networks pay nothing. A query shared is paid as one
    sent: the unit is taken when the step gives the query, before the flight is known, and kept, which errs on the
    side of the budget; only a shed resolution, which waits on nothing, and a query withdrawn unsent get it back
    (`Resolving::shed`, `Resolving::withdraw`). A reload with the same budget
    keeps the buckets, as validation's (D117): a reload is no fresh burst.
  - Configuration: `type: recurse` with `limits` (D191's), `local_zones.resolve`,
    `client_share`, `rrset_cache_bytes` (default 128 MiB, D193) and `infra_cache_bytes` (default 4 MiB, D194). A
    pipeline forwards or recurses: both are a load error naming the two stages; a stage after a recurse stage is one
    (it answers every query), as after a forward stage. A reload with the same cache settings keeps the caches; one
    serving other zones locally flushes the cache stage before, which holds what they resolved to or were served.
    Each limit has a ceiling, the highest BIND or Unbound allows or uses, or BIND's default where BIND sets no
    maximum, a load error naming it past it, so no setting lets one question cost what neither would by default:
    `queries` 200 (BIND's `max-query-count` default, the queries of a client question, validation's included),
    `restarts` 255 (BIND's `max-query-restarts` range), `referrals` 130 (Unbound's `MAX_REFERRAL_COUNT`,
    `iterator/iterator.h`), `depth` 7 (BIND's `max-recursion-depth` default), `servers` 100
    (BIND's `max-delegation-servers` range), `targets` 16 (Unbound's `MAX_DP_TARGET_COUNT`), `time_ms` 30,000 (a
    client gives up well before, and a resolution holds one of the thread's upstream queries, D47, all along).
  - Descriptors: `dedensd` raises its soft `RLIMIT_NOFILE` to the hard limit at start, as BIND
    (`named_os_adjustnofile`) and Unbound (`checkrlimits`): a thread's authoritative mode holds up to 1056 sockets
    (D190). At start whatever the pipeline, since a reload may add a recurse stage. macOS refuses an unlimited soft
    limit, and one above `kern.maxfilesperproc`, with `EINVAL`, and its `setrlimit(2)` asks for `min(OPEN_MAX,
    hard)` instead: refused, the soft limit is raised to that, `OPEN_MAX` 10240, or kept where it is above already
    (`launchctl limit maxfiles`). The limit obtained is logged.
  - Metrics:
    `dedens_resolver_queries_total{outcome=answer|lame|unusable|undecodable|timeout|tcp_timeout|server_error|
    local_error}` (a shared reply counted once; `tcp_timeout` a query moved to TCP, D197);
    `dedensd_recurse_errors_total{error=no_socket|tcp_busy|ports_exhausted|local|forged|unreachable|tcp}`, D190's
    errors (`ports_exhausted` the bind's `AddrInUse`, `unreachable` the ICMP);
    `dedensd_recurse_shed_total`; gauges `dedensd_recurse_{rrset,infra}_cache_{entries,bytes}`, set by a
    resolution at most once a second of a thread's clock (reading them locks every shard of both caches: a sweep
    after each resolution cost 6% of a miss's user CPU, D201); D191's `dedens_resolver_limits_total{limit}`.
  - Left to later steps or open: no prefetch nor stale refresh with a recurse stage (the cache stage's refresh
    finds no forward stage and only replies), and `prewarm` needs a forward stage (TODECIDE); validation (step 10) is D197's, QNAME
    minimisation D198's, negative caching D199's; D199 adds the `aggressive_nsec` setting (default true).
  - Tests: `crates/dedens-server/tests/recurse.rs` (each capture of `testdata/recursion` through the pipeline, the
    cache stage answering it again; TTL bounds; DO; priming; the local zones; the budget),
    `crates/dedens-sim/tests/recurse.rs` (`dedensd`'s loop on the captured servers' simulated Internet: priming
    once, 100 identical questions sending each query once, and past the waiters on a silent server one query sent,
    one resolution shed, each reply within `Limits::time`), `apps/dedensd/tests/recurse.rs` (the local zones from
    the process only, where the step file asked for a capture resolved from the process: a process cannot reach the
    captured servers' addresses, so the capture is resolved in the simulation), the config tests in
    `apps/dedensd/src/config/recurse.rs`, the shared queries' unit tests in `apps/dedensd/src/serve/recurse.rs`
    (`asked`, a send given: the outcome handed over, a local error too, a waiter's wait past its own timeout and
    until its end, a timeout cut short not shared, the shed; `hand`: what was sent judges the server, what was
    shared does not, a shed ends), the shared reply and the timeout cut short in
    `crates/dedens-resolver/tests/iteration.rs`. The `serve_query` fuzz target answers through a recurse stage, its
    input every server's response.
  - Rejected: the resolution inside `Upstream` (its forward accessors would mean nothing for it); stepping it in
    `Pipeline::query` (no clock nor randomness there); D86's process-wide flights (a lock across threads); waiters
    without bound (one slow server holding every client).
- D197 (amends D188, D190, D191, D195; builds on D73, D75, D77, D86, D93, D114, D117, D128, D186, D193)
  DNSSEC validation in the recursive resolver (recursive step 10): the resolution judges its answer (RFC 4035 §5), each question of the
  validator iterated by the resolution itself.
  - Shape: `Resolution::validated(Validator, unix)`. When the client question ends `Answer`, `NoData` or
    `NxDomain`, `Resolved::message(question, true)` rebuilds the response (chain, data, SOA, and the `denials` the
    scrubber kept: NSEC, NSEC3 and their RRSIGs, now in `Resolved`) and `Validator::start` judges it; each
    `Next::Ask` (a DS or a DNSKEY) becomes the resolution's next question, iterated as the client's: same caches,
    servers, `restarts`, `referrals` and `time`, a DS asked of the parent (D191), a DNSKEY of the zone. Its outcome
    is handed back as a message (`answer(None)` for a failure: indeterminate). One state machine, one set of limits,
    sans-IO as D191; the server drives a validated resolution as any other.
  - Outcomes already judged are not judged again: every RRset `Secure` in the `RRset` cache gives a secure answer,
    `Secure` or `Insecure` an insecure one, any `Bogus` a bogus one, and one `Unchecked` (glue, a resolution without
    the validator, a referral's NS) has the whole answer validated. So an answer made of unsigned glue or additional
    data, or cached by a resolution that did not validate, is never taken for secure. A wildcard expansion (an RRSIG
    of fewer labels than its owner, every RRSIG's, RFC 4035 §5.3.4, `Rrset::expanded`: one junk signature does not
    make one) is not taken from the cache unless judged
    insecure or bogus: the cache holds no proof of it, so the authorities are asked (`docs/TODECIDE.md`). Without a
    validator (CD) a secure one is served unchecked, without AD, its proof missing.
  - Verdicts, each RRset's own (`Validation::verdict_of`, Unbound's `val_verify_rrset_entry` and
    `rrset_update_sec_status`): an answer's parts may be of other zones, so a CNAME from an unsigned or a bogus zone
    does not make its signed target insecure or bogus in the cache. A verdict is of the data judged, not of its
    owner and type (the scrubber may keep two sets of one owner and type, in the answer and the authority). The
    DS and DNSKEY sets the walk checked have theirs too (Unbound's `chain_blacklist`), and the sets the validator's
    questions fetched are written back as the answer's: a bogus key set is held for the bogus TTL, not its own.
    Each RRset, NSEC and NSEC3 (owned within the zone they prove for) included, is re-inserted with its verdict
    (D193's merge: the same data held unchecked takes it) and the time it has left: `Secure { ttl }`
    `Checked::Secure` capped to `ttl` (`Rrset::cap_ttl`: the signatures' validity, RFC 4035 §5.3.3), `Insecure`
    capped by D93, `Bogus` for the bogus TTL (D124). One without a verdict of its own (after a bogus one, or a
    CNAME a DNAME synthesized) stays as held. The answer served takes the response's verdict:
    `Bogus { ede }` fails `Failure::Bogus(code)`; `Indeterminate` and the verdicts a final answer cannot give
    (`Incomplete`, `Referral`) fail `Failure::Indeterminate(code)`. Both failures carry the validator's EDE (RFC
    8914 §4, D77). A CNAME synthesized from a DNAME is not cached at all (RFC 6672 §3.4 lets its TTL be 0): it is
    the DNAME's to give, and not signed.
  - A bogus answer is asked again of other servers, as Unbound's `val_blacklist`: each answer records the sets its
    response gave; the servers that gave a set bogus by itself, a DS, DNSKEY or denial the validator fetched first
    (what is below a bogus key set is bogus through it), else one of the answer (all that answered the client's
    question, not those that referred it, when none is), are left out of the delegation of the zone they were
    asked as servers of (a server of two zones still serves the other), the client's question asked anew, what the
    cache holds bogus not taken, at most 5 times (Unbound's `VAL_MAX_RESTART_COUNT`), its queries counted in
    `limits.validation` and the time in `time`. A bogus set no server gave came from the cache: held unchecked, it
    is asked again all the same, the cache passed over (Unbound's `val_blacklist` of an unknown origin); held bogus,
    it is the cache's settled verdict until it expires (RFC 4035 §4.7), not asked again, as Unbound's bad key
    cached leaves no restart. A set the validator fetched is written bogus before a retry, not only when none
    follows as Unbound's `key_cache_insert` waits on `val_can_restart`: the last attempt may fetch nothing (its
    servers shunned) and leave the set unchecked, to be fetched by the next resolution; a retry that does better
    writes the good set over it, and a resolution beside one still retrying takes the bogus verdict meanwhile. A
    spoofed or garbled response from one server, of the answer or of a key set, then does not make the answer bogus
    while another serves it right. The validations of the retries share one D75 budget, as Unbound keeps
    `num_validation_attempts` across `val_restart` (`Validator::restart`, the cost told cumulative), and its
    questions: a deep chain, whose walks ask more, gets fewer retries. None follows one that gave up on KeyTrap's
    failed signatures or spent the budget (signature verifications, NSEC3 hash blocks, as Unbound's
    `val_hash_attempts`) or the questions (`Validation::can_restart`). Out of servers, retries, budget or a bound,
    the answer is bogus with the first code. D86's key cache never holds a bogus key set: the
    `RRset` cache holds it, for the bogus TTL.
  - YXDOMAIN is judged as an answer: bogus unless the chain ends in a DNAME whose substitution makes a name longer
    than 255 bytes (RFC 6672 §2.2, `Chain::overflow`), that DNAME validated. RRSIG questions stay NOTIMP
    (D195); a query with CD, or not class IN, is resolved without the validator (RFC 4035 §3.2.2), and gets what the
    `RRset` cache holds as it is held: AD when every RRset is held secure (RFC 4035 §3.2.3, RFC 6840 §5.8), bogus
    data included (RFC 6840 §5.9), as Unbound. The reply follows the verdicts held (`Resolved::checked`), not
    whether the stage validates.
  - Bounds: `Limits::validation` 32, the queries all the validator's questions of one client question may send
    (`Limit::Validation`), beside `queries`, which counts the client's own: a validation needs about two per zone
    of the chain, and the client's 32 are not to be spent on it. Unbound gives each validator fetch its own
    `max-sent-count` within `MAX_GLOBAL_QUOTA` 200 (`iterator/iterator.h`): `limits.validation` is capped at 200
    too, and D195's "`queries`, validation's included" now reads: the client's queries. The validator's own
    bounds (D75: questions, depth, verification budget, KeyTrap's failed checks) hold as in a forward stage. A bound
    of the resolution reached while validating leaves the answer indeterminate: `Failure::Indeterminate` with EDE 5
    (DNSSEC Indeterminate, RFC 8914 §4.7), not the bound's EDE 22.
  - DS from the child (Unbound's `iter_ds_toolow` and `processDSNSFind`, `iterator/iter_utils.c`,
    `iterator/iterator.c`): a DS question answered NODATA with an SOA at or below the name was answered by the
    child (a server serving both sides): the NS of the name's parent are looked up (`Purpose::Cut`), then of its
    parent, up to the zone asked; an NS answer (not through a CNAME: an alias is no cut) or a referral for that name
    makes it the delegation the DS is asked of. Only a NODATA, an NXDOMAIN or a CNAME goes on up; a lookup that
    fails (no server answers, a bound) fails the DS question, which leaves the validation indeterminate, as
    `processDSNSFind`. Reaching the zone asked, the NODATA stands, as Unbound's: from the name's parent at once
    (`iter_dp_cangodown`). Each lookup is a sub-resolution under `depth` and the limits, one
    per label between the name and the zone asked, where Unbound stops at `MAX_DSNS_FIND_COUNT` 20: `queries`
    bounds them first.
  - With D198: each validator question and each cut's NS lookup is a task, minimised as the client's. D198's
    relaxed NXDOMAIN on a minimised name still asks the full name, where Unbound ends on a zone it expects signed:
    the full name's response is the one judged, its denial proven or bogus. D188's captures are a full-name
    iterator's, so the validation tests resolve with `Minimisation::Off`.
  - The recurse stage: `Recurse::validating(Validating)` as a forward stage (D77): AD on a secure answer (D114's
    `present`, signatures and denials cut to those that cover it), SERVFAIL with the EDE for a bogus one, no stale
    data in its place and no failure held (asked again, the `RRset` cache answers bogus without a query); an
    indeterminate one is a failure (D43). The allowance: a unit at the start (`admit`) of a question it resolves
    (one refused or not implemented costs none), then at each step what the validation grew by (questions,
    verifications, NSEC3 blocks, D106's `work`); past `per_query` indeterminate,
    the bucket in debt SERVFAIL with EDE 14, not parked (D186: a parked resolution would hold its state and
    queries; the client asks again). The share is the validation's (`DEFAULT_SHARE`, D117), the stage's
    `client_share` stays the queries'.
  - Configuration: a recurse stage takes `dnssec` (`validate` by default, where a forward stage's is `off`, D77:
    a resolver from the root is the one that tells a client what the Internet answers, as Unbound's and BIND's
    are by default, and has no upstream to leave the judgement to; `off` is written to leave it), `trust_anchors`
    and `insecure` as a forward stage (D77, D127, D128: the root's anchors from `state_dir`, fetched with `roots`
    on, bundled with it `off`, D200) and
    `limits.validation`. A reload validating the same way keeps the validator (its key cache, D86) and the caches;
    one validating otherwise flushes the `RRset` cache and the cache stage, which hold the old verdicts.
  - Deviations from the step file: no `start_referral` at each referral: the walk of the final answer asks the DS
    of every cut from the anchor down (D73's walk by labels, the key cache D86 keeping zones), so a stripped
    signature anywhere is bogus all the same, for one walk instead of two. The simulation's validated run (on
    D196's world) covers the captures of the tool's first run only, at its time: `dname` and `rrsig`, captured
    again a day on, hold zones signed anew whose signatures start after `example.com`'s end, and the world answers
    each question with the first response captured, so no one clock finds them all valid. The capture tool asks
    the DS of each label of the answer's owners below their zone, as the validator walks them (`dname`
    recaptured). The captures made for the validation's tests (`cname-to-signed`, `cname-signed`, `wildcard`,
    `wildcard-optout`) stay out of the `recursion` family: they took its time on GitHub's runners from 7.6 s to
    13.5 s and the crate past D133's budget, for shapes the iteration does not tell apart.
  - The default holds no test to the clock (D188): the captures' signatures end within days (`signed-com`'s, in 1 to 2
    days of its capture, the root's and the others' in 8 to 12; `just captures-expiry` says how many are left), so each test validating them
    runs at the capture's `captured_at` (the simulation's clock, `Validating::new`'s injected time), and `dedensd`'s
    tests on the real clock use a stage that validates nothing, `dnssec: off` written, or no capture at all.
    `just recapture-signed` makes them anew.
  - A query moved to TCP that times out there (`ServerError::TcpTimedOut`, `Reply::TcpTimeout`) has the next server
    asked, as a timeout, but leaves the server's timeout over UDP as it was, as Unbound's `serviced_tcp_callback`
    backs off only a query over TCP from the start: the server answered over UDP. A server whose TCP times out is
    asked again on each truncation (`docs/TODECIDE.md`).
  - Tests: `crates/dedens-resolver/tests/validation.rs` (every signed capture secure and cached so, every unsigned
    one insecure; a stripped signature, a changed DS, another zone's keys bogus; a KeyTrap-shaped DNSKEY set within
    the budget; a budget of one verification indeterminate; the validation's queries bounded, indeterminate; forged
    glue not the answer; an unvalidated cached answer validated; the DS from the child asked again of the parent,
    its cut lookup failing the question, and no cut sought for another type; a CNAME from an unsigned and from a
    bogus zone leaving its signed target's verdict its own; a wildcard expansion asked again, its proof kept; a
    forged YXDOMAIN bogus; a garbled answer from one server asked again of another, its retries within one budget,
    5 at most; a garbled DNSKEY asked again of another server, held bogus for the bogus TTL when all garble it; a
    server shunned in one zone only, one that referred not at all; a stripped answer cached unchecked fetched
    again; a junk RRSIG no expansion), `crates/dedens-dnssec/tests/validator.rs` (each RRset's own verdict, of its data,
    the walk's keys included, a denial owned outside its zone without one, the proof of a name beneath an insecure
    zone the zone's; a restart within what the validations before it left, none after KeyTrap's failed checks,
    by RRSIGs or DS digests; a YXDOMAIN without its DNAME bogus),
    `crates/dedens-resolver/tests/iteration.rs` and `crates/dedens-net/tests/authoritative.rs` (a TCP timeout
    leaving the server's timeout), `crates/dedens-server/tests/recurse.rs` (AD on each
    secure capture, from the cache stage
    too; bogus SERVFAIL EDE 10, asked again with no query; CD not validated, AD on data held secure, the bogus
    data held; the allowance's ends, a refused query counted shed; a validator question unanswered indeterminate;
    the validation's cost), the config tests in `apps/dedensd/src/config/recurse.rs` and `sources.rs` (the kept
    root anchors of a validating recurse stage), `crates/dedens-sim/tests/recursion.rs` (each capture of the first
    run resolved validated from the root by `dedensd`'s loop, AD as signed, within `queries` and `validation`).
  - Rejected: the validator beside the resolution in the server, each question a resolution of its own (two state
    machines, limits per question: a client question could cost 64 resolutions); Unbound's quota per validator
    fetch (64 questions of 32 queries); judging cached verdicts again (the signature memo, D86, makes it cheap, but
    the verdict is held already); stale data for a bogus answer (the data is what failed).
- D198 (amended by D199; builds on D191, D195) The recursive resolver minimises its questions (recursive step 11, RFC 9156),
  relaxed by default: privacy without the failures strict mode meets on servers that deny empty non-terminals.
  - Shape: `dedens_resolver::Minimisation { Off, Relaxed, Strict }`, the fifth argument of `Resolution::start`;
    `Recurse::with_minimisation` (default `Relaxed`); `dedensd`'s `recurse` stage `qname_minimisation: relaxed |
    strict | none` (the step's `off` is YAML's boolean false). Each name a task resolves (the client's, a server
    name looked up, a CNAME's target) is minimised on its own, from the root: the servers of a zone are asked the
    name one label below it, type A (§2.1, §3 step 3), the full question once that is the name. The QTYPE is the
    client's at the full name (a DS question asks its parent, one label short, so in full; §3 step 3).
  - Responses (§3 step 6) to a minimised question: a referral is followed (D191); an answer, a CNAME or NODATA show
    the name exists, and the next label is asked (6c), as does a CNAME chain to NXDOMAIN, whose chain would answer
    the client's name wrongly (Unbound reads the RCODE alone and takes it as a failure). Relaxed, NXDOMAIN (§1: servers deny empty non-terminals), REFUSED, SERVFAIL, FORMERR or an
    unusable response has the full name asked, as Unbound's `qname-minimisation-strict: no`; strict, NXDOMAIN ends the resolution (RFC 8020 §2) and any other
    failure goes to the next server, minimised. A server that responded usably may be asked the next question,
    and the one whose response turned minimisation off the full name, but for one that failed (REFUSED, SERVFAIL,
    unusable): it is asked the full name after the servers not asked yet, as a timed-out one is (D194), not at
    once. Unbound's relaxed mode too goes on to its next target.
  - Bounds (§2.3 MUST), Unbound's (`iterator/iterator.h`, `processQueryTargets`): `MINIMISE_COUNT` 10 questions per
    name, the 10th the full name; `ONE_LABEL` 4, the first questions one label longer each, the rest of a name of 10
    labels or more spread over the 6 left: 34 labels of `ip6.arpa` take 10 queries, not 34 (labels 1, 2, 3, 4, 9,
    14, 19, 24, 29, 34). Relaxed, `MINIMISE_TIMEOUTS` 3 timeouts in a row on one minimised question have the full
    name asked (`MAX_MINIMISE_TIMEOUT_COUNT`). The count restarts at a CNAME's target and at a delegation from the
    cache below the last question, as Unbound's `INIT` state. Every minimised query leaves through
    `Resolution::send`, so `Limits::queries` (32) and the time bound hold: a name adds at most 9 minimised
    questions, within the same bounds. The shared queries of D195 are keyed by the question sent, the
    minimised one: a resolution waiting on another's minimised query reads the reply against its own question.
  - Deviations from Unbound and from the step: relaxed NXDOMAIN asks the full name where Unbound ends on a name it
    expects signed (no validation yet, step 10); a minimised name answered from the cache is asked again where
    Unbound skips cached NOERROR, negative caching (D199) skips it for a NODATA cached by name and type, and RFC 8020's NXDOMAIN cut for a secure NXDOMAIN;
    no shortcut for underscore labels (§2.3 MAY); the full name's QTYPE is the client's where Unbound asks A first
    for other types; the step asked NXDOMAIN on a minimised name to end the resolution in every mode, which only
    strict does, the relaxed mode's point being the servers that deny empty non-terminals.
  - Test data: `testdata/recursion/minimised/` (`just capture-minimisation`, `examples/capture_minimisation.rs`)
    holds resolutions the resolver itself made, strict, one server pinned per zone and its draws seeded, so the
    replay sends the same questions: `ent` (`_xmpp-server._tcp.jabber.org SRV`, through the empty non-terminal
    `_tcp.jabber.org`) and `ip6` (a 34-label PTR). D188's captures are of a full-name iterator, so their tests
    resolve with `Minimisation::Off`.
  - Tests: `crates/dedens-resolver/tests/minimisation.rs`: each zone asked one label below it, type A; the 10
    questions of a long name and of §2.3's 18-label example; the queries bound reached by minimised questions; the
    empty non-terminal's response changed to NXDOMAIN (relaxed: the full name; strict: NXDOMAIN) and to REFUSED; 3
    timeouts; a minimised query shared with a resolution of the name it asks. The config tests in `apps/dedensd/src/config/recurse.rs`.
  - Rejected: strict by default (RFC 9156 §1 reports relaxed causes almost no failures, strict some); a bound per
    zone (the per-name count with `Limits::queries` bounds the whole); `Limits` fields for the counts (RFC 9156
    and Unbound fix them; nobody tunes them).
- D199 (amends D193, D195, D198; builds on D22, D74, D77, D124, D191, D197) The recursive resolver caches negative
  answers and resolution failures (recursive step 12): RFC 2308 §5, RFC 8020 §2, RFC 8198 §4-§5, RFC 9520 §3.2.
  - Entries. `Entry` of D193 gains two variants in the same `Store`, so the byte budget (D116) and the eviction
    stay one. `Absent`: the SOA and the denial records (NSEC, NSEC3) of one negative answer, their ranks, the
    verdict and the expiry, under a key of `0x80` (no wire name starts above 63), the name lowered, and the type
    asked for a NODATA, ANY for an NXDOMAIN. `Held`: a failure, under `0x81`, the name, the type and a server set.
    Neither key has a class, unlike an `RRset`'s: only IN is resolved, so a second class would need it in both.
    `KEY_LEN` is 1 + 255 + 2 + 8. A positive lookup ignores both; an entry over `entry_limit` is not cached; the
    cost is the `Rrset`s' (`tests/memory.rs`). A new entry replaces a held one that expired, that has a lesser verdict (secure over
    insecure over unchecked) or the same verdict and other data; one with a lesser verdict is dropped.
  - What is stored, when. The client's question only, when its resolution settles: a NODATA or an NXDOMAIN judged
    secure or insecure (D197), or, with no validator, unchecked. Never bogus, failed, without SOA (D192), YXDOMAIN
    or the answer to a lookup of the resolution's own (an address, a cut). The validator's own questions' negative
    answers (a DS's NODATA) are not stored: their verdict is the validator's end, and it reads no entry (to
    decide, TODECIDE). With a validator an unchecked entry is ignored. The name is the end of the CNAME chain
    (the chain itself is the cache's), so a chain's NXDOMAIN is cached under the last target.
  - TTL (RFC 2308 §5): the least of the SOA's TTL, its MINIMUM field and the sets' TTLs, as `Config::negative_lifetime`
    bounds it: `min_ttl` raised to for unchecked or insecure, none for secure, `max_negative_ttl` (3 hours,
    D124) at most, and `bogus_ttl` and `max_insecure_ttl` as for any set. An entry's sets are all served with the
    time it has left. Unbound: `max_negative_ttl` 1 hour by default, the same least of two (`dns_cache_store`).
  - Lookup (`Resolution::begin`, after the positive entry and a CNAME, before `closest`): the NODATA under (name,
    type), the NXDOMAIN under (name, ANY), RFC 8020 §2: the NXDOMAIN of an ancestor (not the root's), then RFC 8198:
    the spans. Every hit is logged at `debug!` and counted: `dedens_resolver_denials_total{source=exact |
    below_nxdomain | aggressive}`. The answer is the entry's SOA and denial records, with the chain the resolution
    held.
  - RFC 8020 §2: only a secure NXDOMAIN denies the names below it. Unbound's `harden-below-nxdomain` (default yes,
    `services/cache/dns.c`) does too, from the secure message only, not above the stub's or a forward zone's
    cut, and marks the synthesised answer unchecked so the validator runs again; here the entry's proof stays
    attached and is served as it was, not validated again, within its TTL. An insecure NXDOMAIN (an unsigned
    zone, or a signed one under an opt-out span) denies the one name: no proof says its server answers as RFC 8020
    asks, and a wrong cached NXDOMAIN would deny a whole subtree.
  - RFC 8198: `Spans`, an index kept by `RrsetCache::insert` for each secure NSEC or NSEC3 `RRset` whose signer is
    above its owner (the apex): per apex, the NSEC owners in canonical order (RFC 4034 §6.1) or the NSEC3 hashes
    (only a set whose signatures all have one signer, an extra one being a server's;
    one salt and iteration count, SHA-1 only, at most 150, as D74's `MaxIterations`; a zone whose parameters
    change starts again; an NSEC3 only when its owner is one label below the apex, RFC 5155 §3, so one at the
    apex of its signer, a child's, is not indexed under the hash its first label spells). It holds names only:
    `aggressive::synthesise` fetches the neighbours' `RRset`s, each fresh and secure, and the zone's SOA (secure),
    and hands them to `dedens_dnssec::denial::prove`, the validator's own proof (D74), for the name and type. A set counts only if every signature on it has the apex for signer (RFC
    6840 §4.1, as the index requires on insert): a `RRset` is keyed by owner, type and class, so a child zone's NSEC
    at its apex, or an NSEC3 of a child named like one of the parent's hashes, may have replaced the parent's
    record the index still names, and the child's span proves nothing for the parent's names. An NSEC or NSEC3 at the
    apex of its signer (a signature of it has the owner for signer, whoever else signed it) is kept under its own
    key (`0x82`), apart from the one of the same name that another zone signs (the parent's NSEC for a delegation,
    the parent's NSEC3 at the hash of a child's name), so neither evicts the other and a lookup of one of the two
    types prefers the apex's. Unbound's `PACKED_RRSET_NSEC_AT_APEX` (`validator/val_neg.c`) is set for an NSEC
    alone, from the data's SOA bit (`util/data/msgparse.c`), and it fetches an NSEC3 with no flag; dedens goes
    further for NSEC3, because anyone may register a name equal to a hash of the parent and sign an NSEC3 at it,
    the attack below, which the key closes for both types. Without it anyone could register `<hash of nl.>.nl`,
    sign an NSEC3 at its apex and ask for it: the answer is secure, replaces the TLD's record at the hash of its
    apex, which every closest encloser proof under it needs, and the proofs fail until the record is stored again
    (78 queries for a name under nl., measured, repeatable at will). The proof: the closest encloser and the wildcard are
    proved, §5.3 and §5.4. NXDOMAIN (not the compact form, which has no NXDOMAIN), NODATA and wildcard NODATA are
    synthesised. Not synthesised: a proof with the opt-out flag (an unsigned
    delegation may be there, RFC 5155 §6: an opt-out answer is insecure, so a captured one never enters the index, but
    a record inserted secure does, and the proof is refused: tested); a DS, ANY, RRSIG or NXNAME question; a name
    whose proof needs an NSEC3 hash beyond `NSEC3_BLOCKS` (2048 SHA-1 blocks a lookup, D77's idea); a wildcard
    that matches (§5.1: the cache does not synthesise the positive answer). The index's bytes (an estimate per name,
    `Owner` plus its wire length plus a node) are 1/32 of the cache's capacity (`SPANS_SHARE`), taken out of the
    store's, in shards by apex; over it, the zone of the shard used least recently goes whole (a lookup that finds
    the zone is a use, as Unbound's negative cache is an LRU, so a busy zone stays; the least recent is found by
    a scan of the shard's zones, once per eviction under its lock, which costs nothing at 1/32 of the capacity but
    is quadratic if one insert evicts many tiny zones). An owner or hash whose record the cache does not hold fresh,
    secure and signed by the apex any more (expired, evicted, replaced) is dropped when a lookup misses it: it would
    shadow its range until its zone went. The drop races a store of the record: the insert may find the owner still
    indexed (nothing to add), then the drop removes it, and the fresh record is not indexed until it is stored again,
    a miss and no more. A synthesised answer's TTL is the least of
    the sets', the SOA's MINIMUM included (§5.4).
  - Switch: `aggressive_nsec: true` by default in the `recurse` stage (`Recurse::aggressive_nsec`,
    `Resolution::aggressive_nsec`): it is the owner's choice (plan README, choice 5), RFC 8198 being a SHOULD,
    Unbound's `aggressive-nsec` being on by default as well. Off, only the exact entries and RFC 8020 act.
  - Unbound (`validator/val_neg.c`) differs: its negative cache (`neg_cache_size`, 1 MiB by default) is a separate
    store of names and the NSEC `RRset`s stay in the rrset cache, as here, but it reads NSEC3 for DS questions only
    ("no aggressive use of NSEC3 for now"), accepts an NSEC set that is unchecked with a signature, and
    synthesises the positive answer from a cached wildcard set. Here NSEC3 serves every type, only a secure set
    counts, a DS never uses a span (the opt-out insecure delegation of `neg_nsec3_proof_ds` needs the trust
    anchor's name, `topname`, which a cache has not), and a wildcard answer is not synthesised.
  - RFC 9520 §3.2: a resolution that ends `Unreachable`, `Network` or `Unusable` (every server of the delegation
    asked, nothing usable: `Heard::failure`) holds the failure under (name, type, server set): the zone and the first
    `Limits::servers` of its NS names (an `Rrset` sorts its RDATA: the same first names whatever the order they
    came in), hashed in any order with a keyed hash, the delegation the resolution would ask:
    the closest one with an address, and each cached one closer with none, which `closest` goes by and a lookup of
    the question would ask the parent about again (the zones of TsuNAME and NXNSAttack have no address). The next resolution of the same question to the same set ends at once with that failure,
    logged and counted (`dedens_resolver_failure_holds_total{outcome=recorded | served}`), until the hold expires.
    The hold is `failure_min` (5 s by default, 1 s at least, §3.2) and doubles for each failure after one expired,
    to `failure_max` (5 minutes at most, §3.2); a failure during a hold is not counted; a quiet spell longer than
    `failure_max` starts again (D43's schedule, one rule in two caches). `Limit`, `Bogus` and `Indeterminate` are
    not held, nor is a failure after a limit was reached (an address lookup's) or a bogus retry shunned the
    servers: a limit is the question's own, and a bogus answer is asked again of other servers (D197). Nor is a
    failure after an exchange failed on our side (`Reply::LocalError`: a send error, no sign of the servers failing;
    `Resolution::failed_here`, set in an address lookup too: the servers of a zone whose addresses were not found
    were never heard failing). An ICMP unreachable (`Reply::Unreachable`) may hold, as §3.2 allows: a spoofed one
    can make a resolver hold a set for up to `failure_max`, a cost the RFC accepts. A hold
    that would outlast `failure_max` (a clock gone back) is no hold, as in the response cache. The
    server set is part of the key so that a delegation that changed, or another name's servers, is asked. Unbound
    holds nothing per question: its infra cache backs each server off (D194) and `serve-expired` is another matter.
  - Rejected: a separate negative cache (a second budget; Unbound's); RFC 8020 from an insecure NXDOMAIN (Unbound
    does not either); validating the synthesised answer again (the proof is already secure and attached, a second
    validation spends the budget of D117 for the same verdict); synthesising from unchecked NSEC records
    (Unbound does: a record whose signature nobody checked proves nothing); the hold per server (D194's) or per
    name alone (a failing server set would be asked for each other type).
  - Tests: `crates/dedens-resolver/tests/negative.rs` (the captured NXDOMAIN of sidn.nl with NSEC, of nl with NSEC3,
    an opt-out zone's insecure answer, NODATA of signed and unsigned zones): an entry per name and type, the TTL
    bounds, a name below a secure NXDOMAIN not asked and below an insecure one asked, a second name in a span
    answered without a query (NSEC and NSEC3, any type, with the switch off asked, a name not covered asked), a
    failing set held, backing off to `failure_max`, not held for another type, a limit and a local send error not
    held; each guard of the index and the synthesis (secure only, the apex the one signer, opt-out, DS, the SOA's
    MINIMUM, a validating resolution reading no unchecked entry) with a test that fails without it, the real records
    moved to another zone's names where no capture has them (a child's NSEC, a changed chain or hash, an expired
    owner, a zone used while others come);
    `tests/memory.rs` with the spans and negative entries; `apps/dedensd/src/config/recurse.rs` the setting.
- D200 (amends D72, D73, D127, D128, D195) The recursive resolver follows the root's trust anchors through a key
  rollover by RFC 5011 (recursive step 13), from the root's DNSKEY `RRset` it asks itself; the signed download
  (D127, D128) seeds it. A server that missed a rollover's download (IANA unreachable, a file refused) follows
  the zone, the source the keys sign.
  - Shape: `dedens_dnssec::Rollover` (sans-IO, `anchor/rollover.rs`, beside `TrustAnchors` and the `rrsig`
    verification it needs; `dedens-roots` holds data, no crypto). Per key `KeyState { AddPend { until }, Valid,
    Missing { since }, Revoked { seen } }`; RFC 5011 §4's Start and Removed are a key not held, as Unbound drops
    them (`autr_cleanup_keys`). `Rollover::seed(anchors, records, now)` verifies the `RRset` with the anchors in
    use, DS or DNSKEY: the keys they name are Valid (Unbound's `key_matches_a_ds`; a DNSKEY anchor in its revoked
    form is a tombstone, not a key), other SEP keys AddPend.
    `observe(records, now)` applies revocations first, a REVOKE key signing the `RRset` itself (§2.1;
    `rrsig::verify_revocation`, the one check a revoked key passes, D73), of a Valid or Missing key only (an AddPend key
    whose plain form is gone is dropped, §4's KeyRem; Unbound's `do_revoked` revokes only VALID or MISSING keys), even
    when no trusted key signs the rest; then needs a Valid or Missing key's signature, else changes nothing more and
    errs. The table (§4): a new SEP key AddPend until now plus the larger of 30 days and the RRSIGs' original TTL, the
    lowest one so that a bogus signature beside them stretches nothing (§2.4.1), Valid when seen past it, dropped when
    unseen before; Valid unseen Missing, Missing seen Valid; Revoked kept for good, a tombstone (§2.4.2 lets a resolver
    forget it after 30 days, but a stale seed would trust it again: §2.1 and §4 make a revocation final). This
    deviates from Unbound, which moves a revoked key to REMOVED after the del-holddown and then neither writes nor keeps
    it (`autr_cleanup_keys`): it never reseeds while a state exists, and `reseed` here does, so a tombstone forgotten
    would be trusted again by a stale download. `reseed(anchors, records, now)` replaces the state by `seed`, the
    tombstones kept: a key held Revoked is trusted through no DNSKEY anchor, no DS, no answer.
    `without_revoked(anchors)` takes a tombstone's key out of other anchors. `anchors()` are the DNSKEYs of Valid
    and Missing keys, none when none.
  - Bounds (`Rollover` constants, compared with Unbound's `validator/autotrust.c` and BIND's `lib/dns/zone.c`):
    hold-downs 30 days (Unbound's defaults, BIND's `dns_zone_mkey_month`); `KEEP_MISSING` 366 days, a Missing key
    dropped past it while another is Valid (Unbound's `keep-missing`; BIND and RFC 5011 keep it forever); the
    wait between queries the verified TTL's half (the least of the `RRset`'s, original TTL and seconds to the
    signatures' end, D73) within an hour and 15 days (§2.3's floor, as Unbound's `set_tp_times` and BIND's
    `refresh_time`: the root's TTL of 2 days makes it a cached answer's or a signature's end drawing near that
    reaches it); an hour after a failure (§2.3's `retryTime` floor); the default verification budget per answer;
    the state text 64 KiB, which is read and written no longer (a longer one is not saved, warn!); 32 keys
    followed that are not revoked, missing ones included (RFC 5011 §2.4.3 expects a handful), a new key past it
    not followed, warn! once when it is reached; a new key is also not followed when the text would pass 64 KiB
    with every key held written revoked, its longest line, so that a state saved is always read again; 32
    tombstones besides, the oldest revocation forgotten past them, so that a key signing what it should not
    cannot fill the state. A key a DS anchor digests, which signs the `RRset` a state is seeded from, is followed
    past the bounds (the operator's anchors are few): a state that held none of the keys it verified with would
    be seeded with an `RRset` it cannot verify.
  - `dedensd`: a validating `recurse` stage without `trust_anchors` follows the root's keys. The state is
    `root-5011` in `state_dir`: `dedens rfc5011 1`, a line per key (state, time, DNSKEY), `end` last so that a
    file cut short does not read; written whole (D104) when it changed, kept by the leftover sweep, read at the
    first load. Its anchors win over D128's, downloaded or bundled, with a warn! when they disagree (once at each
    change of either, debug! at the reloads between): the state was proven from the zone, key by key, since a seed
    the download gave. No state (no file: only NotFound), or one whose content does not read (warn!; a corrupt
    text, not UTF-8, too long, no regular file or a symbolic link): D128's anchors serve and seed a new state from
    the next answer; the file is first renamed `root-5011.bad.<unix seconds>` (`.<n>` more in the same second, 16
    names at most, flushed to disk: an earlier one is the evidence of what went wrong first, never overwritten,
    never swept), for the operator, since the new state would overwrite its tombstones. A file that cannot be
    renamed (no free name, a directory not writable) is kept as it is, as the next case. A file the system fails
    to read (EACCES, EIO, no memory: it may be a good state), or of a version of `dedens rfc5011` this build does
    not know (a newer build's, run before a rollback: its tombstones are not this build's to discard; told by its header
    alone, a number above 1 of digits and no leading zero, whatever length or end follows), stays where it is, with a
    warn!: D128's anchors serve, a probe fails with `RETRY`, nothing is seeded or written, and the next use reads the
    file again. Until it does, the validators hold D128's anchors as they are, so a key the state holds revoked is
    trusted while it stays unreadable: the trade-off of serving anyway, where refusing to serve would fail every answer
    on the mode of a file. The first answer after the state reads again reloads them, filtered by it, also when a reload
    that read it failed later (a bad configuration keeps the old pipeline): the seed served stays noted until an answer
    takes it. A state whose keys are all revoked is kept, serving D128's anchors less the tombstones (warn!), also when
    D128's anchors predate the revocation: a validator never trusts nothing, where RFC 5011 §5 and Unbound
    (`autr_tp_remove`) make the zone insecure. A state no key of which signs an answer D128's anchors sign, offline past
    a whole rollover (RFC 5011 §6 leaves it to the operator), is replaced by those, the tombstones kept, with a warn!.
    Forward stages keep D128's anchors.
  - Operator: the state is the server's to write and the operator's to read, and to reset (a key lost to a mistake,
    a tombstone to forget): stop `dedensd`, delete `root-5011` (and the `root-5011.bad.*` once read) in `state_dir`,
    start it: D128's anchors seed a new state at the first answer, as a first start does, and the tombstones
    are forgotten: a key the download still lists is trusted again unless the zone publishes it revoked.
  - Queries: `Probe` in `reload::Current` holds the next query's time; the first serving thread past it takes it
    and resolves `. DNSKEY` through `Pipeline::root_keys` beside the query it serves, as priming (D195): no client,
    no validation (`Rollover` verifies), and the `RRset` cache may answer, its TTL bounding the age. The answer, its
    RRSIGs with it (empty when it failed), goes to the thread reloading, which observes it, saves the state, sets
    the next time and reloads (D55's last configuration) when the anchors trusted changed; a reload that fails
    (a file the configuration names that does not load now, or the downloaded lists) is tried again on the next
    tick (D104), the state being saved already; so is a SIGHUP's that fails after an answer queued with it changed
    the anchors (it is followed all the same), where a SIGHUP's that changed none waits for the next one. A server
    with no queries asks nothing; a start asks at the first query. A task that took the query and was dropped or
    panicked hands an empty answer (a guard, `Probe::take`), a failure asked again in an hour, not left unasked.
    `dedensd_root_key_probes_total{outcome}`: `followed`,
    `failed`.
  - Test data: `testdata/dnssec/rollover-*.zone` (`just capture-rollover`), the root's DNSKEY `RRset` and its
    RRSIGs from the Internet Archive's copies of `https://www.internic.net/domain/root.zone`, through the
    KSK-2010 to KSK-2017 rollover (2017 to 2019): KSK-2017 added, signing, KSK-2010 revoked (tag 19164) then gone.
    The KSK-2017 to KSK-2024 rollover has not revoked yet.
  - Tests: `crates/dedens-dnssec/tests/rfc5011.rs` (hold-downs, revocation, missing, an answer no trusted key
    signs, the state text, its prefixes and an unknown version), `apps/dedensd/src/rollover.rs` (seeding, a restart, a
    state that does not read, is a link, is of an unknown version, cannot be set aside or cannot be read, a revoked key
    never trusted again, also after the state read again, the query's time), the config test in
    `apps/dedensd/src/config/sources.rs`, the `. DNSKEY` resolution in `crates/dedens-server/tests/recurse.rs`; fuzz
    target `parse_5011_state`.
  - Rejected: the download winning (a file on a site; the zone is what RFC 5011 trusts, and a download missing
    the roll would keep a revoked key); following without the download (a start with no state would trust the
    bundled anchors alone, older than the download); a timer thread in `dedensd` (the serving threads own the
    I/O and the stage); Unbound's DS entries kept in the state (the seed's DS name keys that turn Valid at once);
    following forward stages' anchors (the upstream's answers, out of the step); non-root anchors (out of the step).
- D204 (amends D74; amended by D206, D207) Zones (`dedens-zone`, the authoritative phase's data): a `Zone` is what `Zone::load(origin, source, include,
  &Limits)` returns for zone text, checked, and it never changes: a change loads a new `Zone` and the server swaps
  it in whole (`Arc`, as D24's pipeline), so a query sees one version from start to end and a reload that fails
  leaves the served one. Loading does no I/O: `$INCLUDE` is a callback giving the bytes of a file (D25: the
  reader hands it back to the caller); the journal's file is D207's. Layout: a sorted `Vec` of names in canonical order (a `BTreeMap` first, D206) (`Name` orders so, RFC 4034 §6.1,
  moved from `denial`, which amends D74 where the order was private), each `Node` with its `RRset`s by type, RDATA
  already wire bytes, the RRSIGs apart by the type they cover, a `Kind` (authoritative, delegation point, occluded,
  empty non-terminal) and the wildcard and DNAME owner marks. Every ancestor of a name down to the apex is a node
  (RFC 4592 §2.2.2). An `RRset` has one TTL and its duplicates merged. A sequence and not a trie: answering needs a
  lookup and a predecessor in canonical order (NSEC), which a sorted sequence gives; D206 replaced the first
  layout, a `BTreeMap`, by a `Vec`, measured.
  - Errors, each with file, line and column (`ZoneReader::at`), all reported up to `Limits::errors`, the load
    refused: another class than the first record's (RFC 1035 §5.2), a record outside the zone (§5.2), RDATA its
    type refuses, no SOA at the apex, a second SOA or one below the apex, no NS at the apex (§5.2), a CNAME beside
    other data but RRSIG and NSEC (RFC 2181 §10.1), a second CNAME (§10.1) or DNAME (RFC 6672 §2.4) at a name, a
    CNAME and a DNAME at one (§2.4), a DNAME beside an NS below the apex (§2.3), text the reader refuses, an
    `$INCLUDE` the callback refuses.
  - Warnings, the load accepted: the TTLs of an `RRset` differ (RFC 2181 §5.2); a delegation's name server inside
    the delegation with no A or AAAA record at it (RFC 9471 §2: the glue is missing); names below a DNAME (RFC 6672
    §2.4: kept, occluded, never answered from), once per DNAME. Data below a delegation point is kept, occluded
    (RFC 1034 §4.2.1).
  - TTLs of an `RRset`: the lowest, with a warning. NSD warns and keeps the first (`zonec.c` `zonec_accept`, "TTL
    does not match the TTL of the RRset"), BIND warns and takes the prior one (`lib/dns/master.c`, "TTL set to
    prior TTL"), Knot warns and takes the last (`src/knot/zone/zonefile.c`, `node.c`); all three exempt RRSIG. The
    first and the last depend on the file's order; RFC 2181 §5.2 says to treat the set as the lowest.
  - Against the prior art: a DNAME's children are an error in Knot (`check_dname`), a warning here with the data
    kept occluded; Knot's glue check (`check_delegation`) is an error, here a warning, the glue being the parent's
    to give.
  - `Limits`, each a field with a reason and a test (`crates/dedens-zone/tests/limits.rs`): records 2^24, names 2^24
    (empty non-terminals count), records per `RRset` 100 and `RRset`s per name 100 (BIND's `max-records-per-type` and
    `max-types-per-name`; its `max-records` is unlimited), RDATA bytes 2^30, `$INCLUDE` depth 8 (Knot and BIND have
    no bound: a file that includes itself must end), errors reported 100.
  - Test data: the RFC example zones of `testdata/zones/` (RFC 1035 §5.3 with its `$INCLUDE`, RFC 4035 and RFC 5155
    appendix A), each refused in a broken variant by the check naming it. `every_type.zone`, the fuzzing seed, is not
    a zone for the loader: it holds records of the classes CH, HS and CLASS32 and a name outside the zone, so the
    tests show its refusals and load it with them made right. The root zone's capture is not loaded here (D207's tests load it). Fuzz target `load_zone`; bench `load_dedens` (`crates/dedens-bench/benches/zone.rs`).
  - Rejected: a `Zone` edited in place (a query would see half a change; a lock on the read path); the first or
    last TTL (the file's order would decide); an error for differing TTLs (BIND, NSD and Knot accept them); refusing
    data below a delegation (RFC 1035 §6.1 zones hold glue; a transfer carries occluded data); the checks as a pass
    over a finished `Zone` (the errors would lose their lines).

- D205 TSIG (RFC 8945, `dedens-tsig`): sans-I/O, in a crate of its own: the keys and the signing belong to the
  authoritative server (steps 09 to 15) and to `dedens` (transfers, updates), not to the wire format, and the crate
  adds `ring`'s HMAC, `subtle` and `zeroize` to what depends on it only. `dedens-proto` has what is the wire format:
  `RecordType::TKEY` and `TSIG`, `TsigError` (BADSIG 16, BADKEY 17, BADTIME 18, BADTRUNC 22: the TSIG error field is
  16 bits, apart from the 12 bits of an `Rcode`), `Tsig` (the RDATA) and `find_tsig` (the last record of the
  additional section, which a second TSIG, one anywhere else or bytes after it make an error). TSIG is a meta type
  (RFC 6895 §3.1): it has no text form, the reader refuses it, and `Message::decode` leaves it an opaque record.
  - Algorithms (`Algorithm`): `hmac-sha256`, `hmac-sha384`, `hmac-sha512`, and `hmac-sha1` for interoperability
    (RFC 8945 §6: the one implementation that cannot do better); no `hmac-md5`, which the RFC makes optional. A key
    names one algorithm, a TSIG that names another gets BADKEY (§5.2.1). Names compare without case (§4.3.3: the
    key's, the algorithm's), and the MAC takes the key's name in lowercase. A `Key` zeroes its secret when dropped
    and its `Debug` never shows it; the HMAC key `ring` derives from the secret for each message is not zeroed
    (`ring` has no way: a limit, not a leak through the crate's API). The base64 of a secret is decoded by
    `dedens-proto`, which has no `zeroize`: the bytes of a decode that fails half way are not wiped (`Key::new`
    wraps a successful decode at once). Secrets are base64 as `kdig -y` and Knot write them, empty ones refused. The key files and the read before the privilege drop are step 09's.
  - Server, `verify_request(&Keyring, wire, now)`, in RFC 8945 §5.2's order: a TSIG that does not parse, of a class
    other than ANY or with a TTL, or a MAC longer than the hash or shorter than the larger of 10 bytes and half of it
    (§5.2.2.1) is FORMERR, unsigned; an unknown key or algorithm is NOTAUTH with BADKEY, unsigned; a MAC that does
    not match is BADSIG, unsigned, compared in constant time (`subtle`); a time more than the fudge from the clock
    is BADTIME, signed, with the request's time and fudge and the server's time in Other Data (§5.2.3); only then
    the truncation policy. Each refusal says what to answer: `Refusal::Format`, or `NotAuth` which signs the answer
    in place (`sign`). A message with no TSIG gives `None`: whether to serve it is the server's policy (step 09).
    The unsigned answer carries the request's Time Signed and the server's fudge, whatever the clock: RFC 8945
    §5.3.2 gives neither, and Knot's `knot_tsig_add` writes the request's time. Knot answers the unsigned errors as
    this does, in its captures (`axfr-tsig-bad-secret`, tested with a clock that is not the request's, so that the
    bytes match only by the request's time), and BADTIME signed (`axfr-tsig-bad-time`); for an unknown key it sends
    NOTAUTH with no TSIG at all (`axfr-tsig-unknown-key`, and for a key not allowed by the ACL), which RFC 8945
    §5.2.1 does not say (it asks for BADKEY, unsigned): the server here follows the RFC, and a client takes both.
  - Truncation: a MAC shorter than the algorithm's full length that passes the length rule and matches its prefix
    is refused BADTRUNC, signed with the full MAC over the truncated request MAC (§5.2.4, §5.4.4: the digest takes
    the MAC as it came), with the request's fudge and the server's time. No configuration: Knot refuses every
    truncated MAC too (`knot_tsig_server_check`'s "MAC truncation isn't supported", as FORMERR); a client of this
    crate never truncates and refuses a server's truncated MAC. Rejected: accepting truncation (the policy is the receiver's, §5.2.4; a truncated MAC weakens the
    key and nothing in the captured exchanges uses one).
  - Time: `FUDGE` is 300 s on what the crate signs (§10 recommends it; Knot's `KNOT_TSIG_FUDGE_DEFAULT`); the
    check takes the sender's fudge, either side of the clock, edges included, and never moves the clock (§5.4.3). A
    time signed has 48 bits at most (`MAX_TIME_SIGNED`). `now` is a parameter, so the tests pin it (`captures`
    replays Knot's exchanges at their own times). Rejected for now: a cache of the last Time Signed of each key,
    which §5.2.3 recommends (a SHOULD) against a replay inside the fudge window. Knot and NSD have none, a verifier
    that keeps state belongs to the server that owns the keys, and a replayed AXFR or IXFR request is read-only. The
    request that matters is an UPDATE (step 14: `docs/TODECIDE.md`). The fudge a sender writes is not capped either:
    it is the sender's to choose (§5.2.3) and a large one only widens the window.
  - Responses: `Request::signer` gives a `ResponseSigner`, which signs every message of a response: the first over
    the request's MAC, the message and the variables (§5.3), the next ones over the MAC before and the message and
    the timers alone (§5.3.1); every message, as §5.3.1 requires (a client accepts unsigned ones, below). The
    message must have room for the record: the signer refuses (`SignError::TooLong`) a message that the record
    would take past 65535 bytes and does not shorten it; fitting a UDP response (§5.3: the answer cut, TC set, the
    question and the TSIG kept) is the serving stage's job, step 09.
  - Client: `sign_request` gives the `ResponseVerifier` of its response, and `ResponseVerifier::new` the one of a
    request signed elsewhere. `verify` takes each message of the response in order: the first must carry a TSIG
    (`Missing`), key and algorithm are the request's (`Key`), a MAC is full length (`MacSize`), the time is within
    the fudge (`BadTime`: no clock adjustment), and not earlier than the one before in the stream
    (`TimeDecreased`, as Knot's `prev_time_signed`). Unsigned messages between signed ones are accepted, up to
    `MAX_UNSIGNED` = 99 in a row (§5.3.1: a client MUST accept them); the next signed MAC covers them,
    so a changed one fails it, and `finish` refuses a stream whose last message is unsigned. An error from the server
    is `Refused` with its code and whether its MAC checked: an empty MAC (BADSIG, BADKEY from Knot) is not
    authenticated, a BADTIME or BADTRUNC verifies over the request's MAC. `verify` works on a copy of the digest and
    keeps the state of the stream only when the message passes: a refused message leaves the verifier as it was, so
    over UDP a forged answer does not stop the real one from verifying (the client keeps waiting), and over TCP the
    caller closes the connection and takes none of the stream as an answer. `Verified::Unsigned` says "not yet
    authenticated": a later signed message covers it. The caller still checks the ID and the question.
  - Tests: Knot's captures (D203: AXFR, IXFR, UPDATE signed; bad secret, unknown key, key not allowed, bad time):
    its requests verify, its responses verify, and ours, signed at its times, are its bytes; every bit of a signed
    request and response flipped, and only the ID and the case bits of the names stay valid (§4.3.2, §4.3.3); the
    algorithms against a second computation of the digest from RFC 8945 §4.3; a stream as long as the root AXFR's
    (82 messages) signed and verified, with a message dropped, repeated, swapped or changed, and with up to 99 unsigned
    messages; a real stream, Knot's signed AXFR of 1200 records of the root, five messages (`axfr-tsig-stream`),
    verified by the client and reproduced byte for byte by the signer at Knot's times, and refused with a message
    dropped or swapped; a received MAC under 10 bytes never matches (`matches`, §5.2.2.1's floor, whatever the
    prefix); fuzz target `tsig_verify`. No signed NOTIFY was captured (D203's NOTIFY recordings are unsigned): the
    request is a message like any other to sign (RFC 1996 §3.7), and step 11 tests it.
  - Rejected: TSIG in `dedens-proto` (its keys and clock are not the wire format's); MD5 (the RFC deprecates it, no
    interoperability need); `ring::hmac::verify` alone (it compares the whole tag: a truncated MAC needs the prefix
    compared in constant time); the system clock inside the crate (untestable, and the server owns its clock).

- D206 (amends D204) The answer of a zone (`dedens-zone`, the authoritative phase): `Zone::answer(&Question) -> Answer`
  is RFC 1034 §4.3.2 as a loop over the name asked, with RFC 4592 wildcards, RFC 6672 DNAME and RFC 9471 glue, no
  DNSSEC record (step 07 adds them from what the answer carries). The answer refers to the zone and copies nothing:
  a chain of links, then one end. A link is a CNAME followed or a DNAME with the CNAME synthesised from it (owner the
  name asked, the DNAME's TTL, RFC 6672 §3.1); the end is data (the `RRset` asked for, from a node or from the
  wildcard that gave it, with the closest encloser), no data, NXDOMAIN (with the closest encloser, which a proof
  needs), a referral (the cut), YXDOMAIN, a synthesised CNAME asked for, a chain that goes on out of the zone or past
  the bound (`End::Open`: the client asks again from there), or REFUSED (a name outside the zone, a class other than
  the zone's and not ANY, RFC 1035 §3.2.5). The step file's list of variants is this chain-and-end shape: a CNAME
  or DNAME is a link and not an outcome, so that a chain ending in a referral or in NXDOMAIN is one value; the call takes no
  `Limits` (those bound a load): the chain bound is `MAX_CHAIN`. `Answer::fill` writes the records into a `Message`
  borrowing the zone's names and RDATA (`Name::reborrow`, `WireRdata::reborrow`, no copy) and `Glue::encode` encodes
  it; no zone data is allocated for a query (the `Vec`s of the message are).
  - Algorithm: the name or its closest encloser, found with one bisection when the name is a node and at most two
    when it is not (`Zone::locate`), and one more for the wildcard of an absent name, whatever its depth. A node is
    found first: an authoritative one, or an empty non-terminal, answers at once, and an `Occluded` one carries the
    index of its cut, set by the loader (the outermost delegation or DNAME owner above it), so no walk finds the
    cut. A name that is no node ends the bisection where it would sort;
    every ancestor of a node is a node (D204), so its closest encloser is the ancestor it shares the most labels with
    the node before it (the apex, the first node, without a second bisection; the node before itself when it is the
    ancestor), and that node's kind says whether a cut is above the name: the cut of an `Occluded` node, or the node
    itself when a delegation or a DNAME owner. The cut is the outermost: the names below it answer as it does, a
    delegation a referral and a DNAME the synthesis (RFC 6672 §2.4: data below a DNAME is occluded). The time is
    that of a bisection of names of the length asked, 17 comparisons of up to 127 labels, with nothing allocated: a
    client picks the length, and a walk from the apex that looked up each ancestor of a name cost 120 bisections for
    120 labels, 490 µs (`docs/benchmarks.md`). A node that holds only NSEC3 records and has no node below it
    is no name (RFC 5155 §7.2.8: the server acts as if its owner did not exist; Knot keeps NSEC3 records in a tree
    of their own, so its main tree has none): the builder marks it (`Node::is_proof_only`), asked for it is absent,
    and as the closest encloser of a name below it, its parent takes its place, with no more bisection when the
    parent is the apex (the label count is one less) and one more otherwise
    (a name that is not there is no closest encloser, and no NSEC3 record could prove it as one, §7.2.1). The
    trigger is the query's shape, not the zone's: any client can ask `x.<hash>.<zone>.` of an NSEC3 zone, and with
    a wildcard at the apex the answer is its synthesis, as Knot's (NSD handles the exact name only, so differs
    below it; D203 takes Knot). One with a node below it exists, as an empty non-terminal: no data for any type, the
    NSEC3 records included, and no wildcard (RFC 4592 §2.2.1). A proof-only node is no wildcard source either.
    The marking is Knot's for an NSEC3 owner one label below the apex (RFC 5155 §3, §7.1), the only place a
    conforming zone puts one; the loader warns (`WarningKind::Nsec3Owner`) of any other. For a deeper owner dedens
    still differs: an empty non-terminal that exists only for it (`<hash>.a.b.` makes `a.b.` one, D204) answers
    NODATA here, and Knot, which has no such name, NXDOMAIN with another closest encloser. Marking proof-only
    the subtrees in the builder's reverse pass would close it (TODECIDE); no client can cause it, only the
    operator's zone. An existing name, an empty
    non-terminal included, answers itself: no wildcard (RFC 4592 §2.2.1), no data when the type is absent. An absent
    name: `*.<encloser>` answers if it exists (its owner is the name asked, the case as asked), else NXDOMAIN. A
    wildcard that is itself a delegation (`*.a NS`) refers, as Knot, but for DS (RFC 4592 §4.2 leaves it undefined,
    §4.2.1 discarding the notion of treating it as data: TODECIDE). DS at a delegation is answered from the parent
    side, the zone being the parent (RFC 4035 §3.1.4.1; Knot and NSD alike); another type there, ANY included, is a
    referral.
    AA is set but for a referral and a refusal (a chain that ends in a referral keeps it: RFC 6604 §2.1, AA is the
    first owner's, and Knot does the same). The meta types AXFR, IXFR, OPT, TSIG, MAILA and MAILB are asked of the
    zone as any type (AA, NODATA): the transfer and the OPT are the server's (steps 06 and 08), not the answer's.
  - Negative answers carry the SOA with the least of its TTL and MINIMUM (RFC 2308 §3, Knot's `SOAMINTTL`); a name
    that holds only NSEC3 records, with none below it, is absent (RFC 5155 §7.2.8; both servers answer NXDOMAIN, and
    no NSEC3 as data).
  - Chains: followed in the zone up to `MAX_CHAIN` = 11 links, then `Open`. Knot stops at 5 (`CNAME_CHAIN_MAX`), NSD at
    18 (`MAX_CNAME_CHAIN`); 11 is what the resolver accepts in a response (D192), so a dedens client never refuses
    what `dedensd` sends. A name met twice ends the chain (shown once, as Knot's duplicate check). Not followed for the
    types CNAME, RRSIG, NSEC and ANY (Knot); an alias asked below a DNAME is the synthesised one. A name made past 255
    bytes or 127 labels is YXDOMAIN with the DNAME in the answer and no SOA (RFC 6672 §2.2; Knot the same).
  - ANY: one `RRset`, the lowest type but NSEC3 (RFC 8482 §4.2), Knot's choice (D203 difference 3); NSD prefers A,
    AAAA and other small types. RRSIG asked: the signatures of the first type (D203 difference 4; step 07).
  - Additional section: the A and AAAA of in-zone NS, MX and SRV targets, in answers and referrals, the A
    before the AAAA; none for a CNAME target (RFC 2181 §10.3); no apex NS in the authority of a positive answer
    (D203 difference 1, Knot). Knot adds SVCB and HTTPS records too: left to TODECIDE. An answer's addresses come
    from authoritative nodes, then, as optional data, from glue below a delegation point, as Knot does: the root
    zone's `. NS` priming answer (RFC 8109 §3) carries the root servers' addresses, which sit below `net.`'s
    delegation. One lookup of the host decides: an authoritative node, a delegation point itself, or a node whose
    cut is a delegation (`Zone::address_node`) has its addresses given; one below a DNAME owner never (RFC 6672
    §2.4; Knot gives them, so `reference.rs` leaves them out of its side). An address at a delegation point is
    glue for it, as Knot gives it. It is never required, so no TC. A referral takes them by the same rule.
    The collection is bounded by what the response can hold: it stops between two hosts once the records taken
    (12 bytes at least each, and the RDATA) pass the limit `fill` is given, the requester's size or 65 535, so an
    `RRset` of 100 hosts of 200 addresses each costs a response's worth, 5 µs, and not 20 000 records, 3.5 ms; a
    host is looked at once however many records name it.
  - Referral (RFC 9471): NS in the authority, glue first for the servers inside the delegated domain (required), then
    the other servers' addresses in the zone, glue below another cut included (RFC 9471 §2.2; optional). TC is set
    only when required glue does not fit (§3.1: a response without in-domain glue is useless); optional glue is
    dropped whole by `encode_truncated` without TC, as Knot. NSD's cut of the additional section is compared by TC
    alone (D203 difference 7); its additional section is checked to be a subset of ours, since it adds less (no SVCB,
    apex NS hosts' addresses with the NS it adds).
  - Layout, amending D204: the nodes are a sorted `Vec`, searched by bisection, not a `BTreeMap`: the map's lookup
    with a name of the query's lifetime ties the node it returns to that lifetime, and the answer must keep it for the
    zone's. Cost (`lookup_*` in `benches/zone.rs`, 100 000-record zone, one name): 215 ns against 196 ns for the
    map, 10% more; a load of 63 ms and 47 MB is the same. The predecessor in canonical order is the previous index.
  - Test data: RFC 1034 §6.2 on the §6.1 root zone, RFC 4592 §2.2.1 and RFC 6672 §2.2, §6 examples
    (`crates/dedens-zone/tests/answer.rs`), and every answer captured from Knot and NSD for each zone of D203
    (`reference.rs`), by D203's rules: signed zones without DO (the proofs are step 07's), Knot's answer (NSD's
    for the ISI zone, which Knot refuses), the names of RDATA compared lowercase (both servers lower them; `Record`'s
    equality ignores case there, strings and the rest are exact), owners as asked (as stored for NSD). Fuzz target
    `zone_answer`; bench `answer_zone`, `reply_zone`, `reply_mx`, `reply_ptr`, `reply_root` (answers 0.25-1.3 µs,
    replies 0.3-1.3 µs on the 100 000-record zone; a root referral 5.7 µs, 15 allocations of the message's `Vec`s;
    names of 120 labels 6-12 µs and a DNAME chain that grows a name 65 µs, which were 490 µs and 23 µs with the
    walk from the apex and 370 µs and 3.5 ms searched from the name up; an MX of 100 hosts of 200 addresses 5 µs,
    which was 3.7 ms), and the proptest of `tests/lookup.rs` against the RFC's search label by label.
  - Rejected: following chains without bound (a loop is an infinite reply); Knot's 5 (a resolver of ours would
    take the chain for one it must ask again); every `RRset` for ANY (RFC 8482); TC for any glue that does not fit
    (resolvers would fall back to TCP for nothing, RFC 9471 §3.1); a wildcard for an empty non-terminal (RFC 4592
    §2.2.1); authoritative addresses only in an answer (the first choice of review round 1: the root's priming
    answer lost its servers' addresses, which RFC 8109 §3 has a resolver expect).

- D207 (amends D204) Zone differences and the journal (`dedens-zone`): a `Changeset` is the difference between two
  versions of a zone as RFC 1995 §4 sends it: the old and the new SOA record and the records removed and added, each
  with its owner, class, TTL and RDATA, RRSIGs as ordinary records. `Changeset::new` checks what the sequence needs:
  both ends SOA, one owner and class, the new serial ahead of the old by RFC 1982 §3.2, no SOA among the rest.
  `Zone::diff(&old, &new)` lists what changed: an `RRset` is compared as a set of RDATA (the order of a file is no
  difference, RFC 2181 §5), one whose TTL changed goes whole and comes again (an `RRset` has one TTL, §5.2), the
  rest as the records that differ, as Knot does (`diff_rrsets` in `src/knot/zone/zone-diff.c`: the records with no
  match removed, those with none added). `Zone::apply(&changeset, &Limits)` builds the next version through the
  `Builder` seeded with the old one, so every check of a load runs again, on the whole zone, and the `Zone` it
  returns is as if loaded: it refuses a changeset whose old SOA is not the zone's (`WrongVersion`) and a record to
  remove that is not there (`RemoveAbsent`, RFC 1995 §4), each with the changeset's record number as its line; a
  record is removed by owner, type and RDATA, its TTL ignored (RFC 1995 §4 sends the sender's TTL, which may not be
  the receiver's). The cost is a copy of the zone's nodes (D204: a version never changes; the copy is O(zone) per
  change, to be measured with the serving stage). A name is the same in another case (`Name` compares so), so a
  change of case alone is no difference. `Changeset::condense(next)` is RFC 1995 §6's net difference of two
  consecutive changesets: a record added by one and removed by the other cancels, as Knot's `changeset_merge`
  (`src/knot/updates/changesets.c`) does by adding the second's removals then its additions with its check; the
  result applied to a zone equals the two in turn. `Serial` (RFC 1982) is in `dedens-proto`: RRSIG validity
  (D73) and cookie timestamps (D113) use it in place of their own arithmetic.
  - The journal, `dedens_zone::journal::Journal`, is one file per zone, at a path the caller gives (its directory
    writable: a rewrite goes through the path with `.tmp` added). Append-only: an 8-byte header `dedensj1`, then
    a record per changeset, `length` (u32), `CRC-32` (u32, ISO-HDLC, of the length and the payload), the payload
    being the RFC 1995 §4 sequence in wire form (names uncompressed): old SOA, removed, new SOA, added. Each record
    starts from the serial the one before ends at, so the file is a chain, which `changes_since(serial)` walks:
    the changesets from a serial to the last version, none for the last, and `None` when the serial is older than
    the first, unknown or ahead, so that the caller sends the whole zone (RFC 1995 §4). The whole file is read into
    memory (bounded by the limits) when the journal is opened, and kept.
  - Durability: `append` writes the record and `fsync`s the file before it returns, and changes nothing in memory
    until then; the journal never reports a changeset done that a crash would lose. A crash in the middle of a
    write leaves a torn record (cut short, or its length past the end): `open` finds it, cuts the file there and
    syncs, and the changesets before it are kept. A bad CRC, a payload that is no changeset or a record that does
    not follow the one before ends the file there too, and everything after it is lost with it (a record after a
    hole is no use to an IXFR, and bytes after a bad one cannot be told from noise); the bytes cut are counted
    (`discarded`). A file with another header is refused and left, never overwritten; one over 2^30 bytes
    (`MAX_FILE`) is not read. Dropping the oldest changesets, clearing, and making the file write the kept ones to
    `<path>.tmp`, `fsync`, rename over the journal and `fsync` the directory: a crash leaves the old file or the new
    one, and a leftover `.tmp` is overwritten by the next rewrite. A write that fails poisons the journal
    (the file's state is unknown after a failed `fsync`): it refuses until it is opened again, which reads the file.
    The calls block: the caller runs them off the thread that serves queries. The crate does file I/O for the
    journal only; loading stays free of it (amends D204).
  - Limits (`JournalLimits`, a test each): 100 MiB of file and 20 changesets, the oldest dropped until the new one
    fits. Knot keeps both, `journal-max-usage` 100 MiB and `journal-max-depth` 20 (`src/knot/conf/schema.c`); NSD
    keeps `ixfr-size` 1 MiB and `ixfr-number` 5 (`IXFR_SIZE_DEFAULT`, `IXFR_NUMBER_DEFAULT` in `ixfr.h`) and drops
    the oldest until the new one fits (`zone_ixfr_make_space` in `ixfr.c`); BIND bounds the size only, twice the
    zone's by default, 4096 bytes at least (`max-journal-size`, `lib/dns/zone.c`, `DNS_JOURNAL_SIZE_MIN` in
    `lib/dns/include/dns/journal.h`). A changeset over a limit alone is not kept and empties the journal
    (`Stored::TooBig`, NSD's `ixfr_store_cancel`): its predecessors would end at a version that is not kept, and a
    client behind it is sent the zone. `MAX_FILE` 2^30 is the read bound, below BIND's `DNS_JOURNAL_SIZE_MAX`
    (`INT32_MAX`).
  - Against the prior art: BIND's journal rewrites a header in place and syncs twice per transaction
    (`dns_journal_commit`, `lib/dns/journal.c`); an append of one `fsync` and a self-checking record needs no header
    update, and a torn record is told by its CRC. Knot's journal is an LMDB database (`src/knot/journal/`, which
    also merges old changesets into a zone-in-journal); NSD writes one IXFR file per version (`ixfr.c`); neither is
    a file of one writer to link without a database or a second format.
  - Test data: the zone of RFC 4035 appendix A and small zones of `crates/dedens-zone/tests/util.rs`, each version
    the one before with a change written next to the test; the journal file as a crash leaves it, cut at every byte
    of its last record and flipped at every byte of each. `fuzz/seeds/example.journal` is a journal of three
    versions of the RFC 4035 zone, made again with `DEDENS_WRITE_SEED=1 cargo test -p dedens-zone fuzz_seed`. Fuzz
    target `journal_read` (reading, then writing again what was read). The root zone at two serials and the IXFR
    Knot 3.6.2 sent between them (D203, `tests/captures.rs`): Knot's changeset applied to the older zone gives the
    newer, the difference of the two zones is Knot's (the same records removed and added), and a journal of it
    reopened takes the older serial to the newer.
  - Rejected: a changeset applied in place (D204); a database for the journal (a dependency for a log that is
    written once and read whole); a header rewritten per append (BIND: two syncs, and a crash between them needs
    recovery logic); a CRC-less record with a length only (a flipped byte in a name would apply a wrong change); a
    record after a refused one kept (a hole breaks the chain); one `Changeset` per RRset (RFC 1995 §4's sequence is
    per version); keeping a changeset over the limit alone and dropping the rest (the oldest of a chain is what
    goes first, NSD).
