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
- D41 (amended by D43, D46, D77, D111, D114) Server core (`dedens-server`), sans-IO as D26: `Pipeline::query` takes the query's
  bytes and transport and returns a step: a reply in the caller's buffer, nothing, or a request for an upstream
  server whose response goes back through `Pipeline::receive`; `apps/dedensd` does the I/O. Before the stages the
  core answers what none should see: responses and bytes shorter than a header are dropped; FORMERR to a query it
  cannot read (the header alone, no OPT), that breaks a rule (D9) or has no question; NOTIMP to opcodes other than
  QUERY; BADVERS to EDNS versions above 0; REFUSED to AXFR and IXFR, and when no stage answers. A reply has the
  client's ID, opcode and question in its case; QR and RA set, RD and CD copied, AA clear, AD only for a query with
  AD or DO (RFC 6840 §5.8); our OPT (1232 bytes, DO copied) only when the query had one (RFC 6891 §6.1.1, §7),
  so a FORMERR to OPT records breaking a rule has ours too: several (§6.1.1), one outside the additional section or
  not owned by the root (§6.1.2), one with an invalid option (§7); with no OPT read, DO is clear and the payload
  512. An option overrunning its OPT record fails `Query::read`: the header-alone FORMERR has no OPT, short of §7.
  Over UDP it fits the client's payload, 512 to 1232 bytes, 512 without EDNS, truncated as D10; over TCP it comes
  whole. The forward stage asks its servers in order, the next on no response, one undecodable or breaking a rule,
  or TC. An upstream response is usable only with RCODE NOERROR, NXDOMAIN or YXDOMAIN (RFC 6672 §2.2). Any other
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
- D43 (amends D41; amended by D45, D46, D77, D114, D124) Cache stage (D22 in D41's pipeline): `Stage::Cache` looks the query up at `now`,
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
- D47 (amends D42; amended by D64, D90, D91, D113) `dedensd` limits, per thread (RFC 7766 §10, D42 had none): 1024 upstream queries in flight (past them a
  UDP query is dropped, a TCP one answered SERVFAIL), 256 TCP connections (past them a new one is closed at once);
  per connection, 64 queries in flight (reading waits; a bounded channel is the semaphore), 128 KiB of queued
  replies (reading waits), and 10 s for each write of the queued replies (a client that stops reading loses its
  connection; one that reads slower than it asks waits on the 128 KiB). A query waiting upstream holds no reply buffer until a reply is made. A QUIC
  Initial from an address not yet validated is answered with a Retry (RFC 9000 §8.1.2) and takes no connection
  slot, so forged sources cannot fill them; always on, at the cost of a round trip for a first connection (a
  client holding a token from an earlier one skips it). A QUIC connection (DoQ, HTTP/3) is a TCP one in these
  limits: no new stream within the idle time, whatever pings keep it alive, ends it once the queries asked are
  answered, and a reply not written within the write time is given up with its stream reset: a client granting
  no flow control credit keeps the connection for the write time past the idle time at most, and its slot only
  for the idle time. No per-address cap, for TCP either. Constants for now; configuration with need. Client
  allow and block lists come later (`docs/TODECIDE.md`); per-address caps are the deployment's (D90; UDP is limited per network by D113).
- D48 (amends D42; amended by D123) Several tasks answer on each UDP socket of a thread, so a receive does not wait while one
  answers: one task waited for its reply to go out before receiving again. Four at first; two since D123 queued the
  replies, which no task waits to see sent. `just bench-dnsperf` (Linux, io_uring, one
  core, cache hits) measures `dedensd` against a git ref: 1 task about 310k queries/s, 2 about 340k, 4 about
  415k, 8 and 16 no better. A TCP connection's writer writes the replies queued meanwhile together, up to 65535
  bytes: one write a reply held TCP to about 185k queries/s, batches reach about 1.8M (dnsperf pipelines 500
  queries). Copying each reply for the writer costs nothing measurable there (copying it twice did not move the
  numbers), so replies keep their copy and the writer task, which reads on while writing and keeps the replies
  of concurrent queries whole.
- D49 (amends D42) UDP queries arrive in buffers made once per thread (256 of 4096 bytes, compio's buffer pool): on Linux one
  io_uring multishot receive per socket fills them, and the socket's tasks (D48) take turns at its stream
  of datagrams behind a lock, each giving its buffer back before its reply waits to be sent. About 400k →
  480k queries/s (`just bench-dnsperf`); 16 tasks no better. A query longer than a buffer (about 3.9 KiB) is
  cut short and read as broken; the socket keeps datagrams while every buffer is taken. Rejected: a receive
  asked for each datagram into the task's own 64 KiB buffer (one submission and one buffer per receive).
- D50 (amends D27; amended by D108) Upstream UDP queries share a fixed pool of 256 sockets per server and client (`dedens-net::udp`), each opened
  on first use on port 0 and connected, then kept: a query takes one at random and waits for datagrams with its
  ID, which the socket's task receives for every query on it. An off-path attacker guesses the ID and the
  socket: 16 + 8 bits (RFC 5452 §9.2), against about 32 with a socket per query; cookies (RFC 7873) and `0x20`
  stay the way to win more. Matching stays D27's: a datagram goes to each query waiting for its ID (four kept for
  each, D108), and the exchange drops those of another question. A datagram is received whole, up to 65535 bytes, into
  one buffer per socket, whatever size the queries advertised. A socket error goes to the queries that sent on
  it, each counting it as a lost try, as does a send refused for an earlier datagram's ICMP error (another send
  error ends the exchange); errors in a row pause the socket's task 10 ms. Forwarding to a second `dedensd` (`just bench-dnsperf HEAD forward`): about 125k → 127k queries/s,
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
- D54 (amends D23; amended by D64, D110, D118, D120) Plugins (D23's custom stage types, for built-in stages too): `dedens_server::Plugin`, a trait object in
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
    its first name, TTL 3600 unless set (as `CoreDNS`); a listed name asked another type has no data (RFC 2308
    §2.2) unless `fallthrough` passes it on; addresses with a zone (`fe80::1%lo0`) are left out.
  - `blocklist`: names, one a line or in the `/etc/hosts` format of published lists, blocking themselves and
    their subdomains; `action` NXDOMAIN (default), NODATA, REFUSED or the unspecified address, each with EDE 15
    Blocked (RFC 8914 §4.16), AA clear. Of hosts lines only those of `0.0.0.0`, `::`, `127.0.0.1`, `::1` count,
    without names of one label or starting with `localhost`: such files open with their host's own entries
    (`127.0.0.1 localhost`, `127.0.0.1 local`), and blocking `local` would block all of mDNS's `.local`. A plain line
    of one label: D56.
    Any class asked (D110). Formats, duplicates and the allowlist in D56.
- D55 (amended by D64, D107, D122) `dedensd` reloads its configuration file on SIGHUP (systemd's `ExecReload=kill -HUP $MAINPID`): the file
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
- D104 (amends D57, D64; amended by D120, D122) List downloads, from the audit (S4, S15.a, S15.c, L13, L16):
  - Size: `ureq` is built without `gzip` (`default-features = false`, keeping `rustls` and `platform-verifier`) and
    asks for `Accept-Encoding: identity` (RFC 9110 §12.5.3: no header would let a server send gzip, which is no
    list). The 256 MiB cap counted the compressed bytes, so a gzip body of that size could inflate about a
    thousandfold in memory. Rejected: keeping gzip and capping the decoded body (`take(MAX + 1)` on the decoder).
    Gzip saves bandwidth only, about 4× on a list; without it a 36 MB list within the 30 s timeout needs about
    10 Mbit/s, and a bounded decoder is code to keep. Revisit if a list server needs it. `ureq`'s limit is
    exclusive: a body of exactly 256 MiB is refused.
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
- D65 (amends D42, D44; amended by D84) Each upstream server of a forward stage has its own transport, written as in the CLI (D60,
  D61): `IP[:PORT]` over the client's (UDP for a query over UDP, TCP for one over a connection), `tls://` over TLS
  and `quic://` over QUIC, port 853 unless set, `#NAME` for the name the certificate must hold, else the address
  (RFC 8310 §8.1). An address only: a host name would need resolving before `dedensd` can resolve. One stage
  can mix transports, the first server over TLS and the next plain. Upstream certificates are checked against
  the OS trust store, or the PEM file of a top-level `upstream_ca`, which a reload cannot change (each thread's
  `dedens_net::Client` holds it; changing it logs that it takes a restart). `dedens-server` only carries the
  transport and name (`Server`, `Via`), staying sans-IO. Rejected: transport settings per stage (`transport:
  tls`, `tls_name`), which cannot mix servers.
- D66 (amends D42, D44; amended by D115, D122) `dedensd` answers over TLS (RFC 7858) and QUIC (RFC 9250) on `listen` addresses behind
  `tls://` and `quic://`, port 853 unless set; with a top-level `tls: {certificate, key}` of PEM files, required
  with such an address and refused without one. A reload reads the files again and the next handshakes present
  the new certificate (`dedens_net::tls::Presented`, a rustls certificate resolver); a bad file fails the reload.
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
  TCP ones, idle time and write time D47's (no new request within the idle time, none being answered, ends it, pings or not), 64 request streams and 16 unidirectional ones (control and QPACK, D83) at once, the
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
    network (random `RandomState` key, as D22 and D58: an attacker cannot aim at a bucket). Memory never grows, whatever
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
    exemption from the limit. A bad length stays FORMERR (§5.2.2); a cookie and no question is a request for a cookie
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
    cookie; a limited query costs half a hit.
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
  - A runtime is never dropped (`ManuallyDrop` in the thread's closure, `main.rs`): dropping one on a thread that
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
    still hold 256 while it runs.
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
  - Tests: `the_debt_of_a_flood_stops_at_one_burst` and `the_bucket_is_in_debt_only_below_zero` in `budget.rs`,
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
    quotes, or sit between quotes of the template, and is escaped for them; elsewhere it is refused. A control
    character or line break is refused. `${VAR:-default}` text is the template's and stays as written. Rejected:
    quoting every value (breaks a number and a value inside the template's own quotes) and substituting in the
    parsed tree (loses the line numbers of errors and numbers' types).
  - Saved lists (D57, D104). A copy that does not exist yet is an empty list, so a blocklist fails open until the
    first fetch; a copy that is no list is warned about and left out. A copy that exists and cannot be read
    (permissions, a directory) refuses the start or the reload, as before: serving without the list would not mend
    when the next fetch runs. Now tested and documented.
  - `threads` (D42). Serving threads, 1 to 1024, fixed at start (a reload warns, as for `listen`). Default as before:
    one per core on Linux, one elsewhere; above 1 off Linux is refused, where `SO_REUSEPORT` spreads nothing and a
    second thread would serve no query. Each thread costs about 1 MiB of buffers, 64 KiB of scratch and a 4 MiB
    receive buffer per UDP socket, so fewer threads than cores serve a small host; 1024 stops a typo.
  - Tests: `a_key_readable_by_others_is_refused` (`tests/listeners.rs`: refused, kept on a reload, group warned),
    `a_long_key_file_is_refused_and_an_exposed_one_too` (`odoh/mod.rs`), `forward_patience_is_bounded`,
    `a_variable_cannot_inject_yaml`, `a_value_is_the_text_it_stands_for` (every text of up to three characters
    from an alphabet of YAML's syntax, in five templates: read back as that text or refused, which stands for a
    fuzz target, `dedensd` being a binary), `an_unreadable_saved_list_refuses_the_start`, `threads_are_bounded`,
    `threads_default_to_the_cores_on_linux` (`config/limits.rs`), `threads_set_the_serving_threads` (`tests/listeners.rs`).
    Test and bench key files are written 0600 (`util::write_key`). No hot path touched, no bench.
- D116 (amends D22, D44; amended by D118) The cache's memory, evictions and truncated hits (audit step 18; L12, E8, P1):
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
    a hold to refuse it). It was refused only when it was larger than a whole shard, so one 60 KiB response could
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
- D117 (amends D77, D79, D94, D106; builds on D91, D113) Client budgets, from the audit (S3, S14): what one client can
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
    have a bucket of their own and a flood from spoofed UDP sources of a network does not shed them.
  - Validation (S3). `Pipeline::query` passes the source (address, proven bit) and its `now` (the cache's clock,
    D43, monotonic; the validator keeps reading the wall clock for signatures) to `Validating::admit`, which takes
    one unit of the network's share, then one of the global allowance, and gives the first back if the second
    refuses. `Check::next` charges both with what the validation spent (D106) and sheds when either is in debt:
    SERVFAIL with EDE 14, nothing held, counted `verdict="shed_share"` for the share and `verdict="shed"` for
    the allowance. Cache hits, CD and classes other than IN cost neither, as before. A source on D113's
    `rrl.exempt` list has no share and still spends the allowance. `client_share: {rate, burst}` on the forward
    stage, default 1000 and 2000, a tenth of the allowance, so that ten networks at their share spend all of it
    and no one network can: 2000 units are about 160 cold validations (`docs/benchmarks.md`). A reload keeps the
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
    `serve_warm`, `serve_shed` (`crates/dedens-bench/benches/dnssec.rs`), `budget_admit`, `budget_refuse`,
    `budget_refuse_one_network`, `decrypt_query_message` (`crates/dedens-bench/benches/odoh.rs`).

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
    taken, D117: the response was read and reviewed), and the validated
    answer again, for the validator's chase may have lengthened the chain; a refused response is never stored,
    since only a validated one is stored there. A stage without validator: the response is reviewed before it is
    stored; a refused one is stored all the same, unmarked, and refused again on each hit, as the block answer
    itself is never cached (a block action may change at a reload, a response is the cache's only unit): not
    storing it would send each repeat upstream. Not stored when the refusing plugin is after the cache stage,
    which a hit does not ask.
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
    `a_validated_response_is_reviewed` (`dedens-server/tests/stages.rs`); fuzz `parse_lists` runs a chain of
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
    before `GOAWAY` are answered (the connection ends only once none is in flight), and dedens' client opens a new
    connection for the next query (`http3.rs`: a rejected or closed connection is set aside, not reused).
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
    errors stay start errors. Unwinding stays (no `panic = "abort"`).
  - Runtime or driver panic (`poll_with` on `EBADR`: completions lost): the process logs it and exits 1, for systemd or
    Kubernetes. A new runtime on the same sockets is rejected: D107 keeps the old ring, whose in-flight receives would
    take datagrams of sockets still in their `SO_REUSEPORT` group, a share of queries lost with no sign.
  - Open (`docs/TODECIDE.md`): a panic inside a compio-quic worker is hidden in compio's task; bare `spawn`s in
    `dedens-net`. Rejected: forking compio.
  - Tests: `serve/mod.rs` (65 queries panic on one connection, the 66th is answered; a listener panics and answers again;
    100 restarts under load, Linux), `serve/isolate.rs`. Cost: `hit_guarded` equals `hit` (0 allocations), `bench udp` within
    noise (`docs/benchmarks.md`); not measured on `io_uring`.

- D122 (amends D42, D44, D55, D66, D104, D107, D115) `dedensd` drops root once its sockets are bound, from the audit (S5): a
  server started as root to bind :53, :443 and :853 kept root while it parsed hostile input.
  - Configuration: top-level `user:` (a name or a numeric id, number or string) and `group:` (the same; only with
    `user`). Linux only: `PR_SET_NO_NEW_PRIVS` and the `/proc/PID/status` that the checks read are Linux's, and
    nothing else is tested; elsewhere either key is refused when the file is read, `validate` included. The target is
    resolved before any socket is bound, so a name that does not exist, a `user` or a group that is root, or a numeric
    uid with no passwd entry and no `group` ends the start at once.
  - Order (`src/privileges/mod.rs`, called from `src/main.rs`): after the sockets are bound and the keys, lists and
    certificates of the start are read, before the first thread starts (a second thread is refused: `NO_NEW_PRIVS` is
    inherited by the threads started after it): `initgroups` (the groups that list the user, plus `group`; none for
    a numeric id with no entry), `setgid`, `setuid`. Then the real, effective and saved ids are read back, no group
    is root, `setuid(0)` and `setgid(0)` must fail, `PR_SET_NO_NEW_PRIVS` is set and read back, and `CapPrm`,
    `CapEff` and `CapAmb` of `/proc/self/status` must be 0, or the start ends. The kernel clears them on `setuid`
    from root, `AmbientCapabilities=CAP_NET_BIND_SERVICE` included, the sockets being bound already.
  - Root without `user`: a warning, not a refusal (containers, development). Not root with `user`: refused, naming
    the uid, unless it is the user and the group already running (real, effective and saved ids all the same: a
    saved id of root is a way back and is refused): nothing is dropped, `NO_NEW_PRIVS` is set, the kept capabilities
    are logged.
  - Read again as the user: right after the drop the start reads the configuration, and the files it names, once
    more as the user; a file it cannot read ends the start with a message naming `user:`, not the first reload.
  - Reload (D55) runs as the user: the certificate and key (D66), the files of `blocklist` and `hosts` stages,
    `upstream_ca`, the saved downloads (D104) must be readable by it. The recommended key is `root:<group>` 0640 with
    `<group>` the user's group, which D115 accepts quietly (as PostgreSQL does a root-owned key: as the user, when it
    is in the group); others stay refused. A file it cannot read fails the reload, the old configuration keeps
    serving (D55, D115). A change of `user` or `group` at reload is warned and ignored, as `listen`: `Fixed` in
    `src/reload.rs`; it compares what is written, so `user: 990` for `user: dedens` warns too.
  - Downloads directory (D104): with `downloads.urls`, a missing `dir` is made before the drop (parents included,
    0755), its last directory given to the user by `lchown`; an existing one is never touched (a `dir` that names
    `/etc` must not be given away), and after the drop the user must be able to create a file in it, or the start ends
    with the `chown` to run. A `urls` added at reload needs a `dir` writable by the user already. Moving a server from
    root to `user`: `chown -R` its `/var/cache/dedensd`; the saved copies are 0666 less the umask (`UMask=0077`
    makes them root's alone).
  - io_uring (D107): the rings are made after the drop; with `kernel.io_uring_disabled=1` the user must be in
    `kernel.io_uring_group`, or the threads serve on `poll`, warned at start.
  - Rejected: dropping capabilities only (`CAP_NET_BIND_SERVICE` kept: uid 0 still owns and reads every file, and
    the `prctl` keep-caps sequence is more to get wrong than `setuid`); `chroot` (the process needs `/etc`, the
    certificates and the lists, and the reload must read the real ones; the unit's `ProtectSystem` does it without
    copies); refusing root without `user` (breaks containers); a privileged helper that passes the sockets (a second
    process; socket activation does it with no code: `docs/TODECIDE.md`); `user` off Linux (nothing there is tested).
  - Open (`docs/TODECIDE.md`): the systemd unit, and Kubernetes `securityContext`.
- D123 (amends D48, D51, D63; builds on D107, D121) Replies to UDP queries go through a queue and one sender a
  socket, the tasks answering on it drop from four to two, and the `io_uring` flags of D51 stay (audit P2, P12). Each
  of D48's tasks waited for its reply to go out before receiving again, so each reply cost its own `io_uring_enter`.
  Now `Outbox` (`serve/udp.rs`), made with the socket beside its supervised loop so a restart (D121) keeps it, takes the
  replies, made at once or after upstream, in a bounded queue (64, `flume`) that `send_replies`, one more future of
  the socket's task, sends from, up to 64 at once: the replies of one turn of the runtime go out in one submission.
  A task whose reply finds the queue full waits, so nothing grows. The reply buffers move with the replies (D63: a
  task's buffer is no longer owned by its send) and come back as spare ones, at most 64 of 1232 bytes: a socket
  holds at most 2 + 64 queued + 64 sending buffers, 130 × 1232 B ≈ 160 KB a thread, of which 79 KB stay after a
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
  - Tests: `serve/udp.rs` (`a_full_outbox_makes_the_next_reply_wait`, `queued_replies_are_all_sent_and_their_buffers_reused`,
    `a_failed_send_costs_only_its_reply`, `a_new_sender_sends_what_the_last_one_left_queued`).
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
