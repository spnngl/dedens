# Decisions

Each decision: the choice, its reason, the alternatives rejected. A number is never reused: a replaced decision is
marked superseded. Measurements: [`benchmarks.md`](benchmarks.md). Open questions: [`TODECIDE.md`](TODECIDE.md).

## Scope

- D1 Crates per [`ARCHITECTURE.md`](../ARCHITECTURE.md); later `dedens-resolver`, `dedens-server` and
  `apps/dedensd`, all on the same crates. CLI and server are separate binaries.
- D2 Order: unencrypted core DNS first (wire format, UDP, TCP), then DNSSEC and encrypted transports (DoT, DoH,
  DoQ). A stub resolver and CLI first; forwarder, recursive and authoritative servers follow.
- D3 Own wire format, for full control of RFC behaviour and speed. hickory-dns and NLnet Labs' `domain` are
  reference code only.
- D4 Runtime: compio, features `io-uring` and `polling`: io_uring on Linux, polling at runtime where io_uring
  is blocked (containers, seccomp), kqueue on macOS, rustls and QUIC ready. Rejected: tokio-uring (dead since
  2024-05), monoio (5 commits a year), glommio (dead since 2025-04), tokio's `io-uring` feature (files only), raw
  `io-uring` (we would write a runtime). Fallback: tokio. Risk: compio is 0.x, contained by D5.
- D5 `dedens-proto` is sans-IO, so a runtime change touches one crate and the server reuses the codec as is.
- D6 Linux and macOS. Stable pinned in `rust-toolchain.toml` and bumped by Renovate, so new lints arrive as a
  PR, not a red CI; MSRV 1.95. One nightly pinned by date in the justfile, bumped by hand with RAPx, for
  rustfmt, `-Z` flags and RAPx only: an unpinned nightly reformats code on its own.

## Wire format

- D7 `Name<'a>`: wire-form bytes, case kept, compared and hashed ASCII case-insensitively (RFC 4343); built only
  through validating constructors. Private representation: a slice of the input without pointers, input plus
  offset with pointers (labels read on demand, pointers checked once), or owned bytes. Rejected: a 255-byte
  inline buffer (about 300 bytes per record); copying compressed names at decode (the allocation borrowing
  removes).
- D7a Decoding borrows: one set of types with a lifetime, `Message<'static>` is the owned form (`into_owned()`
  or built by hand). Variable-length values (TXT, SVCB parameters, CAA, opaque RDATA, EDNS options) stay as
  checked wire bytes read through accessors, so they keep their invariants. Rejected: a borrowed view beside
  the owned types (every RDATA type twice); a lazy message (errors at every access).
- D8 `Message`: header, questions, answer, authority, additional, and EDNS lifted out of additional, so no
  caller searches for the OPT record.
- D9 Decoder: a compression pointer points strictly before the current label (no loops), past the header, to
  labels ending before the bytes that point to them (a prior name, RFC 1035 §4.1.4), at most 127 per name
  (no long chains); unknown types are opaque (RFC 3597); every input decodes or errors (fuzzed). Broken structure
  is an error. A readable message breaking a rule (several OPT, OPT outside additional or not at the root,
  QDCOUNT > 1 per RFC 9619, trailing bytes) decodes with violations: the CLI shows them, the server answers
  FORMERR. Well-delimited but invalid RDATA or EDNS option is kept opaque with a violation, so typed values
  always hold their invariants; except in types whose names may be compressed (RFC 3597 §4), where it is an
  error, since their pointers mean nothing outside the message.
- D10 Encoder: into a caller buffer with a size limit, no allocation (fits io_uring registered buffers), plus a
  `Vec` convenience. Compresses names only in RFC 1035 types (RFC 3597 §4), never into the header, through a fixed open-addressing
  table matched byte for byte (case kept, no allocation); a record with the owner of the previous one points
  to it without a lookup, as Unbound does (TXT answer 367 → 170 ns). Truncation stops at the first record that does not
  fit; TC only when answer or authority lost records; a cut additional RRset goes whole, since without TC a
  partial RRset passes for complete (RFC 2181 §9); OPT is always kept and opens additional (RFC 6891 §7). Header
  fields too large for their bits are an error, never masked. EDNS UDP payload 1232 (DNS Flag Day 2020).
- D11 Typed RDATA: A, AAAA, NS, CNAME, SOA, PTR, MX, TXT, SRV, CAA, SVCB, HTTPS, OPT; others opaque until
  added. The other types with compressible names (RFC 3597 §4: MD MF MB MG MR MINFO, RP AFSDB RT SIG PX NXT
  NAPTR) are parsed by a field layout and kept opaque with their names expanded, so opaque data never holds a
  pointer.
- D12 Typed EDNS options: cookie (RFC 7873), Extended DNS Error (RFC 8914), padding (RFC 7830), client subnet
  (RFC 7871), TCP keepalive (RFC 7828), NSID (RFC 5001). Typed SVCB keys: RFC 9460 keys 0-6 and dohpath (RFC
  9461). Others opaque. An opaque option (`UnknownOption::new`) refuses data that reads as its typed option, so
  an option has one form and equals itself read back.
- D13 Topic modules, RDATA and conformance tests by RFC (`crates/dedens-proto/AGENTS.md`). Rejected strict
  `rfcNNNN/` folders: names, the header and rcodes are each defined across several RFCs.
- D19 Codes (type, class, opcode, rcode, EDNS option, SVCB key) are newtypes with named constants, not enums
  with an `Unknown` arm: every value has one representation and a new code is one constant. `Record` has no
  type field: its RDATA gives the type, so they cannot disagree.
- D20 (superseded by D28) `MessageView`: a message read in place for the server's hot path (cache lookups,
  serving cached bytes with lower TTLs). One pass checks exactly what `Message::decode` checks (fuzzed against
  it) and stores two 16-bit offsets per entry in a `MessageIndex` sized once for the most entries a 65535-byte
  message holds (13104, 52 KB): never allocates, never trusts claimed counts. Gains: no allocation, O(1)
  access to any record, TTL offsets for rewriting a copy.
- D21 `Query`: a query read in place, without the D20 table: header, first question, `EdnsView`, violations;
  checks what `Message::decode` checks (fuzzed against it). `Edns::append` writes an OPT after a message
  already in a buffer, so the server adds EDNS to cached bytes without re-encoding.
- D28 `Record` keeps its RDATA as checked wire bytes with its type (`WireRdata`), borrowed from the message
  (names in it may point elsewhere there) or owned (no pointers); `Record::data()` reads the typed `RData` on
  demand. No hot path reads inside RDATA (the cache serves bytes, a forwarder checks then stores), so decode
  checks every RDATA (D9) and builds nothing; encode copies the bytes, except for the types whose names may be
  compressed (RFC 3597 §4), read and written again. Equality and hashing go through `RData`, so names in RDATA
  compare without case (RFC 4343). Replaces D20: with decoding into reused vectors (`decode_reusing`), one
  `Message` is as cheap as the view, and `message::ttl_offsets` gives the cache the TTL positions. Messages over
  65535 bytes are refused. Gain: one message type instead of two, at the same measured speed
  (`docs/benchmarks.md`); typed records were expected to explain the encode gap with Unbound and did not.
  Rejected: expanding compressed names at decode (one allocation per such record).

## Transports

- D26 `dedens-net` splits like `dedens-proto`: a sans-IO client core (retries, response matching, TC fallback,
  EDNS fallback, cookies) fed bytes and time, so tests drive drops, delays and forged replies exactly without a
  server; a thin compio layer moves the bytes, tested over loopback only. Public at both levels: `Client` for
  the whole exchange, and the UDP and TCP exchanges for callers that pick the transport (`+tcp`, the
  forwarder). Rejected: an in-process test server (slower, less exact), real servers in CI (cannot forge a
  wrong ID or a drop). compio 0.19.2 until 0.20 is released.
- D27 Client behaviour:
  - UDP: a new connected socket on port 0 per query, the OS picking a random port, and a random ID from
    `getrandom`: about 32 bits an off-path attacker must guess (RFC 5452 §9.2). Muxing queries on a fixed socket
    leaves 16 (the ID field cannot grow), so it waits for the forwarder (`TODECIDE.md`).
  - Matching: source address, ID and question (case-insensitive) or the datagram is dropped and the wait goes
    on, as hickory and Unbound do; miekg/dns fails on a wrong ID and CoreDNS checks the ID only. `0x20` case
    randomization of the question is an option, off by default as in Unbound.
  - dig's defaults: 3 tries, 5 s each. TC over UDP is retried over TCP. EDNS is dropped once on FORMERR or
    NOTIMP to an EDNS query (RFC 6891 §7), never on a timeout (RFC 8906); `+noednsneg` turns it off.
  - Cookies (RFC 7873 §5): the client cookie drawn from `getrandom` once per pair of source and server
    addresses, a memoized random function of both as §4.1 asks, without a hash to pick; server cookies kept
    per server for the life of the client, BADCOOKIE retried once.
  - TCP (RFC 7766): one connection per server, queries pipelined and matched by ID in any order, idle close,
    edns-tcp-keepalive sent empty in TCP queries and its timeout honoured when shorter (RFC 7828), a closed
    connection retried once on a new one. Queries are written whole by a task of the connection, so a query that
    stops waiting never cuts a message short.
- D31 The sans-IO exchange (`dedens-net::exchange`) takes the query whole from the caller, ID and cookie in
  it, and owns no randomness or secret; `0x20` takes its random bits as an option, which also turns on the
  exact-case match, so a randomized question is never matched loosely. Each step consumes the `Exchange`
  and returns `Send`, `Wait` or `Done`: a finished exchange cannot be fed. Only timeouts spend tries; the TC,
  EDNS and cookie fallbacks each happen a bounded number of times. Stricter than dig: FORMERR and NOTIMP
  alone may leave the question out; once a server has sent a cookie, a response without one is dropped, even
  without OPT (RFC 7873 §5.3 MUST), at the price of timeouts if that server loses cookie support mid-process.

## Presentation format

- D25 Zone text (`dedens-proto::text`, RFC 1035 §5, RFC 2308 §4, RFC 3597 §5): own lexer, base64 and hex.
  Read: BIND TTL units, `\#` for every type (known ones typed), case as written. Written: one tab-separated
  line per record, absolute names, TTL in seconds, `\#` on request (`generic()`). `ZoneReader` hands
  `$INCLUDE` to the caller (no file I/O in the library; the caller bounds depth and vets paths) and stops at
  the first error, with line and column. No `$GENERATE`. Stricter than BIND where BIND only warns: TTL over
  2³¹−1 is an error, no SOA-minimum fallback, query and meta types and classes (RFC 6895 §3.1-3.2) and RDATA
  over 65535 bytes are refused. A `"` opens a quoted part at a token's start, or after the first `=` in SVCB
  parameters only (RFC 9460 §2.1), as BIND; a `\` ending a line outside quotes is an error (it joins entries).
  `\#` RDATA its type refuses stays opaque with the reason (`DecodedRecord`), as on the wire (D9). RFC 1035
  §5.2 zone checks belong to the zone-loading layer.
- D29 A quoted part ends on its line: an unescaped newline inside quotes is an error, as in BIND (`isc_lex`
  without `ISC_LEXOPT_QSTRINGMULTILINE`, how it reads zone files); `\` before the newline keeps it in the
  text. RFC 1035 §5.1 leaves it open; a missing `"` would otherwise swallow the entries after it silently.

## Performance and safety

- D14 Bar: no slower than hickory-proto; target: faster than `domain`. Baselines run in the same benches:
  hickory-proto, `domain` and Go's `miekg/dns` (the codec of CoreDNS), in `crates/dedens-bench` as regular
  dependencies so `cargo deny` checks them; Unbound's C codec, built from a pinned release by
  `just bench-unbound`. CoreDNS and Unbound as servers: dnsperf, later. `unsafe` only where a profile
  shows bounds checks matter. A server decodes with `Message::decode_reusing`: no allocation once warm.
- D15 `unsafe` is a hot-path tool: the bench first, then Miri and RAPx. Every crate root has
  `#![forbid(unsafe_code)]`, which nothing below can override; a crate opting in replaces it with the
  workspace's `deny` (`Cargo.toml`) and allows `unsafe_code` on the one module of the measured hot path.
- D16 Checks beyond the gate, each added with its trigger: Miri with the first `unsafe`, loom with the first
  hand-written concurrent structure, cargo-semver-checks with the first crates.io release, fuzzing with the
  first fuzz target. RAPx weekly, outside the gate: it builds on rustc internals and breaks on unrelated
  nightly changes.
- D22 Response cache (`dedens-cache`, sans-IO, time passed in as seconds): one cache shared by compio's
  per-core threads, `Mutex` shards picked by keyed SipHash (no collision flooding). Own code, not
  `moka`/`quick_cache`: slab shards with S3-FIFO eviction under a byte budget (a scan of one-time names leaves
  popular ones; a ghost queue of evicted hashes sends a key asked again to main). Whole responses only; an
  RRset cache comes with the recursive resolver. Key: lowercased question, type, class, DO, CD, of standard
  queries only (QR clear, opcode QUERY), not meta types (RFC 6895 §3.1; ANY is cached). `insert` takes the
  client's query and the response the forwarder decoded, never decoding again; the caller asks upstream with
  the query's DO and CD. Checked (RFC 2308, no TC, no violations, no client subnet scope above 0, RFC 7871
  §7.3.1) and encoded once (no OPT, ID 0, one TTL, TTL offsets kept). Negative (NXDOMAIN, or no answer of the
  type asked, after any CNAME chain) only with an SOA at or above the chain's last name, and the chain's TTLs
  within the negative TTL (RFC 2308 §2, §5). A hit copies and patches ID, flags (AA and Z clear, AD only when
  asked), question case and TTLs, never above the stored TTL; one too large for the buffer is encoded again
  truncated, outside the lock. Serve-stale (RFC 8767: 30 s answer TTL, 3 days kept) and failure holds (RFC
  9520: 5 s doubling to 300 s, 30 s with stale data, never above 300 s; a failure during a hold does not count,
  a quiet spell over 300 s starts over); the caller decides when stale data may answer.

## CLI

- D17 Query files (`dedens-scenario`), so the server's tests reuse them: one serde model (queries, options,
  optional expectations; a failed one makes `dedens` exit non-zero) from JSON (serde_json) or YAML
  (serde-saphyr), by extension or `--format`, `-` for stdin. Rejected: serde_yaml (archived 2024-03),
  serde-yaml-ng (no commit in a year).
- D18 `dedens`, dig but better: dig argv (`@server name type class +opts`) and long flags; query files;
  compact output by default (doggo-like), dig's layout behind a flag, `--json` with a stable schema (the
  server's tests read it), `+short`, color; several names, types or servers per run, concurrent, side by side;
  timing, transport, sizes, EDNS, cookies and EDE in words; `+trace`; `--repeat N` with latency percentiles;
  `--save-wire` (the source of captured test data); default server from `/etc/resolv.conf`. `-x ADDR` asks PTR
  for the `in-addr.arpa` or `ip6.arpa` name of an address (RFC 1035 §3.5, RFC 3152). The `resolv.conf`
  search list (`search`, `domain`, `ndots`) applies only with `+search`, as in dig: a debugging tool asks for
  the name typed. Unicode names are converted to A-labels (IDNA2008, RFC 5891 and 5895) and shown as such,
  with labels mixing scripts flagged (IDN homographs).

## Server

- D23 Pipeline: each listener runs an ordered chain of stages; a stage answers, passes the query on, or passes
  it on and sees the response back. Order from the config, not the build (CoreDNS's fixed `plugin.cfg` order
  confuses users). Branching is a router stage (zone, client CIDR, listener, qtype, view), no general graph: a
  query has one response. Declarative matchers compiled at load; scripting costs microseconds against a
  150 ns cache hit. Built-in stages are enum variants behind Cargo features; custom binaries register extra
  stage types (trait objects) on the server library. Stages before the cache are synchronous, without
  allocation or copy of the query.
- D24 Configuration: a directory of TOML, YAML or JSON files, one serde model (as D17), merged; components
  named, typed by a `type` key. Errors, not warnings: unknown field, duplicate name, unused component.
  `${VAR}`, `${VAR:-default}` (`$$` escapes), `SECRET[backend.key]`. `dedensd validate` builds the pipeline
  without binding; JSON Schema from the types (schemars); config tests run D17 query files. Reload (SIGHUP,
  file watch) builds the new pipeline, then swaps it (`ArcSwap`); in-flight queries finish on the old one;
  cache and upstream connections survive.

## Observability

- D30 Metrics through the `metrics` facade, tracing through `tracing`; each library takes them behind its own
  `metrics` or `tracing` Cargo feature, compiled away without it, and the binaries turn them on by default.
  Handles are made once with the component, not looked up per event; no recorder means no-op handles.
  `dedens-proto` has none: its functions are pure and return errors, violations and truncation as values, which
  the server counts where it calls them. The cache counts lookups by outcome, prefetches, inserts and evictions
  (names in `crates/dedens-cache/src/metrics.rs`); spans belong to net, server and CLI, not to hot paths of proto
  or cache. `dedensd` exports Prometheus; the CLI prints `tracing-subscriber` text under `-v`; OpenTelemetry
  later. Cost in `docs/benchmarks.md`.
