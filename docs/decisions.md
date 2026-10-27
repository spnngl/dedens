# Decisions

Each decision records the choice, its reason and the alternatives rejected. Numbers are stable: a replaced
decision is marked superseded, never reused. The rules a decision produces live in `AGENTS.md`.

## Scope and architecture

- D1 Crates: `dedens-proto` (wire format), `dedens-net` (transports), `dedens-scenario` (query files, D17),
  `apps/dedens` (CLI). Later `dedens-resolver`, `dedens-server`, `apps/dedensd` (stages such as kubernetes,
  D23), all built on these crates. CLI and server are separate binaries.
- D2 Order: unencrypted core DNS first (wire format, UDP, TCP), then DNSSEC and encrypted transports (DoT, DoH,
  DoQ). A stub resolver and CLI come first; forwarder, recursive and authoritative servers follow.
- D3 Own wire format, for full control of RFC behaviour and of speed. hickory-dns and NLnet Labs' `domain` are
  reference code only.
- D4 Runtime: compio with features `io-uring` and `polling`. io_uring on Linux, falling back to polling at
  runtime where io_uring is blocked (containers, seccomp), kqueue on macOS; rustls and QUIC support ready for
  DoT and DoQ. Rejected: tokio-uring (no commit since 2024-05), monoio (5 commits a year), glommio (no commit
  since 2025-04), tokio's `io-uring` feature (files only), raw `io-uring` (we would write a runtime). Fallback:
  plain tokio. Risk: compio is 0.x, contained by D5.
- D5 `dedens-proto` is sans-IO, so a runtime change touches one crate and the server reuses the codec as is.
- D6 Platforms: Linux and macOS. Toolchain: latest stable, pinned in `rust-toolchain.toml` and bumped by
  Renovate, so a release's new lints arrive as a PR rather than a red CI; MSRV 1.95. One nightly, pinned by date
  in the justfile and bumped by hand together with RAPx, only for rustfmt, `-Z` flags and RAPx: an unpinned
  nightly reformats code without any change on our side.

## Wire format

- D7 `Name<'a>`: wire-form bytes, case preserved, compared and hashed ASCII case-insensitively (RFC 4343); built
  only through validating constructors (label 1..=63 bytes, name <= 255). Representation private: a slice of
  the input when the name has no pointer, the input and the name's offset when it has (labels read on demand,
  pointers checked once at decode), or owned bytes for a built name. Rejected: a fixed 255-byte inline buffer,
  about 300 bytes per record whatever the name; copying compressed names at decode, which costs the allocation
  borrowing removes.
- D7a Decoding borrows (D14 bench: dedens allocated 7 times for one A record, `domain` none): one set of types
  with a lifetime, `Message<'a>` down to `Name<'a>`; `Message<'static>` is the owned message, from
  `into_owned()` or built by hand. Variable-length values (TXT strings, SVCB parameters, CAA, opaque RDATA,
  EDNS option data, EDE text) are kept as their checked wire bytes, borrowed or owned, read through iterators
  or accessors, so a decoded value still holds its invariants. SVCB parameters come out of the iterator
  owned: rare, so their allocation moves to whoever reads them. Sections and EDNS options stay `Vec`s.
  Rejected: a separate borrowed view next to the owned types (every RDATA type twice); a lazy message
  re-parsed on each pass (errors at every access).
- D8 `Message`: header, questions, answer, authority, additional, and EDNS lifted out of additional into its
  own field, so no caller searches for the OPT record.
- D20 `MessageView`: the same message read in place, for the server's hot path (cache lookups, serving cached
  bytes with lower TTLs). One pass checks the input exactly as `Message::decode` does (fuzzed against it) and
  stores two 16-bit offsets per entry in a `MessageIndex` table allocated once at the most entries a 65535-byte
  message holds (13104, 52 KB), so reading never allocates nor sizes from claimed counts. Fields, names and
  RDATA are parsed on access. Measured: the check costs 65-80% of a full decode, since parsing names and RDATA,
  not building records, is most of decoding; the gain is no allocation, O(1) access to any record, and TTL
  offsets for rewriting a copy of the bytes.
- D21 `Query`: a query read in place for the server, without the D20 table: header, first question, EDNS as
  an `EdnsView` (fields, options iterated from the input), violations. Checks all of the message as
  `Message::decode` does (fuzzed against it), allocates only to list violations. `Edns::append` writes an OPT
  record after a message already in a buffer, so the server adds its EDNS to cached bytes without re-encoding.
- D9 Decoder: bounds-checked cursor; a compression pointer must point strictly before the current label, which
  rules out loops, and a name follows at most 127 pointers, which rules out long chains; unknown types stay
  opaque RDATA (RFC 3597); every input decodes or errors (fuzzed).
  Strictness: broken structure (lengths, pointers, name size) is an error. A readable message that breaks a
  rule (several OPT, OPT outside additional, OPT owner not root, QDCOUNT > 1 per RFC 9619, trailing bytes)
  decodes and carries the violations: the CLI shows them, the server answers FORMERR. RDATA or an EDNS option
  that is well delimited but invalid inside (SVCB key order, CAA tag, client subnet prefix) is kept as received,
  opaque, with a violation, so typed values always hold their invariants. Exception: invalid RDATA of a type
  whose names may be compressed (RFC 3597 §4) is an error, since its pointers mean nothing outside this message.
- D10 Encoder: writes into a caller buffer with a size limit and no allocation (fits io_uring registered
  buffers), plus a `Vec<u8>` convenience. Compresses names only inside RFC 1035 types (RFC 3597 §4).
  Truncation: stop at the first record that does not fit; set TC only when the answer or authority section lost
  records; when only additional data is lost, TC stays clear and the whole cut RRset goes, since without TC a
  partial RRset passes for the whole one (RFC 2181 §9); OPT is always kept (RFC 6891 §7) and opens the
  additional section, so it is the OPT a decoder lifts; RFC 9471 glue rules come with the server. Compression
  table: an open-addressing hash table of earlier names (256 slots, 192 names, keyed on first label and length), matched
  byte for byte, so output keeps each name's case (RFC 4343) and needs no allocation. Header fields that do not
  fit their bits (opcode, 4-bit rcode) are an encode error, never masked. EDNS UDP payload 1232 by default (DNS Flag Day 2020).
- D11 RDATA v1: A, AAAA, NS, CNAME, SOA, PTR, MX, TXT, SRV, CAA, SVCB, HTTPS, OPT; every other type is opaque
  RFC 3597 data until added. Opaque data never holds a pointer: the other types whose names receivers
  decompress (RFC 3597 §4: MUST for MD, MF, MB, MG, MR, MINFO; SHOULD for RP, AFSDB, RT, SIG, PX, NXT, NAPTR)
  are parsed by a field layout and kept opaque with their names expanded.
- D12 Typed EDNS options v1: cookie (RFC 7873), Extended DNS Error (RFC 8914), padding (RFC 7830), client
  subnet (RFC 7871), TCP keepalive (RFC 7828), NSID (RFC 5001); others opaque. Typed SVCB parameters: RFC 9460
  keys 0-6 and dohpath (RFC 9461); others opaque.
- D13 `dedens-proto` layout by topic, RDATA and conformance tests by RFC (rule in `AGENTS.md`). Rejected strict
  `rfcNNNN/` folders: names, the header and rcodes are each defined across several RFCs.
- D19 Codes (type, class, opcode, rcode, EDNS option, SVCB key) are newtypes over the integer with named
  constants, not enums with an `Unknown` arm: every value is representable once, and a new code is one constant.
  `Record` holds no type field: the type comes from its RDATA, so they cannot disagree.

## Performance and safety

- D14 Decode borrows (D7a); measured with divan, including the cost of `into_owned()`. Baselines
  in the same benches: hickory-proto and `domain`, plus Go's `miekg/dns` (the codec of CoreDNS) through
  `go test -bench` on the same files; all in `crates/dedens-bench`, regular dependencies so `cargo deny` checks
  them. Every encoder compresses names. CoreDNS as a server is measured with dnsperf later. Bar: no slower
  than hickory-proto; beating `domain` is the optimisation target. Numbers (Apple M-series, median, ns, one
  run; `a`/`mx`/`txt_large` = 72/161/1187-byte captured responses): decode dedens 208/552/1437, hickory
  250/708/1791, domain 146/297/620, miekg 281/766/2170; encode into a reused buffer dedens 73/330/461, miekg
  162/637/1056; encode into a fresh buffer dedens 88/317/718, hickory 416/1291/1697, domain 198/666/771, miekg
  177/667/1135. The bar is met; `domain` was 1.4-2.3x faster to decode because it borrowed: the owned decode
  allocated 7 times (328 B) for `a` and 15 times (779 B) for `mx`, `domain` none. Borrowed decode (D7a), same
  run, median ns a/mx/txt_large: dedens 73/153/289 with 3 allocations (the section `Vec`s), `domain`
  94/191/432, `into_owned()` after it 138/378/743. Re-encoding a borrowed message costs 13-33% more than an
  owned one (a/mx/txt_large 60/302/351 vs 53/227/305): a name with pointers is used in place when it has one run of labels (an owner that is only a
  pointer), else its runs are copied on the stack. `unsafe` only where a profile shows bounds checks matter:
  replacing the checked slicing of `Reader` with `get_unchecked` was measured no faster. A server decodes with
  `Message::decode_reusing`, into the section vectors of the previous message: no allocation once warm, median
  ns a/mx/txt_large 77/174/325 against 97/195/341 for decoding and dropping. Medians swing up to 2x between
  runs (threads move between P and E cores), so changes are compared on instructions and cycles retired
  (`/usr/bin/time -l`) over a fixed iteration count. Parse pass (phase 2), all three captures per iteration,
  cycles: `decode_reusing` 4323 → 3706 (`domain` 3517, more instructions: 17325 against 15615),
  `MessageIndex::read` 3301 → 2896, view 5456 → 4618: a `Name` of 24 bytes instead of 32 (16-bit
  offset; a name past 65535 bytes, only in a larger buffer, is copied out), records built in place, the fixed
  fields read with one bounds check. Tried and dropped: reading labels from a re-sliced window (2% fewer
  instructions, no fewer cycles), `#[inline]` hints (no change).
- D15 `unsafe` is a hot-path tool: the bench comes first, Miri and RAPx follow.
- D16 Checks beyond the gate, each added with its trigger: Miri with the first `unsafe`, loom with the first
  hand-written concurrent structure, cargo-semver-checks with the first crates.io release, the fuzz workflow
  with the first fuzz target. RAPx runs weekly, outside the gate: it compiles against rustc internals and
  breaks on nightly changes unrelated to our code.
- D22 Response cache (`dedens-cache`, sans-IO, time passed in as seconds): one cache shared by compio's
  per-core threads, split in `Mutex` shards picked by keyed SipHash (`RandomState`) so names chosen to collide
  cannot pile up. Own code, no `moka`/`quick_cache`: each shard is a slab indexed by hash with S3-FIFO eviction
  under a byte budget (a scan of one-time names leaves popular ones in place). Whole responses only; an RRset
  cache comes with the recursive resolver. Key: lowercased question, type, class, DO, CD. A response is checked
  (RFC 2308 rules, no TC, no violations) and encoded once at insert, without OPT, ID 0, one TTL for all records,
  with the offsets of its TTL fields; a hit copies the bytes and patches ID, flags, question case and TTLs (no
  decode, no allocation; a response larger than the client's buffer takes a decode and `encode_truncated`
  outside the lock). Serve-stale (RFC 8767: 30 s answer TTL, 3 days kept) and failure holds (RFC 9520: 5 s
  doubling to 300 s, 30 s when stale data answers) per key; the caller chooses when stale data may answer.
  Numbers (median, one run): hit including `Query::read` 147/149/170 ns for a/mx/txt_large, insert
  0.9/1.5/2.5 µs; one hot name on 8 threads 312 ns (one shard lock), 10 000 names on 8 threads 333 ns.

## CLI

- D17 Query files: own crate, so the server's tests reuse it. One serde model (queries, options, optional
  expectations; a failed expectation makes `dedens` exit non-zero), read from JSON (serde_json) or YAML
  (serde-saphyr), format from the extension or `--format`, `-` for stdin; a new format is one deserializer call.
  Rejected: serde_yaml (archived 2024-03), serde-yaml-ng (no commit in a year).
- D18 `dedens`, dig but better:
  - dig argv (`@server name type class +opts`) and long flags.
  - Query files (D17) for advanced tests.
  - Compact modern output by default (doggo-like); dig zone-file layout behind a flag; `--json` with a stable
    schema (the server's tests consume it); `+short`; color.
  - Several names, types or servers per run, queried concurrently, servers side by side.
  - Timing, transport, sizes, EDNS, cookies (RFC 7873), Extended DNS Errors (RFC 8914) in words.
  - `+trace` from the root; `--repeat N` with latency percentiles, to load-test `dedensd`.
  - `--save-wire` writes raw responses, the source of captured test data.
  - Default server from `/etc/resolv.conf`.

## Server

Built after the CLI (PLAN.md phase 7). CoreDNS's job (blocklists, rewrite, kubernetes, forward, cache) with
Vector's configuration tooling.

- D23 Pipeline: each listener runs an ordered chain of stages; a stage answers, or passes the query on, or
  passes it on and sees the response on the way back (rewrite undoes its change there). Order comes from the
  config, not from the build (CoreDNS's fixed `plugin.cfg` order confuses users). Branching is a router stage
  choosing a chain by zone, client CIDR, listener, qtype or view; no general graph (Vector's DAG serves
  continuous streams with fan-out and buffers; a query has one response). Match rules are declarative matchers
  compiled at load; a small typed rule language may come later, VRL-like scripting costs microseconds against a
  150 ns cache hit. Stage types: built-in ones are variants of one enum dispatched by `match`, each behind a
  Cargo feature (a config naming a compiled-out type fails with the feature to enable). Others plug in without
  a fork: the server is a library crate, `dedensd` a thin binary over its registry, and a custom binary
  registers extra stage types (a trait object, dynamic dispatch only for them). Stages before the cache stay
  synchronous, without allocation or copy of the query. Dynamic loading (WASM, gRPC) is undecided; if it comes,
  it is one stage type used after a cache miss (Vector dropped its WASM transform; a Rust dylib needs an ABI
  workaround; gRPC costs milliseconds).
- D24 Configuration: a directory of files in TOML, YAML (serde-saphyr) or JSON, one serde model (as D17),
  merged; each component named, its type chosen by a `type` key. Errors, not warnings: unknown field, duplicate
  name across files, component defined but used by no listener. `${VAR}` and `${VAR:-default}` interpolate
  environment variables (`$$` escapes), `SECRET[backend.key]` reads a secret backend. `dedensd validate`
  builds the whole pipeline without binding; a JSON Schema is generated from the types (schemars); config
  tests run D17 query files against the built pipeline. Reload (SIGHUP and file watch) builds the new pipeline
  completely, then swaps it atomically (`ArcSwap`); queries in flight finish on the old one; the cache and
  upstream connections live outside it and survive. What needs a restart (listeners, thread count) is decided
  when the server starts.
- D25 Presentation format and zone files (`dedens-proto::text`, RFC 1035 §5, RFC 2308 §4, RFC 3597 §5): own
  lexer, base64 and hex, no dependency. Read: BIND TTL units, `\#` for every type (known types decoded to
  their typed form), case kept as written (RFC 4343 §2.1). Written: one tab-separated line per record,
  absolute names, TTL in seconds, the typed form (or `\#` on request with `generic()`). `ZoneReader` yields
  records and `$INCLUDE`s: the caller reads the included file (the library does no file I/O) and reads it with
  `ZoneReader::include`, which keeps the TTL and class defaults and leaves the parent's origin alone. Omitted
  TTL: explicit, else `$TTL`, else the last explicit one, else an error; omitted class: the last one, else IN.
  The first error stops the reader, with line and column. No `$GENERATE`. Stricter than BIND where BIND
  only warns: a TTL over 2³¹−1 is an error (BIND uses 0), and there is no fallback to the SOA minimum. Records
  of a query or meta class or type (RFC 6895 §3.1-3.2, e.g. ANY, NONE, OPT, AXFR) and RDATA over 65535 bytes
  are refused. RDATA that `\#` gives but its type refuses is kept opaque, as on the wire (D9), so every decoded
  record reads back from its text. The caller bounds `$INCLUDE` depth and cycles and vets paths from untrusted
  zones. Zone-level checks (RFC 1035 §5.2: SOA first, one class, records inside the zone, CNAME alone) belong
  to the later zone-loading layer. A 100 000-record zone reads in
  9 ms, `domain` 10.5 ms, hickory-proto 57 ms (it also builds record sets; `just bench`).

## Later, undecided

crates.io publishing, container image, dnsperf benchmarks against Unbound and CoreDNS, dynamic plugins (D23).
