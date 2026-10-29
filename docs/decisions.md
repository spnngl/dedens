# Decisions

Each decision: the choice, its reason, the alternatives rejected. A number is never reused: a replaced decision is
marked superseded. Measurements: [`benchmarks.md`](benchmarks.md). Open questions: [`TODECIDE.md`](TODECIDE.md).

## Scope

- D1 Crates per [`ARCHITECTURE.md`](../ARCHITECTURE.md), all on `dedens-proto`. CLI and server are separate
  binaries.
- D2 (amended by D60) Order: unencrypted core DNS first (wire format, UDP, TCP), then DNSSEC and encrypted transports (DoT, DoH,
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
  `Vec` convenience. Compresses names only in RFC 1035 types (RFC 3597 §4), never into the header, through a fixed
  open-addressing table matched byte for byte (case kept, no allocation); a record with the owner of the previous
  one points to it without a lookup, as Unbound does (TXT answer 367 → 170 ns). Truncation stops at the first
  record that does not fit; TC only when answer or authority lost records; a cut additional RRset goes whole, since
  without TC a partial RRset passes for complete (RFC 2181 §9); OPT is always kept and opens additional (RFC 6891
  §7). Header fields too large for their bits are an error, never masked. EDNS UDP payload 1232 (DNS Flag Day
  2020).
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
- D59 The fixed wire layouts, the header and the fields after a question's or a record's name, are `zerocopy`
  structs of big-endian byte-array fields (`network_endian::U16`), read in place with one bounds check
  (`Reader::fields`) and written with one copy. No `unsafe` of ours, no alignment need on the input. Measured
  in one session (`docs/benchmarks.md`): cache hit 3-8% faster, query read ~10%, decode and encode the same
  or a few % faster. Rejected: `#[repr(C, packed)]` native integers (a byte swap per read on little-endian
  CPUs anyway, references to fields refused, `unsafe` to cast the input); a `union` of RDATA (no tag, `unsafe`
  reads, and names, strings and lists cannot be laid over the wire: `RData` is that union with its tag, read
  on demand, D28). Names stay hand-parsed: their length varies and they may point elsewhere.

## Transports

- D26 `dedens-net` splits like `dedens-proto`: a sans-IO client core (retries, response matching, TC fallback,
  EDNS fallback, cookies) fed bytes and time, so tests drive drops, delays and forged replies exactly without a
  server; a thin compio layer moves the bytes, tested over loopback only. Public at both levels: `Client` for
  the whole exchange, and the UDP and TCP exchanges for callers that pick the transport (`+tcp`, the
  forwarder). Rejected: an in-process test server (slower, less exact), real servers in CI (cannot forge a
  wrong ID or a drop). compio 0.19.2 until 0.20 is released.
- D27 (amended by D50, D53) Client behaviour:
  - UDP: a pool of sockets per server (D50); a random ID from `getrandom`, drawn 256 bytes at a time: a call costs
    846 ns on macOS, 14 ns on Linux (vDSO).
  - Matching: source address, ID and question (case-insensitive) or the datagram is dropped and the wait goes
    on, as hickory and Unbound do; miekg/dns fails on a wrong ID and CoreDNS checks the ID only. `0x20` case
    randomization of the question is an option, off by default as in Unbound.
  - dig's defaults: 3 tries, 5 s each. TC over UDP is retried over TCP. EDNS is dropped once on FORMERR or
    NOTIMP to an EDNS query (RFC 6891 §7), never on a timeout (RFC 8906); `+noednsneg` turns it off. A query
    changed by a fallback goes with the next ID, so a late response to the query before cannot end the exchange.
  - Cookies (RFC 7873 §5): the client cookie drawn from `getrandom` once per pair of source and server
    addresses, a memoized random function of both as §4.1 asks, without a hash to pick; server cookies kept
    per server for the life of the client, including the fresh one of a BADCOOKIE; BADCOOKIE retried with it
    over UDP, then over TCP (§5.3).
  - TCP (RFC 7766): one connection per server, queries pipelined and matched by ID in any order, each under an
    ID free on the connection (§6.2.1), the caller's put back in the response; the ID of a query that stopped
    waiting stays taken until its response comes. Idle close; edns-tcp-keepalive sent empty in TCP queries only
    and its timeout honoured when shorter, 0 taking no new query (RFC 7828); a closed
    connection retried once on a new one, as is one whose IDs are all taken. Queries are written whole by a task of
    the connection, so a query that stops waiting never cuts a message short; those queued meanwhile go in one
    write (D53). A write lasts the idle time at most, and a query that times out with nothing read on its
    connection since it was sent closes it: a server that stopped reading or answering is replaced. A connection
    that cannot open fails each query waiting for it with its error. A connection slower than a try, waited for
    the source address of a cookie, costs that try, not the exchange.
- D31 The sans-IO exchange (`dedens-net::exchange`) takes the query whole from the caller, ID and cookie in
  it, and owns no randomness or secret; `0x20` takes its random bits as an option, which also turns on the
  exact-case match, so a randomized question is never matched loosely. Each step consumes the `Exchange`
  and returns `Send`, `Wait` or `Done`: a finished exchange cannot be fed. Only timeouts spend tries, and tries lost to a socket error or a slow connection; the TC,
  EDNS and cookie fallbacks each happen a bounded number of times. Stricter than dig: FORMERR and NOTIMP
  alone may leave the question out; once a server has sent a cookie, a response without one is dropped, even
  without OPT (RFC 7873 §5.3 MUST), at the price of timeouts if that server loses cookie support mid-process.
- D60 (amends D2) Encrypted transports come before DNSSEC: DoT, then DoQ and DoH, each in the client and CLI
  first, then in `dedensd`. DoT (RFC 7858) is D27's TCP connection with a TLS session on it: one pipelined
  connection per server, the same idle, keepalive and retry rules. The TLS stream splits into halves locked only
  while polled (futures-util); compio's split holds its lock across a read and would stall the writer. rustls
  with ring, already in the lock through ureq; TLS 1.2 and 1.3 (RFC 8310 §9); ALPN `dot` (RFC 9461 §4.1).
  - Strict privacy profile by default (RFC 8310 §6.6): the OS trust store (`rustls-platform-verifier`, as D57),
    and the certificate must hold the name after `#`, else the host name given, else the address (§8.1).
    `--tls-ca=FILE` trusts the authorities of a PEM file instead; `--tls-insecure` any certificate, for tests.
    Rejected: dig's default, which verifies nothing without `+tls-ca`.
  - Queries over TLS are padded to a multiple of 128 bytes (RFC 8467 §4.1); padding the caller set is replaced.
    The CLI refuses `+noedns` over TLS or QUIC, which would leave a query unpadded.
  - The CLI writes a TLS server `tls://HOST[:PORT][#NAME]`, or any server with `+tls`; port 853 unless given. An
    address, `[ADDRESS]:PORT` or with its zone, is taken as such before any name; a name for TLS is made only
    over TLS or QUIC.
  - Tests make their certificates with rcgen at run time, so no private key is checked in.
- D61 DoQ (RFC 9250) goes through compio's QUIC (`compio-quic`, quinn-proto underneath), no QUIC of our own.
  One connection per server and certificate name, opened on first use: queries meanwhile wait for it instead of
  opening another. Each query goes alone on its own bidirectional stream, behind its length, with ID 0
  (§4.2.1) and no cookie, since QUIC checks the client's address itself. The connection closes after D27's idle
  time (§4.4) and is opened again on the next query; a query on a reused connection found closed goes again once
  on a new one, as D27's TCP. A query given up is cancelled with STOP_SENDING and RESET_STREAM (§4.3.1). A
  response is read up to its 2 + 65535 bytes, a longer stream being a protocol error; the server may open no
  stream (§4.3.3), the client allowing none.
  - TLS 1.3 only (RFC 9001 §4.2), ALPN `doq`, the same trust as D60 (strict profile). No 0-RTT, early data off: a query waits for
    the handshake, since one in early data could be replayed (§4.5).
  - Queries are padded as over TLS (§5.4), and carry no edns-tcp-keepalive (§5.5.2).
  - The CLI writes a QUIC server `quic://HOST[:PORT][#NAME]`, or any server with `+quic`; UDP port 853 unless
    given.
- D62 DoH (RFC 8484) waits for compio to release tokio's I/O traits on its streams (the `h2` crate needs them;
  draft on branch `feat/io-tokio-compat` of compio); no adapter of our own meanwhile. HTTP/3 waits for compio
  too. Queries go by GET by default, ID 0 so HTTP caches can keep them (§4.1), and by POST with
  `+https-post`, as dig.

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
  `just bench-unbound`. `unsafe` only where a profile shows bounds checks matter. `Message::decode_reusing`
  decodes without allocating once warm; the server decodes each upstream response once with `Message::decode`
  (D46).
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
  §7.3.1) and encoded once without OPT, its TTL offsets after it in the same allocation. Negative (NXDOMAIN, or no
  answer of the type asked, after any CNAME chain) only with an SOA at or above the chain's last name, and the
  chain's TTLs within the negative TTL (RFC 2308 §2, §5). A hit copies and patches ID, flags (AA and Z clear, AD
  only when asked), question case and TTLs, never above the stored TTL; one too large for the buffer is encoded
  again truncated, outside the lock. Serve-stale (RFC 8767: 30 s answer TTL, 3 days kept) and failure holds (RFC
  9520: 5 s doubling to 300 s, 30 s with stale data, never above 300 s; a failure during a hold does not count, a
  quiet spell over 300 s starts over); the caller decides when stale data may answer.

## CLI

- D17 (superseded by D36) Query files in JSON or YAML, picked by extension or `--format`.
- D36 Query files (`dedens-scenario`), so the server's tests reuse them: one serde model (queries, options,
  optional expectations; a failed one makes `dedens` exit non-zero) read as YAML 1.2 by serde-saphyr, `-` for
  stdin. JSON is YAML 1.2, so JSON files read too, at the price of YAML-worded errors; no input format flag, no
  second reader. `dedens` drops dig's layout (`--dig`): JSON and YAML serve scripts, the human output people, and
  dig itself a side-by-side comparison. Rejected: serde_yaml (archived 2024-03), serde-yaml-ng (no commit in a
  year).
- D18 `dedens`, dig but better: dig argv (`@server name type class +opts`) and long flags; query files;
  output for humans by default, JSON or YAML for scripts (D37), `+short`, color; several names, types or servers
  per run, concurrent, side by side; timing, transport, sizes, EDNS, cookies and EDE in words; `+trace`;
  `--repeat N` with latency percentiles; `--save-wire` (the source of captured test data); default server from
  `/etc/resolv.conf`. `-x ADDR` asks PTR for the `in-addr.arpa` or `ip6.arpa` name of an address (RFC 1035 §3.5,
  RFC 3152). The `resolv.conf` search list (`search`, `domain`, `ndots`) applies only with `+search`, as in dig: a
  debugging tool asks for the name typed. Unicode names are converted to A-labels (IDNA2008, RFC 5891 and 5895) and
  shown as such, with labels mixing scripts flagged (IDN homographs).
- D32 CLI arguments: a pre-pass turns dig tokens into long flags (`@srv` → `--server srv`, `+opt` → `--opt`,
  `+noopt` → `--opt=false` for an on/off flag only, `+opt=v` → `--opt=v`, `opt` any unique prefix as in dig;
  `-t TYPE`, `-c CLASS`, `-q NAME` → words; `-p PORT` for a server without one), leaving the value of a flag and
  anything after `--` alone, then clap parses. One option set for both spellings (clap derived on
  `dedens_scenario::Options` behind its `clap` feature), one help. An option needing EDNS (`bufsize`, `dnssec`,
  `nsid`, `cookie`) with `+noedns` is a usage error; AXFR/IXFR are refused until supported; several
  `@servers`: D38. At most 64 queries in flight; each result prints, in argument order, as soon as it is ready.
  Several names and types per run go concurrently on one compio runtime; as in dig, a name is asked the types
  written after it, and one without any the types written before the first name, else A. Output formats: D37;
  color with anstream/anstyle, `--color auto|always|never`, `NO_COLOR` honoured. IDNA with the `idna` crate (UTS 46
  nontransitional, near RFC 5895) and `unicode-script` for mixed-script labels (Han with kana, Hangul or Bopomofo,
  and Latin, being one writing, UTS 39 §5.2), both in `apps/dedens`: the library stays ASCII. `resolv.conf` read by
  our own parser (`nameserver`, `search`, `domain`, `ndots`), `DEDENS_RESOLV_CONF` overriding its path for tests;
  no Windows yet. `+search` tries the next candidate on NXDOMAIN. A class word applies to every query of the run.
  `-f FILE --only ID` runs some queries of a file.
- D33 Exit codes of `dedens`: 0 a response came, whatever its rcode (as dig); 1 an expectation failed; 2 usage;
  9 no reply (timeout, a refused or reset connection); 10 any other error, a failed `--save-wire` write too,
  which leaves the other results.
- D34 Query file schema (D36): top-level `server` and `options`, then `queries`, each with `id` (the
  `--save-wire` file name, so no `/`, `\`, `.` or `..`, unique in the file; default `name_type`, `root_type`
  for the root), `name`, `type`, its own `server`/`options`, and `expect`: `rcode`, `flags` that must be set,
  and `answer`/`authority`/`additional` as presentation lines compared as lists in any order, a line written
  twice expecting two records, the TTL compared only when written. `--save-wire DIR` writes the response to
  `DIR/<id>.bin`. Options are dig's `+` options by name (`tcp`, `ignore`, `recurse`, `cdflag`, `adflag`, `edns`,
  `bufsize`, `dnssec`, `nsid`, `cookie`, `time`, `tries`), each one left out inherited (command line, query, file,
  dig's default); `cookie` is `true`, `false` or a fixed cookie in hex, so captures repeat. `+ignore` and
  `+nocookie` need `dedens-net` exchange options `tcp_fallback` and `cookies`.
- D35 (superseded by D37) `--json` as JSON lines, every field present however empty.
- D37 `dedens --format human|short|json|yaml` (`+short`, `--json`, `--yaml` its shorthands, one at most), each
  response printed as it is ready. `human`, the default, is for reading: a status line (question, rcode in color
  and in words unless NOERROR, RTT, server without port 53, transport), then each non-empty section under its
  name, a record's owner shown once per run of the same owner and its TTL as a duration (`45m41s`); `no records`
  for an empty NOERROR answer; one quiet line of the flags worth a word (authoritative, truncated, recursion
  unavailable, DNSSEC-validated, checking disabled), EDNS and the sizes; EDE, violations and failures in red, one
  per line. `json` (one object per line) and `yaml` (one `---` document each) are for programs and stay short:
  the `dedens-scenario` report, TTLs in seconds, RTT in microseconds, an empty list or string and EDNS version 0
  left out, an absent field meaning empty. Server, transport, RTT (`rtt_us`), sends and query size sit in an
  `exchange` object, absent for a response read from a file; each record is `{name, ttl, class, type, data}`
  with `data` its presentation text; EDNS options are typed (`nsid`, `cookie`, `ede`, else `other` with the data
  in words, EDE text with control characters escaped); protocol violations (D9) go in `violations`, broken
  expectations in `failures`. Serialized only, until the server's tests need to read it back. Replaces D35,
  whose objects held every field however empty.
- D38 Several `@servers`: each query is asked of each, the blocks of one query together in argument order,
  each id then `name_type@server` (port left out when 53, `+tls` or `+quic` after it for a `tls://` or
  `quic://` server) so `--save-wire` keeps them apart. A query file's
  queries go to the command line's servers when given. The human format ends a query's blocks with
  `servers disagree: a, b vs c` when the rcodes or answer records, TTL and order aside, differ; JSON and YAML
  leave the comparison to their reader. A server that does not answer is left out of it.
- D39 `--repeat N` (`+repeat=N`): each query is asked of each server N times in a row, not concurrently, so
  the round trips are the server's and not our queue's. The last response is printed, with a `latency` object
  when N > 1: `sent`, `errors` (left out when 0) and `min_us`/`p50_us`/`p90_us`/`p99_us`/`max_us`, nearest
  rank over the answered round trips; the human format shows them in milliseconds on one line. Exit code 0 when
  any answer came, else the last error's.
- D40 `+trace`: each query asked from the root servers (IANA's `named.root`, bundled; `just root-hints`
  refreshes it) without RD, down the referrals (RFC 1034 §4.3.2: NOERROR, no answer, no AA, NS and no SOA in
  the authority section, a SOA being NODATA per RFC 2308 §2.2), one report per hop, until an answer, NXDOMAIN,
  NODATA or an authoritative response. A referral that comes no closer, an error rcode or a lame response sends
  the hop to the next address (RFC 1034 §5.3.3), three at most, IPv4 and IPv6 in turn so either route works.
  Glue is an address record of a name server inside the answering server's zone (RFC 2181 §5.4.1), unlike dig;
  name servers without glue are looked up the same way, A then AAAA, at most 4 deep, those inside the referred
  zone skipped (they lead back to the same referral). A trace makes 100 exchanges at most. No DNSSEC
  validation, no CNAME following. Refused with `@server`, `-f`, `--repeat`, `--search`, `+tls` and `+quic`. The human format
  counts the additional records of a referral hop instead of listing them. `DEDENS_ROOTS` replaces the roots
  for tests.

## Server

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
- D41 (amended by D43, D46) Server core (`dedens-server`), sans-IO as D26: `Pipeline::query` takes the query's
  bytes and transport and returns a step: a reply in the caller's buffer, nothing, or a request for an upstream
  server whose response goes back through `Pipeline::receive`; `apps/dedensd` does the I/O. Before the stages the
  core answers what none should see: responses and bytes shorter than a header are dropped; FORMERR to a query it
  cannot read (the header alone, no OPT), that breaks a rule (D9) or has no question; NOTIMP to opcodes other than
  QUERY; BADVERS to EDNS versions above 0; REFUSED to AXFR and IXFR, and when no stage answers. A reply has the
  client's ID, opcode and question in its case; QR and RA set, RD and CD copied, AA clear, AD only for a query with
  AD or DO (RFC 6840 §5.8); our OPT (1232 bytes, DO copied) only when the query had one. Over UDP it fits the
  client's payload, 512 to 1232 bytes, 512 without EDNS, truncated as D10; over TCP it comes whole. The forward
  stage asks its servers in order, the next on no response, one undecodable or breaking a rule, TC, or SERVFAIL,
  REFUSED, NOTIMP, FORMERR (RFC 1035 §7.3); after the last, SERVFAIL. Upstream gets the client's question, RD set,
  AD and CD copied, our EDNS with DO and none of the client's options: the client subnet never leaves (privacy),
  cookies are per hop (D27). Rejected: an async stage trait over a mock upstream (sans-IO tests are exact, as D26).
- D42 (amended by D45, D47-D49, D52) `dedensd` I/O around D41: one compio thread per core on Linux, each with its
  own UDP socket and TCP listener on every `listen` address (`SO_REUSEPORT`, the kernel spreading queries), one
  thread elsewhere, where `SO_REUSEPORT` does not spread; IPv6 sockets IPv6-only, so `[::]` and `0.0.0.0` bind
  together. Every socket is bound before any thread starts, so a taken address fails the start. A reply the
  pipeline builds at once goes out from the socket's task; a query for upstream gets a task owning its `Upstream`
  and asks with the thread's `dedens_net::Client`, over the client's transport, with the forward stage's timeout
  and tries (D45). TCP (RFC 7766): queries read in turn, each answered when ready, replies in any order through one
  writer (§6.2.1.1); reading stops after 10 s without a query, the connection closes once pending replies are
  written (§6.2.3). Listeners and upstreams from the configuration (D44). Rejected: one socket shared by all
  threads (contention on one receive queue); a task per query on the cached path (an allocation per hit).
- D43 (amended by D45, D46) Cache stage (D22 in D41's pipeline): `Stage::Cache` looks the query up at `now`,
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
- D44 (amended by D64) `dedensd` configuration, D24 narrowed for the first server: one YAML file (`--config`), as D36's query
  files; `listen` addresses, `zero_buffers` (D52), `pipeline` (stage names in order), `stages` (name to settings
  under `type`: `cache` with `dedens_cache::Config`'s fields, `forward` with `servers`, `IP` meaning port 53).
  `${VAR}` is replaced in the text before YAML reads it; a value spanning lines is refused, as it would add YAML.
  Errors: unknown fields, duplicate names, a stage listed and not defined, defined and not listed, listed twice or
  after a forward stage (which answers every query). `dedensd validate` reads the file and builds the pipeline
  without binding; SIGHUP reloads it (D55). Later, with need: a directory merged, `SECRET[..]`, JSON Schema.
- D45 Upstream patience and the client response timer (RFC 8767 §5), changing D42 and D43: a forward stage
  waits `timeout_ms` per query (default 3000, slow authoritative chains take over 1 s) and sends each server
  `tries` queries (default 2), carried on `Upstream` (`Upstream::patience`). A cache stage's
  `stale_answer_after_ms` (default 1800, the RFC's suggestion; 0 waits for resolution) is the client response
  timer: `dedensd` races it against the upstream exchange, and when it ends first calls `Pipeline::stale`,
  which answers with expired data (`StalePolicy::Always`, TTL 30, EDE 3 or 19) if the cache keeps any. The
  exchange goes on: its response only refreshes the entry, so the next query has it fresh; its failure is held,
  with no second reply. A refresh of a fresh entry (D43) has no timer. Rejected: a stale answer without
  resolution going on (the next query would wait again); a second task per query for the timer (the exchange
  future is polled with a deadline, then awaited).
- D46 Review fixes to D41-D45. A query without RD gets fresh cached data only (RFC 1034 §4.3.1: no recursion;
  RFC 8767 §5: no expired data), else REFUSED with EDE 20 (Not Authoritative, RFC 8914 §4.21); it never goes
  upstream, so it cannot start a hold every client shares. Upstream queries set RD (a refresh started by such a
  query too) and copy the client's AD (RFC 6840 §5.7), so AD can come back. `dedensd` turns the EDNS fallback
  off: a response without OPT would be stored for clients with DO (RFC 3225). A failure of ours
  (`ClientError::is_local`: no randomness, no socket, any socket error but the network or server refusing,
  resetting or unreachable) is `Pipeline::abandon`: SERVFAIL, no next server, no hold. The configuration refuses
  a second cache stage (it would never be filled). A panicking serving thread ends `dedensd` with an error.
  The client response timer of D45 runs only when the cache keeps expired data for the query
  (`Lookup::Expired`). A cache hit allocates nothing (`benches/server.rs`). The exchange checks a response with
  `Query::read`, and the pipeline decodes it once.
- D47 (amended by D64) `dedensd` limits, per thread (RFC 7766 §10, D42 had none): 1024 upstream queries in flight (past them a
  UDP query is dropped, a TCP connection closed), 256 TCP connections (past them a new one is closed at once);
  per connection, 64 queries in flight (reading waits; a bounded channel is the semaphore) and 10 s to write a
  reply (a client that stops reading loses its connection). A query waiting upstream holds no reply buffer until
  a reply is made. Constants for now; configuration with need. Client allow and block lists come later
  (`docs/TODECIDE.md`).
- D48 Four tasks answer on each UDP socket of a thread, so a receive stays posted while one answers or sends:
  one task waited for its reply to go out before receiving again. `just bench-dnsperf` (Linux, io_uring, one
  core, cache hits) measures `dedensd` against a git ref: 1 task about 310k queries/s, 2 about 340k, 4 about
  415k, 8 and 16 no better. A TCP connection's writer writes the replies queued meanwhile together, up to 65535
  bytes: one write a reply held TCP to about 185k queries/s, batches reach about 1.8M (dnsperf pipelines 500
  queries). Copying each reply for the writer costs nothing measurable there (copying it twice did not move the
  numbers), so replies keep their copy and the writer task, which reads on while writing and keeps the replies
  of concurrent queries whole.
- D49 UDP queries arrive in buffers made once per thread (256 of 4096 bytes, compio's buffer pool): on Linux one
  io_uring multishot receive per socket fills them, and the socket's four tasks (D48) take turns at its stream
  of datagrams behind a lock, each giving its buffer back before its reply waits to be sent. About 400k →
  480k queries/s (`just bench-dnsperf`); 16 tasks no better. A query longer than a buffer (about 3.9 KiB) is
  cut short and read as broken; the socket keeps datagrams while every buffer is taken. Rejected: a receive
  asked for each datagram into the task's own 64 KiB buffer (one submission and one buffer per receive).
- D50 Upstream UDP queries share a fixed pool of 256 sockets per server and client (`dedens-net::udp`), each opened
  on first use on port 0 and connected, then kept: a query takes one at random and waits for datagrams with its
  ID, which the socket's task receives for every query on it. An off-path attacker guesses the ID and the
  socket: 16 + 8 bits (RFC 5452 §9.2), against about 32 with a socket per query; cookies (RFC 7873) and `0x20`
  stay the way to win more. Matching stays D27's: a datagram goes to each query waiting for its ID, and the
  exchange drops those of another question. A datagram is received whole, up to 65535 bytes, into
  one buffer per socket, whatever size the queries advertised. A socket error goes to the queries that sent on
  it, each counting it as a lost try; errors in a row pause the socket's task 10 ms. Forwarding to a second `dedensd` (`just bench-dnsperf HEAD forward`): about 125k → 127k queries/s,
  the upstream on one core being the limit there. Rejected: renewing sockets on a timer (no attack measured
  against a kept port yet); muxing by question too (the exchange checks it).
- D51 The io_uring of a serving thread runs completion work cooperatively (`COOP_TASKRUN` and `TASKRUN_FLAG`,
  Linux 5.19): when the thread enters the kernel, instead of interrupting it as a signal does. Forwarding
  (`just bench-dnsperf HEAD forward`): 135k → 158k queries/s; cache hits over UDP and TCP unchanged. Rejected:
  `SINGLE_ISSUER` with `DEFER_TASKRUN` (Linux 6.1), no better (160k); `SQPOLL` (cache hits over UDP 475k → 230k,
  forwarding 155k → 82k).
- D52 A TCP query answered after upstream writes its reply into a 65535-byte buffer the thread kept from an
  earlier one (up to 32, 2 MiB), not a new one. The buffer is zeroed first unless `zero_buffers: false` in the
  configuration: no byte of an earlier reply stays in it, should a bug ever send past the reply's length (the
  encoder writes before it reads, so nothing leaks today). Only these spare buffers are: the buffer each UDP
  task and each TCP connection reuse for the replies made at once (cache hits, plugins) keeps earlier replies'
  bytes past the current one's length; whether to zero or drop them is open. Forwarding over TCP (`just bench-dnsperf HEAD forward-tcp`):
  84k zeroing new buffers → 90k-92k reusing them unzeroed; zeroing them again costs part of it (79k-88k against
  87k-90k). Rejected: skipping the zeroing of new buffers (uninitialized memory behind `unsafe`).
- D53 Upstream TCP: the connection's writer task writes the queries queued meanwhile together, up to 65535 bytes,
  as D48's writer does for replies: one write and one wake-up of the server for many. Forwarding over TCP
  (`just bench-dnsperf HEAD forward-tcp`): about 87k → 275k queries/s, average latency 5.7 → 1.8 ms.
- D54 (amended by D64) Plugins (D23's custom stage types, for built-in stages too): `dedens_server::Plugin`, a trait object in
  `Stage::Plugin`, answers a query at once from what it holds, or passes it on; no upstream, no cache entry.
  Plugins live in `dedens-plugins`, configured in `dedensd` under their own `type`; cache and forward stay core
  stages, tied to the upstream steps. An answer is a response code, records already in wire form
  (`dedens_server::Records`, written once after a question for their name, so their compression pointers hold
  in any reply to that name), AA, and an extended error: the reply copies the records after the client's
  question, allocating nothing; records that do not fit are left out with TC (RFC 2181 §9). AA when the plugin
  holds the name's data as local knowledge (RFC 1035 §4.1.1, RFC 9499 §6), clear when it applies a policy.
  Plugins answer queries without RD too: their data is local. Rejected: a stage enum per plugin in the core
  (each plugin would grow `dedens-server`); plugins writing the reply themselves (each would redo D41's flags,
  OPT and sizing). Files are read at start and on each reload (D55).
  - `hosts`: lines in the `/etc/hosts` format, inline then from a file; A, AAAA and the PTR of each address to
    its first name, TTL 3600 unless set (as `CoreDNS`); a listed name asked another type has no data (RFC 2308
    §2.2) unless `fallthrough` passes it on; addresses with a zone (`fe80::1%lo0`) are left out.
  - `blocklist`: names, one a line or in the `/etc/hosts` format of published lists, blocking themselves and
    their subdomains; `action` NXDOMAIN (default), NODATA, REFUSED or the unspecified address, each with EDE 15
    Blocked (RFC 8914 §4.16), AA clear. Of hosts lines only those of `0.0.0.0`, `::`, `127.0.0.1`, `::1` count,
    without names of one label or starting with `localhost`: such files open with their host's own entries
    (`127.0.0.1 localhost`, `127.0.0.1 local`), and blocking `local` would block all of mDNS's `.local`.
    Formats, duplicates and the allowlist in D56.
- D55 (amended by D64) `dedensd` reloads its configuration file on SIGHUP (systemd's `ExecReload=kill -HUP $MAINPID`): the file
  is read and the pipeline built as at start, then swapped in. Each serving thread compares a generation counter
  before each query (one atomic load) and takes the new pipeline under a lock only when it changed, holding it in
  an `Rc` so a query touches no count shared between threads; a query waiting on upstream ends on the pipeline it
  started on. The cache stage is an `Arc<Cache>` kept while its settings are unchanged, else a new empty one. A
  file that does not read, or a hosts or blocklist file it names, leaves the running pipeline and logs an error;
  `listen` and `zero_buffers` take a restart (a warning), as does the thread count. Counted in
  `dedensd_reloads_total{result="ok|error"}`. The handler comes from `signal-hook`, installed before the
  server logs that it serves, so no SIGHUP ends the process. Rejected: compio's `signal`, which restores the
  default action between two waits, so a second SIGHUP during a reload would end the process; `arc-swap`,
  whose guards may not be held across an await and whose `Arc` clones share a count between threads. Later:
  watching the file, and upstreams pushed while running (D-Bus, for a systemd-resolved replacement).
- D56 Blocklist contents. `*.name`, hagezi's format for Blocky, is read as `name`: Blocky's documentation says it
  blocks the name and its subdomains, as any entry here does. A plain line holds one name. Names are host names,
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
- D57 (amended by D64) `dedensd` downloads blocklist and allowlist `urls` (`https://`, or `http://` for a server of one's own)
  with `ureq` 3, blocking, on the thread that reloads on SIGHUP: off the query path, and one thread so a refresh
  never swaps in a pipeline older than a reload's. Rejected: `cyper`, compio's client (hyper, a 0.10 beta).
  Certificates are checked against the OS trust store (`rustls-platform-verifier`); list hosts are resolved by
  the system resolver, possibly `dedensd` itself, which forwards them. Each list is kept in `downloads.dir`
  (`/var/cache/dedensd`) under the 64-bit FNV-1a hash of its URL, written to a `.part` file then renamed, with
  its `ETag` beside it: a start or reload reads the copies and serves at once (a list not downloaded yet is
  empty), and fetching sends `If-None-Match`, so an unchanged list is neither downloaded nor read again (304).
  A text replaces the copy only when it reads as a downloaded list (D56), at most 256 MB, within 30 s. Lists
  are fetched once the server serves, on each SIGHUP after its reload, and every `downloads.refresh_minutes`
  (1440, as numa and Pi-hole); a failure keeps the copy and retries after 1 min, doubling up to the interval. A
  change rebuilds the pipeline as a reload does (D55; the cache kept). Counted in
  `dedensd_list_fetches_total{result="changed|unchanged|error"}`. Later, with need: a list swapped alone instead
  of the pipeline, per-list intervals.
- D58 A blocklist holds the 64-bit `SipHash` of each name's lowercase wire form under a key drawn per `Lists`
  (std's `RandomState`), in a `HashSet<u64>` hashing them no further: 8 bytes a name instead of the name and its
  allocation. Published lists of 2.29M names: 110 MB resident instead of 240 MB, read in 0.64 s instead of
  0.87 s, lookups as fast (`benches/blocklist.rs`). A false match needs two names of equal hash, 2^-64 a pair:
  ~10^12 queries per wrong answer against 2M names, and the key, unknown outside the process, keeps a client from
  aiming at one. The cost: names cannot be listed back, so a blocked name under a blocked parent is no longer
  dropped (2% of those lists, 0.4 MB). Rejected: names in one buffer with offsets (~55 MB, exact, more code); a
  sorted `Vec<u64>` (18 MB instead of the set's 37 MB, a binary search per label); a trie or FST (a dependency,
  slower to build).
- D64 Review fixes to D44, D47, D54, D55 and D57.
  - Limits (D47): a TCP connection bounds the bytes of its queued replies, not their count: reading waits while
    more than 128 KiB wait for the writer, and the queue must empty within 10 s of its first reply, else the
    connection closes (a client asking faster than it reads). Replies of upstream queries are queued without
    waiting, so none holds its 65535-byte buffer meanwhile; the worst left is 64 replies of 64 KiB in flight past
    the bound. A TCP query the thread has no upstream slot for gets SERVFAIL (`Pipeline::abandon`) instead of
    closing the connection; a UDP one is still dropped. A UDP receive that fails right after another waits
    100 ms, as `accept` does, instead of spinning.
  - Panics: a serving thread waits on the tasks of its sockets, so one that panics (compio catches the panic and
    keeps it silent) fails the thread, and `dedensd` (D46). The reload thread runs each fetch and each reload
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

## Observability

- D30 Metrics through the `metrics` facade, tracing through `tracing`; each library takes them behind its own
  `metrics` or `tracing` Cargo feature, compiled away without it, and the binaries turn them on by default.
  Handles are made once with the component, not looked up per event; no recorder means no-op handles.
  `dedens-proto` has none: its functions are pure and return errors, violations and truncation as values, which
  the server counts where it calls them. The cache counts lookups by outcome, prefetches, inserts and evictions
  (names in `crates/dedens-cache/src/metrics.rs`); spans belong to net, server and CLI, not to hot paths of proto
  or cache. `dedensd` will export Prometheus (not yet: it builds the cache without `metrics`); the CLI prints
  `tracing-subscriber` text on stderr (`dedensd` one JSON object a line, `--log-format text` for people, so tests
  and log pipelines read fields, not prose), `-v` for debug (dropped messages, retries, fallbacks, `+trace` referrals, a
  span per hop) and `-vv` for trace (every message sent and received), without `env-filter` and its regexes; its
  `dedens: …` errors stay plain output. OpenTelemetry later. Cost in `docs/benchmarks.md`.
