# Decisions

Each decision records the choice, its reason and the alternatives rejected. Numbers are stable: a replaced
decision is marked superseded, never reused. The rules a decision produces live in `AGENTS.md`.

## Scope and architecture

- D1 Crates: `dedens-proto` (wire format), `dedens-net` (transports), `dedens-scenario` (query files, D17),
  `apps/dedens` (CLI). Later `dedens-resolver`, `dedens-server`, `apps/dedensd` and a kube backend, all built on
  these crates. CLI and server are separate binaries.
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
  ns a/mx/txt_large 77/174/325 against 97/195/341 for decoding and dropping.
- D15 `unsafe` is a hot-path tool: the bench comes first, Miri and RAPx follow.
- D16 Checks beyond the gate, each added with its trigger: Miri with the first `unsafe`, loom with the first
  hand-written concurrent structure, cargo-semver-checks with the first crates.io release, the fuzz workflow
  with the first fuzz target. RAPx runs weekly, outside the gate: it compiles against rustc internals and
  breaks on nightly changes unrelated to our code.

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

## Later, undecided

crates.io publishing, container image, dnsperf benchmarks against Unbound and CoreDNS.
