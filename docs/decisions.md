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

- D7 `Name`: wire-form bytes, case preserved, compared and hashed ASCII case-insensitively (RFC 4343); built
  only through validating constructors (label 1..=63 bytes, name <= 255). Representation private: a compact
  heap copy first, a bench picks the final one (inline or borrowed). Rejected: a fixed 255-byte inline buffer,
  about 300 bytes per record whatever the name.
- D8 `Message`: header, questions, answer, authority, additional, and EDNS lifted out of additional into its
  own field, so no caller searches for the OPT record.
- D9 Decoder: bounds-checked cursor; a compression pointer must point strictly before the current label, which
  rules out loops; unknown types stay opaque RDATA (RFC 3597); every input decodes or errors (fuzzed).
  Strictness: broken structure (lengths, pointers, name size) is an error. A readable message that breaks a
  rule (several OPT, OPT outside additional, OPT owner not root, QDCOUNT > 1 per RFC 9619, trailing bytes)
  decodes and carries the violations: the CLI shows them, the server answers FORMERR. RDATA or an EDNS option
  that is well delimited but invalid inside (SVCB key order, CAA tag, client subnet prefix) is kept as received,
  opaque, with a violation, so typed values always hold their invariants. Exception: invalid RDATA of a type
  whose names may be compressed (RFC 3597 §4) is an error, since its pointers mean nothing outside this message.
- D10 Encoder: writes into a caller buffer with a size limit and no allocation (fits io_uring registered
  buffers), plus a `Vec<u8>` convenience. Compresses names only inside RFC 1035 types (RFC 3597 §4).
  Truncation: stop at the first record that does not fit; set TC only when the answer or authority section lost
  records, not for additional data (RFC 2181 §9); OPT is always kept (RFC 6891 §7); RFC 9471 glue rules come
  with the server. Compression table: a fixed-capacity array of earlier name offsets, matched byte for byte, so
  output keeps each name's case (RFC 4343) and needs no allocation. EDNS UDP payload 1232 by default (DNS Flag Day 2020).
- D11 RDATA v1: A, AAAA, NS, CNAME, SOA, PTR, MX, TXT, SRV, CAA, SVCB, HTTPS, OPT; every other type is opaque
  RFC 3597 data until added.
- D12 Typed EDNS options v1: cookie (RFC 7873), Extended DNS Error (RFC 8914), padding (RFC 7830), client
  subnet (RFC 7871), TCP keepalive (RFC 7828), NSID (RFC 5001); others opaque. Typed SVCB parameters: RFC 9460
  keys 0-6 and dohpath (RFC 9461); others opaque.
- D13 `dedens-proto` layout by topic, RDATA and conformance tests by RFC (rule in `AGENTS.md`). Rejected strict
  `rfcNNNN/` folders: names, the header and rcodes are each defined across several RFCs.
- D19 Codes (type, class, opcode, rcode, EDNS option, SVCB key) are newtypes over the integer with named
  constants, not enums with an `Unknown` arm: every value is representable once, and a new code is one constant.
  `Record` holds no type field: the type comes from its RDATA, so they cannot disagree.

## Performance and safety

- D14 Owned decode first, measured with divan; a borrowed zero-copy view once a bench shows the gain. Baselines
  in the same benches: hickory-proto and `domain` (dev-dependencies). Bar: no slower than hickory-proto;
  beating `domain` is the optimisation target.
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
