# Architecture

## Crates

| Path | Role | I/O |
|---|---|---|
| `crates/dedens-proto` | Wire format and zone-file text: messages, names, records, EDNS | none (sans-IO) |
| `crates/dedens-cache` | Response cache for the server: sharded, serve-stale | none, time passed in |
| `crates/dedens-server` | Server core: client access lists (D91), UDP and DoC rate limit and Server Cookies (D113), client budgets (D117), the stage pipeline and the replies it builds itself | none (sans-IO) |
| `crates/dedens-plugins` | Plugin stages (D54): hosts, blocklist | none (sans-IO) |
| `crates/dedens-dnssec` | DNSSEC validation (D69): signatures, denial of existence, chain of trust and the verdict on a response | none (sans-IO), time passed in |
| `crates/dedens-odoh` | Oblivious DoH (RFC 9230), experimental (D69, D78): configurations, message encryption | none (sans-IO) |
| `crates/dedens-net` | UDP, TCP, TLS, QUIC, HTTP/3 (DoH, D83) and CoAP (DoC, D81) transports on compio over sans-IO cores; the client's pools behind the `Io` seam (D134); Oblivious DoH, `odoh` feature (D79); `resolv.conf` | sockets, timers |
| `crates/dedens-scenario` | Query files: queries, options, expectations; the JSON and YAML report | none |
| `crates/dedens-bench` | Benches (divan) of the workspace, against hickory-proto, `domain`, Go's `miekg/dns`, Unbound; `dedensd` under dnsperf (`just bench-dnsperf`); the cache's hit ratio (`examples/hit_ratio.rs`, D116) | none |
| `crates/dedens-testkit` | Test-only (D161): `testdata/` read and decoded, the RFC examples' keys, the test certificates and the loopback responder of the binaries' tests | files, sockets (`responder`) |
| `crates/dedens-sim` | Simulation tests (D133, D134): the sans-IO server core and `dedens-net`'s client, pools included, as hosts of a seeded turmoil network | simulated |
| `crates/dedens-repo` | The repository checks of the gate (D140, D163), its tests alone: decisions, RFC coverage, `CLAUDE.md` links, pinned Rust | files (`git ls-files`) |
| `apps/dedens` | The dig-like CLI | via `dedens-net`, files |
| `apps/dedensd` | The server: threads and sockets around `dedens-server`, upstream via `dedens-net`; drops root once bound (D122) | sockets, files, HTTP (lists) |
| `deploy/` | What a release ships beside the binaries (D153, D156, D158): the image's `dedensd.yaml`, the deb and rpm packages' files (systemd unit, sysusers, maintainer scripts, man pages that `just man` writes and each binary's tests compare with its command line), the licence report's `about.toml` | none |
| `fuzz/` | libFuzzer targets of the parsers of outside data, own workspace | none |
| `testdata/` | Real data the tests, benches, fuzz targets and simulations share: captures, RFC example zones, lists (D161) | read as files |

Planned: `dedens-resolver`.

## Data flow

- Client: `Message::query` → `encode` into a buffer → `dedens-net` → `Message::decode` (borrows the input) →
  output, with any `Violation` shown.
- Server hot path: client address → access lists (D91, REFUSED or nothing for a denied one) → bytes →
  `Query::read` → Server Cookie check and, over UDP and DoC without a valid one, the rate limit of the client network
  (D113, TC=1 or nothing when over it) (in place, no allocation) → `Cache::lookup` → hit: copy the stored bytes, cut
  to the client's buffer (D116), patch ID, flags, question case and TTLs, append our OPT record (`Edns::append`), pad
  over TLS and QUIC (RFC 8467) → send (UDP: queued to the socket's `Outbox`, one sender a socket, D123). Miss: the D23
  stage pipeline (plugins, cache, forward; a plugin may review the responses of later stages, D118; ANY over UDP and
  DoC gets an empty TC reply, D114), then `Cache::insert`.
- `dedensd` listens on UDP, TCP, TLS, QUIC (D66), DoH over HTTP/3 (D84) and CoAP (DoC, D81), as an Oblivious DoH target (D79) and proxy (D94) with `odoh`, and asks each upstream over its own transport (D65).
- Server-side reading of responses: `Message::decode` (records keep RDATA as bytes, D28) → `forward::usable` →
  `Cache::insert`, whose `Response::build` (before the shard lock) encodes it once with its TTL offsets
  (`ttl_offsets`) and cut points, and floors and caps its TTL (`min_ttl`, `max_ttl`; D116, D124); the reply
  is then served from the entry as a hit (D43). A forward stage with `dnssec: validate` puts `dedens-dnssec`'s
  `Validation` between `forward::usable` and `Cache::insert_checked`: each question it asks is one more upstream
  `Step`, the verdict is kept with the entry and sets AD (D77, `crates/dedens-server/src/validate.rs`). A query's cost
  to the validator is capped and drawn from one shared allowance and the client network's share of it (SERVFAIL with
  EDE 14 beyond either, D117); `dedensd` shares the validator's questions in flight across threads
  (`apps/dedensd/src/flights.rs`, D77, D86).
- Zone files: `ZoneReader` → `DecodedRecord`s; `$INCLUDE` goes back to the caller.

## Documents

- [`docs/decisions/`](docs/decisions/README.md): every design choice and its reason (`Dn`), a file per section and
  an index.
- [`docs/TODECIDE.md`](docs/TODECIDE.md): open questions with proposed defaults.
- [`tests/interop/`](tests/interop/odoh.py): `dedensd` as an Oblivious DoH target for Cloudflare's `odoh-rs`
  (`just odoh-interop`, by hand, needs `uv` and the network); `just odoh-live` asks public targets (D79).
- [`docs/benchmarks.md`](docs/benchmarks.md): measurements behind the performance decisions.
- [`docs/alloc-security.md`](docs/alloc-security.md): what each candidate allocator stops (D152).
- [`docs/providers/providers.yaml`](docs/providers/providers.yaml): public resolvers and their endpoints,
  checked by `just providers` (D67).
- [`docs/blocklists/blocklists.yaml`](docs/blocklists/blocklists.yaml): published blocklists and their
  formats, checked by `just blocklists` (D87).
- [`docs/rfc/coverage.md`](docs/rfc/coverage.md): each RFC's status, code and tests; the RFC texts are in
  `docs/rfc/archive/`, the list in `docs/rfc/list.md`.
