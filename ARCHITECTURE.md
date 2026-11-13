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
| `crates/dedens-net` | UDP, TCP, TLS, QUIC, HTTP/3 (DoH, D83) and CoAP (DoC, D81) transports on compio over sans-IO cores; the client's pools and `dedensd`'s serving loop behind the `Io` seam (D134, D182); Oblivious DoH, `odoh` feature (D79); DNS stamps, `dnscrypt` feature (D102); `resolv.conf` | sockets, timers |
| `crates/dedens-scenario` | Query files: queries, options, expectations; the JSON and YAML report | none |
| `crates/dedens-bench` | Benches (divan) of the workspace, against hickory-proto, `domain`, Go's `miekg/dns`, Unbound; `dedensd` under dnsperf (`just bench-dnsperf`); the cache's hit ratio (`examples/hit_ratio.rs`, D116) | none |
| `crates/dedens-testkit` | Test-only (D161): `testdata/` read and decoded, the RFC examples' keys, the test certificates and the loopback responder of the binaries' tests | files, sockets (`responder`) |
| `crates/dedens-sim` | Simulation tests (D133, D134, D182): the sans-IO server core, `dedensd`'s serving loop and `dedens-net`'s client, pools included, as hosts of a seeded turmoil network | simulated |
| `crates/dedens-repo` | The repository checks of the gate (D140, D163), its tests alone: decisions, RFC coverage, `CLAUDE.md` links, crates' `clippy.toml`, pinned Rust | files (`git ls-files`) |
| `apps/dedens` | The dig-like CLI; a library its binary and `fuzz/` call (D181) | via `dedens-net`, files |
| `apps/dedensd` | The server: threads and sockets around `dedens-server`, upstream via `dedens-net`; drops root once bound (D122); a library its binary and `fuzz/` call (D181) | sockets, files, HTTP (lists) |
| `deploy/` | What a release ships beside the binaries (D153, D156, D158): the image's `dedensd.yaml`, the deb and rpm packages' files (systemd unit, sysusers, maintainer scripts, man pages that `just man` writes and each binary's tests compare with its command line), the licence report's `about.toml` | none |
| `fuzz/` | libFuzzer targets of the parsers of outside data, the binaries' included (D181), own workspace | none |
| `testdata/` | Real data the tests, benches, fuzz targets and simulations share: captures, RFC example zones, lists (D161) | read as files |

Planned: `dedens-resolver`.

## Data flow

- Client (`apps/dedens`): `Options::query` → `dedens-net` (Oblivious DoH through `Client::exchange_oblivious`, D79) →
  `Message::decode` → with `+validate`, `src/validate.rs` over `dedens-dnssec` (D76) → `Report::exchanged` →
  `src/output.rs` (D37), with any `Violation` shown.
- Server, a query: `apps/dedensd/src/serve/` (a module per transport, D65, D66, D81, D84; ODoH in
  `apps/dedensd/src/odoh/`, D79, D94) → `crates/dedens-server/src/access.rs` (D91) → `Query::read` →
  `cookie.rs` and `rrl.rs` (D113) → the stage pipeline (`pipeline/`, D23) of stages `plugin.rs`, `cache.rs` and
  `forward.rs`; a cache hit is copied and patched in place (`dedens-cache`, D116), every reply fitted to the query by
  `reply.rs` → send (UDP: the socket's `Outbox`, D123).
- Server, a response from upstream: `Message::decode` (D28) → `forward::usable` → with `dnssec: validate`,
  `validate.rs` (D77; its cost: `budget.rs`, D117; questions in flight shared: `apps/dedensd/src/flights.rs`, D86)
  → `Cache::insert` or `Cache::insert_checked`, encoded once there and served as a hit from then on (D43).
- Server, prewarm: a cache stage's `prewarm` names → `Pipeline::with_prewarm` (`crates/dedens-server/src/pipeline/prewarm.rs`)
  → one task of thread 0 (`apps/dedensd/src/serve/prewarm.rs`) asks each through `Pipeline::prewarm`, as a prefetch,
  when `Cache::refresh` says (D96).
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
