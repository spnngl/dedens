# Architecture

## Crates

| Path | Role | I/O |
|---|---|---|
| `crates/dedens-proto` | Wire format and zone-file text: messages, names, records, EDNS | none (sans-IO) |
| `crates/dedens-cache` | Response cache for the server: sharded, serve-stale | none, time passed in |
| `crates/dedens-server` | Server core: the stage pipeline and the replies it builds itself | none (sans-IO) |
| `crates/dedens-plugins` | Plugin stages (D54): hosts, blocklist | none (sans-IO) |
| `crates/dedens-dnssec` | DNSSEC validation (D69): signatures (`crypto/`; `rrsig/`: an `RRset` by its RRSIG and DNSKEY, a DNSKEY `RRset` by its DS), denial of existence, chain of trust and the verdict on a response (`validator`) | none (sans-IO), time passed in |
| `crates/dedens-odoh` | Oblivious DoH (RFC 9230), experimental (D69): configurations, message encryption | none (sans-IO) |
| `crates/dedens-net` | UDP, TCP, TLS, QUIC and HTTP/3 (DoH, D83) transports on compio over a sans-IO exchange; the sans-IO core of DoH (D82); `resolv.conf` | sockets, timers |
| `crates/dedens-scenario` | Query files: queries, options, expectations; the JSON and YAML report | none |
| `crates/dedens-bench` | Benches against hickory-proto, `domain`, Go's `miekg/dns`, Unbound | none |
| `apps/dedens` | The dig-like CLI | via `dedens-net`, files |
| `apps/dedensd` | The server: threads and sockets around `dedens-server`, upstream via `dedens-net` | sockets, files, HTTP (lists) |
| `fuzz/` | libFuzzer targets, own workspace | none |

Planned: `dedens-resolver`.

## Data flow

- Client: `Message::query` → `encode` into a buffer → `dedens-net` → `Message::decode` (borrows the input) →
  output, with any `Violation` shown.
- Server hot path: bytes → `Query::read` (in place, no allocation) → `Cache::lookup` → hit: copy the stored
  bytes, patch ID, flags, question case and TTLs, append our OPT record (`Edns::append`), pad over TLS and QUIC
  (RFC 8467) → send. Miss: the D23 stage pipeline (plugins, cache, forward), then `Cache::insert`.
- `dedensd` listens on UDP, TCP, TLS, QUIC (D66) and DoH over HTTP/3 (D84) and asks each upstream over its own transport (D65).
- Server-side reading of responses: `Message::decode` (records keep RDATA as bytes, D28) → `forward::usable` →
  `Cache::insert`, which encodes it once with its TTL offsets (`message::ttl_offsets`); the reply is then
  served from the entry as a hit (D43).
- Zone files: `ZoneReader` → `DecodedRecord`s; `$INCLUDE` goes back to the caller.

## Documents

- [`docs/decisions.md`](docs/decisions.md): every design choice and its reason (`Dn`).
- [`docs/TODECIDE.md`](docs/TODECIDE.md): open questions with proposed defaults.
- [`docs/benchmarks.md`](docs/benchmarks.md): measurements behind the performance decisions.
- [`docs/providers/providers.yaml`](docs/providers/providers.yaml): public resolvers and their endpoints,
  checked by `just providers` (D67).
- [`docs/blocklists/blocklists.yaml`](docs/blocklists/blocklists.yaml): published blocklists and their
  formats, checked by `just blocklists` (D87).
- [`docs/rfc/coverage.md`](docs/rfc/coverage.md): each RFC's status, code and tests; the RFC texts are in
  `docs/rfc/archive/`, the list in `docs/rfc/list.md`.
