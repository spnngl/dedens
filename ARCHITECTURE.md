# Architecture

dédéns: a DNS library, the dig-like CLI `dedens` and the server `dedensd`. Each folder's `AGENTS.md`
says what it holds.

## Crates

| Path | Role | I/O |
|---|---|---|
| `crates/dedens-proto` | Wire format and zone-file text: messages, names, records, EDNS | none (sans-IO) |
| `crates/dedens-cache` | Response cache for the server: sharded, serve-stale | none, time passed in |
| `crates/dedens-server` | Server core: the stage pipeline and the replies it builds itself | none (sans-IO) |
| `crates/dedens-net` | UDP and TCP transports on compio over a sans-IO exchange; `resolv.conf` | sockets, timers |
| `crates/dedens-scenario` | Query files: queries, options, expectations; the JSON and YAML report | none |
| `crates/dedens-bench` | Benches against hickory-proto, `domain`, Go's `miekg/dns`, Unbound | none |
| `apps/dedens` | The dig-like CLI | via `dedens-net`, files |
| `apps/dedensd` | The server: threads and listeners around `dedens-server`, upstream through `dedens-net` | sockets |
| `fuzz/` | libFuzzer targets, own workspace | none |

Everything builds on `dedens-proto`; `dedens-scenario` also on `dedens-net`; `apps/dedens` on both; `apps/dedensd`
on `dedens-server` and `dedens-net`. Planned: `dedens-cache` in `dedensd`, then `dedens-resolver`.

## Data flow

- Client: `Message::query` → `encode` into a buffer → `dedens-net` → `Message::decode` (borrows the input) →
  output, with any `Violation` shown.
- Server hot path: bytes → `Query::read` (in place, no allocation) → `Cache::lookup` → hit: copy the stored
  bytes, patch ID, flags, question case and TTLs, `Edns::append` → send. Miss: the D23 stage pipeline, then
  `Cache::insert`.
- Server-side reading of responses: `Message::decode_reusing` (records keep RDATA as bytes, D28) → the
  forwarder's checks → `Cache::insert(query, decoded)`, which encodes it once and finds its TTLs with
  `message::ttl_offsets`.
- Zone files: `ZoneReader` → `DecodedRecord`s; `$INCLUDE` goes back to the caller.

## Documents

- [`docs/decisions.md`](docs/decisions.md): every design choice and its reason (`Dn`).
- [`docs/TODECIDE.md`](docs/TODECIDE.md): open questions with proposed defaults.
- [`docs/benchmarks.md`](docs/benchmarks.md): measurements behind the performance decisions.
- [`docs/rfc/coverage.md`](docs/rfc/coverage.md): each RFC's status, code and tests; the RFC texts are in
  `docs/rfc/archive/`, the list in `docs/rfc/list.md`.
- `justfile`: every task; `just check` is the gate.
