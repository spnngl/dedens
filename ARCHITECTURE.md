# Architecture

dédéns: a DNS library, the dig-like CLI `dedens` and, later, the server `dedensd`. Each folder's `AGENTS.md`
says what it holds.

## Crates

| Path | Role | I/O |
|---|---|---|
| `crates/dedens-proto` | Wire format and zone-file text: messages, names, records, EDNS | none (sans-IO) |
| `crates/dedens-cache` | Response cache for the server: sharded, serve-stale | none, time passed in |
| `crates/dedens-net` | UDP and TCP transports on compio (phase 4, empty) | sockets, timers |
| `crates/dedens-scenario` | Query files: queries, options, expectations (empty) | none |
| `crates/dedens-bench` | Benches against hickory-proto, `domain`, Go's `miekg/dns`, Unbound | none |
| `apps/dedens` | CLI (empty) | via `dedens-net` |
| `fuzz/` | libFuzzer targets, own workspace | none |

Everything builds on `dedens-proto`; `dedens-cache` is its only user so far. Planned: `apps/dedens` on
`dedens-net` and `dedens-scenario`; later `dedens-resolver`, `dedens-server` and `apps/dedensd` on all of them.

## Data flow

- Client: `Message::query` → `encode` into a buffer → `dedens-net` → `Message::decode` (borrows the input) →
  output, with any `Violation` shown.
- Server hot path: bytes → `Query::read` (in place, no allocation) → `Cache::lookup` → hit: copy the stored
  bytes, patch ID, flags, question case and TTLs, `Edns::append` → send. Miss: the D23 stage pipeline, then
  `Cache::insert`.
- Server-side reading of responses: `MessageIndex::read` → `MessageView` (in place, O(1) record access).
- Zone files: `ZoneReader` → `DecodedRecord`s; `$INCLUDE` goes back to the caller.

## Documents

- [`docs/decisions.md`](docs/decisions.md): every design choice and its reason (`Dn`).
- [`docs/TODECIDE.md`](docs/TODECIDE.md): open questions with proposed defaults.
- [`docs/benchmarks.md`](docs/benchmarks.md): measurements behind the performance decisions.
- [`docs/rfc/coverage.md`](docs/rfc/coverage.md): each RFC's status, code and tests; the RFC texts are in
  `docs/rfc/archive/`, the list in `docs/rfc/list.md`.
- `justfile`: every task; `just check` is the gate.
