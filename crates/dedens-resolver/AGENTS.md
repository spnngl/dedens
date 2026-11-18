# dedens-resolver

The recursive resolver. Sans-IO: the caller passes the time in seconds and the random source, so tests drive
both. The rustdoc holds the rules; D192 the scrubber's choices, D193 the `RRset` cache's, D194 the infra cache's.

The caches keep their entries in `dedens_cache::Store` (D193): its sharding, byte budget and S3-FIFO are
`dedens-cache`'s, tested there. Feature `metrics` (D30): counters in `src/metrics.rs`, tested in `tests/metrics.rs`.
The integration tests are one binary, `tests/tests.rs` (D162), but for `memory.rs`, which sets the process's
`#[global_allocator]`.

## Invariants

- Nothing reaches a cache or a client but through `scrub`: it alone knows the zone a server was asked as, which
  bounds what the server is trusted with (RFC 2181 §6.1). Its `Rank`s are what the cache's replacement reads.
- A rule of `scrub` changes with D192 and a test in `tests/scrub.rs`; a bound is a named constant with its Unbound
  value, and a test reaches it.
- `scrub` is total: any message, any zone, no panic. The fuzz target `scrub_response` checks that what it keeps is
  within the zone.
- A value's `Cost` counts the bytes asked for every allocation it owns (`Rrset::cost`: the `Arc`, the owner name,
  the RDATA slices, each RDATA); `tests/memory.rs` checks it against the allocator's count. The allocator's rounding
  and headers are not counted: up to 1.5 times more on glue (D193). A new owned field means a new term.
- `insert` trusts its rank: the input is scrubbed (step 05), in bailiwick. Only answer non-authoritative and
  above, or secure data, may answer a client (RFC 2181 §5.4.1); `get` returns every rank.
- Replacement follows Unbound's `need_to_update_rrset` but for three choices of D193: verdicts on the same data,
  an NS `RRset` bounded whatever its trust, and an address over glue pinned whatever its TTL and across a verdict
  (`Cached::pins`). A change there goes to D193 and `tests/rrset_cache.rs`.
- Keys are the owner name in lowercase (RFC 4343): a lookup lowers its name the same way, through `key_of`.
- The infra cache's lame keys lower the zone the same way, through `lame_key`; its `Cost` is 0: its entries own no
  allocation, the key and slot are the store's.
- The infra cache's random draw takes a `CryptoRng` (RFC 5452 §4.4): the server asked must not be predictable.
- The value is an enum (`Entry`) so that negative entries (step 12) share the `RRset` cache's key space: add a
  variant, not a second store.
- Time is `u32` seconds from any origin and may go back: use saturating arithmetic.
- The metric names are public: Prometheus series.
