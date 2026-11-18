# dedens-resolver

The recursive resolver. Sans-IO: the caller passes the time in seconds, so tests drive the
clock. The rustdoc holds the rules; D193 the `RRset` cache's choices.

The caches keep their entries in `dedens_cache::Store` (D193): its sharding, byte budget and S3-FIFO are
`dedens-cache`'s, tested there. Feature `metrics` (D30): counters in `src/metrics.rs`, tested in `tests/metrics.rs`.
The integration tests are one binary, `tests/tests.rs` (D162), but for `memory.rs`, which sets the process's
`#[global_allocator]`.

## Invariants

- A value's `Cost` counts every allocation it owns (`Rrset::cost`: the `Arc`, the owner name, each RDATA);
  `tests/memory.rs` holds the allocator's count to 1.05 times the capacity. A new owned field means a new term.
- Keys are the owner name in lowercase (RFC 4343): a lookup lowers its name the same way, through `key_of`.
- The value is an enum (`Entry`) so that negative entries (step 12) share the `RRset` cache's key space: add a
  variant, not a second store.
- Time is `u32` seconds from any origin and may go back: use saturating arithmetic.
- The metric names are public: Prometheus series.
