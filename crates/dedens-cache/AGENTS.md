# dedens-cache

The server's response cache (D22). The rustdoc holds its rules; `README.md` the memory an entry costs and the
complexity of each operation: update both in the same change as the behaviour they describe.

Sans-IO: the caller passes the time in seconds, so tests drive the clock. Speed is benched in
`crates/dedens-bench/benches/cache.rs`. Feature `metrics` (D30): counters in `src/metrics.rs`, tested in
`tests/metrics.rs`.

## Invariants

- A hit that fits `out` copies and patches under the shard lock: no decode, no allocation. Slower work (truncation)
  runs on an `Arc` clone after the lock is released. The `hit` bench of `benches/server.rs` counts allocations;
  keep it at zero.
- Every change to an entry goes through `Shard::update`, which keeps `small_bytes` and `main_bytes` exact; the
  proptest in `src/shard.rs` (`Shard::check`) asserts it, so extend `check` with any new field that costs bytes.
- The shard is picked from bits 40 and up of the hash: `HashMap` takes buckets from the low bits and tags from the
  top 7. A wider shard count or another map must keep those bit ranges apart.
- Time is `u32` seconds from any origin and may go back: use saturating arithmetic and keep `Response::left` and
  `Cache::held` bounded.
- `Config` field names and the metric names are public: `dedensd`'s configuration file and Prometheus series.
