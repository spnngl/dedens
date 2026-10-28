# dedens-cache

The server's response cache (D22). Sans-IO: the caller passes the time in seconds, so tests drive the clock.
Speed is benched in `crates/dedens-bench/benches/cache.rs`. Feature `metrics` (D30): counters in
`src/metrics.rs`, tested in `tests/metrics.rs`.
