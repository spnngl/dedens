# dedens-cache

The server's response cache (D22). Sans-IO: the caller passes the time in seconds, so tests drive the clock.
RFC behaviour is tested per RFC in `tests/rfcNNNN.rs`; speed in `crates/dedens-bench/benches/cache.rs`.
Feature `metrics` (D30): counters in `src/metrics.rs`, tested in `tests/metrics.rs`.
