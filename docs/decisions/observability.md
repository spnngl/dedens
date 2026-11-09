# Observability

Decisions; the rules and the index are in [`README.md`](README.md).

- D30 Metrics through the `metrics` facade, tracing through `tracing`; each library takes them behind its own
  `metrics` or `tracing` Cargo feature, compiled away without it, and the binaries turn them on by default.
  Handles are made once with the component, not looked up per event; no recorder means no-op handles.
  `dedens-proto` has none: its functions are pure and return errors, violations and truncation as values, which
  the server counts where it calls them. The cache counts lookups by outcome, prefetches, inserts and evictions
  (names in `crates/dedens-cache/src/metrics.rs`); spans belong to net, server and CLI, not to hot paths of proto
  or cache. `dedensd` will export Prometheus (not yet: it builds the cache without `metrics`); the CLI prints
  `tracing-subscriber` text on stderr (`dedensd` one JSON object a line, `--log-format text` for people, so tests
  and log pipelines read fields, not prose), `-v` for debug (dropped messages, retries, fallbacks, `+trace` referrals, a
  span per hop) and `-vv` for trace (every message sent and received), without `env-filter` and its regexes; its
  `dedens: …` errors stay plain output. OpenTelemetry later. Cost in `docs/benchmarks.md`.
