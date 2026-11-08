# dedens

The dig-like CLI (D18, D32, D33): a thin binary over `dedens-net` and `dedens-scenario`, errors through `anyhow`.

- `src/args.rs`: dig's tokens turned into long flags, then clap; the words turned into names and types.
- `src/run/mod.rs`: the queries of the command line or of a query file, asked concurrently on one compio runtime,
  each printed in order as soon as it is ready (D32); the exit code. `run/server.rs`: the servers they go to, from
  the command line or `resolv.conf`.
- `src/output.rs`: `Format`: human (default), short, JSON and YAML outputs of a `dedens_scenario::Report` (D37).
- `src/idn.rs`: Unicode names to A-labels, mixed-script warnings.
- `src/validate.rs`: `+validate` (D76), the glue over `dedens_dnssec::Validator`: asks each question it wants of the
  server of the query, chases a CNAME chain, builds the report's `dnssec` (a secure response is shown as `covered`); `DEDENS_NOW` is its clock.
- `src/trace.rs`: `+trace` (D40), from the bundled `src/named.root`, which `just root-hints` refreshes.
- `tests/odoh.rs`: `+odoh-proxy` (D79) against the loopback target of `tests/common`, with the `odoh` feature.
- `tests/cli.rs`: the binary against `tests/common`, a UDP and TCP (or TLS, QUIC, HTTP/3 or CoAP) loopback server answering
  with the captured responses of `crates/dedens-proto/tests/testdata`; insta snapshots in `tests/snapshots/`, accepted with
  `INSTA_UPDATE=always` after review. `DEDENS_RESOLV_CONF` points the binary at a test `resolv.conf`. The loopback server also serves the captures of
  `crates/dedens-dnssec/tests/testdata`, which `+validate` is tested with at their `captured_at` (`DEDENS_NOW`).
