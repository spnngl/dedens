# dedensd

The server binary (D42, D44-D57): `src/main.rs` parses flags and starts the threads, `src/config.rs` reads the
YAML configuration into a pipeline (D44), `src/serve.rs` binds the sockets and runs the UDP, TCP and upstream
tasks around `dedens_server::Pipeline`, `src/reload.rs` swaps the pipeline on SIGHUP (D55) and once downloaded
lists changed, which `src/download.rs` fetches (D57). RFC behaviour belongs in `crates/dedens-server` and its
sans-IO tests.

`tests/serve.rs`, `tests/reload.rs` and `tests/end_to_end.rs` run the binary on loopback against a responder
answering captured bytes (`tests/common/mod.rs`), reading its events as JSON, the default log format
(`Server::event`); `tests/end_to_end.yaml`, a `dedens` query file, holds what the replies must be.
`tests/lists.rs` serves lists from a loopback HTTP server; `tests/encrypted.rs` asks upstream over TLS and QUIC, with
the responder of `apps/dedens/tests/common` and its test certificates.

Measure a change to `src/serve.rs` with `just bench-dnsperf <base> <mode>` (modes in the justfile) and record it
in `docs/benchmarks.md`.
