# dedensd

The server binary (D42, D44-D57, D63-D66, D84, D81): `src/main.rs` parses flags and starts the threads, `src/config.rs`
reads the YAML configuration into a pipeline (D44), `src/serve.rs` binds the sockets and runs the UDP, TCP, TLS,
QUIC, DoH over HTTP/3, DoC (`src/serve/coap.rs`, feature `doc`) and upstream tasks around `dedens_server::Pipeline`, `src/reload.rs` swaps the pipeline and the TLS
certificate on SIGHUP (D55, D66) and once downloaded lists changed, which `src/download.rs` fetches (D57). RFC
behaviour belongs in `crates/dedens-server` and its sans-IO tests.

`tests/serve.rs`, `tests/reload.rs` and `tests/end_to_end.rs` run the binary on loopback against a responder
answering captured bytes (`tests/common/mod.rs`), reading its events as JSON, the default log format
(`Server::event`); `tests/end_to_end.yaml`, a `dedens` query file, holds what the replies must be.
`tests/lists.rs` serves lists from a loopback HTTP server; `tests/encrypted.rs` asks upstream over TLS and QUIC,
with the responder of `apps/dedens/tests/common` and its test certificates; `tests/listeners.rs` answers over TLS
and QUIC with the certificates of `crates/dedens-net/tests/common`; `tests/rfc8484.rs` serves DoH over HTTP/3;
`tests/rfc9953.rs` DoC (feature `doc`); `tests/blocklists.rs` checks `docs/blocklists/blocklists.yaml` (D87).
`benches/doh3.rs` measures DoH over HTTP/3 (`docs/benchmarks.md`).

Measure a change to `src/serve.rs` with `just bench-dnsperf <base> <mode>` (modes in the justfile) and record it
in `docs/benchmarks.md`.
