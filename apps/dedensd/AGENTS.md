# dedensd

The server binary (D42, D44-D53): `src/main.rs` parses flags and starts the threads, `src/config.rs` reads the
YAML configuration into a pipeline (D44), `src/serve.rs` binds the sockets and runs the UDP, TCP and upstream
tasks around `dedens_server::Pipeline`. RFC behaviour belongs in `crates/dedens-server` and its sans-IO tests.

`tests/serve.rs` and `tests/end_to_end.rs` run the binary on loopback against a responder answering captured bytes
(`tests/common/mod.rs`); `tests/end_to_end.yaml`, a `dedens` query file, holds what the replies must be.

Measure a change to `src/serve.rs` with `just bench-dnsperf <base> <mode>` (modes in the justfile) and record it
in `docs/benchmarks.md`; `zero_buffers` (D52) trades safety for TCP forwarding speed.
