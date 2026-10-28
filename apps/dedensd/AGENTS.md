# dedensd

The server binary (D42): `src/main.rs` parses flags and starts the threads, `src/serve.rs` binds the sockets and
runs the UDP, TCP and upstream tasks around `dedens_server::Pipeline`. RFC behaviour belongs in
`crates/dedens-server` and its sans-IO tests; `tests/serve.rs` runs the binary on loopback against a responder
answering captured bytes.
