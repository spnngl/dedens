# dedensd

The server binary (D42, D44): sockets, files, signals and threads around `dedens_server::Pipeline`. RFC behaviour
belongs in `crates/dedens-server` and its sans-IO tests.

- State that `src/reload.rs` and `src/flights.rs` share between threads takes its types from `src/sync.rs`, so the
  loom tests beside them see it (`just loom`, D135).
- A new listener applies `action: drop` (`Pipeline::drops`) before it takes a connection slot or does a handshake
  (D91).
- A test that writes a key file goes through `util::write_key` (0600): a key others can read is refused (D115).
- `tests/listeners.rs` expects the `io_uring` driver on Linux; set `DEDENS_TEST_ALLOW_POLL` where seccomp refuses it.
- Measure a change to `src/serve/` with `just bench-dnsperf <base> <mode>` (modes in the justfile) and record it in
  `docs/benchmarks.md`.
