# dedensd

The server binary (D42, D44): sockets, files, signals and threads around `dedens_server::Pipeline`. RFC behaviour
belongs in `crates/dedens-server` and its sans-IO tests.

- State that `src/reload.rs` and `src/flights.rs` share between threads takes its types from `src/sync/mod.rs`, so the
  loom tests beside them see it (`just loom`, D135).
- A new listener applies `action: drop` (`Pipeline::drops`) before it takes a connection slot or does a handshake
  (D91).
- A test that writes a key file goes through `util::write_key` (0600): a key others can read is refused (D115).
- The benches include `tests/util/server.rs` alone by `#[path]` (D170): it names nothing else of `util`.
- `tests/listeners.rs` expects the `io_uring` driver on Linux 6.0 or later (D174); set `DEDENS_TEST_ALLOW_POLL` where seccomp refuses it.
- Measure a change to `src/serve/` with `just bench-dnsperf <base> <mode>` (modes in the justfile) and record it in
  `docs/benchmarks.md`.
- `src/lib.rs` is the crate, `src/main.rs` only calls `dedensd::main` (D181). A configuration setting naming a file
  to read goes in `names_files` (`src/config/`), or `fuzz/`'s `read_config` opens the paths its inputs name.
