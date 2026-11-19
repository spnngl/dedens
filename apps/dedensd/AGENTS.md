# dedensd

The server binary (D42, D44): sockets, files, signals and threads around `dedens_server::Pipeline`. RFC behaviour
belongs in `crates/dedens-server` and its sans-IO tests.

- State that `src/reload.rs` and `src/flights.rs` share between threads takes its types from `src/sync/mod.rs`, so the
  loom tests beside them see it (`just loom`, D135).
- A new listener applies `action: drop` (`Pipeline::drops`) before it takes a connection slot or does a handshake
  (D91).
- A `dnscrypt://` listener (D99) denies before it decrypts: `Pipeline::denies`, for both actions, in `serve/dnscrypt.rs` (UDP
  and the TCP codec), before any key work. Its keys live in `src/dnscrypt/`, one `Service` for all threads; time comes
  from the thread's `Io`, never `SystemTime`, but at start. `dnscrypt-keygen` is in the command line whatever the
  features, or the man page differs by build.
- A test that writes a key file goes through `util::write_key` (0600): a key others can read is refused (D115).
- The benches include `tests/util/server.rs` alone by `#[path]` (D170): it names nothing else of `util`.
- `tests/listeners.rs` expects the `io_uring` driver on Linux 6.0 or later (D174); set `DEDENS_TEST_ALLOW_POLL` where seccomp refuses it.
- `serve/udp.rs`, `tcp.rs`, `dnscrypt.rs`, `upstream.rs`, `recurse.rs`, `prewarm.rs` and `isolate.rs` take the
  clock, tasks, timers and sockets from the thread's `Io` (`thread.io`, `serve::pause`), `clippy.toml` denying the
  rest, so that `dedens-sim` runs them (D182); a change there gets its scenario in `crates/dedens-sim/tests/serving.rs`,
  `recurse.rs`'s in `crates/dedens-sim/tests/recurse.rs`.
- A transport turns a `Step::Upstream` of `Pipeline::query` into an `Ask` with `Ask::after`, or its query jumps the
  line of those waiting for the validation allowance (D186), and hands a `Step::Park` to `upstream::answer`, which
  waits; a `Step::Resolve` becomes `Ask::Resolve`, which `serve/recurse.rs` drives (D195): its queries in flight
  are the thread's own, never shared across threads.
- Measure a change to `src/serve/` with `just bench-dnsperf <base> <mode>` (modes in the justfile) and record it in
  `docs/benchmarks.md`. It builds on glibc, with the system allocator: measure a change to the allocator or its
  settings with `just bench-compare`, which runs the `Containerfile`'s musl binary.
- `src/lib.rs` is the crate; `src/main.rs` holds the musl build's allocator and its huge-page flag (D154), then calls
  `dedensd::main` (D181). A configuration setting naming a file
  to read goes in `names_files` (`src/config/`), or `fuzz/`'s `read_config` opens the paths its inputs name.
- A root file (D128) is read through `roots::open`: a regular file, itself no link (`O_NOFOLLOW`), of a capped length. The anchors kept
  in `state_dir` are what the validators trust without a signature: written only from a pair `TrustAnchors::verified`
  accepted, and a reload that cannot read them keeps those `Held` in the `Store`.
