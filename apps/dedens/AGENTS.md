# dedens

The dig-like CLI (D18, D32, D33): a thin binary over `dedens-net` and `dedens-scenario`, errors through `anyhow`.

- The tests run the binary against `dedens_testkit::responder`. `DEDENS_RESOLV_CONF` points it at a test
  `resolv.conf`; `DEDENS_NOW` sets the clock of `+validate`, the `captured_at` of `testdata/dnssec/`.
- Exit 9 is the errors `no_reply` of `src/run/mod.rs` names (D33): a new transport's timeout, refusal or reset goes
  there, or it exits 10.
- A usage check in `src/args.rs` that reads a server (`discovers_where_it_can`) reads it as `src/run/server.rs`
  does: it exits 2 before the run, so a mismatch refuses a server the run would ask.
- An error of `run` exits 10 unless it carries `run::Usage` (exit 2): a usage error only the run can find, such as
  a file an option names, takes that context.
