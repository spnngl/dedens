# dedens

The dig-like CLI (D18, D32, D33): a thin binary over `dedens-net` and `dedens-scenario`, errors through `anyhow`.

- The tests run the binary against `dedens_testkit::responder`. `DEDENS_RESOLV_CONF` points it at a test
  `resolv.conf`; `DEDENS_NOW` sets the clock of `+validate`, the `captured_at` of `testdata/dnssec/`.
- Exit 9 is the errors `no_reply` of `src/run/mod.rs` names (D33), and for `+tld` and `+rdap` the one of
  `src/run/rdap.rs`, which covers the body's read too: a new transport's timeout, refusal or reset goes there, or
  it exits 10.
- A usage check in `src/args.rs` that reads a server (`discovers_where_it_can`) reads it as `src/run/server.rs`
  does: it exits 2 before the run, so a mismatch refuses a server the run would ask.
- An error of `run` exits 10 unless it carries `run::Usage` (exit 2, D33): each mistake in the user's input the run
  finds (a name, a server's text, a query file, a file an option names) is one, found before any query and before
  `--save-wire` makes its directory; the network or a server failing never is. A `Usage` raised in a query's task
  exits 9 or 10, not 2.
- A `sdns://` server (D98, feature `dnscrypt`) is found in three places that agree: `refuse_conflicts` and
  `stamped` of `src/run/server.rs`, the `+dnscrypt-cert`, `+dnscrypt-relay` (D100), `+dnscrypt-pq`,
  `+dnscrypt-resume` (D101) and `+trace` checks of `src/args.rs`, and the `Endpoint`'s `dnscrypt` in
  `src/run/mod.rs`; a new option that is a transport goes in all three. Clap docs end in
  `deploy/packages/man/dedens.1`: `just man` writes it again.
- `+tld` (D129) and `+rdap` (D130) refuse every query option but `+time` by comparing `Options` whole, and each
  other field of `Cli` by name in `Cli::try_parse_dig`: a new field they cannot honour joins that list.
- `src/lib.rs` is the crate, `src/main.rs` only calls `dedens::main` (D181). `parse_args` is the entry of `fuzz/`: a
  usage check in `Cli::try_parse_dig` returns its error, never exits, or it ends the fuzz run.
- A transfer (D212, `src/run/transfer.rs`) is not D210's strict reader: it prints what arrives and ends on the SOA that
  repeats the first. `transfer::check` refuses every option it cannot honour (`job.options` equal to the defaults but
  `+time`): a new query option that a transfer ignores must not slip past it. A response failing TSIG is a failure
  (exit 1), shown, never dropped; `Report::exchanged` takes the TSIG record out of the sections, `exchange.tsig`
  carries the verdict.
