# dedens

The dig-like CLI (D18, D32, D33): a thin binary over `dedens-net` and `dedens-scenario`, errors through `anyhow`.

- `src/args.rs`: dig's tokens turned into long flags, then clap; the words turned into names and types.
- `src/run.rs`: the queries of the command line or of a query file, asked concurrently on one compio runtime (64
  in flight), each printed in order as soon as it is ready; the exit code.
- `src/output.rs`: compact, `+short` and `--json` outputs of a `dedens_scenario::Report`.
- `src/idn.rs`: Unicode names to A-labels, mixed-script warnings.
- `tests/cli.rs`: the binary against `tests/common`, a UDP and TCP loopback server answering with the captured
  responses of `crates/dedens-proto/tests/testdata`; insta snapshots in `tests/snapshots/`, accepted with
  `INSTA_UPDATE=always` after review. `DEDENS_RESOLV_CONF` points the binary at a test `resolv.conf`.
