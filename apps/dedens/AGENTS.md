# dedens

The dig-like CLI (D18, D32, D33): a thin binary over `dedens-net` and `dedens-scenario`, errors through `anyhow`.

- The tests run the binary against `dedens_testkit::responder`. `DEDENS_RESOLV_CONF` points it at a test
  `resolv.conf`; `DEDENS_NOW` sets the clock of `+validate`, the `captured_at` of `testdata/dnssec/`.
