# testdata

Real data read by the tests, benches, fuzz targets and simulations of more than one package (D161); data one package
reads stays in it. A package reads it through `dedens_testkit` or an `include_bytes!` of the file, never through
another package's directory.

- Never edit a capture by hand: capture it again (`just capture`, `just capture-dnssec`, the `capture.nu` of `doh/`
  and `coap/`), and update the `README.md` beside it where there is one.
- A new capture of `dnssec/` with a denial goes in the tables of `crates/dedens-dnssec/tests/denial.rs`.
