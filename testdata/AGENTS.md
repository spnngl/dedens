# testdata

Real data read by the tests, benches, fuzz targets and simulations of more than one package (D161), through
`dedens_testkit` (`captured`, `dnssec::capture`, `zone`, `path` for any other file) or an `include_bytes!` of the
file. Never edit a capture by hand: capture it again.

- `proto/`: real responses from `just capture` (the queries of `capture.yaml`), read by
  `crates/dedens-proto/tests/message.rs` and as the answers of the other crates' tests; fuzz seeds.
- `dnssec/`: real responses from `just capture-dnssec` (the queries of `capture.yaml`), `captured_at` the "now"
  of the tests, `README.md` what each shows and the verdict a validator gives. Read by
  `crates/dedens-dnssec/tests/validator.rs` and `rrsig.rs`, and as the upstream of the validation tests;
  fuzz seeds. A new capture with a denial goes in the table of `crates/dedens-dnssec/tests/denial.rs`.
- `zones/`: zone files: the RFC examples (RFC 1035 §5, RFC 4035 and RFC 5155 Appendix A) and `every_type.zone`.
- `odoh/`: the Cloudflare ODoH config and the odoh-go vectors; its `README.md` gives their sources.
- `doh/`: responses of public DoH servers (`capture.nu` has the commands), read by `crates/dedens-net`'s tests.
- `coap/`: datagrams of aiocoap and libcoap (`capture.nu` has the commands), read by `crates/dedens-net`'s tests
  and `benches/coap.rs` of `dedens-bench`; their bodies draw on `doh/`.
- `plugins/`: published blocklists and hosts files, read by `crates/dedens-plugins`'s tests and
  `benches/blocklist.rs` of `dedens-bench`.
