# dedens-proto tests

One test binary, `tests.rs` (D162): a module per topic (`wire`, `message`, `rdata`, `dnssec`, `svcb`, `edns`,
`text`), each citing in its docs the RFCs and sections it tests, and each test of an RFC section prefixed by it
(`s4_1_4_...`). Shared helpers and proptest strategies: `util.rs`.

- `message.rs` reads the responses of `testdata/proto/`; zone tests read `testdata/zones/`.
- `snapshots/`: insta snapshots, named `tests__<module>__<test>`; accept a reviewed change with
  `INSTA_UPDATE=always cargo test`.
