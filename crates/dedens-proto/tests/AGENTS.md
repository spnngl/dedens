# dedens-proto tests

Conformance tests, each test of an RFC file (`rfc1035.rs`) prefixed by its section (`s4_1_4_...`); topic
files (`message.rs`, `wire_rdata.rs`, `query.rs`, `text.rs`) for what spans RFCs. Shared helpers and proptest
strategies: `common/mod.rs`.

- `testdata/`: real responses from `just capture` (the queries of `capture.yaml`), read by `captured.rs` and
  used as fuzz seeds. Never edit by hand.
- `zones/`: zone files, the RFC examples and `every_type.zone`.
- `snapshots/`: insta snapshots; accept a reviewed change with `INSTA_UPDATE=always cargo test`.
