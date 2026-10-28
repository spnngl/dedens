# dedens-proto tests

Conformance tests, one file per RFC (`rfc1035.rs`), each test prefixed by its section (`s4_1_4_...`); topic
files (`message.rs`, `view.rs`, `query.rs`, `text.rs`) for what spans RFCs. Shared helpers and proptest
strategies: `common/mod.rs`.

- `testdata/`: real responses from `just capture` (`scripts/capture.py`), read by `captured.rs` and used as
  fuzz seeds. Never edit by hand.
- `zones/`: zone files, the RFC examples and `every_type.zone`.
- `snapshots/`: insta snapshots; accept a reviewed change with `INSTA_UPDATE=always cargo test`.
